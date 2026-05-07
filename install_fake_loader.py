#!/usr/bin/env python3
import json
import os
import shutil
import sys

from elf_payloads import native_arch, normalize_arch, sleep_loader_payload

STATE = "fake-loader-state.json"
DEFAULT_LOADERS = {
    "x86_64": (
        "/lib64/ld-linux-x86-64.so.2",
        "/lib/ld-linux-x86-64.so.2",
        "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
    ),
    "aarch64": (
        "/lib/ld-linux-aarch64.so.1",
        "/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1",
    ),
}


def state_path(work):
    return os.path.join(work, STATE)


def loader_paths():
    override = os.environ.get("DCF_FAKE_LOADER_PATH")
    if override:
        return [override]
    arch = normalize_arch(os.environ.get("DCF_PAYLOAD_ARCH") or native_arch())
    return list(DEFAULT_LOADERS[arch])


def backup_path(work, loader):
    safe = loader.strip("/").replace("/", "_")
    return os.path.join(work, safe + ".backup")


def install(work):
    seconds = int(os.environ.get("DCF_FAKE_LOADER_SLEEP", "1"))
    arch = normalize_arch(os.environ.get("DCF_PAYLOAD_ARCH") or native_arch())
    states = []
    payload = sleep_loader_payload(seconds, arch)

    for loader in loader_paths():
        state = {
            "path": loader,
            "existed": os.path.lexists(loader),
            "backup": backup_path(work, loader),
            "was_symlink": os.path.islink(loader),
            "symlink_target": None,
        }

        os.makedirs(os.path.dirname(loader), exist_ok=True)
        if state["existed"]:
            try:
                os.unlink(state["backup"])
            except FileNotFoundError:
                pass

            if state["was_symlink"]:
                state["symlink_target"] = os.readlink(loader)
            else:
                shutil.copy2(loader, state["backup"])

        tmp = loader + ".fake"
        with open(tmp, "wb") as f:
            f.write(payload)
        os.chmod(tmp, 0o755)
        os.replace(tmp, loader)
        states.append(state)
        print(f"[+] fake loader installed at {loader} arch={arch} sleep={seconds}s", flush=True)

    with open(state_path(work), "w") as f:
        json.dump(states, f)


def restore(work):
    try:
        with open(state_path(work)) as f:
            states = json.load(f)
    except FileNotFoundError:
        return

    if isinstance(states, dict):
        states = [states]

    for state in reversed(states):
        path = state["path"]
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass

        if state["existed"]:
            if state["was_symlink"]:
                os.symlink(state["symlink_target"], path)
            else:
                shutil.copy2(state["backup"], path)

        print(f"[+] fake loader restored at {path}", flush=True)


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in ("install", "restore"):
        raise SystemExit(f"usage: {sys.argv[0]} install|restore WORKDIR")

    if sys.argv[1] == "install":
        install(sys.argv[2])
    else:
        restore(sys.argv[2])


if __name__ == "__main__":
    main()
