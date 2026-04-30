#!/usr/bin/env python3
import os
import shutil
import subprocess
import sys
import urllib.request


URLS = {
    "libc6.deb": "https://archive.ubuntu.com/ubuntu/pool/main/g/glibc/libc6_2.39-0ubuntu8_amd64.deb",
    "libseccomp2.deb": "https://archive.ubuntu.com/ubuntu/pool/main/libs/libseccomp/libseccomp2_2.5.5-1ubuntu3.1_amd64.deb",
}


def extract_ar_member(deb_path, extract_dir, zstd):
    data = open(deb_path, "rb").read()
    if not data.startswith(b"!<arch>\n"):
        raise SystemExit(f"bad deb archive: {deb_path}")

    off = 8
    while off + 60 <= len(data):
        member = data[off : off + 16].decode().strip().rstrip("/")
        size = int(data[off + 48 : off + 58].decode().strip())
        off += 60
        blob = data[off : off + size]
        off += size + (size % 2)

        if not member.startswith("data.tar"):
            continue

        tarball = f"{deb_path}.{member}"
        open(tarball, "wb").write(blob)
        if member.endswith(".zst"):
            p1 = subprocess.Popen([zstd, "-d", "-c", tarball], stdout=subprocess.PIPE)
            p2 = subprocess.run(["/bin/tar", "-C", extract_dir, "-xf", "-"], stdin=p1.stdout)
            p1.stdout.close()
            rc = p1.wait()
            if rc or p2.returncode:
                raise SystemExit(f"extract failed for {tarball}: {rc}/{p2.returncode}")
        else:
            subprocess.check_call(["/bin/tar", "-C", extract_dir, "-xf", tarball])
        return

    raise SystemExit(f"no data.tar member in {deb_path}")


def copy_tree_contents(src, dst):
    if not os.path.isdir(src):
        return

    os.makedirs(dst, exist_ok=True)
    for item in os.listdir(src):
        s = os.path.join(src, item)
        d = os.path.join(dst, item)
        if os.path.lexists(d):
            if os.path.isdir(d) and not os.path.islink(d):
                shutil.rmtree(d)
            else:
                os.unlink(d)

        if os.path.islink(s):
            os.symlink(os.readlink(s), d)
        elif os.path.isdir(s):
            shutil.copytree(s, d, symlinks=True)
        else:
            shutil.copy2(s, d)


def main():
    work = sys.argv[1]
    pyroot = os.environ.get("PYROOT", "/tmp/pyroot")
    libdir = os.path.join(work, "ubuntu-libs")
    extract_dir = os.path.join(libdir, "extract")
    zstd = os.path.join(pyroot, "usr/bin/zstd")
    if not os.path.exists(zstd):
        zstd = "/usr/bin/zstd"

    os.makedirs(libdir, exist_ok=True)
    shutil.rmtree(extract_dir, ignore_errors=True)
    os.makedirs(extract_dir, exist_ok=True)

    for name, url in URLS.items():
        path = os.path.join(libdir, name)
        if not os.path.exists(path) or os.path.getsize(path) < 1024:
            print(f"[+] downloading {url}", flush=True)
            urllib.request.urlretrieve(url, path)
        extract_ar_member(path, extract_dir, zstd)

    copy_tree_contents(os.path.join(extract_dir, "usr/lib64"), "/lib64")
    copy_tree_contents(os.path.join(extract_dir, "usr/lib/x86_64-linux-gnu"), "/lib/x86_64-linux-gnu")
    print("[+] glibc loader/libs installed", flush=True)


if __name__ == "__main__":
    main()
