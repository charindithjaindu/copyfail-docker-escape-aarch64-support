#!/usr/bin/env python3
import os
import subprocess
import tempfile


def helper_path():
    return os.environ.get("DCF_COPYFAIL_HELPER", os.path.join(os.path.dirname(__file__), "copyfail_write"))


def copy_fail_path(path, data, offset=0):
    tmp = tempfile.NamedTemporaryFile(prefix="copyfail-payload.", delete=False)
    try:
        with tmp:
            tmp.write(data)
        subprocess.check_call([helper_path(), path, str(offset), tmp.name])
    finally:
        try:
            os.unlink(tmp.name)
        except FileNotFoundError:
            pass


def copy_fail_fd(fd, data, offset=0):
    copy_fail_path(f"/proc/{os.getpid()}/fd/{fd}", data, offset)
