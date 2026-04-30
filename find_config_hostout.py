#!/usr/bin/env python3


def unescape_mount(s):
    out = ""
    i = 0
    while i < len(s):
        if s[i] == "\\" and i + 3 < len(s) and s[i + 1 : i + 4].isdigit():
            out += chr(int(s[i + 1 : i + 4], 8))
            i += 4
        else:
            out += s[i]
            i += 1
    return out


for line in open("/proc/self/mountinfo"):
    parts = line.split()
    if len(parts) > 4 and parts[4] == "/config":
        root = unescape_mount(parts[3]).rstrip("/")
        print(root + "/realflag.txt")
        raise SystemExit

raise SystemExit("could not find /config in mountinfo")
