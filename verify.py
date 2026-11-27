#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""校验仓库 README 与 MANIFEST 的 sha256 是否一致。仅用标准库。"""
import hashlib, json, sys, urllib.request

RAW = "https://raw.githubusercontent.com/icqims-cpu/dsh-windows-sandbox-acl-note/main/README.md"

def main():
    try:
        local = open("MANIFEST.json", encoding="utf-8").read()
    except OSError:
        local = None
    if local:
        expect = json.loads(local)["readme_sha256"]
    else:
        req = urllib.request.Request(
            "https://raw.githubusercontent.com/icqims-cpu/dsh-windows-sandbox-acl-note/main/MANIFEST.json",
            headers={"User-Agent": "verify/1.0"})
        expect = json.loads(urllib.request.urlopen(req, timeout=30).read().decode())["readme_sha256"]

    req = urllib.request.Request(RAW, headers={"User-Agent": "verify/1.0"})
    body = urllib.request.urlopen(req, timeout=30).read()
    got = hashlib.sha256(body).hexdigest()
    print("expect", expect)
    print("got   ", got)
    print("PASS" if got == expect else "FAIL")
    return 0 if got == expect else 2

if __name__ == "__main__":
    sys.exit(main())
