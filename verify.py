#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""校验仓库 README 与 MANIFEST 的 sha256 是否一致。仅用标准库。"""
import hashlib, json, sys, urllib.request

BASE = "https://raw.githubusercontent.com/icqims-cpu/dsh-windows-sandbox-acl-note/main/"

def main():
    try:
        man = json.loads(urllib.request.urlopen(
            urllib.request.Request(BASE + "MANIFEST.json", headers={"User-Agent": "verify/1.0"}),
            timeout=30).read().decode("utf-8"))
        expect = man["readme_sha256"]
        body = urllib.request.urlopen(
            urllib.request.Request(BASE + "README.md", headers={"User-Agent": "verify/1.0"}),
            timeout=30).read()
    except Exception as e:
        print("FAIL:", e)
        return 2
    got = hashlib.sha256(body).hexdigest()
    print("expect", expect)
    print("got   ", got)
    print("PASS" if got == expect else "FAIL")
    return 0 if got == expect else 2

if __name__ == "__main__":
    sys.exit(main())
