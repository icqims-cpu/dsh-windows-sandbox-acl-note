#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""校验仓库内 README.md 与 diagnose-dsh-acl.ps1 的 sha256 是否与 MANIFEST.json 一致。仅用标准库。"""
import hashlib, json, sys, urllib.request

BASE = "https://raw.githubusercontent.com/icqims-cpu/dsh-windows-sandbox-acl-note/main/"
FILES = [("README.md", "readme_sha256"), ("diagnose-dsh-acl.ps1", "script_sha256")]

def fetch(name):
    req = urllib.request.Request(BASE + name, headers={"User-Agent": "verify/1.0"})
    return urllib.request.urlopen(req, timeout=30).read()

def main():
    try:
        manifest = json.loads(fetch("MANIFEST.json").decode("utf-8"))
    except Exception as e:
        print("MANIFEST fetch failed:", e)
        return 2
    ok = True
    for name, key in FILES:
        expect = manifest.get(key)
        if not expect:
            print(f"{name}: MISSING_IN_MANIFEST")
            ok = False
            continue
        got = hashlib.sha256(fetch(name)).hexdigest()
        same = got == expect
        ok = ok and same
        print(f"{name}: {'PASS' if same else 'FAIL'}")
        if not same:
            print("  expect", expect)
            print("  got   ", got)
    print("RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 2

if __name__ == "__main__":
    sys.exit(main())
