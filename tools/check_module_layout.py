#!/usr/bin/env python3
"""Check the module layout contract.

- every source/*.ixx is a module interface unit whose name is its stem;
- source/dllmain.cpp is the only plain TU in source/;
- every module unit is part of the CMake CXX_MODULES file set;
- source/patch.ixx exists (the only installer).
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    args = parser.parse_args()

    source = pathlib.Path(args.source)
    if not source.is_dir():
        print(f"FAIL layout: {source} is not a directory")
        return 1

    failures = 0
    units = sorted(source.glob("*.ixx"))
    if not units:
        print("FAIL layout: no module interface units found")
        return 1

    for path in units:
        text = path.read_text(encoding="utf-8", errors="replace")
        match = re.search(r"^export\s+module\s+([A-Za-z_][\w.]*)\s*;", text, re.MULTILINE)
        if match is None:
            print(f"FAIL layout: {path.name} has no `export module` line")
            failures += 1
        elif match.group(1) != path.stem:
            print(
                f"FAIL layout: {path.name} declares module {match.group(1)!r}, "
                f"expected {path.stem!r}"
            )
            failures += 1
        if not re.search(r"^module\s*;", text, re.MULTILINE):
            print(f"FAIL layout: {path.name} has no global module fragment")
            failures += 1

    plain = sorted(source.glob("*.cpp"))
    for path in plain:
        if path.name != "dllmain.cpp":
            print(f"FAIL layout: {path.name} is a second plain TU in source/")
            failures += 1

    if not (source / "patch.ixx").is_file():
        print("FAIL layout: source/patch.ixx is missing")
        failures += 1

    cmake = (source.parent / "CMakeLists.txt").read_text(encoding="utf-8")
    listed = set(re.findall(r"source/([A-Za-z_][\w]*)\.ixx", cmake))
    for path in units:
        if path.stem not in listed:
            print(f"FAIL layout: {path.stem}.ixx is not in the CMake module file set")
            failures += 1

    if failures:
        return 1
    print(f"PASS layout: {len(units)} module unit(s), one plain TU, CMake file set complete")
    return 0


if __name__ == "__main__":
    sys.exit(main())
