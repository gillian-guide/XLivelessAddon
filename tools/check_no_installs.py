#!/usr/bin/env python3
"""Fail the build if a feature module installs anything itself.

`source/patch.ixx` is the only unit allowed to touch the game image or the IAT.
A feature module describes a site and calls `patch::...`; it must never name the
vendored installer, the branch helpers or VirtualProtect. This is the
FusionFixSkeleton `ffx_no_patches` invariant, adapted to the store/branch API
this tree exports.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

FORBIDDEN = [
    (re.compile(r"\binjector::"), "injector store/branch"),
    (re.compile(r"\bsafetyhook::"), "safetyhook"),
    (re.compile(r"\bMake(?:JMP|CALL|NOP|RET)\s*\("), "injector Make* branch"),
    (re.compile(r"\bWriteMemory(?:Raw)?\s*\("), "injector write"),
    (re.compile(r"\bMemoryFill\s*\("), "injector fill"),
    (re.compile(r"\bVirtualProtect\s*\("), "VirtualProtect"),
    (re.compile(r"\bWriteProcessMemory\s*\("), "WriteProcessMemory"),
    (re.compile(r"\bGetBranchDestination\s*\("), "branch destination"),
    (re.compile(r"\bIATHook\b"), "IATHook"),
]

ALLOWED = {"patch.ixx"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    args = parser.parse_args()

    source = pathlib.Path(args.source)
    if not (source / "patch.ixx").is_file():
        print("FAIL no-installs: source/patch.ixx is missing")
        return 1

    failures = 0
    for path in sorted(source.glob("*")):
        if path.suffix not in {".ixx", ".cpp"}:
            continue
        if path.name in ALLOWED:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for line_number, line in enumerate(text.splitlines(), start=1):
            for pattern, what in FORBIDDEN:
                if pattern.search(line):
                    print(f"FAIL no-installs: {path.name}:{line_number}: {what}: {line.strip()}")
                    failures += 1

    if failures:
        print(f"{failures} install call(s) outside source/patch.ixx")
        return 1
    print("PASS no-installs: every store/branch is in source/patch.ixx")
    return 0


if __name__ == "__main__":
    sys.exit(main())
