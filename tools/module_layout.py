#!/usr/bin/env python3
"""Check the C++23 module layout of XLivelessAddon.

The layout is a contract (see AGENTS.md and GTAIV.EFLC.FusionFix):

  * one module interface unit per feature: `source/<stem>.ixx` declaring
    `export module xla.<stem>;`
  * `source/common.hxx` is the single shared include header, included in the
    `module;` global fragment of every interface unit;
  * `source/dllmain.cpp` is the only plain translation unit in `source/` (the
    entry point); the vendored libraries compile their own TUs under `external/`
    (Hooking.Patterns and the IniReader pimpl implementation);
  * every interface unit is listed in the `XLA_MODULES` CXX_MODULES file set,
    so CMake scans it instead of compiling it as an ordinary source;
  * standard headers live in `common.hxx` — nothing is included after the module
    declaration, and no `import <header>;` header units are used (CMake has no
    portable equivalent).

Run it directly, or through CTest (`xla_module_layout`).
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

PLAIN_TUS = {"dllmain.cpp"}
HEADERS = {"common.hxx"}
MODULE = re.compile(r"^\s*export\s+module\s+([A-Za-z_][\w.]*)\s*;", re.M)
IMPORT = re.compile(r"^\s*import\s+([^;]+);", re.M)
INCLUDE = re.compile(r"^\s*#include\s+", re.M)


class Failure(Exception):
    pass


def strip_comments(text: str) -> str:
    out: list[str] = []
    i, n, in_block = 0, len(text), False
    while i < n:
        c = text[i]
        if in_block:
            if text.startswith("*/", i):
                in_block = False
                i += 2
                continue
            out.append(c if c == "\n" else " ")
            i += 1
            continue
        if text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
            continue
        if text.startswith("/*", i):
            in_block = True
            i += 2
            continue
        if c in "\"'":
            quote = c
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == quote:
                    j += 1
                    break
                j += 1
            out.append(text[i:j])
            i = j
            continue
        out.append(c)
        i += 1
    return "".join(out)


def check_interface_unit(path: Path) -> list[str]:
    problems: list[str] = []
    text = strip_comments(path.read_text(encoding="utf-8", errors="replace"))
    stem = path.stem

    declarations = MODULE.findall(text)
    if len(declarations) != 1:
        problems.append(f"{path.name}: expected exactly one `export module`, found "
                        f"{len(declarations)}")
        return problems
    expected = f"xla.{stem}"
    if declarations[0] != expected:
        problems.append(f"{path.name}: declares module {declarations[0]!r}, expected {expected!r}")

    module_line = MODULE.search(text)
    fragment = text[:module_line.start()]
    if not re.search(r"^\s*module\s*;", fragment, re.M):
        problems.append(f"{path.name}: `module;` must start the global module fragment")
    if 'include "common.hxx"' not in fragment and "include <common.hxx>" not in fragment:
        problems.append(f"{path.name}: the global module fragment must include common.hxx")

    if module_line:
        tail = text[module_line.end():]
        if INCLUDE.search(tail):
            problems.append(f"{path.name}: #include after the module declaration")

    imports = [value.strip() for value in IMPORT.findall(text)]
    for value in imports:
        if value.startswith("<"):
            problems.append(f"{path.name}: header unit `import {value};` is not portable")
        elif not value.startswith("xla."):
            problems.append(f"{path.name}: imports {value!r}; only xla.* modules are allowed")
    if len(set(imports)) != len(imports):
        problems.append(f"{path.name}: duplicate import")
    return problems


def check_cmake(root: Path, modules: set[str]) -> list[str]:
    problems: list[str] = []
    text = (root / "CMakeLists.txt").read_text(encoding="utf-8")
    match = re.search(r"set\(XLA_MODULES(.*?)\)", text, re.S)
    if not match:
        return ["CMakeLists.txt: no XLA_MODULES file-set list"]
    listed = {Path(entry).stem for entry in re.findall(r"source/([\w.]+)", match.group(1))}
    missing = sorted(modules - listed)
    extra = sorted(listed - modules)
    if missing:
        problems.append(f"CMakeLists.txt: XLA_MODULES is missing {', '.join(missing)}")
    if extra:
        problems.append(f"CMakeLists.txt: XLA_MODULES lists missing files {', '.join(extra)}")
    if "FILE_SET CXX_MODULES" not in text:
        problems.append("CMakeLists.txt: modules are not a CXX_MODULES file set")
    if not re.search(r"set\(XLA_PLAIN_SOURCES(.*?)\)", text, re.S):
        problems.append("CMakeLists.txt: no XLA_PLAIN_SOURCES list")
    return problems


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    root = Path(__file__).resolve().parent.parent
    parser.add_argument("--source", type=Path, default=root / "source")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    try:
        if not args.source.is_dir():
            raise Failure(f"source directory not found: {args.source}")

        files = sorted(path for path in args.source.iterdir() if path.is_file())
        by_suffix: dict[str, list[Path]] = {}
        for path in files:
            by_suffix.setdefault(path.suffix.lower(), []).append(path)

        problems: list[str] = []
        plain = {path.name for path in by_suffix.get(".cpp", [])}
        headers = {path.name for path in by_suffix.get(".hxx", [])}
        interfaces = by_suffix.get(".ixx", [])

        if plain != PLAIN_TUS:
            problems.append(
                f"source/*.cpp is {sorted(plain)}, expected the plain TU(s) {sorted(PLAIN_TUS)}")
        if headers != HEADERS:
            problems.append(
                f"source/*.hxx is {sorted(headers)}, expected {sorted(HEADERS)}")
        if not interfaces:
            problems.append("source/ has no module interface units")

        modules = {path.stem for path in interfaces}
        for path in interfaces:
            problems.extend(check_interface_unit(path))

        problems.extend(check_cmake(root, modules))

        if problems:
            for problem in problems:
                print(f"module layout: {problem}", file=sys.stderr)
            print(f"module layout: FAIL ({len(problems)} problem(s))", file=sys.stderr)
            return 1

        if not args.quiet:
            print(f"module layout: OK - {len(interfaces)} interface units, "
                  f"{len(plain)} plain TU(s), {len(headers)} header(s)")
            for path in interfaces:
                print(f"  {path.name}: xla.{path.stem}")
        return 0
    except Failure as error:
        print(f"module layout: FAIL - {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

