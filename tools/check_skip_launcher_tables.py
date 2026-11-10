#!/usr/bin/env python3
"""Recovered-table parity for the readable SkipLauncher rewrite.

The data in `source/skip_launcher_recovered.inc` and the shipping rows in
`source/skip_launcher.ixx` are recovered data, not code. This check resolves the
named offsets and the `ops::` windows back to bytes and compares the result with
`tests/skip_launcher_tables.tsv`, captured from the old addon's pre-modular
source. A row added, removed, reordered or changed fails the test.

Run it directly, or through CTest (`xla_skip_tables`).
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

OPS = {
    "kJmpRel8": "EB",
    "kJmpRel32": "E9",
    "kRet": "C3",
    "kXorEaxEax": "33C0",
    "kNopMovMoffsEax": "90A3",
    "kNop2": "9090",
    "kNop3": "909090",
    "kNop4": "90909090",
    "kNop6": "90" * 6,
    "kNop8": "90" * 8,
    "kNop11": "90" * 11,
    "kNop14": "90" * 14,
    "kXorEaxRetNop": "33C0C390",
    "kMovAl1RetNop": "B001C390",
    "kRet8": "C20800",
}


def strip_comments(text: str) -> str:
    out = []
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


def join_literals(text: str) -> str:
    return re.sub(r'"\s*\n?\s*"', "", text)


def split_fields(text: str) -> list[str]:
    fields = []
    depth = 0
    start = 0
    i = 0
    while i < len(text):
        c = text[i]
        if c == '"':
            i += 1
            while i < len(text):
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == '"':
                    break
                i += 1
            i += 1
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "," and depth == 0:
            fields.append(text[start:i].strip())
            start = i + 1
        i += 1
    tail = text[start:].strip()
    if tail:
        fields.append(tail)
    return fields


def block(text: str, header: str) -> str:
    start = text.index(header)
    i = text.index("{", start)
    depth = 0
    for j in range(i, len(text)):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return text[i + 1 : j]
    raise RuntimeError(f"unbalanced block: {header}")


def call(text: str):
    name, args = text.split("(", 1)
    args = args.rsplit(")", 1)[0]
    return name.strip(), [a.strip() for a in split_fields(args)]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--golden", required=True, type=Path)
    args = parser.parse_args()

    inc = join_literals(strip_comments(
        (args.source / "skip_launcher_recovered.inc").read_text(encoding="utf-8")))
    ixx = join_literals(strip_comments(
        (args.source / "skip_launcher.ixx").read_text(encoding="utf-8")))

    consts = {"kSkipLauncherJumpTargetEntry": 1}
    for text in (inc, ixx):
        for match in re.finditer(
            r"constexpr\s+std::(?:u?int(?:8|16|32)_t)\s+(k\w+)\s*=\s*([^;]+);", text
        ):
            consts[match.group(1)] = int(match.group(2).strip(), 0)

    def resolve(expr: str) -> int:
        expr = expr.strip()
        return consts[expr] if expr in consts else int(expr, 0)

    entries = []
    for index, row in enumerate(split_fields(block(inc, "constexpr Entry kEntries[] = {"))):
        match = re.match(
            r'\{"([^"]*)",\s*"([^"]*)",\s*(kEntry\d+Edits|std::span<const Edit>\{\})\}',
            row,
            re.S,
        )
        if not match:
            raise SystemExit(f"cannot parse entry row {index}: {row}")
        entries.append((match.group(1), match.group(2), match.group(3)))

    edit_arrays = {
        match.group(1): match.group(2)
        for match in re.finditer(
            r"constexpr Edit (kEntry\d+Edits)\[\] = \{(.*?)\n    \};", inc, re.S
        )
    }

    entry_records = []
    write_records = []
    for index, (_label, signature, edits_name) in enumerate(entries):
        entry_records.append(f"entry\t{index}\t{signature}")
        if edits_name.startswith("std::span"):
            continue
        for field in split_fields(edit_arrays[edits_name]):
            name, call_args = call(field)
            if name == "WriteBytes":
                offset = resolve(call_args[0])
                data = OPS[call_args[1].split("ops::")[1]]
                write_records.append(f"write\t{index}\t{offset}\t{len(data) // 2}\t{data}\t-\t-")
            elif name == "Nop":
                offset = resolve(call_args[0])
                count = resolve(call_args[1])
                write_records.append(f"write\t{index}\t{offset}\t{count}\t-\t90\t-")
            elif name == "JumpTo":
                offset = resolve(call_args[0])
                target = resolve(call_args[1])
                write_records.append(f"write\t{index}\t{offset}\t4\t-\t-\t{target}")
            elif name == "XorEax":
                write_records.append(
                    f"write\t{index}\t{resolve(call_args[0])}\t2\t33C0\t-\t-")
            elif name == "XorEaxRetNop":
                write_records.append(
                    f"write\t{index}\t{resolve(call_args[0])}\t4\t33C0C390\t-\t-")
            elif name == "Ret":
                write_records.append(
                    f"write\t{index}\t{resolve(call_args[0])}\t1\tC3\t-\t-")
            else:
                raise SystemExit(f"unknown edit helper {name}")

    records = entry_records + write_records

    for index, row in enumerate(split_fields(block(inc, "constexpr Collector kCollectors[] = {"))):
        match = re.match(
            r'\{"([^"]*)",\s*"([^"]*)",\s*Collector::Target::(\w+),\s*ops::(\w+)\}',
            row,
            re.S,
        )
        if not match:
            raise SystemExit(f"cannot parse collector {index}: {row}")
        stub = OPS[match.group(4)]
        records.append(
            f"collector\t{index}\t{match.group(2)}\t{match.group(3)}\t{stub}\t{len(stub) // 2}"
        )

    capture_pattern = re.search(r'constexpr std::string_view kDfaCapturePattern = "([^"]*)"', ixx)
    capture_offset = re.search(r"constexpr std::int32_t kDfaCaptureSlotOffset = (\d+)", ixx)
    records.append(f"capture\t{capture_pattern.group(1)}\t{capture_offset.group(1)}")

    for kind, header in (
        ("dfa", "constexpr Install kDfaHooks[] = {"),
        ("rom", "constexpr Install kRomHooks[] = {"),
    ):
        for index, row in enumerate(split_fields(block(ixx, header))):
            match = re.match(
                r'\{"([^"]*)",\s*"([^"]*)",\s*([^,]+),\s*'
                r"Opcode::(kCallRel32|kJmpRel32),\s*SkipHook::(\w+)\}",
                row,
                re.S,
            )
            if not match:
                raise SystemExit(f"cannot parse {kind} install {index}: {row}")
            opcode = "E8" if match.group(4) == "kCallRel32" else "E9"
            records.append(
                f"install\t{kind}\t{index}\t{match.group(2)}\t{resolve(match.group(3))}\t"
                f"{opcode}\t{match.group(5)}"
            )

    targets = []
    for row in split_fields(block(ixx, "constexpr CollectedTarget kDfaCollectedTargets[] = {")):
        match = re.match(r'\{"([^"]*)",\s*"([^"]*)",\s*(\d+)\}', row, re.S)
        if not match:
            raise SystemExit(f"cannot parse collected target: {row}")
        targets.append((int(match.group(3)), match.group(2)))
    for index, (target_index, signature) in enumerate(targets):
        records.append(f"collectedtarget\t{index}\t{target_index}\t{signature}")

    for row in split_fields(block(ixx, "constexpr CollectedInstall kDfaCollected[] = {")):
        match = re.match(
            r'\{"([^"]*)",\s*"([^"]*)",\s*kDfaCollectedTargets,'
            r"\s*std::size\(kDfaCollectedTargets\)\}",
            row,
            re.S,
        )
        if not match:
            raise SystemExit(f"cannot parse collected install: {row}")
        records.append(f"collectedinstall\t0\t{match.group(2)}\t{len(targets)}")

    golden = [
        line
        for line in args.golden.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if records != golden:
        for index, (new, old) in enumerate(zip(records, golden)):
            if new != old:
                print(f"FAIL: first difference at record {index}:\n  new: {new}\n  old: {old}")
                break
        if len(records) != len(golden):
            print(f"FAIL: record count differs: new {len(records)} old {len(golden)}")
        return 1

    print(f"PASS: {len(records)} records match the recovered golden")
    return 0


if __name__ == "__main__":
    sys.exit(main())
