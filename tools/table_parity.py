#!/usr/bin/env python3
"""Recovered-table parity check for XLivelessAddon.

The launcher tables and the `[v1005]` NOP plan are recovered data: signature
strings, offsets, lengths, stored bytes, fill values, jump-target entries, the
install rows (opcode + hook) and the collectors. This check parses the current
sources, resolves every `ops::` window / `Byte(Opcode::…)` back to the bytes it
writes and every named `constexpr` site offset back to its integer, and compares
the result with a committed golden captured from the pre-modular source:

  tests/skip_launcher_tables.tsv  25 entries, 32 write rows, 2 collectors,
                                  the DFA capture pattern/offset, 8 install rows,
                                  2 collected targets, 1 collected install
  tests/patches_v1005.tsv         the nine `[v1005]` missing-test rows and their
                                  exact NOP plan (head 3 at +0, tail 11 at +6 for
                                  the 2/9 and 3/9 rows)

Failing cases: any table row added/removed/reordered, any offset/length/byte/fill/
jump/opcode/hook/target change, a `ops::` window whose bytes changed, or a
`[v1005]` row whose writes changed (including the two tail NOPs that the
double-scan fix restored).

Run it directly, or through CTest (`xla_table_parity`).
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Lexing helpers
# ---------------------------------------------------------------------------


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


def join_literals(text: str) -> str:
    return re.sub(r'"\s*\n?\s*"', "", text)


def split_fields(text: str) -> list[str]:
    fields: list[str] = []
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


def brace_groups(inner: str) -> list[str]:
    """Yield the body of each top-level {...} group in `inner`."""
    groups: list[str] = []
    depth = 0
    start = 0
    i = 0
    while i < len(inner):
        c = inner[i]
        if c == '"':
            i += 1
            while i < len(inner):
                if inner[i] == "\\":
                    i += 2
                    continue
                if inner[i] == '"':
                    break
                i += 1
            i += 1
            continue
        if c == "{":
            if depth == 0:
                start = i + 1
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                groups.append(inner[start:i])
        i += 1
    return groups


def block_body(text: str, pattern: str) -> str | None:
    match = re.search(pattern, text)
    if not match:
        return None
    start = text.find("{", match.end())
    if start < 0:
        return None
    depth = 0
    i = start
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
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[start + 1:i]
        i += 1
    return None


def blocks(text: str, pattern: str) -> list[tuple[str, str]]:
    """All (name, body) for `pattern` declarations in `text`."""
    found: list[tuple[str, str]] = []
    for match in re.finditer(pattern, text):
        start = text.find("{", match.end())
        if start < 0:
            continue
        depth = 0
        i = start
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
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    found.append((match.group(1), text[start + 1:i]))
                    break
            i += 1
    return found


# ---------------------------------------------------------------------------
# Source parsing
# ---------------------------------------------------------------------------


def parse_opcodes(common: str) -> dict[str, int]:
    values: dict[str, int] = {}
    block = block_body(common, r"enum class Opcode\s*:\s*std::uint8_t")
    if block:
        for match in re.finditer(r"(\w+)\s*=\s*0x([0-9A-Fa-f]+)", block):
            values[match.group(1)] = int(match.group(2), 16)
    return values


def parse_byte_arrays(text: str, opcodes: dict[str, int]) -> dict[str, list[int]]:
    arrays: dict[str, list[int]] = {}
    for name, body in blocks(
            text,
            r"(?:inline\s+)?(?:constexpr\s+|const\s+)?(?:std::)?uint8_t\s+(\w+)\s*\[\s*\]\s*(?:=\s*)?"):
        values: list[int] = []
        for token in re.finditer(r"Byte\(Opcode::(\w+)\)|0x([0-9A-Fa-f]{1,2})", body):
            if token.group(1):
                values.append(opcodes[token.group(1)])
            else:
                values.append(int(token.group(2), 16))
        arrays[name] = values
    return arrays


def resolve_bytes(expr: str, arrays: dict[str, list[int]]) -> list[int] | None:
    expr = expr.strip()
    if expr == "nullptr":
        return None
    if expr.startswith("ops::"):
        expr = expr.split("::", 1)[1]
    if expr not in arrays:
        raise SystemExit(f"table_parity: cannot resolve byte array {expr!r}")
    return arrays[expr]


def parse_int_constants(text: str) -> dict[str, int]:
    """Resolve `constexpr <int type> kName = <literal>;` to its value.

    The tables name their site offsets (a bare +34 or -165 in a row is not
    reviewable), so the parser has to follow the identifier back to the number
    before it can render the golden.
    """
    values: dict[str, int] = {}
    for match in re.finditer(
            r"(?:inline\s+)?constexpr\s+(?:std::)?(?:u?int(?:16|32)_t|size_t|int)\s+"
            r"(\w+)\s*=\s*(-?(?:0[xX][0-9A-Fa-f]+|\d+))\s*;", text):
        values[match.group(1)] = int(match.group(2), 0)
    return values


def parse_integer(expr: str, constants: dict[str, int], what: str) -> int:
    expr = expr.strip()
    if expr in constants:
        return constants[expr]
    if re.fullmatch(r"-?(?:0[xX][0-9A-Fa-f]+|\d+)", expr):
        return int(expr, 0)
    raise SystemExit(f"table_parity: cannot resolve {what} {expr!r}")


# The named builders that expand to one recovered byte window. `WriteBytes`
# takes the window as an argument; these are the single-instruction aliases.
FORCED_OPS = {
    "ForceEaxZero": "kXorEaxEax",
    "ForceEaxZeroRetNop": "kXorEaxRetNop",
    "ForceRet": "kRet",
}


def parse_patch_ops(text: str, arrays: dict[str, list[int]], jump_target: int,
                    constants: dict[str, int]) -> dict[str, list[dict]]:
    """Parse every `PatchOp <name>[] = { WriteBytes(...), NopFill(...), ... }`.

    A byte row's length is derived from the span it names (there is no second
    number in the table); a fill row carries its count and the recovered NOP
    byte; a jump row is the four rel32 bytes the branch builder rewrites.
    """
    tables: dict[str, list[dict]] = {}
    for name, body in blocks(text, r"PatchOp\s+(\w+)\s*\[\s*\]\s*="):
        rows: list[dict] = []
        for expression in split_fields(body):
            expression = expression.strip()
            if not expression:
                continue
            call = re.fullmatch(r"(\w+)\s*\((.*)\)", expression, re.S)
            if not call:
                raise SystemExit(f"table_parity: {name}: cannot parse op {expression!r}")
            helper = call.group(1)
            arguments = split_fields(call.group(2))
            if helper == "WriteBytes":
                if len(arguments) != 2:
                    raise SystemExit(f"table_parity: {name}: WriteBytes needs 2 arguments")
                offset = parse_integer(arguments[0], constants, "write offset")
                stored = resolve_bytes(arguments[1], arrays)
                if stored is None:
                    raise SystemExit(f"table_parity: {name}: WriteBytes(nullptr)")
                rows.append({"offset": offset, "length": len(stored), "bytes": stored,
                             "fill": None, "jump": None})
            elif helper == "NopFill":
                if len(arguments) != 2:
                    raise SystemExit(f"table_parity: {name}: NopFill needs 2 arguments")
                offset = parse_integer(arguments[0], constants, "fill offset")
                count = parse_integer(arguments[1], constants, "fill count")
                rows.append({"offset": offset, "length": count, "bytes": None,
                             "fill": 0x90, "jump": None})
            elif helper == "Jump":
                if len(arguments) != 2:
                    raise SystemExit(f"table_parity: {name}: Jump needs 2 arguments")
                offset = parse_integer(arguments[0], constants, "jump offset")
                target_expr = arguments[1].strip()
                target = jump_target if target_expr == "kSkipLauncherJumpTargetEntry" \
                    else parse_integer(target_expr, constants, "jump target")
                rows.append({"offset": offset, "length": 4, "bytes": None,
                             "fill": None, "jump": target})
            elif helper in FORCED_OPS:
                if len(arguments) != 1:
                    raise SystemExit(f"table_parity: {name}: {helper} needs 1 argument")
                offset = parse_integer(arguments[0], constants, "write offset")
                stored = arrays[FORCED_OPS[helper]]
                rows.append({"offset": offset, "length": len(stored), "bytes": stored,
                             "fill": None, "jump": None})
            else:
                raise SystemExit(f"table_parity: {name}: unknown patch helper {helper!r}")
        tables[name] = rows
    return tables


def parse_entries(text: str, op_tables: dict[str, list[dict]]) -> list[dict]:
    body = block_body(text, r"EntryPatch\s+kSkipLauncherEntries\s*\[\s*\]\s*=")
    if body is None:
        raise SystemExit("table_parity: kSkipLauncherEntries not found")
    entries: list[dict] = []
    for group in brace_groups(body):
        fields = split_fields(group)
        if len(fields) != 2:
            raise SystemExit(f"table_parity: entry row has {len(fields)} fields")
        signature = fields[0].strip()
        if not (signature.startswith('"') and signature.endswith('"')):
            raise SystemExit(f"table_parity: entry signature {signature!r}")
        ops_expr = fields[1].strip()
        if ops_expr.endswith("{}"):
            # The empty span spells "this entry has no edits" (`{}` or the
            # explicit `std::span<const PatchOp>{}`).
            entries.append({"signature": signature[1:-1], "writes": None})
        elif ops_expr in op_tables:
            entries.append({"signature": signature[1:-1], "writes": ops_expr})
        else:
            raise SystemExit(f"table_parity: {signature[1:-1]!r}: unknown ops {ops_expr!r}")
    return entries


def parse_collectors(text: str, arrays: dict[str, list[int]],
                     constants: dict[str, int]) -> list[dict]:
    body = block_body(text, r"SkipLauncherCollector\s+kSkipLauncherCollectors\s*\[\s*\]\s*=")
    if body is None:
        raise SystemExit("table_parity: kSkipLauncherCollectors not found")
    collectors: list[dict] = []
    for group in brace_groups(body):
        fields = split_fields(group)
        if len(fields) != 4:
            raise SystemExit(f"table_parity: collector row has {len(fields)} fields")
        pattern = fields[0].strip().strip('"')
        target = fields[1].strip()
        if target.endswith("first_two"):
            target = "first_two"
        elif target.endswith("last_two"):
            target = "last_two"
        else:
            raise SystemExit(f"table_parity: unknown collector target {fields[1]!r}")
        stub_bytes = resolve_bytes(fields[2], arrays)
        length_expr = fields[3].strip()
        # `kCollectorStubLength` is std::size(ops::kMovAl1RetNop) in the source;
        # derive it from the stub the row names instead of hard-coding 4 here.
        length = len(stub_bytes) if length_expr == "kCollectorStubLength" \
            else parse_integer(length_expr, constants, "collector length")
        collectors.append({"pattern": pattern, "target": target,
                           "bytes": stub_bytes, "length": length})
    return collectors


def parse_capture(text: str) -> tuple[str, int]:
    pattern_match = re.search(r'kDfaCapturePattern\s*=\s*"([^"]*)"', text)
    offset_match = re.search(r"kDfaCaptureSlotOffset\s*=\s*(\d+)", text)
    if not pattern_match or not offset_match:
        raise SystemExit("table_parity: capture constants not found")
    return pattern_match.group(1), int(offset_match.group(1))


def parse_installs(text: str, opcodes: dict[str, int],
                   constants: dict[str, int]) -> dict[str, list[dict]]:
    installs: dict[str, list[dict]] = {}
    for table in ("kSkipLauncherDfaInstalls", "kSkipLauncherRomInstalls"):
        body = block_body(text, rf"SkipLauncherInstall\s+{table}\s*\[\s*\]\s*=")
        if body is None:
            raise SystemExit(f"table_parity: {table} not found")
        rows: list[dict] = []
        for group in brace_groups(body):
            fields = split_fields(group)
            if len(fields) != 4:
                raise SystemExit(f"table_parity: {table} row has {len(fields)} fields")
            signature = fields[0].strip().strip('"')
            offset = parse_integer(fields[1], constants, f"{table} site offset")
            opcode_expr = fields[2].strip()
            if opcode_expr.startswith("Opcode::"):
                opcode = opcodes[opcode_expr.split("::", 1)[1]]
            elif opcode_expr in ("kCallOpcode", "kJumpOpcode"):
                # Pre-modular spelling; only the one-off golden derivation sees it.
                opcode = 0xE8 if opcode_expr == "kCallOpcode" else 0xE9
            else:
                raise SystemExit(f"table_parity: unknown opcode {opcode_expr!r}")
            hook = fields[3].strip().split("::", 1)[-1]
            rows.append({"signature": signature, "offset": offset,
                         "opcode": opcode, "hook": hook})
        installs[table] = rows
    return installs


def parse_collected(text: str) -> tuple[list[dict], list[dict]]:
    targets: list[dict] = []
    for name, body in blocks(
            text, r"SkipLauncherCollectedTarget\s+(\w+)\s*\[\s*\]\s*="):
        for group in brace_groups(body):
            fields = split_fields(group)
            if len(fields) != 2:
                raise SystemExit(f"table_parity: {name} target row has {len(fields)} fields")
            targets.append({"table": name, "signature": fields[0].strip().strip('"'),
                            "index": int(fields[1])})
    installs: list[dict] = []
    body = block_body(text, r"SkipLauncherCollectedInstall\s+kSkipLauncherDfaCollected\s*\[\s*\]\s*=")
    if body is None:
        raise SystemExit("table_parity: kSkipLauncherDfaCollected not found")
    for group in brace_groups(body):
        fields = split_fields(group)
        if len(fields) != 3:
            raise SystemExit(f"table_parity: collected install row has {len(fields)} fields")
        collector = fields[0].strip().strip('"')
        target_table = fields[1].strip()
        count_expr = fields[2].strip()
        count_match = re.fullmatch(r"(?:std::size|CountOf)\((\w+)\)", count_expr)
        if not count_match:
            raise SystemExit(f"table_parity: collected install count is {count_expr!r}, "
                             "expected std::size(...)/CountOf(...)")
        installs.append({"collector": collector, "targets": target_table,
                         "count_expr": count_expr, "count_table": count_match.group(1)})
    table_counts: dict[str, int] = {}
    for target in targets:
        table_counts[target["table"]] = table_counts.get(target["table"], 0) + 1
    for install in installs:
        table = install["count_table"]
        if table not in table_counts:
            raise SystemExit(f"table_parity: collected install names unknown table {table!r}")
        install["count"] = table_counts[table]
    return targets, installs


def validate(tables: dict) -> None:
    """Invariants that must hold even if the golden file were edited to match."""

    def require(condition: bool, message: str) -> None:
        if not condition:
            raise SystemExit(f"table_parity: {message}")

    entries = tables["entries"]
    require(len(entries) == 25, f"expected 25 entries, parsed {len(entries)}")
    write_rows = 0
    referenced = set()
    for index, entry in enumerate(entries):
        require(bool(entry["signature"].strip()), f"entry {index} has an empty signature")
        if entry["writes"] is None:
            continue
        referenced.add(entry["writes"])
        require(entry["writes"] in tables["writes"],
                f"entry {index}: unknown op table {entry['writes']!r}")
        rows = tables["writes"][entry["writes"]]
        require(bool(rows), f"entry {index}: empty op table")
        for row in rows:
            write_rows += 1
            require(row["length"] > 0, f"entry {index}: zero-length op row")
            require(row["offset"] >= 0, f"entry {index}: negative op offset")
            if row["bytes"] is not None:
                require(row["fill"] is None,
                        f"entry {index} +{row['offset']}: bytes and fill both set")
                require(row["length"] == len(row["bytes"]),
                        f"entry {index} +{row['offset']}: length {row['length']} != "
                        f"{len(row['bytes'])} stored bytes")
            elif row["jump"] is None:
                require(row["fill"] == 0x90,
                        f"entry {index} +{row['offset']}: the installer writes NOPs, so "
                        f"fill must be kNop (0x90), got {row['fill']!r}")
    require(write_rows == 32, f"expected 32 patch rows, parsed {write_rows}")
    for name in tables["writes"]:
        require(name in referenced, f"patch table {name} is not referenced by any entry")
    require(len(tables["collectors"]) == 2,
            f"expected 2 collectors, parsed {len(tables['collectors'])}")
    for index, collector in enumerate(tables["collectors"]):
        require(bool(collector["pattern"].strip()), f"collector {index}: empty pattern")
        require(collector["length"] == len(collector["bytes"]),
                f"collector {index}: length {collector['length']} != "
                f"{len(collector['bytes'])} stub bytes")
    capture_pattern, capture_offset = tables["capture"]
    require(bool(capture_pattern.strip()), "capture pattern is empty")
    require(capture_offset >= 0, "capture slot offset is negative")
    dfa = tables["installs"]["kSkipLauncherDfaInstalls"]
    rom = tables["installs"]["kSkipLauncherRomInstalls"]
    require(len(dfa) == 6, f"expected 6 DFA installs, parsed {len(dfa)}")
    require(len(rom) == 2, f"expected 2 ROM installs, parsed {len(rom)}")
    for install in dfa + rom:
        require(bool(install["signature"].strip()), "install row has an empty signature")
        require(install["opcode"] in (0xE8, 0xE9),
                f"install opcode {install['opcode']:#x} is not a rel32 call/jump")
    require(len(tables["targets"]) == 2,
            f"expected 2 collected targets, parsed {len(tables['targets'])}")
    require(len(tables["collected"]) == 1,
            f"expected 1 collected install, parsed {len(tables['collected'])}")
    require(tables["collected"][0]["targets"] == "kDfaCollectedTargets_0",
            "collected install does not reference kDfaCollectedTargets_0")
    require(tables["collected"][0]["count_table"] == tables["collected"][0]["targets"],
            "collected install count names a different table")
    require(tables["collected"][0]["count"] == len(tables["targets"]),
            "collected install count does not match the target table")


def parse_tables(text: str, common: str, jump_target: int) -> dict:
    opcodes = parse_opcodes(common)
    arrays = parse_byte_arrays(common, opcodes) | parse_byte_arrays(text, opcodes)
    constants = parse_int_constants(text)
    writes = parse_patch_ops(text, arrays, jump_target, constants)
    entries = parse_entries(text, writes)
    collectors = parse_collectors(text, arrays, constants)
    capture = parse_capture(text)
    installs = parse_installs(text, opcodes, constants)
    targets, collected = parse_collected(text)
    tables = {"entries": entries, "writes": writes, "collectors": collectors,
              "capture": capture, "installs": installs, "targets": targets,
              "collected": collected}
    validate(tables)
    return tables


# ---------------------------------------------------------------------------
# Golden rendering / comparison
# ---------------------------------------------------------------------------


def hexbytes(values: list[int]) -> str:
    return "".join(f"{value:02X}" for value in values)


def render(tables: dict) -> list[str]:
    lines: list[str] = []
    for index, entry in enumerate(tables["entries"]):
        lines.append("\t".join(("entry", str(index), entry["signature"])))
    for index, entry in enumerate(tables["entries"]):
        if not entry["writes"]:
            continue
        for row in tables["writes"][entry["writes"]]:
            lines.append("\t".join((
                "write", str(index), str(row["offset"]), str(row["length"]),
                hexbytes(row["bytes"]) if row["bytes"] is not None else "-",
                "-" if row["fill"] is None else f"{row['fill']:02X}",
                "-" if row["jump"] is None else str(row["jump"]))))
    for index, collector in enumerate(tables["collectors"]):
        lines.append("\t".join(("collector", str(index), collector["pattern"],
                                collector["target"], hexbytes(collector["bytes"]),
                                str(collector["length"]))))
    lines.append("\t".join(("capture", tables["capture"][0], str(tables["capture"][1]))))
    for table, label in (("kSkipLauncherDfaInstalls", "dfa"),
                         ("kSkipLauncherRomInstalls", "rom")):
        for index, row in enumerate(tables["installs"][table]):
            lines.append("\t".join(("install", label, str(index), row["signature"],
                                    str(row["offset"]), f"{row['opcode']:02X}",
                                    row["hook"])))
    for index, target in enumerate(tables["targets"]):
        lines.append("\t".join(("collectedtarget", str(index), str(target["index"]),
                                target["signature"])))
    for index, install in enumerate(tables["collected"]):
        lines.append("\t".join(("collectedinstall", str(index), install["collector"],
                                str(install["count"]))))
    return lines


def read_golden(path: Path) -> list[str]:
    return [line for line in path.read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")]


def compare(expected: list[str], actual: list[str], name: str) -> list[str]:
    problems: list[str] = []
    if len(expected) != len(actual):
        problems.append(f"{name}: golden has {len(expected)} rows, source has {len(actual)}")
    for index in range(min(len(expected), len(actual))):
        if expected[index] != actual[index]:
            problems.append(f"{name} row {index + 1}:\n  golden: {expected[index]!r}\n"
                            f"  source: {actual[index]!r}")
    for line in expected[len(actual):]:
        problems.append(f"{name}: missing row: {line!r}")
    for line in actual[len(expected):]:
        problems.append(f"{name}: unexpected row: {line!r}")
    return problems


# ---------------------------------------------------------------------------
# [v1005] plan
# ---------------------------------------------------------------------------


def parse_v1005(text: str) -> list[str]:
    """Return the `[v1005]` rows as `label<TAB>signature<TAB>off:len;...`."""
    rows: list[str] = []
    # 1/9 is the inline `xor eax,eax; nop 4` row.
    anchor = text.find('"8B 50 2C 3B 50 30"')
    if anchor < 0:
        raise SystemExit("table_parity: v1005 1/9 row not found")
    region = text[anchor:]
    region = region[:region.find("kMissingTestSites")]
    if not re.search(r"WriteMemory<std::uint16_t>\(injector::raw_ptr\(site\),\s*kXorEaxEax",
                     region):
        raise SystemExit("table_parity: v1005 1/9 xor write not found")
    nop = re.search(r"MakeNOP\(injector::raw_ptr\(site \+ (\d+)\),\s*(\d+)", region)
    if not nop:
        raise SystemExit("table_parity: v1005 1/9 nop not found")
    rows.append(f"1/9\t8B 50 2C 3B 50 30\t0:2;{int(nop.group(1))}:{int(nop.group(2))}")

    anchor = text.find("kMissingTestSites")
    if anchor < 0:
        raise SystemExit("table_parity: kMissingTestSites not found")
    region = text[anchor:text.find("};", anchor)]
    loop_start = text.find("for (const auto& [signature, label] : kMissingTestSites)")
    if loop_start < 0:
        raise SystemExit("table_parity: missing-test loop not found")
    loop_body = text[loop_start:loop_start + 1200]
    loop_nops = re.findall(r"Nop\(site, (\d+), (\d+), label\)", loop_body)
    if len(loop_nops) != 2:
        raise SystemExit(f"table_parity: expected two head+tail NOPs, found {len(loop_nops)}")
    head, tail = loop_nops
    plan = f"{int(head[0])}:{int(head[1])};{int(tail[0])}:{int(tail[1])}"
    for signature, label in re.findall(r'\{"([0-9A-F? ]+)",\s*"([^"]+)"\}', region):
        match = re.search(r"\((\d)/9\)", label)
        if not match:
            continue
        rows.append(f"{match.group(1)}/9\t{signature}\t{plan}")
    for match in re.finditer(
            r'patch::NopFirst\(\s*"([^"]+)"\s*,\s*(-?\d+)\s*,\s*(\d+)\s*,\s*"([^"]*)"\s*\)',
            text):
        signature, offset, length, label = match.groups()
        label_match = re.search(r"\((\d)/9\)", label)
        if not label_match:
            continue
        rows.append(f"{label_match.group(1)}/9\t{signature}\t{int(offset)}:{int(length)}")
    rows.sort(key=lambda row: int(row.split("/", 1)[0]))
    labels = [row.split("\t", 1)[0] for row in rows]
    if labels != [f"{index}/9" for index in range(1, 10)]:
        raise SystemExit(f"table_parity: v1005 rows are {labels}, expected 1/9..9/9")
    for row in rows:
        plan_text = row.split("\t")[2]
        for part in plan_text.split(";"):
            offset_text, length_text = part.split(":")
            if int(offset_text) < 0 or int(length_text) <= 0:
                raise SystemExit(f"table_parity: bad v1005 plan {part!r} in {row!r}")
    return rows


# ---------------------------------------------------------------------------


def main(argv: list[str]) -> int:
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=root / "source")
    parser.add_argument("--tables", type=Path,
                        default=root / "tests" / "skip_launcher_tables.tsv")
    parser.add_argument("--v1005", type=Path, default=root / "tests" / "patches_v1005.tsv")
    args = parser.parse_args(argv)

    text = join_literals(strip_comments(
        (args.source / "skip_launcher.ixx").read_text(encoding="utf-8", errors="replace")))
    common = (args.source / "common.ixx").read_text(encoding="utf-8", errors="replace")
    jump_target_match = re.search(r"kSkipLauncherJumpTargetEntry\s*=\s*(\d+)", text)
    jump_target = int(jump_target_match.group(1)) if jump_target_match else 1

    try:
        tables = parse_tables(text, common, jump_target)
        table_golden = read_golden(args.tables)
        v1005_golden = read_golden(args.v1005)
        if not table_golden:
            raise SystemExit(f"{args.tables}: golden has 0 rows")
        if not v1005_golden:
            raise SystemExit(f"{args.v1005}: golden has 0 rows")
        problems = compare(table_golden, render(tables), "skip_launcher_tables")

        patches = join_literals(strip_comments(
            (args.source / "patches.ixx").read_text(encoding="utf-8", errors="replace")))
        v1005 = parse_v1005(patches)
        problems += compare(v1005_golden, v1005, "patches_v1005")
    except SystemExit as error:
        print(f"table parity: FAIL - {error}", file=sys.stderr)
        return 1

    if problems:
        for problem in problems:
            print("table parity: " + problem, file=sys.stderr)
        print(f"table parity: FAIL ({len(problems)} problem(s))", file=sys.stderr)
        return 1

    entries = len(tables["entries"])
    writes = sum(len(rows) for rows in tables["writes"].values())
    installs = sum(len(rows) for rows in tables["installs"].values())
    print(f"table parity: OK - {entries} entries, {writes} write rows, "
          f"{len(tables['collectors'])} collectors, {installs} install rows, "
          f"capture + {len(tables['targets'])} collected targets, "
          f"{len(tables['collected'])} collected install, {len(v1005)} v1005 rows")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
