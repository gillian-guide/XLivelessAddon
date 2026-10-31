#!/usr/bin/env python3
"""Signature-parity check for XLivelessAddon.

The recovered add-on scans a fixed list of byte signatures. That list (and its
order) is data: a scan that disappears, moves or is re-ordered silently changes
which sites get patched. This check parses every module interface unit, rebuilds
each module's scan list in source order, and compares it against
`tests/signature_golden.tsv` - a committed golden captured from the pre-modular
source (see the file header for the exact revision and origin of every row).

Scan sites are found from their string literals, so both `hook::pattern("...")`
and `hook::pattern{...}` (and the `patch::Find`-style helpers) are covered.
Adjacent string literals are concatenated exactly as C++ does, comments are
ignored, and signatures are compared by their *byte sequence*: Hooking.Patterns
ignores every character except `?` and hex digits, so `"? 88"` and `"?88"` are
the same scan. The canonical form written in the golden is space-separated.

Failing cases:
  * a golden row had no matching scan in its module (missing),
  * a module's scans are in a different order than the golden (reordered),
  * a module scans a signature the golden does not list (unexpected addition),
  * a golden row is duplicated or claims an occurrence that does not exist,
  * the golden itself is empty or malformed (an empty golden is not parity),
  * a pattern-shaped literal has a dangling hex digit (a silently different scan).

Run it directly, or through CTest (`xla_signature_parity`).
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

HEX_DIGITS = set("0123456789abcdefABCDEF")

GROUPS = ("probe", "savegames", "skip_launcher", "windowed", "patch")

# The minimum number of golden rows; anything smaller means the golden was
# truncated and a green result would be meaningless.
MIN_GOLDEN_ROWS = 100


class Failure(Exception):
    pass


class MalformedSignature(Failure):
    pass


def strip_comments(text: str) -> str:
    """Blank out comments but keep every newline so line numbers stay valid."""
    out: list[str] = []
    i, n = 0, len(text)
    in_block = False
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


def canonical_units(literal: str) -> list[str] | None:
    """Hooking.Patterns byte sequence for `literal`, or None if it is not one.

    The vendored parser ignores every character that is not `?` or a hex digit,
    so spaces are cosmetic. A literal is pattern-shaped when it contains at least
    two units and either a space or a wildcard; plain words are not signatures.
    """
    if " " not in literal and "?" not in literal:
        return None
    units: list[str] = []
    pending: str | None = None
    for ch in literal:
        if ch == "?":
            if pending is not None:
                raise MalformedSignature(
                    f"dangling hex digit before '?' in {literal!r}")
            units.append("?")
        elif ch in HEX_DIGITS:
            if pending is None:
                pending = ch
            else:
                units.append((pending + ch).upper())
                pending = None
        elif ch.isspace():
            continue
        else:
            return None
    if pending is not None:
        raise MalformedSignature(f"dangling hex digit in {literal!r}")
    if len(units) < 2:
        return None
    return units


def pattern_scans(text: str) -> list[tuple[int, tuple[str, ...]]]:
    """Return [(first source line, canonical units)] for pattern literals, in order."""
    stripped = strip_comments(text)
    found: list[tuple[int, tuple[str, ...]]] = []
    i, n = 0, len(stripped)
    line = 1
    while i < n:
        c = stripped[i]
        if c == "\n":
            line += 1
            i += 1
            continue
        if c != '"':
            i += 1
            continue

        start_line = line
        value: list[str] = []
        i += 1
        while i < n:
            c = stripped[i]
            if c == "\n":
                line += 1
            if c == "\\":
                value.append(stripped[i:i + 2])
                i += 2
                continue
            if c == '"':
                i += 1
                break
            value.append(c)
            i += 1

        # Concatenate adjacent string literals exactly as C++ does (no separator).
        while True:
            k = i
            newlines = 0
            while k < n and stripped[k] in " \t\r\n":
                if stripped[k] == "\n":
                    newlines += 1
                k += 1
            if k < n and stripped[k] == '"':
                line += newlines
                i = k + 1
                while i < n:
                    c = stripped[i]
                    if c == "\n":
                        line += 1
                    if c == "\\":
                        value.append(stripped[i:i + 2])
                        i += 2
                        continue
                    if c == '"':
                        i += 1
                        break
                    value.append(c)
                    i += 1
                continue
            break

        literal = "".join(value)
        # Hooking.Patterns emits one wildcard byte per '?', so "??" is two bytes.
        # Every signature in this tree spells one wildcard as "?"; a copied-in
        # "??" would silently widen the pattern, so reject it outright.
        if "??" in literal:
            raise MalformedSignature(
                f"'??' in {literal!r}: Hooking.Patterns reads it as two wildcard bytes; "
                "write \"? ?\" for two wildcards or \"?\" for one")
        units = canonical_units(literal)
        if units is not None:
            found.append((start_line, tuple(units)))
    return found


def normalize(text: str) -> tuple[str, ...]:
    units = canonical_units(text)
    if units is None:
        raise Failure(f"not a signature: {text!r}")
    return tuple(units)


def read_golden(path: Path) -> list[dict]:
    rows: list[dict] = []
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not raw or raw.startswith("#"):
            continue
        fields = raw.split("\t")
        if len(fields) < 6:
            raise Failure(f"{path.name}:{number}: expected 6 or 7 tab-separated fields")
        fields += [""] * (7 - len(fields))
        order, group, index, target, origin, signature, note = fields[:7]
        try:
            row = {
                "order": int(order),
                "group": group,
                "index": int(index),
                "target": target,
                "origin": origin,
                "signature": normalize(signature),
                "note": note,
                "line": number,
            }
        except ValueError as error:
            raise Failure(f"{path.name}:{number}: {error}") from error
        rows.append(row)
    return rows


def render(units: tuple[str, ...]) -> str:
    return " ".join(units)


def validate_golden(rows: list[dict], source_dir: Path) -> None:
    if len(rows) < MIN_GOLDEN_ROWS:
        raise Failure(
            f"golden has {len(rows)} rows; at least {MIN_GOLDEN_ROWS} expected. "
            "An empty or truncated golden proves nothing.")

    orders = sorted(row["order"] for row in rows)
    if orders != list(range(len(rows))):
        raise Failure("golden `order` column is not a 0..N-1 permutation")

    seen_index: set[tuple[str, int]] = set()
    for row in rows:
        if row["group"] not in GROUPS:
            raise Failure(f"golden line {row['line']}: unknown group {row['group']!r}")
        key = (row["group"], row["index"])
        if key in seen_index:
            raise Failure(f"golden line {row['line']}: duplicate {key}")
        seen_index.add(key)
        if row["target"] == "-" and not row["note"]:
            raise Failure(f"golden line {row['line']}: consolidated row needs a note")
        if row["target"] != "-" and not (source_dir / f"{row['target']}.ixx").exists():
            raise Failure(
                f"golden line {row['line']}: target module {row['target']!r} does not exist")

    for group in GROUPS:
        indices = sorted(row["index"] for row in rows if row["group"] == group)
        if indices != list(range(len(indices))):
            raise Failure(f"golden group {group!r}: indices are not contiguous from 0")

    # A consolidated row must point at a row that is still scanned.
    for row in rows:
        if row["target"] == "-":
            twin = any(other["target"] != "-" and other["signature"] == row["signature"]
                       for other in rows)
            if not twin:
                raise Failure(
                    f"golden line {row['line']}: consolidated row has no surviving twin")


def expected_scans(rows: list[dict], module: str) -> list[dict]:
    return sorted((row for row in rows if row["target"] == module),
                  key=lambda row: row["order"])


def compare(module: str, expected: list[dict], actual: list[tuple[int, tuple[str, ...]]]) -> list[str]:
    problems: list[str] = []
    if len(expected) != len(actual):
        problems.append(
            f"{module}.ixx: {len(actual)} scans in source, golden expects {len(expected)}")
    for index in range(min(len(expected), len(actual))):
        golden = expected[index]
        line, signature = actual[index]
        if signature != golden["signature"]:
            problems.append(
                f"{module}.ixx:{line}: scan #{index} is {render(signature)!r}, "
                f"golden expects {render(golden['signature'])!r} "
                f"(original {golden['origin']}, golden line {golden['line']})")
    for extra_index in range(len(expected), len(actual)):
        line, signature = actual[extra_index]
        problems.append(
            f"{module}.ixx:{line}: unexpected scan #{extra_index} {render(signature)!r}")
    for missing_index in range(len(actual), len(expected)):
        golden = expected[missing_index]
        problems.append(
            f"{module}.ixx: scan #{missing_index} missing: {render(golden['signature'])!r} "
            f"(original {golden['origin']}, golden line {golden['line']})")
    return problems


def self_test() -> None:
    """Prove the parser handles the forms the tree uses before trusting a pass."""
    sample = """
        // hook::pattern("DE AD BE EF") must be ignored: it is a comment.
        /* hook::pattern{ "DE AD BE EF" } is ignored too. */
        auto a = hook::pattern{"8A 10 83 C0 01"};             // trailing comment
        auto b = hook::pattern("8A 88 ? ? ? ?" "88 88 ? ? ? ?");
        auto c = patch::Find("75 ? 83 C1 01", "label");
        constexpr std::string_view k = "B0 04 B2 18 B1 20";
        auto d = hook::pattern{k};
        auto not_a_scan = "hello world";
        auto not_a_scan_either = "savegames";
    """
    scans = pattern_scans(sample)
    got = [render(units) for _, units in scans]
    want = ["8A 10 83 C0 01", "8A 88 ? ? ? ? 88 88 ? ? ? ?", "75 ? 83 C1 01",
            "B0 04 B2 18 B1 20"]
    if got != want:
        raise Failure(f"parser self-test failed: got {got!r}, want {want!r}")
    if scans[0][0] != 4:
        raise Failure(f"parser self-test: wrong line number {scans[0][0]} for the first scan")
    if len(scans) != 4:
        raise Failure(f"parser self-test: expected 4 scans, got {len(scans)}")
    try:
        pattern_scans('auto x = "8A 1";')
    except MalformedSignature:
        pass
    else:
        raise Failure("parser self-test: a dangling hex digit was not rejected")
    try:
        pattern_scans('auto x = "8A ?? 0D";')
    except MalformedSignature:
        pass
    else:
        raise Failure("parser self-test: '??' was not rejected")
    # Hooking.Patterns ignores spaces, so these are the same scan.
    if normalize("?88 90") != normalize("? 88 90"):
        raise Failure("parser self-test: whitespace handling is not byte-exact")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    root = Path(__file__).resolve().parent.parent
    parser.add_argument("--source", type=Path, default=root / "source")
    parser.add_argument("--golden", type=Path, default=root / "tests" / "signature_golden.tsv")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    try:
        self_test()
        rows = read_golden(args.golden)
        validate_golden(rows, args.source)

        modules = sorted({row["target"] for row in rows if row["target"] != "-"})
        problems: list[str] = []
        summary: list[tuple[str, int]] = []
        for module in modules:
            actual = pattern_scans((args.source / f"{module}.ixx")
                                   .read_text(encoding="utf-8", errors="replace"))
            expected = expected_scans(rows, module)
            summary.append((module, len(actual)))
            problems.extend(compare(module, expected, actual))

        # A module the golden never mentions must not scan anything.
        for path in sorted(args.source.glob("*.ixx")):
            module = path.stem
            if module in modules:
                continue
            actual = pattern_scans(path.read_text(encoding="utf-8", errors="replace"))
            if actual:
                problems.append(
                    f"{path.name}: {len(actual)} scans but the golden has no rows for it")

        if problems:
            for problem in problems:
                print("signature parity: " + problem, file=sys.stderr)
            print(f"signature parity: FAIL ({len(problems)} problem(s))", file=sys.stderr)
            return 1

        mapped = sum(1 for row in rows if row["target"] != "-")
        consolidated = len(rows) - mapped
        unique = len({row["signature"] for row in rows})
        if not args.quiet:
            print(f"signature parity: OK - {len(rows)} original scan occurrences, "
                  f"{mapped} current scans, {consolidated} consolidated, "
                  f"{unique} distinct signatures")
            for module, count in summary:
                print(f"  {module}.ixx: {count}")
        return 0
    except Failure as error:
        print(f"signature parity: FAIL - {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
