#!/usr/bin/env python3
r"""Prove the ported episodes/stability bodies against the original ASI.

`source/episodes.ixx` and `source/stability.ixx` end in a marked asm tail each: the
bodies the fork (readable-fusion-opcep/source/episodic.ixx and stability.ixx, itself
ported from OpenPreCEPatch) carried for `LoadDLCs`, `BenchmarkFix` and
`CombinedRadioFreezeFix` are transcriptions of the original ZolikaPatch 7.65 ASI's
own bodies at their recovered VAs:

  * `\Episode254\`'s discovery pass (`sub_10023150`) is a C++ rebuild - the fork's
    own `DlcDiscoveryCpp`, and the refused/branched shape is covered by the native
    suite (`TestLoadDLCsDiscovery`), so it carries no proof row, exactly as in the
    fork;
  * everything else is the original's instruction stream and is compared here.

This tool decodes both streams with capstone and compares them instruction by
instruction:

  * the instruction count and the total byte length must match;
  * the mnemonic, the register operands, the stack displacements and every constant
    immediate must match;
  * only operands that name an address may differ: branch targets (call/jmp/jcc
    immediates) and absolute memory operands (the module's `.bss` resume slots read
    through `FF 25` / `FF 15`).

The original ASI is not part of this repository (it is the caller's oracle), so this
is a manual check, not a ctest target:

    python tools/verify_port_bodies.py \\
        --original ../game_refs/ZolikaPatch_original.asi.off \\
        --built build/win-x86/Release/XLivelessAddon.asi \\
        --map build/win-x86/Release/XLivelessAddon.map

Requires `capstone` (`pip install capstone`).
"""

from __future__ import annotations

import argparse
import re
import struct
import sys

import capstone


def pe(path: str):
    data = open(path, "rb").read()
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    assert data[e_lfanew : e_lfanew + 4] == b"PE\0\0", f"{path} is not a PE"
    coff = e_lfanew + 4
    nsections = struct.unpack_from("<H", data, coff + 2)[0]
    opt_size = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    image_base = struct.unpack_from("<I", data, opt + 28)[0]
    sections = []
    at = opt + opt_size
    for _ in range(nsections):
        _vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, at + 8)
        sections.append((image_base + vaddr, rawsize, rawptr))
        at += 40
    return data, sections


def va_to_offset(sections, va: int):
    for base, rawsize, rawptr in sections:
        if base <= va < base + rawsize:
            return rawptr + (va - base)
    return None


def map_symbols(path: str):
    symbols = {}
    for line in open(path, encoding="latin-1"):
        match = re.match(r"\s*0001:\S+\s+(\S+)\s+([0-9A-Fa-f]{8})(?:\s|$)", line)
        if match:
            symbols[match.group(1)] = int(match.group(2), 16)
    return symbols


def find_symbol(symbols, needle: str):
    for name, address in symbols.items():
        if needle in name:
            return address
    return None


def decode(md, data: bytes, at: int, count: int):
    insns = []
    offset = 0
    while len(insns) < count:
        found = list(md.disasm(data[at + offset : at + offset + 64], 0))
        if not found:
            break
        for insn in found:
            if len(insns) >= count:
                break
            insns.append(insn)
            offset += insn.size
    return insns


def signature(insn):
    """The comparison key: mnemonic, registers, and non-address immediates."""
    parts = [insn.mnemonic]
    branch = bool(
        insn.group(capstone.CS_GRP_JUMP)
        or insn.group(capstone.CS_GRP_CALL)
        or insn.mnemonic.startswith("ret")
    )
    for operand in insn.operands:
        if operand.type == capstone.x86.X86_OP_REG:
            parts.append(f"reg:{insn.reg_name(operand.reg)}")
        elif operand.type == capstone.x86.X86_OP_IMM:
            if branch or abs(operand.imm) > 0x00FFFFFF:
                parts.append("address")
            else:
                parts.append(f"imm:{operand.imm:#x}")
        elif operand.type == capstone.x86.X86_OP_MEM:
            mem = operand.mem
            parts.append(
                f"mem:base={insn.reg_name(mem.base) if mem.base else '-'}"
                f",idx={insn.reg_name(mem.index) if mem.index else '-'}"
                f",scale={mem.scale}"
            )
            parts.append(f"disp:{mem.disp:#x}" if (mem.base or mem.index) else "abs")
        else:
            parts.append(f"op{operand.type}")
    return " ".join(parts)


# (family, name, recovered VA in the original ASI, the built module's symbol, exact
# instruction count). The counts are the transcriptions' own (AGENTS.md: the asm
# tail is the original's instruction stream, kept as asm because that is what it is).
BODIES = [
    # episodes.ixx (fork episodic.ixx:674-717)
    ("episodes", "dlc_dummy", 0x10023480, "DlcDummyBody", 2),
    ("episodes", "dlc_struct_fixup", 0x10023490, "DlcStructFixupBody", 19),
    # stability.ixx (fork stability.ixx:355-366, 571-615)
    ("stability", "benchmark_a", 0x10005650, "BenchmarkBodyA", 12),
    ("stability", "benchmark_b", 0x10005670, "BenchmarkBodyB", 12),
    ("stability", "combined_radio", 0x10005ED0, "CombinedRadioFreezeBody", 2),
]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original", required=True, help="the original ASI oracle")
    parser.add_argument("--built", required=True, help="the built XLivelessAddon.asi")
    parser.add_argument("--map", required=True, help="its linker map")
    args = parser.parse_args()

    original, original_sections = pe(args.original)
    built, built_sections = pe(args.built)
    symbols = map_symbols(args.map)

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True

    failures = 0
    for family, name, va, symbol_needle, count in BODIES:
        label = f"{family}/{name}"
        offset = va_to_offset(original_sections, va)
        built_va = find_symbol(symbols, symbol_needle)
        if offset is None or built_va is None:
            print(f"FAIL {label}: original offset {offset} / symbol {symbol_needle} -> {built_va}")
            failures += 1
            continue
        built_offset = va_to_offset(built_sections, built_va)

        original_insns = decode(md, original, offset, count)
        built_insns = decode(md, built, built_offset, count)
        original_size = sum(insn.size for insn in original_insns)
        built_size = sum(insn.size for insn in built_insns)

        ok = (
            len(original_insns) == count
            and len(built_insns) == count
            and original_size == built_size
        )
        detail = []
        if not ok:
            detail.append(
                f"{len(original_insns)} insn/{original_size} B vs "
                f"{len(built_insns)} insn/{built_size} B"
            )
        for index, (left, right) in enumerate(zip(original_insns, built_insns)):
            if signature(left) != signature(right):
                ok = False
                detail.append(
                    f"[{index}] orig {left.mnemonic} {left.op_str} vs "
                    f"built {right.mnemonic} {right.op_str}"
                )
        if ok:
            print(
                f"PASS {label}: {count} instruction(s), {original_size} byte(s) identical "
                f"apart from address operands"
            )
        else:
            failures += 1
            print(f"FAIL {label}: " + "; ".join(detail))

    print(f"{len(BODIES) - failures}/{len(BODIES)} transcribed body/bodies match")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
