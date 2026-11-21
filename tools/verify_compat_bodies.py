#!/usr/bin/env python3
"""Prove the transcribed compatibility bodies against the original ASI.

`source/compatibility.ixx` ends in a marked asm tail: the bodies OpenPreCEPatch carried
for `NewFilesCompatibility`/`NewSavesCompatibility` are transcriptions of the original
ZolikaPatch 7.65 ASI's own bodies at their recovered VAs (the two update bodies and the
prepare/convert pair are C++ rebuilds and carry no proof row, exactly as in the fork).

This tool decodes both streams with capstone and compares them instruction by
instruction:

  * the instruction count and the total byte length must match;
  * the mnemonic, the register operands, the stack displacements and every constant
    immediate must match (so `push 5`, `cmp bl,22h` and `imul eax,eax,401h` cannot
    drift);
  * only operands that name an address may differ: branch targets (call/jmp/jcc
    immediates), absolute memory operands (the `.bss` slots and the /GS cookie) and a
    `push OFFSET <data>` literal.

The original ASI is not part of this repository (it is the caller's oracle), so this is
a manual check, not a ctest target:

    python tools/verify_compat_bodies.py \\
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
            # A branch target and a pushed OFFSET (an address of the module's own
            # data) differ between the two binaries; every other immediate is a
            # constant the transcription must keep.
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


# (name, recovered VA in the original ASI, the built module's symbol, exact
# instruction count). The counts are the transcription's own (AGENTS.md: the asm tail
# is the original's instruction stream, kept as asm because that is what it is).
BODIES = [
    ("register_tail", 0x10051600, "NewfilesRegisterBody", 4),
    ("read_hook", 0x10051A90, "NewSavesReadHook", 20),
    ("second_load", 0x10051AD0, "NewSavesSecondLoadHook", 33),
    ("trampoline", 0x100521E0, "NewSavesTrampoline", 8),
    ("resolver", 0x10003E50, "ResolveFileNameBody", 67),
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
    for name, va, symbol_needle, count in BODIES:
        offset = va_to_offset(original_sections, va)
        built_va = find_symbol(symbols, symbol_needle)
        if offset is None or built_va is None:
            print(f"FAIL {name}: original offset {offset} / symbol {symbol_needle} -> {built_va}")
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
                f"PASS {name}: {count} instruction(s), {original_size} byte(s) identical "
                f"apart from address operands"
            )
        else:
            failures += 1
            print(f"FAIL {name}: " + "; ".join(detail))

    print(f"{len(BODIES) - failures}/{len(BODIES)} transcribed body/bodies match")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
