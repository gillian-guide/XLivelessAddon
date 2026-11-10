// SPDX-License-Identifier: GPL-3.0-or-later
//
// The recovered main table from the original handler at 0x10045CE0. This is a
// data include, not a module: `skip_launcher.ixx` defines the Edit/Entry types
// and includes this file inside the module.
//
// It is NOT part of the shipping path. XLivelessAddon only ever ran the DFA and
// ROM stages; applying this table after the add-on had hooked the launcher broke
// the GFWL session. It is kept because it is recovered data and because the
// native suite pins its shape; `ApplySkipLauncher(..., SkipLauncherStage::main)`
// is the only caller that applies it.
//
// Every row is one signature scan and the exact in-place instruction edits the
// original makes at the first match. The labels describe the code, the comments
// give the recovered reasoning. Do not "clean up" an offset or a byte: the
// numbers are the original's.

namespace
{
    // ---- named site offsets ------------------------------------------------
    // Match-relative byte offsets. A zero is written at the match itself; every
    // other offset is named so a row cannot hide which instruction it lands on.

    // Entry 0: the two one-byte short-branch opcodes in the same function, both
    // outside the 14-byte matched window.
    constexpr std::int32_t kEntry0Branch0 = 0x22; // +34
    constexpr std::int32_t kEntry0Branch1 = 0xDF; // +223
    // Entry 2: the second `74 E7` (jz) after `cmp [esi+6],bl`.
    constexpr std::int32_t kEntry2Branch1 = 5;
    // Entries 4/5: the `0F 85` of the two compare-and-branch windows.
    constexpr std::int32_t kEntry4Jcc = 3;
    constexpr std::int32_t kEntry5Jcc = 3;
    // Entry 7: the `75 BD` after `cmp eax,[esi+18]`, and the `A3` store five
    // bytes past the 5-byte window.
    constexpr std::int32_t kEntry7Jcc = 3;
    constexpr std::int32_t kEntry7Store = 10;
    // Entry 8: the recovered 447-byte (0x1BF) memset starts at +1.
    constexpr std::int32_t kEntry8Memset = 1;
    constexpr std::uint16_t kEntry8MemsetLength = 447;
    // Entry 9: the E9 opcode and the rel32 that follows it.
    constexpr std::int32_t kEntry9JmpOpcode = 2;
    constexpr std::int32_t kEntry9JmpRel32 = 3;
    // Entry 11: the four NOPs after the `33 C0`.
    constexpr std::int32_t kEntry11Nop = 2;
    // Entries 12/13: the 11-byte tail after the 6-byte head window.
    constexpr std::int32_t kEntry12Tail = 6;
    constexpr std::int32_t kEntry13Tail = 6;

    // ---- entry 0 -----------------------------------------------------------
    // `test bl,bl; jne +0x143; lea ecx,[esp+28]; mov eax,ecx`. Both rows write
    // the single `EB` of a short branch whose condition byte is outside the
    // matched window, so the branch becomes unconditional.
    constexpr Edit kEntry0Edits[] = {
        WriteBytes(kEntry0Branch0, ops::kJmpRel8),
        WriteBytes(kEntry0Branch1, ops::kJmpRel8),
    };

    // ---- entry 2 -----------------------------------------------------------
    // `74 EC` (jz), `cmp [esi+6],bl`, `74 E7` (jz), `push imm32`. Both jz
    // branches become NOPs.
    constexpr Edit kEntry2Edits[] = {
        WriteBytes(0, ops::kNop2),
        WriteBytes(kEntry2Branch1, ops::kNop2),
    };

    // ---- entry 3 -----------------------------------------------------------
    // `74 C4` (jz), `mov eax,[edi]`, `cmp eax,[esi+18]`, `75 BD`.
    constexpr Edit kEntry3Edits[] = {
        WriteBytes(0, ops::kNop2),
    };

    // ---- entry 4 -----------------------------------------------------------
    // `cmp edx,[esi+18]; jne rel32`: the six bytes are the whole jcc.
    constexpr Edit kEntry4Edits[] = {
        WriteBytes(kEntry4Jcc, ops::kNop6),
    };

    // ---- entry 5 -----------------------------------------------------------
    // `cmp ecx,[esi+18]; jne rel32`.
    constexpr Edit kEntry5Edits[] = {
        WriteBytes(kEntry5Jcc, ops::kNop6),
    };

    // ---- entry 6 -----------------------------------------------------------
    // `jne rel32; mov ecx,[esp+..]; pop edi/esi/ebx; xor ecx,esp`.
    constexpr Edit kEntry6Edits[] = {
        WriteBytes(0, ops::kNop6),
    };

    // ---- entry 7 -----------------------------------------------------------
    // `cmp eax,[esi+18]; jne -0x43`. +3 replaces `75 BD` with `33 C0`
    // (xor eax,eax); +10 is five bytes past the window: `90 A3`
    // (nop; mov [imm32],eax).
    constexpr Edit kEntry7Edits[] = {
        XorEax(kEntry7Jcc),
        WriteBytes(kEntry7Store, ops::kNopMovMoffsEax),
    };

    // ---- entry 8 -----------------------------------------------------------
    // `push edi; push ecx` then three `C7 44 24` immediate stores. The recovered
    // handler memsets 447 bytes starting at +1.
    constexpr Edit kEntry8Edits[] = {
        Nop(kEntry8Memset, kEntry8MemsetLength),
    };

    // ---- entry 9 -----------------------------------------------------------
    // `mov edx,[esi+1C]; cmp edx,[esi+20]; ?? ??; push 0; push 0`. The first
    // seven bytes become `33 C0 E9 rel32`: xor eax,eax, then a jump to entry 1's
    // match (the launcher entry the original keeps for this row).
    constexpr Edit kEntry9Edits[] = {
        XorEax(0),
        WriteBytes(kEntry9JmpOpcode, ops::kJmpRel32),
        JumpTo(kEntry9JmpRel32, kSkipLauncherJumpTargetEntry),
    };

    // ---- entry 10 ----------------------------------------------------------
    // `mov [imm32],esi; call; add esp,4; test al,al`. `90 A3` keeps the store
    // but takes EAX instead of ESI (the `89` becomes `90`).
    constexpr Edit kEntry10Edits[] = {
        WriteBytes(0, ops::kNopMovMoffsEax),
    };

    // ---- entry 11 ----------------------------------------------------------
    // `mov edx,[eax+2C]; cmp edx,[eax+30]` -> `33 C0` + NOP4, so the caller
    // receives eax = 0.
    constexpr Edit kEntry11Edits[] = {
        XorEax(0),
        WriteBytes(kEntry11Nop, ops::kNop4),
    };

    // ---- entry 12 ----------------------------------------------------------
    // `mov ecx,[eax+2C]; sub esp,0x78`, then the function body. NOP3 removes the
    // load; NOP11 fills the 11 bytes after the 6-byte window.
    constexpr Edit kEntry12Edits[] = {
        WriteBytes(0, ops::kNop3),
        Nop(kEntry12Tail, 11),
    };

    // ---- entry 13 ----------------------------------------------------------
    // The same with `sub esp,0x74`.
    constexpr Edit kEntry13Edits[] = {
        WriteBytes(0, ops::kNop3),
        Nop(kEntry13Tail, 11),
    };

    // ---- entry 14 ----------------------------------------------------------
    // `mov ecx,[eax+2C]; cmp ecx,[eax+30]; jz +3`.
    constexpr Edit kEntry14Edits[] = {
        WriteBytes(0, ops::kNop11),
    };

    // ---- entry 15 ----------------------------------------------------------
    // The same compare followed by `push ebx`.
    constexpr Edit kEntry15Edits[] = {
        Nop(0, 32),
    };

    // ---- entry 16 ----------------------------------------------------------
    // The same compare followed by `jz +0x11`.
    constexpr Edit kEntry16Edits[] = {
        Nop(0, 25),
    };

    // ---- entries 17/18 -----------------------------------------------------
    // `mov ecx,[eax+2C]; cmp ecx,[eax+30]; jne -0x24; lea edx,[esp+18/1C]`.
    constexpr Edit kEntry17Edits[] = {
        WriteBytes(0, ops::kNop8),
    };
    constexpr Edit kEntry18Edits[] = {
        WriteBytes(0, ops::kNop8),
    };

    // ---- entry 19 ----------------------------------------------------------
    // `mov ecx,[imm32]; mov edx,[ecx+2C]`.
    constexpr Edit kEntry19Edits[] = {
        WriteBytes(0, ops::kNop14),
    };

    // ---- entry 20 ----------------------------------------------------------
    // Prologue pushes, `mov edi,[imm32]; mov eax,[edi+2C]`; the whole function
    // becomes `ret`.
    constexpr Edit kEntry20Edits[] = {
        Ret(0),
    };

    // ---- entry 21 ----------------------------------------------------------
    // `cmp eax,edi; jne rel32; test eax,eax`.
    constexpr Edit kEntry21Edits[] = {
        Nop(0, 16),
    };

    // ---- entry 22 ----------------------------------------------------------
    // `jne rel32; test eax,eax; je rel32; call rel32; test edx,edx`.
    constexpr Edit kEntry22Edits[] = {
        WriteBytes(0, ops::kNop14),
    };

    // ---- entry 23 ----------------------------------------------------------
    // `sub esp,0x24; mov eax,[imm32]; mov ecx,[eax+14]; push ...`; the whole
    // function becomes `xor eax,eax; ret; nop`.
    constexpr Edit kEntry23Edits[] = {
        XorEaxRetNop(0),
    };

    // ---- entry 24 ----------------------------------------------------------
    // `sub esp,8; mov ecx,[imm32]; mov edx,[ecx+14]; lea eax,[esp]`.
    constexpr Edit kEntry24Edits[] = {
        XorEaxRetNop(0),
    };

    // ---- the table ---------------------------------------------------------
    // In the original's order. Entry 1 is the only row with no edits: entry 9's
    // E9 jumps to its match, so the handler keeps its address and writes nothing.
    constexpr Entry kEntries[] = {
        {"force both short launcher branches to jmp", "84 DB 0F 85 43 01 00 00 8D 4C 24 28 8B C1",
         kEntry0Edits},
        {"jump target of entry 9; no edits of its own",
         "68 ? ? ? ? 89 35 ? ? ? ? E8 ? ? ? ? 83 C4 04 84 C0 0F 84",
         std::span<const Edit>{}},
        {"nop the two conditional launcher jumps", "74 EC 38 5E 06 74 E7 68", kEntry2Edits},
        {"nop the leading conditional launcher jump", "74 C4 8B 07 3B 46 18 75 BD 68",
         kEntry3Edits},
        {"nop the edx compare-and-branch", "3B 56 18 0F 85", kEntry4Edits},
        {"nop the ecx compare-and-branch", "3B 4E 18 0F 85", kEntry5Edits},
        {"nop the leading jne of the epilogue", "0F 85 ? ? ? ? 8B 8C 24 ? ? ? ? 5F 5E 5B 33 CC C6",
         kEntry6Edits},
        {"xor eax,eax and nop the following store", "3B 46 18 75 BD", kEntry7Edits},
        {"wipe 447 bytes (EFC20)", "57 51 C7 44 24 ? ? ? ? ? C7 44 24 ? ? ? ? ? C7 44 24",
         kEntry8Edits},
        {"xor eax,eax then jump to entry 1", "8B 56 1C 3B 56 20 ? ? 6A 00 6A 00", kEntry9Edits},
        {"nop; mov [imm32],eax", "89 35 ? ? ? ? E8 ? ? ? ? 83 C4 04 84 C0", kEntry10Edits},
        {"xor eax,eax; nop4", "8B 50 2C 3B 50 30", kEntry11Edits},
        {"nop3; nop 11-byte tail (sub esp,0x78)", "8B 48 2C 83 EC 78", kEntry12Edits},
        {"nop3; nop 11-byte tail (sub esp,0x74)", "8B 48 2C 83 EC 74", kEntry13Edits},
        {"nop 11 (jz +3)", "8B 48 2C 3B 48 30 74 03", kEntry14Edits},
        {"nop 32 (push ebx)", "8B 48 2C 3B 48 30 53", kEntry15Edits},
        {"nop 25 (jz +0x11)", "8B 48 2C 3B 48 30 74 11", kEntry16Edits},
        {"nop 8 (jne -0x24, esp+18)", "8B 48 2C 3B 48 30 75 DC 8D 54 24 18", kEntry17Edits},
        {"nop 8 (jne -0x24, esp+1C)", "8B 48 2C 3B 48 30 75 DC 8D 54 24 1C", kEntry18Edits},
        {"nop 14", "8B 0D ? ? ? ? 8B 51 2C", kEntry19Edits},
        {"ret", "51 53 55 56 57 8B 3D ? ? ? ? 8B 47 2C", kEntry20Edits},
        {"nop 16", "3B C7 0F 85 ? ? ? ? 85 C0", kEntry21Edits},
        {"nop 14 (second epilogue)", "0F 85 ? ? ? ? 85 C0 0F 84 ? ? ? ? E8 ? ? ? ? 85 D2",
         kEntry22Edits},
        {"xor eax,eax; ret; nop", "83 EC 24 A1 ? ? ? ? 8B 48 14 53 55 56 57", kEntry23Edits},
        {"xor eax,eax; ret; nop (second)",
         "83 EC 08 8B 0D ? ? ? ? 8B 51 14 8D 04 24 50 6A 00 52", kEntry24Edits},
    };
    static_assert(std::size(kEntries) == 25);

    [[nodiscard]] constexpr std::int32_t EditLength(const Edit& edit) noexcept
    {
        switch (edit.kind)
        {
        case Edit::Kind::bytes:
            return static_cast<std::int32_t>(edit.bytes.size());
        case Edit::Kind::nop:
            return static_cast<std::int32_t>(edit.count);
        case Edit::Kind::jump_to_entry:
            return 4; // the rel32 after the E9
        }
        return 0;
    }

    [[nodiscard]] constexpr bool EditsFit(std::span<const Edit> edits) noexcept
    {
        for (const Edit& edit : edits)
        {
            if (edit.offset < 0 || edit.offset + EditLength(edit) > kMaxPatchExtent)
            {
                return false;
            }
        }
        return true;
    }

    [[nodiscard]] constexpr bool AllEntriesFit() noexcept
    {
        for (const Entry& entry : kEntries)
        {
            if (!EditsFit(entry.edits))
            {
                return false;
            }
        }
        return true;
    }
    static_assert(AllEntriesFit());

    // ---- the multi-hit collectors -----------------------------------------
    // The original patches the first two matches of one pattern and the last two
    // of the other with `mov al,1; ret; nop`, forcing a function to report success.
    constexpr Collector kCollectors[] = {
        {"force the first two matches to report success",
         "A1 ? ? ? ? 85 C0 8B 0D ? ? ? ? 75", Collector::Target::first_two, ops::kMovAl1RetNop},
        {"force the last two matches to report success",
         "33 C0 83 3D ? ? ? ? 01 0F 94 C0 C3", Collector::Target::last_two, ops::kMovAl1RetNop},
    };
    static_assert(std::size(kCollectors) == 2);
} // namespace
