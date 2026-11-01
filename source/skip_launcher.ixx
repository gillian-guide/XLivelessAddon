// SPDX-License-Identifier: GPL-3.0-or-later
//
// xla.skip_launcher — the SkipLauncher=1 launcher/SecuROM bypass: the recovered
// ZolikaPatch tables and the hook bodies they jump to.
//
// Recovered from the original's handlers, in their order:
//   0x10045CE0  the 25-signature main table and the two multi-hit collectors
//   0x10004850  the DFA file-API hooks (6 installs) and the 2 collected jumps
//   0x10004620  the ROM message-window hooks (2 installs; bodies at 0x10004570
//               and 0x10004610, service at 0x100041A0..0x10004570)
//
// What lives where
//   1. public surface — types, report, stage mask, pass entry point
//   2. recovered data — named site offsets, typed patch rows, entries, collectors,
//                       the IAT capture pattern and the install rows
//   3. the pass       — ApplySkipLauncher: main table -> collectors -> DFA
//                       capture/publish -> DFA hooks -> collected jumps -> ROM
//                       hooks, one named helper per step
//   4. hook bodies    — skip_hooks::dfa (six file-API bodies) and
//                       skip_hooks::rom (WM_ROM service + RomReset/RomSet)
//
// The data is 1:1 and must stay that way. Row order, bytes, offsets, lengths and
// fill values are pinned by tests/skip_launcher_tables.tsv (CTest
// xla_table_parity); the scan order is pinned by tests/signature_golden.tsv
// (CTest xla_signature_parity). Renaming a C++ identifier is free; changing a
// recovered number, a scan, or the order of either is a behaviour change.
//
// Writes target a caller-owned image. The installers never guess: a missing
// signature is a logged skip, and a store outside the image is an error.
//
// Two live DFA/ROM copies — deliberately not merged
//   SkipLauncher=1 (this file, step `skip-launcher`) is the ZolikaPatch path
//   (upstream dcc4f31:source/skip_launcher.cpp):
//     CreateFile   forwards through the captured IAT slot
//     CloseHandle  a fault returns -1 (EXCEPTION_EXECUTE_HANDLER)
//     ReadFile     hooks the enclosing prologue, 165 bytes before the match
//     DfaInit      0 arguments (the call site pops its own 0xC bytes)
//   SkipLauncher=0 (xla.dfa + xla.rom_window, step `launcher-stage`) is the
//   XLivelessAddon path (upstream dcc4f31:source/dllmain.cpp):
//     CreateFile   calls CreateFileA directly
//     CloseHandle  a fault continues with TRUE
//     ReadFile     hooks at +0
//     DfaInit      3 arguments, the original call shape
//   addon.ixx skips xla.dfa on EFLC 1100/1110 (DFA faulted at 0x00426440).
//   The two WM_ROM services are independent copies of one protocol: the message
//   id (43858) and the 16-entry action table agree, the window recipes and the
//   non-WM_ROM fallback do not. Nothing cross-checks them, so a protocol change
//   must be made in both files.

module;

#include "common.hxx"

export module xla.skip_launcher;

import xla.common;

// ===========================================================================
// 1. Public surface
// ===========================================================================

export namespace xla
{
    // One in-place edit of a matched launcher window. These are instruction
    // patches, not hook bodies: the recovered handler overwrites the game's own
    // launcher check at the match (a NOP, an xor, a one-byte branch, a short
    // jump), so nothing here is callable and there is no ABI to keep.
    struct PatchOp
    {
        enum class Kind : std::uint8_t
        {
            write, // store `bytes` at match + offset
            fill,  // store `count` copies of `fill` (the recovered rows are NOPs)
            jump,  // rewrite the 5-byte branch at match + offset - 1 to `target`
        };

        Kind kind{};
        std::int32_t offset{};                 // match-relative, in bytes
        std::span<const std::uint8_t> bytes{}; // write: the exact bytes (the length)
        std::uint16_t count{};                 // fill: the byte count
        std::uint8_t fill{};                   // fill: the repeated byte (NOP in the data)
        std::uint32_t target{};                // jump: the target entry index
    };

    // The patch builders. A row says what it does, and a byte row's length is the
    // size of its own data: there is no second number to keep in sync. Only the
    // members the kind uses are named; the rest are value-initialised.
    [[nodiscard]] constexpr PatchOp WriteBytes(std::int32_t offset,
                                               std::span<const std::uint8_t> bytes) noexcept
    {
        return {.kind = PatchOp::Kind::write, .offset = offset, .bytes = bytes};
    }

    [[nodiscard]] constexpr PatchOp NopFill(std::int32_t offset, std::uint16_t count) noexcept
    {
        return {.kind = PatchOp::Kind::fill,
                .offset = offset,
                .count = count,
                .fill = Byte(Opcode::kNop)};
    }

    // The rel32 of an E9 whose opcode a preceding row wrote. The installer
    // rewrites the whole branch, so the row names the rel32's offset and the
    // target entry's match supplies the destination.
    [[nodiscard]] constexpr PatchOp Jump(std::int32_t offset, std::uint32_t target) noexcept
    {
        return {.kind = PatchOp::Kind::jump, .offset = offset, .target = target};
    }

    // The byte rows that are one instruction: the name is the effect, not the op.
    [[nodiscard]] constexpr PatchOp ForceEaxZero(std::int32_t offset) noexcept
    {
        return WriteBytes(offset, ops::kXorEaxEax);
    }

    [[nodiscard]] constexpr PatchOp ForceEaxZeroRetNop(std::int32_t offset) noexcept
    {
        return WriteBytes(offset, ops::kXorEaxRetNop);
    }

    [[nodiscard]] constexpr PatchOp ForceRet(std::int32_t offset) noexcept
    {
        return WriteBytes(offset, ops::kRet);
    }

    // One recovered main-table entry: one signature scan and the edits made at
    // its first match. An empty span is the row with no edits (entry 1).
    struct EntryPatch
    {
        std::string_view signature;
        std::span<const PatchOp> ops;
    };

    // Multi-hit collector: the original patches the first two matches of one
    // pattern and the last two of another with "mov al,1; ret; nop". `stub` is the
    // exact byte window it stores; the window's size is the store length, so there
    // is no second number to keep in sync.
    struct SkipLauncherCollector
    {
        enum class Target : std::uint8_t
        {
            first_two,
            last_two,
        };

        std::string_view pattern;
        Target target;
        std::span<const std::uint8_t> stub;
    };

    // Reimplemented hook bodies the installers jump to; the original installs
    // E8/E9 jumps from the game module into its own. The comments are the
    // original's addresses and the contract each body keeps (section 4).
    enum class SkipHook : std::uint8_t
    {
        dfa_init,         // 0x10004780: return 1
        create_file,      // 0x10004820: CreateFileA through the captured slot
        close_handle,     // 0x10004790: CloseHandle with an exception guard
        set_file_pointer, // 0x10004760
        get_file_size_ex, // 0x10004720
        read_file,        // 0x10004740
        rom_reset,        // 0x10004570: ROM window setup + object reset
        rom_set,          // 0x10004610: *(u32*)(a1+32) = *(u32*)(a1+28); return 1
    };

    using SkipHookResolver = std::uintptr_t (*)(SkipHook hook, void* user);

    // One E8/E9 branch the DFA or ROM stage installs: the signature that finds
    // the site, the offset from the match, the branch opcode and the body.
    struct SkipLauncherInstall
    {
        std::string_view signature;
        std::int32_t offset;
        Opcode opcode; // kCallRel32 or kJmpRel32
        SkipHook hook;
    };

    // A collected jump: the anchor match at `index` becomes a jump to the first
    // match of `targetSignature`.
    struct SkipLauncherCollectedTarget
    {
        std::string_view targetSignature;
        std::uint32_t index;
    };

    // The collected-jump table of one anchor signature.
    struct SkipLauncherCollectedInstall
    {
        std::string_view collector;
        const SkipLauncherCollectedTarget* targets;
        std::size_t targetCount;
    };

    // What one pass changed, split by the recovered stage it belongs to. The
    // main-table counters stay 0 on the shipped path: `kShippedStages` never
    // selects `main`, so a healthy log is not reporting a failure.
    struct SkipLauncherReport
    {
        // Main table only (0x10045CE0): the 25 signature rows and 2 collectors.
        std::size_t entriesFound{};
        std::size_t entriesMissing{};
        std::size_t writes{}; // patch ops applied, jumps included
        std::size_t collectorsFound{};
        std::size_t collectorWrites{};
        bool jumpInstalled{};

        std::size_t dfaInstalls{}; // DFA hook branches written
        std::size_t dfaMissing{};  // DFA hooks absent: no body, or no signature
        std::size_t romInstalls{}; // ROM hook branches written
        std::size_t romMissing{};
        std::size_t collectedInstalls{}; // DFA collected-site jumps
        std::uint32_t createFileSlot{};  // captured IAT slot VA (0 when absent)
    };

    // The original's three passes, as a bitmask. `HasStage` is the only place a
    // caller's selection is interpreted; `ApplySkipLauncher` runs the blocks in
    // the recovered order whatever order the bits were named in.
    //
    // The original's stages: main writes, then DFA (0x10004850) under its
    // XLivelessAddon/GTAC.dll/EFLC/one-shot guards, then ROM (0x10004620) always;
    // MiscFixes calls DFA again (0x10024018).
    //
    // The shipping path applies only `kShippedStages` (DFA + ROM). The recovered
    // main table is ZolikaPatch's extra pass: XLivelessAddon only ever ran the
    // DFA and ROM stages, and applying `main` after the add-on had hooked the
    // launcher is what broke the GFWL session (dcc4f31 source/dllmain.cpp:770-773;
    // the call itself passes `dfa | rom` at :774-776). It stays available to
    // callers that pass it explicitly (tests, the parent handler's own pass).
    enum class SkipLauncherStage : std::uint8_t
    {
        main = 1,
        dfa = 2,
        rom = 4,
        all = 7,
    };

    [[nodiscard]] constexpr SkipLauncherStage operator|(SkipLauncherStage a,
                                                         SkipLauncherStage b) noexcept
    {
        return static_cast<SkipLauncherStage>(static_cast<std::uint8_t>(a) |
                                              static_cast<std::uint8_t>(b));
    }

    [[nodiscard]] constexpr bool HasStage(SkipLauncherStage set, SkipLauncherStage stage) noexcept
    {
        return (static_cast<std::uint8_t>(set) & static_cast<std::uint8_t>(stage)) != 0;
    }

    // The stages the add-on itself applies at startup: never `main`.
    inline constexpr SkipLauncherStage kShippedStages =
        SkipLauncherStage::dfa | SkipLauncherStage::rom;

    // The selected stages as their names, "main|dfa|rom" (an empty mask is
    // "none"). The shipping log uses this so it cannot disagree with the argument
    // the pass was called with.
    [[nodiscard]] std::string DescribeStages(SkipLauncherStage stages);

    // Table accessors; the spans cover the recovered rows in the golden's order.
    std::span<const EntryPatch> SkipLauncherEntries() noexcept;
    std::span<const SkipLauncherCollector> SkipLauncherCollectors() noexcept;
    std::span<const SkipLauncherInstall> SkipLauncherDfaInstalls() noexcept;
    std::span<const SkipLauncherInstall> SkipLauncherRomInstalls() noexcept;
    std::span<const SkipLauncherCollectedInstall> SkipLauncherDfaCollected() noexcept;

    // The entry whose match feeds the jump install: the original reads the second
    // entry's match into its jump-target slot (entry 9 jumps here).
    inline constexpr std::uint32_t kSkipLauncherJumpTargetEntry = 1;

    // Applies the passes selected by `stages` to `image`. Missing signatures are
    // skipped, never guessed, exactly like the original; the hook passes need
    // `resolve` and do not run without it. `stages` is required: the shipping set
    // is `kShippedStages`, which deliberately excludes the recovered `main` table.
    std::expected<SkipLauncherReport, PatchError> ApplySkipLauncher(
        std::span<std::byte> image, SkipHookResolver resolve, void* resolverUser,
        SkipLauncherStage stages);

    // Records the CreateFile IAT slot captured from the game; 0 makes the hook
    // call CreateFileA directly.
    void SetCreateFileSlot(std::uint32_t slotVa) noexcept;

    // Publishes the captured CreateFile IAT slot into the hook body. ApplySkipLauncher
    // already calls this inside the DFA stage (before the hooks can run); this entry
    // point exists for tests and out-of-band reinstalls. Returns true when a non-zero
    // slot was published.
    bool PublishCreateFileSlot(const SkipLauncherReport& report) noexcept;

    // Resolves a SkipHook to the reimplemented body; 0 for an unknown hook.
    std::uintptr_t ResolveSkipHook(SkipHook hook, void* user) noexcept;
} // namespace xla

// ===========================================================================
// 2. Recovered data
// ===========================================================================
//
// Everything in this section is recovered from the original handlers. The
// comments decode the windows; they never replace the data.
//
// Site offsets are byte counts from the signature's first matched byte. A zero
// is written inline (the match itself); every other offset is named, because a
// signed byte count in a table row hides which instruction it lands on.
//
// Build scope: the recovered main handler has no per-entry build gate. Every row
// is scanned on every recognized build and a missing signature is the only
// per-build filter — the entries come from launcher variants across the
// supported builds, so several are absent on any one image.

namespace xla
{
    namespace
    {
        constexpr std::size_t kBranchLength = 5; // E8/E9 <rel32>

        // Each collector rule covers two sites: the first two matches, or the last
        // two. (A pattern with a single match is one site for either rule.)
        constexpr std::size_t kCollectorWidth = 2;

        // ---- named site offsets -------------------------------------------

        // Entry 0: the two one-byte short-branch opcodes in the same function,
        // both outside the matched 14-byte window.
        constexpr std::int32_t kEntry0Branch0 = 0x22; // +34
        constexpr std::int32_t kEntry0Branch1 = 0xDF; // +223
        // Entry 2: the second `74 E7` (jz) after the `cmp [esi+6],bl`.
        constexpr std::int32_t kEntry2Branch1 = 5;
        // Entry 4/5: the `0F 85` of the two compare-and-branch windows.
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
        // Entry 12/13: the 11-byte tail after the 6-byte head window.
        constexpr std::int32_t kEntry12Tail = 6;
        constexpr std::int32_t kEntry13Tail = 6;
        // The hook sites outside their matched window (the enclosing function's
        // prologue, the call after the two object stores).
        constexpr std::int32_t kDfaReadFileSite = -165;
        constexpr std::int32_t kRomSetSite = -67;
        constexpr std::int32_t kRomResetCall = 6;

        // ---- the main table's inline patches (0x10045CE0) ------------------
        //
        // These are in-place instruction-window patches, not hook bodies: the
        // recovered handler overwrites the launcher check at the signature match
        // (NOPs, an xor, a one-byte branch or a short jump), so nothing here is
        // callable and there is no ABI to keep. The rows, their order and the
        // bytes are 1:1 with the handler.
        //
        // A byte row is WriteBytes: the original stored literal bytes (memcpy).
        // A fill row is NopFill: the original memset a repeated byte (the long
        // wipes). Both forms are in the golden, so the distinction is data even
        // where the resulting bytes would be equal.
        inline constexpr std::int32_t kMaxPatchExtent = 0x200;

        // Entry 0: `test bl,bl; jne +0x143; lea ecx,[esp+28]; mov eax,ecx`.
        // Both rows write the single `EB` of a short branch in the same function;
        // its condition byte is outside the matched window, so `EB` just forces it.
        constexpr PatchOp kEntry0Ops[] = {
            WriteBytes(kEntry0Branch0, ops::kJmpRel8), // jz/jnz -> jmp
            WriteBytes(kEntry0Branch1, ops::kJmpRel8),
        };
        // Entry 2: `74 EC` (jz), `cmp [esi+6],bl`, `74 E7` (jz), `push imm32`.
        constexpr PatchOp kEntry2Ops[] = {
            WriteBytes(0, ops::kNop2),
            WriteBytes(kEntry2Branch1, ops::kNop2),
        };
        // Entry 3: `74 C4` (jz), `mov eax,[edi]`, `cmp eax,[esi+18]`, `75 BD`.
        constexpr PatchOp kEntry3Ops[] = {
            WriteBytes(0, ops::kNop2),
        };
        // Entry 4: `cmp edx,[esi+18]; jne rel32`; the 6 bytes are the whole jcc.
        constexpr PatchOp kEntry4Ops[] = {
            WriteBytes(kEntry4Jcc, ops::kNop6),
        };
        // Entry 5: `cmp ecx,[esi+18]; jne rel32`.
        constexpr PatchOp kEntry5Ops[] = {
            WriteBytes(kEntry5Jcc, ops::kNop6),
        };
        // Entry 6: `jne rel32; mov ecx,[esp+..]; pop edi/esi/ebx; xor ecx,esp`.
        constexpr PatchOp kEntry6Ops[] = {
            WriteBytes(0, ops::kNop6),
        };
        // Entry 7: `cmp eax,[esi+18]; jne -0x43`. +3 replaces the `75 BD` with
        // `33 C0` (xor eax,eax); +10 is 5 bytes past the window: `90 A3`
        // (nop; mov [imm32],eax).
        constexpr PatchOp kEntry7Ops[] = {
            ForceEaxZero(kEntry7Jcc),
            WriteBytes(kEntry7Store, ops::kNopMovMoffsEax),
        };
        // Entry 8: `push edi; push ecx` then three `C7 44 24` immediate stores.
        // The recovered handler memsets 0x1BF (447) bytes starting at +1.
        constexpr PatchOp kEntry8Ops[] = {
            NopFill(kEntry8Memset, kEntry8MemsetLength),
        };
        // Entry 9: `mov edx,[esi+1C]; cmp edx,[esi+20]; ?? ??; push 0; push 0`.
        // The first 7 bytes become `33 C0 E9 rel32`: xor eax,eax, then a jump to
        // entry 1's match (the launcher entry the original keeps for this row).
        constexpr PatchOp kEntry9Ops[] = {
            ForceEaxZero(0),
            WriteBytes(kEntry9JmpOpcode, ops::kJmpRel32),
            Jump(kEntry9JmpRel32, kSkipLauncherJumpTargetEntry),
        };
        // Entry 10: `mov [imm32],esi; call; add esp,4; test al,al`. `90 A3`
        // keeps the store but takes EAX instead of ESI (the `89` becomes `90`).
        constexpr PatchOp kEntry10Ops[] = {
            WriteBytes(0, ops::kNopMovMoffsEax),
        };
        // Entry 11: `mov edx,[eax+2C]; cmp edx,[eax+30]` -> `33 C0` + NOP4, so
        // the caller receives eax = 0.
        constexpr PatchOp kEntry11Ops[] = {
            ForceEaxZero(0),
            WriteBytes(kEntry11Nop, ops::kNop4),
        };
        // Entry 12: `mov ecx,[eax+2C]; sub esp,0x78`, then the function body.
        // NOP3 removes the load; NOP11 fills the 11 bytes after the 6-byte window.
        constexpr PatchOp kEntry12Ops[] = {
            WriteBytes(0, ops::kNop3),
            NopFill(kEntry12Tail, 11),
        };
        // Entry 13: the same with `sub esp,0x74`.
        constexpr PatchOp kEntry13Ops[] = {
            WriteBytes(0, ops::kNop3),
            NopFill(kEntry13Tail, 11),
        };
        // Entry 14: `mov ecx,[eax+2C]; cmp ecx,[eax+30]; jz +3`.
        constexpr PatchOp kEntry14Ops[] = {
            WriteBytes(0, ops::kNop11),
        };
        // Entry 15: the same compare followed by `push ebx`.
        constexpr PatchOp kEntry15Ops[] = {
            NopFill(0, 32),
        };
        // Entry 16: the same compare followed by `jz +0x11`.
        constexpr PatchOp kEntry16Ops[] = {
            NopFill(0, 25),
        };
        // Entry 17/18: `mov ecx,[eax+2C]; cmp ecx,[eax+30]; jne -0x24;
        // lea edx,[esp+18/1C]`. The 8-byte compare-and-branch window is NOP'd.
        constexpr PatchOp kEntry17Ops[] = {
            WriteBytes(0, ops::kNop8),
        };
        constexpr PatchOp kEntry18Ops[] = {
            WriteBytes(0, ops::kNop8),
        };
        // Entry 19: `mov ecx,[imm32]; mov edx,[ecx+2C]`.
        constexpr PatchOp kEntry19Ops[] = {
            WriteBytes(0, ops::kNop14),
        };
        // Entry 20: prologue pushes, `mov edi,[imm32]; mov eax,[edi+2C]`.
        constexpr PatchOp kEntry20Ops[] = {
            ForceRet(0), // the whole function becomes `ret`
        };
        // Entry 21: `cmp eax,edi; jne rel32; test eax,eax`.
        constexpr PatchOp kEntry21Ops[] = {
            NopFill(0, 16),
        };
        // Entry 22: `jne rel32; test eax,eax; je rel32; call rel32; test edx,edx`.
        constexpr PatchOp kEntry22Ops[] = {
            WriteBytes(0, ops::kNop14),
        };
        // Entry 23: `sub esp,0x24; mov eax,[imm32]; mov ecx,[eax+14]; push ...`.
        constexpr PatchOp kEntry23Ops[] = {
            ForceEaxZeroRetNop(0), // xor eax,eax; ret; nop
        };
        // Entry 24: `sub esp,8; mov ecx,[imm32]; mov edx,[ecx+14]; lea eax,[esp]`.
        constexpr PatchOp kEntry24Ops[] = {
            ForceEaxZeroRetNop(0),
        };

        // ---- the main table (0x10045CE0) ----------------------------------

        // In the original's order. Entry 1 is the only row with no edits: entry
        // 9's E9 jumps to its match, so the handler keeps its address and writes
        // nothing into it.
        constexpr EntryPatch kSkipLauncherEntries[] = {
            // 0: `test bl,bl; jne` launcher check; two EB hook sites
            {"84 DB 0F 85 43 01 00 00 8D 4C 24 28 8B C1", kEntry0Ops},
            // 1: target of entry 9's jump; no edits of its own
            {"68 ? ? ? ? 89 35 ? ? ? ? E8 ? ? ? ? 83 C4 04 84 C0 0F 84",
             std::span<const PatchOp>{}},
            // 2: `74 EC` / `74 E7` conditional launcher jumps
            {"74 EC 38 5E 06 74 E7 68", kEntry2Ops},
            // 3: `74 C4` leading conditional jump
            {"74 C4 8B 07 3B 46 18 75 BD 68", kEntry3Ops},
            // 4: `cmp edx,[esi+18]; jne rel32`
            {"3B 56 18 0F 85", kEntry4Ops},
            // 5: `cmp ecx,[esi+18]; jne rel32`
            {"3B 4E 18 0F 85", kEntry5Ops},
            // 6: leading `jne rel32` of an epilogue sequence
            {"0F 85 ? ? ? ? 8B 8C 24 ? ? ? ? 5F 5E 5B 33 CC C6", kEntry6Ops},
            // 7: `cmp eax,[esi+18]; jne -0x43` and a following store
            {"3B 46 18 75 BD", kEntry7Ops},
            // 8: `push edi; push ecx` + three `C7 44 24` immediate stores
            {"57 51 C7 44 24 ? ? ? ? ? C7 44 24 ? ? ? ? ? C7 44 24", kEntry8Ops},
            // 9: `mov edx,[esi+1C]; cmp edx,[esi+20]` -> xor eax,eax; jmp entry 1
            {"8B 56 1C 3B 56 20 ? ? 6A 00 6A 00", kEntry9Ops},
            // 10: `mov [imm32],esi; call; add esp,4; test al,al`
            {"89 35 ? ? ? ? E8 ? ? ? ? 83 C4 04 84 C0", kEntry10Ops},
            // 11: `mov edx,[eax+2C]; cmp edx,[eax+30]` -> eax = 0
            {"8B 50 2C 3B 50 30", kEntry11Ops},
            // 12: `mov ecx,[eax+2C]; sub esp,0x78` + body tail
            {"8B 48 2C 83 EC 78", kEntry12Ops},
            // 13: the same with `sub esp,0x74`
            {"8B 48 2C 83 EC 74", kEntry13Ops},
            // 14: `mov ecx,[eax+2C]; cmp ecx,[eax+30]; jz +3`
            {"8B 48 2C 3B 48 30 74 03", kEntry14Ops},
            // 15: the same compare followed by `push ebx`
            {"8B 48 2C 3B 48 30 53", kEntry15Ops},
            // 16: the same compare followed by `jz +0x11`
            {"8B 48 2C 3B 48 30 74 11", kEntry16Ops},
            // 17: `... jne -0x24; lea edx,[esp+18]`
            {"8B 48 2C 3B 48 30 75 DC 8D 54 24 18", kEntry17Ops},
            // 18: `... jne -0x24; lea edx,[esp+1C]`
            {"8B 48 2C 3B 48 30 75 DC 8D 54 24 1C", kEntry18Ops},
            // 19: `mov ecx,[imm32]; mov edx,[ecx+2C]`
            {"8B 0D ? ? ? ? 8B 51 2C", kEntry19Ops},
            // 20: prologue pushes + `mov edi,[imm32]; mov eax,[edi+2C]`
            {"51 53 55 56 57 8B 3D ? ? ? ? 8B 47 2C", kEntry20Ops},
            // 21: `cmp eax,edi; jne rel32; test eax,eax`
            {"3B C7 0F 85 ? ? ? ? 85 C0", kEntry21Ops},
            // 22: `jne rel32; test eax,eax; je rel32; call rel32; test edx,edx`
            {"0F 85 ? ? ? ? 85 C0 0F 84 ? ? ? ? E8 ? ? ? ? 85 D2", kEntry22Ops},
            // 23: `sub esp,0x24; mov eax,[imm32]; mov ecx,[eax+14]; push ...`
            {"83 EC 24 A1 ? ? ? ? 8B 48 14 53 55 56 57", kEntry23Ops},
            // 24: `sub esp,8; mov ecx,[imm32]; mov edx,[ecx+14]; lea eax,[esp]`
            {"83 EC 08 8B 0D ? ? ? ? 8B 51 14 8D 04 24 50 6A 00 52", kEntry24Ops},
        };

        static_assert(std::size(kSkipLauncherEntries) == 25);

        // The builders are constexpr, so the extent of every recovered row is
        // checked at compile time: a slipped offset or count fails the build
        // instead of landing on the wrong instruction at run time.
        [[nodiscard]] constexpr std::int32_t PatchOpLength(const PatchOp& op) noexcept
        {
            switch (op.kind)
            {
            case PatchOp::Kind::write:
                return static_cast<std::int32_t>(op.bytes.size());
            case PatchOp::Kind::fill:
                return static_cast<std::int32_t>(op.count);
            case PatchOp::Kind::jump:
                return 4; // the row starts at its rel32; the branch ends at offset + 4
            }
            return 0;
        }

        [[nodiscard]] constexpr bool PatchOpsFit(std::span<const PatchOp> ops) noexcept
        {
            for (const PatchOp& op : ops)
            {
                if (op.offset < 0 || op.offset + PatchOpLength(op) > kMaxPatchExtent)
                {
                    return false;
                }
            }
            return true;
        }

        [[nodiscard]] constexpr bool TablePatchesFit() noexcept
        {
            for (const EntryPatch& entry : kSkipLauncherEntries)
            {
                if (!PatchOpsFit(entry.ops))
                {
                    return false;
                }
            }
            return true;
        }
        static_assert(TablePatchesFit());


        // ---- the multi-hit collectors --------------------------------------

        // `mov al,1; ret; nop` (B0 01 C3 90) forces a function to report success.
        // The original patches the first two matches of one pattern and the last
        // two of the other with it.
        constexpr SkipLauncherCollector kSkipLauncherCollectors[] = {
            // `mov eax,[imm32]; test eax,eax; mov ecx,[imm32]; jne`
            {"A1 ? ? ? ? 85 C0 8B 0D ? ? ? ? 75", SkipLauncherCollector::Target::first_two,
             ops::kMovAl1RetNop},
            // `xor eax,eax; cmp dword [imm32],1; sete al; ret`
            {"33 C0 83 3D ? ? ? ? 01 0F 94 C0 C3",
             SkipLauncherCollector::Target::last_two, ops::kMovAl1RetNop},
        };

        static_assert(std::size(kSkipLauncherCollectors) == 2);

        // ---- the CreateFile IAT capture ------------------------------------

        // `FF 15` is `call [imm32]`, so the IAT slot VA is the operand at +2. The
        // captured slot is what the create_file body forwards through.
        constexpr std::string_view kDfaCapturePattern = "FF 15 ? ? ? ? 8B F0 83 FE FF 74 24";
        constexpr std::int32_t kDfaCaptureSlotOffset = 2;

        // ---- the DFA hook installs (0x10004850) ----------------------------

        // Each row writes E8 (call) or E9 (jump) at `match + offset`. The offset
        // is 0 unless the hook site is outside the matched window.
        constexpr SkipLauncherInstall kSkipLauncherDfaInstalls[] = {
            // `call rel32; add esp,0xC; cmp eax,1; jz +0x11; push 0; push 0`
            // +0: the call that checks DFA init; the body reports success.
            {"E8 ? ? ? ? 83 C4 0C 83 F8 01 74 11 6A 00 6A 00", 0, Opcode::kCallRel32,
             SkipHook::dfa_init},
            // prologue `push ebp; mov ebp,esp; push 0; call`
            // +0: the prologue becomes a jump to the cdecl CreateFile body.
            {"55 8B EC 6A 00 E8", 0, Opcode::kJmpRel32, SkipHook::create_file},
            // `push 0; call; cmp eax,1; pop ecx; jne +0x17; call [slot]; ...`
            // +0: the whole function becomes a jump to the guarded CloseHandle.
            {"6A 00 E8 ? ? ? ? 83 F8 01 59 75 17 FF 15 ? ? ? ? 50 B9 ? ? ? ? E8 ? ? ? ? 8B "
             "40 08 FF 60 0C 33 C0 C3",
             0, Opcode::kJmpRel32, SkipHook::close_handle},
            // The same prologue; the tail differs (`FF 60 ?` + `or eax,-1`).
            {"6A 00 E8 ? ? ? ? 83 F8 01 59 75 17 FF 15 ? ? ? ? 50 B9 ? ? ? ? E8 ? ? ? ? 8B "
             "40 08 FF 60 ? 83 C8 FF C3",
             0, Opcode::kJmpRel32, SkipHook::set_file_pointer},
            // `push esi; mov esi,[esp+0xC]; lea eax,[esi+4]; ...`
            {"56 8B 74 24 0C 8D 46 04 50 FF 74 24 0C E8 ? ? ? ? 59 59 33 C9 83 F8 FF 0F 95 "
             "C1 89 06 5E 8B C1 C3",
             0, Opcode::kJmpRel32, SkipHook::get_file_size_ex},
            // The matched 12 bytes are the middle of the function (`call [eax+60]`
            // then the epilogue); -165 is its prologue, where the jump goes.
            {"FF 50 60 83 C4 14 39 75 F8 89 45 FC", kDfaReadFileSite,
             Opcode::kJmpRel32, SkipHook::read_file},
        };

        static_assert(std::size(kSkipLauncherDfaInstalls) == 6);

        // ---- the ROM hook installs (0x10004620) ----------------------------

        // `mov [esi+3C],eax; mov [esi+40],ecx; call rel32`
        // +6: the E8 itself; the call becomes `call RomResetBody`.
        constexpr SkipLauncherInstall kSkipLauncherRomInstalls[] = {
            {"89 46 3C 89 4E 40 E8", kRomResetCall, Opcode::kCallRel32,
             SkipHook::rom_reset},
            // `jne rel32; push 0x103; push imm32; push 0x104`
            // -67: the enclosing function's prologue, outside the matched window.
            {"0F 85 ? ? ? ? 68 03 01 00 00 68 ? ? ? ? 68 04 01 00 00", kRomSetSite,
             Opcode::kJmpRel32, SkipHook::rom_set},
        };

        static_assert(std::size(kSkipLauncherRomInstalls) == 2);

        // ---- the DFA collected jumps ---------------------------------------

        // The destinations, in the recovered order. `index` is the anchor match
        // that receives the jump; the destination is the first match of each
        // signature.
        constexpr SkipLauncherCollectedTarget kDfaCollectedTargets_0[] = {
            // `cmp byte [esp+...],imm8; push 0`
            {"80 BC 24 ? ? ? ? ? 6A 00", 0},
            // `push 0; push 0x80; push 3; push 0; push 1; push 0x80000000; push edi`
            {"6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 57", 1},
        };

        // The anchor: `mov eax,[imm32]; mov ecx,0x5CDCFAA7; mul ecx;
        // mov ecx,[imm32]; xor esi,esi`. Its matches 0 and 1 become the jumps
        // above (the original's collected-site pair).
        constexpr SkipLauncherCollectedInstall kSkipLauncherDfaCollected[] = {
            {"A1 ? ? ? ? B9 A7 FA DC 5C F7 E1 8B 0D ? ? ? ? 33 F6", kDfaCollectedTargets_0,
             std::size(kDfaCollectedTargets_0)},
        };

        static_assert(std::size(kSkipLauncherDfaCollected) == 1);
        static_assert(std::size(kDfaCollectedTargets_0) == 2);
    } // namespace

    std::span<const EntryPatch> SkipLauncherEntries() noexcept
    {
        return kSkipLauncherEntries;
    }

    std::span<const SkipLauncherCollector> SkipLauncherCollectors() noexcept
    {
        return kSkipLauncherCollectors;
    }

    std::span<const SkipLauncherInstall> SkipLauncherDfaInstalls() noexcept
    {
        return kSkipLauncherDfaInstalls;
    }

    std::span<const SkipLauncherInstall> SkipLauncherRomInstalls() noexcept
    {
        return kSkipLauncherRomInstalls;
    }

    std::span<const SkipLauncherCollectedInstall> SkipLauncherDfaCollected() noexcept
    {
        return kSkipLauncherDfaCollected;
    }
} // namespace xla

// ===========================================================================
// 3. The pass
// ===========================================================================

namespace xla
{
    namespace
    {
        // A signature scan over the caller-owned image, in the original's
        // hook::pattern style.
        hook::pattern Scan(std::span<std::byte> image, std::string_view signature)
        {
            const auto begin = reinterpret_cast<std::uintptr_t>(image.data());
            return hook::make_range_pattern(begin, begin + image.size(), signature);
        }

        // A store outside the mapped image is the pass's one hard failure.
        bool InBounds(std::span<std::byte> image, const void* site, std::size_t length) noexcept
        {
            const auto begin = reinterpret_cast<std::uintptr_t>(image.data());
            const auto address = reinterpret_cast<std::uintptr_t>(site);
            if (begin == 0 || address < begin)
            {
                return false;
            }
            const auto offset = address - begin;
            return length <= image.size() && offset <= image.size() - length;
        }

        // The address a row writes: the match advanced by the row's named offset.
        // A negative offset reaches back into the enclosing function.
        [[nodiscard]] std::uint8_t* MatchAt(std::uint8_t* match, std::int32_t offset) noexcept
        {
            return match + offset;
        }

        // One scanned entry: its recovered row and the first signature match, or
        // null when the signature is absent on this image. Jump ops resolve their
        // target through the plan list, so nothing is scanned twice.
        struct EntryPlan
        {
            const EntryPatch* entry{};
            std::uint8_t* match{};
        };

        using EntryPlanList = std::vector<EntryPlan>;

        // The recovered handler's single-match finder: one site per table row.
        // Used for the report below, never as a gate.
        constexpr std::size_t kSingleSite = 1;

        // True when every jump op's target entry matched. The original shares one
        // guard between the E9 and its 33 C0/rel32 ops, so an absent target skips
        // the whole entry, not just the jump.
        [[nodiscard]] bool JumpTargetsPresent(const EntryPatch& entry,
                                              const EntryPlanList& plans) noexcept
        {
            for (const PatchOp& op : entry.ops)
            {
                if (op.kind == PatchOp::Kind::jump &&
                    (op.target >= plans.size() || plans[op.target].match == nullptr))
                {
                    return false;
                }
            }
            return true;
        }

        // first_two takes the first two matches; last_two takes the final two. A
        // lone match is one site for either rule.
        [[nodiscard]] bool CollectorTakes(SkipLauncherCollector::Target target,
                                          std::size_t hit, std::size_t hits) noexcept
        {
            return target == SkipLauncherCollector::Target::first_two
                       ? hit < kCollectorWidth
                       : hit + kCollectorWidth >= hits;
        }

        // Applies one patch op:
        //   * write: store the op's bytes;
        //   * fill:  repeat the op's byte (NOP in the recovered data);
        //   * jump:  rewrite the whole branch one byte before the rel32 (the
        //            preceding write op put the E9 there), so the displacement is
        //            measured from the end of the instruction, not from the
        //            literal dword.
        PatchOutcome ApplyPatchOp(std::span<std::byte> image, std::uint8_t* match,
                                  const PatchOp& op, const EntryPlanList& plans,
                                  SkipLauncherReport& report)
        {
            std::uint8_t* site = MatchAt(match, op.offset);

            switch (op.kind)
            {
            case PatchOp::Kind::jump:
            {
                std::uint8_t* target = op.target < plans.size() ? plans[op.target].match
                                                                : nullptr;
                if (target == nullptr)
                {
                    // The entry-level check already rejected this case; keep the
                    // guard because this is the only place the target is read.
                    return {};
                }

                std::uint8_t* branch = site - 1;
                if (!InBounds(image, branch, kBranchLength))
                {
                    return std::unexpected(PatchError{PatchErrorCode::out_of_bounds,
                                                      "site out of bounds"});
                }
                injector::MakeJMP(injector::raw_ptr(branch), injector::raw_ptr(target), true);
                report.jumpInstalled = true;
                ++report.writes;
                return {};
            }
            case PatchOp::Kind::write:
            {
                if (!InBounds(image, site, op.bytes.size()))
                {
                    return std::unexpected(PatchError{PatchErrorCode::out_of_bounds,
                                                      "site out of bounds"});
                }
                injector::WriteMemoryRaw(injector::raw_ptr(site),
                                         const_cast<std::uint8_t*>(op.bytes.data()),
                                         op.bytes.size(), true);
                ++report.writes;
                return {};
            }
            case PatchOp::Kind::fill:
            {
                if (!InBounds(image, site, op.count))
                {
                    return std::unexpected(PatchError{PatchErrorCode::out_of_bounds,
                                                      "site out of bounds"});
                }
                // The installer writes the op's own fill byte instead of assuming
                // 0x90; xla_table_parity rejects a non-NOP fill on these rows.
                injector::MemoryFill(injector::raw_ptr(site), op.fill, op.count, true);
                ++report.writes;
                return {};
            }
            }

            return std::unexpected(PatchError{PatchErrorCode::invalid_input,
                                              "unsupported patch op"});
        }

        // Applies one matched entry. The ops are in the recovered order and share
        // the entry's single jump-target guard.
        PatchOutcome ApplyEntry(std::span<std::byte> image, const EntryPlan& plan,
                                const EntryPlanList& plans, SkipLauncherReport& report)
        {
            if (!JumpTargetsPresent(*plan.entry, plans))
            {
                return {};
            }

            for (const PatchOp& op : plan.entry->ops)
            {
                const auto status = ApplyPatchOp(image, plan.match, op, plans, report);
                if (!status)
                {
                    return status;
                }
            }
            return {};
        }

        // Stage main, part 1: the recovered 25-entry table, in order. An absent
        // signature is a miss, never a guess; a present one is applied before the
        // next signature is scanned (the recovered handler does the same, and the
        // order is part of the contract).
        PatchOutcome ApplyMainTable(std::span<std::byte> image, SkipLauncherReport& report)
        {
            const std::span<const EntryPatch> entries = SkipLauncherEntries();
            EntryPlanList plans(entries.size());

            for (std::size_t index = 0; index < entries.size(); ++index)
            {
                const EntryPatch& entry = entries[index];

                hook::pattern pattern = Scan(image, entry.signature);
                if (pattern.empty())
                {
                    ++report.entriesMissing;
                    continue;
                }

                // The recovered row is a single-site patch. A duplicate signature
                // is still applied at the first match, exactly like the original's
                // single-match finder; the count is reported, never gated. get(0)
                // (not get_first) because get_first's own count check would assert
                // on that duplicate in a checked build.
                const std::size_t hits = pattern.size();
                if (hits != kSingleSite)
                {
                    log::Info("skipLauncher: entry {} matched {} site(s), expected {}", index,
                              hits, kSingleSite);
                }

                plans[index] = {&entry, pattern.get(0).get<std::uint8_t>()};
                ++report.entriesFound;

                const auto status = ApplyEntry(image, plans[index], plans, report);
                if (!status)
                {
                    return status;
                }
            }
            return {};
        }

        // Stage main, part 2: the two multi-hit collectors. The recovered stub
        // ("mov al,1; ret; nop") is stored over the first/last matches, never over
        // the signature itself. The original's multi-match finder returns a
        // data-dependent number of sites, so the count is reported, not asserted
        // against a build number; the rule keeps at most two per pattern.
        PatchOutcome ApplyCollectors(std::span<std::byte> image, SkipLauncherReport& report)
        {
            std::size_t collectorIndex = 0;
            for (const SkipLauncherCollector& collector : SkipLauncherCollectors())
            {
                hook::pattern pattern = Scan(image, collector.pattern);
                const std::size_t hits = pattern.size();
                if (hits == 0)
                {
                    ++collectorIndex;
                    continue;
                }

                ++report.collectorsFound;
                std::size_t hit = 0;
                std::size_t applied = 0;
                PatchOutcome status;
                pattern.for_each_result(
                    [&](hook::pattern_match match)
                    {
                        const std::size_t index = hit++;
                        if (!status || !CollectorTakes(collector.target, index, hits))
                        {
                            return;
                        }

                        std::uint8_t* site = match.get<std::uint8_t>();
                        if (!InBounds(image, site, collector.stub.size()))
                        {
                            status = std::unexpected(PatchError{PatchErrorCode::out_of_bounds,
                                                                "site out of bounds"});
                            return;
                        }

                        injector::WriteMemoryRaw(injector::raw_ptr(site),
                                                 const_cast<std::uint8_t*>(collector.stub.data()),
                                                 collector.stub.size(), true);
                        ++report.collectorWrites;
                        ++applied;
                    });

                if (!status)
                {
                    return status;
                }

                log::Info("skipLauncher: collector {} matched {} site(s), patched {}",
                          collectorIndex, hits, applied);
                ++collectorIndex;
            }
            return {};
        }

        // Stage dfa, part 1: read the IAT slot out of the capture window and
        // publish it (or clear a stale slot) before any hook can run. The body
        // reads the slot from the module atomically, so the publish is a single
        // store either way.
        void CaptureCreateFileSlot(std::span<std::byte> image, SkipLauncherReport& report)
        {
            hook::pattern capture = Scan(image, kDfaCapturePattern);
            if (!capture.empty())
            {
                // `FF 15 <rel32>`: the operand at +2 is the IAT slot VA.
                report.createFileSlot = *capture.get_first<std::uint32_t>(kDfaCaptureSlotOffset);
            }

            PublishCreateFileSlot(report);
        }

        // What one install table did: branches written and branches skipped.
        struct HookCounts
        {
            std::size_t installed{};
            std::size_t missing{};
        };

        // Installs one stage's E8/E9 branches. A body the resolver does not know,
        // or a missing signature, counts as missing; a site outside the image is
        // the only failure.
        std::expected<HookCounts, PatchError> InstallHooks(
            std::span<std::byte> image, std::span<const SkipLauncherInstall> installs,
            SkipHookResolver resolve, void* resolverUser)
        {
            HookCounts counts;
            for (const SkipLauncherInstall& install : installs)
            {
                const std::uintptr_t destination = resolve(install.hook, resolverUser);
                if (destination == 0)
                {
                    ++counts.missing;
                    continue;
                }

                hook::pattern hookSite = Scan(image, install.signature);
                if (hookSite.empty())
                {
                    ++counts.missing;
                    continue;
                }

                std::uint8_t* site = MatchAt(hookSite.get_first<std::uint8_t>(), install.offset);
                if (!InBounds(image, site, kBranchLength))
                {
                    return std::unexpected(PatchError{PatchErrorCode::out_of_bounds,
                                                      "site out of bounds"});
                }

                // The recovered opcode column is only ever E8 (call) or E9
                // (jump); anything else is a table defect, not a byte to write.
                switch (install.opcode)
                {
                case Opcode::kCallRel32:
                    injector::MakeCALL(injector::raw_ptr(site), injector::raw_ptr(destination),
                                       true);
                    break;
                case Opcode::kJmpRel32:
                    injector::MakeJMP(injector::raw_ptr(site), injector::raw_ptr(destination),
                                      true);
                    break;
                default:
                    return std::unexpected(PatchError{PatchErrorCode::invalid_input,
                                                      "unsupported branch opcode"});
                }
                ++counts.installed;
            }
            return counts;
        }

        // Stage dfa, part 2: the six file-API hooks.
        PatchOutcome InstallDfaHooks(std::span<std::byte> image, SkipHookResolver resolve,
                                     void* resolverUser, SkipLauncherReport& report)
        {
            const auto counts =
                InstallHooks(image, SkipLauncherDfaInstalls(), resolve, resolverUser);
            if (!counts)
            {
                return std::unexpected(counts.error());
            }
            report.dfaInstalls += counts->installed;
            report.dfaMissing += counts->missing;
            return {};
        }

        // Stage dfa, part 3: each collected anchor match becomes a jump to the
        // first match of its target pattern.
        PatchOutcome InstallCollectedJumps(std::span<std::byte> image, SkipLauncherReport& report)
        {
            for (const SkipLauncherCollectedInstall& install : SkipLauncherDfaCollected())
            {
                hook::pattern anchor = Scan(image, install.collector);
                for (std::size_t index = 0; index < install.targetCount; ++index)
                {
                    const SkipLauncherCollectedTarget& target = install.targets[index];
                    if (target.index >= anchor.size())
                    {
                        continue;
                    }

                    hook::pattern targetPattern = Scan(image, target.targetSignature);
                    if (targetPattern.empty())
                    {
                        continue;
                    }

                    std::uint8_t* site = anchor.get(target.index).get<std::uint8_t>();
                    if (!InBounds(image, site, kBranchLength))
                    {
                        return std::unexpected(PatchError{PatchErrorCode::out_of_bounds,
                                                          "site out of bounds"});
                    }

                    injector::MakeJMP(injector::raw_ptr(site),
                                      injector::raw_ptr(targetPattern.get_first<std::uint8_t>()),
                                      true);
                    ++report.collectedInstalls;
                }
            }
            return {};
        }

        // Stage rom: the two message-window hooks.
        PatchOutcome InstallRomHooks(std::span<std::byte> image, SkipHookResolver resolve,
                                     void* resolverUser, SkipLauncherReport& report)
        {
            const auto counts =
                InstallHooks(image, SkipLauncherRomInstalls(), resolve, resolverUser);
            if (!counts)
            {
                return std::unexpected(counts.error());
            }
            report.romInstalls += counts->installed;
            report.romMissing += counts->missing;
            return {};
        }
    } // namespace

    std::expected<SkipLauncherReport, PatchError> ApplySkipLauncher(
        std::span<std::byte> image, SkipHookResolver resolve, void* resolverUser,
        SkipLauncherStage stages)
    {
        if (image.empty())
        {
            return std::unexpected(PatchError{PatchErrorCode::invalid_input,
                                              "invalid skip launcher input"});
        }

        SkipLauncherReport report;

        // Stage main (0x10045CE0). Not part of the shipping set; it runs only
        // when a caller asks for it explicitly.
        if (HasStage(stages, SkipLauncherStage::main))
        {
            if (auto status = ApplyMainTable(image, report); !status)
            {
                return std::unexpected(status.error());
            }
            if (auto status = ApplyCollectors(image, report); !status)
            {
                return std::unexpected(status.error());
            }
        }

        // Stage dfa (0x10004850), capture half: the slot must be known before the
        // hooks can run, so this happens even when no resolver is supplied.
        if (HasStage(stages, SkipLauncherStage::dfa))
        {
            CaptureCreateFileSlot(image, report);
        }

        // The hook stages need a resolver. Without one the capture above still
        // runs (it only reads the image), but no branch is written.
        if (resolve)
        {
            // Stage dfa, install half: the six file-API hooks, then the two
            // collected jumps (the original's order inside 0x10004850).
            if (HasStage(stages, SkipLauncherStage::dfa))
            {
                if (auto status = InstallDfaHooks(image, resolve, resolverUser, report); !status)
                {
                    return std::unexpected(status.error());
                }
                if (auto status = InstallCollectedJumps(image, report); !status)
                {
                    return std::unexpected(status.error());
                }
            }

            // Stage rom (0x10004620): last, as in the original.
            if (HasStage(stages, SkipLauncherStage::rom))
            {
                if (auto status = InstallRomHooks(image, resolve, resolverUser, report); !status)
                {
                    return std::unexpected(status.error());
                }
            }
        }

        return report;
    }

    std::string DescribeStages(SkipLauncherStage stages)
    {
        std::string text;
        const auto append = [&](SkipLauncherStage stage, std::string_view name) {
            if (!HasStage(stages, stage))
            {
                return;
            }
            if (!text.empty())
            {
                text += '|';
            }
            text += name;
        };
        append(SkipLauncherStage::main, "main");
        append(SkipLauncherStage::dfa, "dfa");
        append(SkipLauncherStage::rom, "rom");
        return text.empty() ? std::string{"none"} : text;
    }
} // namespace xla

// ===========================================================================
// 4. Windows hook bodies
// ===========================================================================
//
// The bodies the install rows jump to. They run inside the game process, so the
// ABI is part of the recovered contract:
//   * CreateFile, CloseHandle, SetFilePointer, GetFileSizeEx, ReadFile, DfaInit
//     and RomReset are __cdecl (plain `ret`): the patched site's caller pops the
//     arguments, exactly as it popped the original's.
//   * RomSet takes the object in ESI and returns with `ret 8` (the site pushed
//     two arguments the callee must pop). MSVC rejects a naked exported module
//     member, and a C function cannot express a register argument plus a callee
//     stack pop, so its eleven opcode bytes are assembled into an executable page
//     at install time (the internal-linkage SkipIntroBody in patches.ixx is the
//     one naked exception in this tree).
// The originals live at 0x10004720..0x1000484e (file API + DFA) and
// 0x100041A0..0x10004710 (WM_ROM service, RomReset, RomSet).

namespace xla
{
    namespace skip_hooks
    {
        // The CreateFile IAT slot captured by the DFA stage; 0 means the body
        // calls CreateFileA directly (no slot captured yet, or none on this image).
        inline std::atomic<std::uint32_t> gCreateFileSlot{0};

        // ---- DFA bodies (SkipLauncher=1) -----------------------------------

        namespace dfa
        {
            using CreateFileAFn = HANDLE(WINAPI*)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES,
                                                  DWORD, DWORD, HANDLE);

            // 0x10004780: replaces the DFA init call so it reports success.
            // ABI: __cdecl, no arguments. The call site is
            // `E8 rel32; 83 C4 0C`, so the caller discards the three arguments
            // itself; a parameterless body is the correct shape.
            inline int __cdecl DfaInitBody()
            {
                return 1;
            }

            // 0x10004820: CreateFileA through the captured IAT slot, falling back
            // to the import when nothing was captured. The original trampoline is
            // __cdecl (plain ret; the caller pops the seven arguments), so the ABI
            // must match - a stdcall body would corrupt the stack.
            inline HANDLE __cdecl CreateFileBody(LPCSTR fileName, DWORD desiredAccess,
                                                 DWORD shareMode,
                                                 LPSECURITY_ATTRIBUTES security,
                                                 DWORD creationDisposition, DWORD flags,
                                                 HANDLE templateFile)
            {
                const std::uint32_t slot = gCreateFileSlot.load();
                if (slot != 0)
                {
                    const auto* fn =
                        *reinterpret_cast<CreateFileAFn*>(static_cast<std::uintptr_t>(slot));
                    if (fn != nullptr)
                    {
                        return fn(fileName, desiredAccess, shareMode, security,
                                  creationDisposition, flags, templateFile);
                    }
                }

                return ::CreateFileA(fileName, desiredAccess, shareMode, security,
                                     creationDisposition, flags, templateFile);
            }

            // 0x10004790: the original wraps CloseHandle in SEH and returns -1
            // (its `or eax,-1` filter at 0x100047ec) when it faults. __cdecl like
            // the original trampoline; the SEH keywords are MSVC-only.
            inline BOOL __cdecl CloseHandleGuardedBody(HANDLE handle)
            {
                __try
                {
                    return ::CloseHandle(handle);
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    return static_cast<BOOL>(-1);
                }
            }

            // 0x10004760: plain forwarding, same four arguments.
            inline DWORD __cdecl SetFilePointerBody(HANDLE handle, LONG distance,
                                                    PLONG distanceHigh, DWORD moveMethod)
            {
                return ::SetFilePointer(handle, distance, distanceHigh, moveMethod);
            }

            // 0x10004720: plain forwarding, same two arguments.
            inline BOOL __cdecl GetFileSizeExBody(HANDLE handle, PLARGE_INTEGER size)
            {
                return ::GetFileSizeEx(handle, size);
            }

            // 0x10004740: plain forwarding, same five arguments.
            inline BOOL __cdecl ReadFileBody(HANDLE handle, LPVOID buffer, DWORD toRead,
                                             LPDWORD read, LPOVERLAPPED overlapped)
            {
                return ::ReadFile(handle, buffer, toRead, read, overlapped);
            }
        } // namespace dfa

        // ---- the WM_ROM service and the two ROM bodies ---------------------

        namespace rom
        {
            // The original's message window is addressed by a private window
            // message and a class name; a second class name is the fallback when
            // the first registration fails.
            inline constexpr UINT kRomMessage = 43858; // WM_ROM in the original
            inline constexpr char kClassName[] = "MessageWindow";
            inline constexpr char kClassFallback[] = "MessageWindow2";

            // xmmword_10104050..0x10104080: the table the ROM service hands to
            // the game (action 18 copies all 16 dwords).
            inline constexpr std::array<std::uint32_t, 16> kActionTable{
                8, 11, 241, 1, 240, 2, 7, 12, 3, 243, 9, 6, 10, 5, 4, 242,
            };

            // WM_ROM payload: [4] is the action, [5] and [6] are its operands.
            inline constexpr std::size_t kPayloadAction = 4;
            inline constexpr std::size_t kPayloadArg0 = 5;
            inline constexpr std::size_t kPayloadArg1 = 6;

            inline constexpr std::uint32_t kActionCopyTable = 18;
            inline constexpr std::uint32_t kActionAdd = 51;
            inline constexpr std::uint32_t kActionSet = 100;

            // RomReset's object (0x10004570): 19 32-bit slots. The window handle
            // sits in slot 1 and the WM_ROM id in slot 4; the original zeroes slot
            // 0, 2, 3 and 5..18 first, so a whole-object zero followed by the two
            // publishes ends in the same state.
            struct RomObject
            {
                std::uint32_t slot0{};
                std::uint32_t window{};                                      // slot 1
                std::uint32_t slot2{};
                std::uint32_t slot3{};
                std::uint32_t message{};                                     // slot 4
                std::array<std::uint32_t, 14> tail{};                        // slots 5..18
            };
            static_assert(offsetof(RomObject, window) == sizeof(std::uint32_t));
            static_assert(offsetof(RomObject, message) == 4 * sizeof(std::uint32_t));
            static_assert(sizeof(RomObject) == 19 * sizeof(std::uint32_t));

            // The service readiness wait: 200 attempts, 1 ms apart (the original
            // polls once per millisecond for a short while instead of blocking).
            inline constexpr int kReadyPollLimit = 200;
            inline constexpr DWORD kReadyPollMs = 1;

            inline std::atomic<HWND> gWindow{nullptr};
            inline std::atomic<bool> gReady{false};
            inline std::atomic<bool> gStarted{false};

            inline LRESULT CALLBACK RomWindowProc(HWND window, UINT message, WPARAM wparam,
                                                  LPARAM lparam)
            {
                if (message == WM_NCCREATE)
                {
                    gWindow.store(window);
                    gReady.store(true);
                }
                else if (message == WM_DESTROY)
                {
                    gWindow.store(nullptr);
                    ::PostQuitMessage(0);
                    return 0;
                }
                else if (message == kRomMessage)
                {
                    auto* payload = reinterpret_cast<std::uint32_t*>(lparam);
                    switch (payload[kPayloadAction])
                    {
                    case kActionCopyTable:
                        std::memcpy(reinterpret_cast<void*>(
                                        static_cast<std::uintptr_t>(payload[kPayloadArg1])),
                                    kActionTable.data(), sizeof(kActionTable));
                        return 0;
                    case kActionAdd:
                        return static_cast<LRESULT>(payload[kPayloadArg0] + payload[kPayloadArg1]);
                    case kActionSet:
                        *reinterpret_cast<std::uint32_t*>(
                            static_cast<std::uintptr_t>(payload[kPayloadArg0])) = 1;
                        return 0;
                    default:
                        return 0;
                    }
                }

                return ::DefWindowProcA(window, message, wparam, lparam);
            }

            // 0x100043D0's thread body: register the class, create the hidden
            // message window, pump messages until WM_QUIT, then unregister.
            inline DWORD WINAPI RomServiceThread(LPVOID)
            {
                WNDCLASSEXA wc{};
                wc.cbSize = sizeof(wc);
                wc.lpfnWndProc = &RomWindowProc;
                wc.hInstance = ::GetModuleHandleA(nullptr);
                wc.lpszClassName = kClassName;

                ATOM atom = ::RegisterClassExA(&wc);
                if (atom == 0)
                {
                    wc.lpszClassName = kClassFallback;
                    atom = ::RegisterClassExA(&wc);
                    if (atom == 0)
                    {
                        return 1;
                    }
                }

                // The ATOM is passed back to CreateWindowExA in its integer form
                // (MAKEINTATOM), which is what the cast expresses.
                ::CreateWindowExA(0, reinterpret_cast<LPCSTR>(static_cast<std::uintptr_t>(atom)),
                                  "", 0, 0, 0, 0, 0, HWND_MESSAGE, nullptr, wc.hInstance,
                                  nullptr);

                MSG msg;
                while (::GetMessageA(&msg, nullptr, 0, 0))
                {
                    ::TranslateMessage(&msg);
                    ::DispatchMessageA(&msg);
                }

                ::UnregisterClassA(reinterpret_cast<LPCSTR>(static_cast<std::uintptr_t>(atom)),
                                   wc.hInstance);
                return 0;
            }

            // 0x100043D0: start the ROM service once and wait until the window
            // exists (the two ROM bodies publish the handle and the message id).
            inline void StartRomService()
            {
                if (gStarted.exchange(true))
                {
                    return;
                }

                const HANDLE thread =
                    ::CreateThread(nullptr, 0, &RomServiceThread, nullptr, 0, nullptr);
                if (thread != nullptr)
                {
                    ::CloseHandle(thread);
                }

                for (int attempt = 0; attempt < kReadyPollLimit && !gReady.load(); ++attempt)
                {
                    ::Sleep(kReadyPollMs);
                }
            }

            // 0x10004610: the object arrives in ESI (the patched site keeps it
            // there) and the site pushed two arguments the callee must pop. The
            // original is `mov ecx,[esi+1c]; mov [esi+20],ecx; mov al,1; ret 8`;
            // a C function cannot express that, so the eleven opcode bytes are
            // assembled into an executable page once and cached.
            inline void* RomSetStub()
            {
                static std::atomic<void*> cached{nullptr};
                if (void* existing = cached.load(); existing != nullptr)
                {
                    return existing;
                }

                // VirtualAlloc rounds the request up to a page; the body below uses
                // eleven bytes of it.
                constexpr std::size_t kStubAllocationBytes = 64;
                void* memory = ::VirtualAlloc(nullptr, kStubAllocationBytes,
                                              MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (memory == nullptr)
                {
                    log::Write("rom: cannot allocate the RomSet stub");
                    return nullptr;
                }

                // 8B 4E 1C   mov ecx,[esi+0x1c]  (ModRM 4E = mod 01, reg ecx,
                //                                  r/m esi + disp8 0x1C)
                // 89 4E 20   mov [esi+0x20],ecx  (the same object field pair)
                // B0 01      mov al,1            (the original's success value)
                // C2 08 00   ret 8               (pop the two pushed arguments)
                constexpr std::uint8_t kCode[] = {
                    Byte(Opcode::kMovR32Rm32), 0x4E, 0x1C,       // mov ecx,[esi+0x1c]
                    Byte(Opcode::kMovRm32R32), 0x4E, 0x20,       // mov [esi+0x20],ecx
                    Byte(Opcode::kMovAlImm8), 0x01,              // mov al,1 (imm8)
                    ops::kRet8[0], ops::kRet8[1], ops::kRet8[2], // ret 8
                };
                static_assert(std::size(kCode) == 11);
                static_assert(std::size(ops::kRet8) == 3);
                std::memcpy(memory, kCode, sizeof(kCode));
                ::FlushInstructionCache(::GetCurrentProcess(), memory, sizeof(kCode));
                cached.store(memory);
                return memory;
            }

            // 0x10004570: start the ROM service, reset the object and publish the
            // window handle plus the WM_ROM id. ABI: __cdecl with one stack
            // argument, returning the window handle in eax (plain ret).
            inline int __cdecl RomResetBody(RomObject* object)
            {
                StartRomService();
                if (object == nullptr)
                {
                    return 0;
                }

                *object = RomObject{};
                object->window =
                    static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(gWindow.load()));
                object->message = kRomMessage;
                return static_cast<int>(object->window);
            }
        } // namespace rom
    } // namespace skip_hooks

    inline void SetCreateFileSlot(std::uint32_t slotVa) noexcept
    {
        skip_hooks::gCreateFileSlot.store(slotVa);
    }

    inline bool PublishCreateFileSlot(const SkipLauncherReport& report) noexcept
    {
        SetCreateFileSlot(report.createFileSlot);
        return report.createFileSlot != 0;
    }

    inline std::uintptr_t ResolveSkipHook(SkipHook hook, void*) noexcept
    {
        switch (hook)
        {
        case SkipHook::dfa_init:
            return reinterpret_cast<std::uintptr_t>(&skip_hooks::dfa::DfaInitBody);
        case SkipHook::create_file:
            return reinterpret_cast<std::uintptr_t>(&skip_hooks::dfa::CreateFileBody);
        case SkipHook::close_handle:
            return reinterpret_cast<std::uintptr_t>(&skip_hooks::dfa::CloseHandleGuardedBody);
        case SkipHook::set_file_pointer:
            return reinterpret_cast<std::uintptr_t>(&skip_hooks::dfa::SetFilePointerBody);
        case SkipHook::get_file_size_ex:
            return reinterpret_cast<std::uintptr_t>(&skip_hooks::dfa::GetFileSizeExBody);
        case SkipHook::read_file:
            return reinterpret_cast<std::uintptr_t>(&skip_hooks::dfa::ReadFileBody);
        case SkipHook::rom_reset:
            return reinterpret_cast<std::uintptr_t>(&skip_hooks::rom::RomResetBody);
        case SkipHook::rom_set:
            return reinterpret_cast<std::uintptr_t>(skip_hooks::rom::RomSetStub());
        }
        return 0;
    }
} // namespace xla
