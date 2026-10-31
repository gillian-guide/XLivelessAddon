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
//   2. recovered data — named site offsets, write rows, entries, collectors,
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
    // One store relative to a signature match. Exactly one of three kinds:
    //   * bytes != nullptr     store `length` recovered bytes at match + offset
    //   * jumpToEntry != kNoJumpTarget
    //                          the rel32 of an E9 whose opcode the preceding
    //                          row wrote; the installer rewrites the whole
    //                          5-byte branch to that entry's match
    //   * otherwise            repeat `fill` `length` times (the recovered fill
    //                          rows are all NOPs)
    // `length` is always the number of bytes the row owns (for a jump row, the
    // four rel32 bytes the branch builder overwrites).
    struct SkipLauncherWrite
    {
        std::int32_t offset;
        std::uint16_t length;
        const std::uint8_t* bytes; // null on a fill or jump row
        std::uint8_t fill;         // must be Byte(Opcode::kNop) on a fill row
        std::uint32_t jumpToEntry; // kNoJumpTarget, or an entry index
    };

    // "This row installs no jump" sentinel; compare with == and never write it.
    inline constexpr std::uint32_t kNoJumpTarget = std::numeric_limits<std::uint32_t>::max();

    // One row of the recovered main table: a signature and the stores it makes.
    // Entry 1 has no stores: it is the jump target of entry 9.
    struct SkipLauncherEntry
    {
        std::string_view signature;
        const SkipLauncherWrite* writes;
        std::size_t writeCount;
    };

    // Multi-hit collector: the original patches the first two matches of one
    // pattern and the last two of another with "mov al,1; ret; nop".
    struct SkipLauncherCollector
    {
        enum class Target : std::uint8_t
        {
            first_two,
            last_two,
        };

        std::string_view pattern;
        Target target;
        const std::uint8_t* bytes;
        std::uint16_t length;
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
        std::size_t writes{}; // write rows applied, jump rows included
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

    // Table accessors; the spans cover the recovered rows in the golden's order.
    std::span<const SkipLauncherEntry> SkipLauncherEntries() noexcept;
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

        // The collectors write the shared "mov al,1; ret; nop" window.
        constexpr std::uint16_t kCollectorStubLength =
            static_cast<std::uint16_t>(std::size(ops::kMovAl1RetNop));

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

        // ---- the main table's write rows (0x10045CE0) ----------------------
        //
        // One array per entry, in the original's order: {offset, length, bytes
        // (null = fill or jump), fill byte, jump-target entry}.

        // Entry 0: `test bl,bl; jne +0x143; lea ecx,[esp+28]; mov eax,ecx`.
        // Both rows write the single `EB` opcode of a short branch in the same
        // function. The condition byte is outside the matched window, so the
        // signature does not say which branch it was; `EB` makes it unconditional.
        constexpr SkipLauncherWrite kSkipEntryWrites_0[] = {
            {kEntry0Branch0, 1, ops::kJmpRel8, 0, kNoJumpTarget}, // jz/jnz -> jmp
            {kEntry0Branch1, 1, ops::kJmpRel8, 0, kNoJumpTarget},
        };
        // Entry 2: `74 EC` (jz), `cmp [esi+6],bl`, `74 E7` (jz), `push imm32`.
        // Both conditional jumps are removed with two NOPs.
        constexpr SkipLauncherWrite kSkipEntryWrites_2[] = {
            {0, 2, ops::kNop2, 0, kNoJumpTarget},
            {kEntry2Branch1, 2, ops::kNop2, 0, kNoJumpTarget},
        };
        // Entry 3: `74 C4` (jz), `mov eax,[edi]`, `cmp eax,[esi+18]`, `75 BD`.
        constexpr SkipLauncherWrite kSkipEntryWrites_3[] = {
            {0, 2, ops::kNop2, 0, kNoJumpTarget}, // the leading jz
        };
        // Entry 4: `cmp edx,[esi+18]; jne rel32`; NOP6 covers the whole jcc.
        constexpr SkipLauncherWrite kSkipEntryWrites_4[] = {
            {kEntry4Jcc, 6, ops::kNop6, 0, kNoJumpTarget},
        };
        // Entry 5: `cmp ecx,[esi+18]; jne rel32`; same 6-byte jcc.
        constexpr SkipLauncherWrite kSkipEntryWrites_5[] = {
            {kEntry5Jcc, 6, ops::kNop6, 0, kNoJumpTarget},
        };
        // Entry 6: `jne rel32; mov ecx,[esp+..]; pop edi/esi/ebx; xor ecx,esp`.
        constexpr SkipLauncherWrite kSkipEntryWrites_6[] = {
            {0, 6, ops::kNop6, 0, kNoJumpTarget},
        };
        // Entry 7: `cmp eax,[esi+18]; jne -0x43`. +3 replaces the `75 BD` with
        // `33 C0` (xor eax,eax); +10 is 5 bytes past the window: `90 A3`
        // (nop; mov [imm32],eax).
        constexpr SkipLauncherWrite kSkipEntryWrites_7[] = {
            {kEntry7Jcc, 2, ops::kXorEaxEax, 0, kNoJumpTarget},
            {kEntry7Store, 2, ops::kNopMovMoffsEax, 0, kNoJumpTarget},
        };
        // Entry 8: `push edi; push ecx` then three `C7 44 24` immediate stores.
        // The recovered handler memsets 0x1BF (447) bytes starting at +1.
        constexpr SkipLauncherWrite kSkipEntryWrites_8[] = {
            {kEntry8Memset, kEntry8MemsetLength, nullptr, Byte(Opcode::kNop),
             kNoJumpTarget},
        };
        // Entry 9: `mov edx,[esi+1C]; cmp edx,[esi+20]; ?? ??; push 0; push 0`.
        // The first 7 bytes become `33 C0 E9 rel32`: xor eax,eax, then a jump to
        // entry 1's match (the launcher entry the original keeps for this row).
        constexpr SkipLauncherWrite kSkipEntryWrites_9[] = {
            {0, 2, ops::kXorEaxEax, 0, kNoJumpTarget},
            {kEntry9JmpOpcode, 1, ops::kJmpRel32, 0, kNoJumpTarget},
            {kEntry9JmpRel32, 4, nullptr, 0, kSkipLauncherJumpTargetEntry}, // rel32
        };
        // Entry 10: `mov [imm32],esi; call; add esp,4; test al,al`. `90 A3`
        // keeps the store but takes EAX instead of ESI (the `89` becomes `90`).
        constexpr SkipLauncherWrite kSkipEntryWrites_10[] = {
            {0, 2, ops::kNopMovMoffsEax, 0, kNoJumpTarget},
        };
        // Entry 11: `mov edx,[eax+2C]; cmp edx,[eax+30]` -> `33 C0` + NOP4, so
        // the caller receives eax = 0.
        constexpr SkipLauncherWrite kSkipEntryWrites_11[] = {
            {0, 2, ops::kXorEaxEax, 0, kNoJumpTarget},
            {kEntry11Nop, 4, ops::kNop4, 0, kNoJumpTarget},
        };
        // Entry 12: `mov ecx,[eax+2C]; sub esp,0x78`, then the function body.
        // NOP3 removes the load; NOP11 fills the 11 bytes after the 6-byte window.
        constexpr SkipLauncherWrite kSkipEntryWrites_12[] = {
            {0, 3, ops::kNop3, 0, kNoJumpTarget},
            {kEntry12Tail, 11, nullptr, Byte(Opcode::kNop), kNoJumpTarget},
        };
        // Entry 13: the same with `sub esp,0x74`.
        constexpr SkipLauncherWrite kSkipEntryWrites_13[] = {
            {0, 3, ops::kNop3, 0, kNoJumpTarget},
            {kEntry13Tail, 11, nullptr, Byte(Opcode::kNop), kNoJumpTarget},
        };
        // Entry 14: `mov ecx,[eax+2C]; cmp ecx,[eax+30]; jz +3`.
        constexpr SkipLauncherWrite kSkipEntryWrites_14[] = {
            {0, 11, ops::kNop11, 0, kNoJumpTarget},
        };
        // Entry 15: the same compare followed by `push ebx`.
        constexpr SkipLauncherWrite kSkipEntryWrites_15[] = {
            {0, 32, nullptr, Byte(Opcode::kNop), kNoJumpTarget},
        };
        // Entry 16: the same compare followed by `jz +0x11`.
        constexpr SkipLauncherWrite kSkipEntryWrites_16[] = {
            {0, 25, nullptr, Byte(Opcode::kNop), kNoJumpTarget},
        };
        // Entry 17/18: `mov ecx,[eax+2C]; cmp ecx,[eax+30]; jne -0x24;
        // lea edx,[esp+18/1C]`. The 8-byte compare-and-branch window is NOP'd.
        constexpr SkipLauncherWrite kSkipEntryWrites_17[] = {
            {0, 8, ops::kNop8, 0, kNoJumpTarget},
        };
        constexpr SkipLauncherWrite kSkipEntryWrites_18[] = {
            {0, 8, ops::kNop8, 0, kNoJumpTarget},
        };
        // Entry 19: `mov ecx,[imm32]; mov edx,[ecx+2C]`.
        constexpr SkipLauncherWrite kSkipEntryWrites_19[] = {
            {0, 14, ops::kNop14, 0, kNoJumpTarget},
        };
        // Entry 20: prologue pushes, `mov edi,[imm32]; mov eax,[edi+2C]`.
        constexpr SkipLauncherWrite kSkipEntryWrites_20[] = {
            {0, 1, ops::kRet, 0, kNoJumpTarget}, // the whole function becomes `ret`
        };
        // Entry 21: `cmp eax,edi; jne rel32; test eax,eax`.
        constexpr SkipLauncherWrite kSkipEntryWrites_21[] = {
            {0, 16, nullptr, Byte(Opcode::kNop), kNoJumpTarget},
        };
        // Entry 22: `jne rel32; test eax,eax; je rel32; call rel32; test edx,edx`.
        constexpr SkipLauncherWrite kSkipEntryWrites_22[] = {
            {0, 14, ops::kNop14, 0, kNoJumpTarget},
        };
        // Entry 23: `sub esp,0x24; mov eax,[imm32]; mov ecx,[eax+14]; push ...`.
        constexpr SkipLauncherWrite kSkipEntryWrites_23[] = {
            {0, 4, ops::kXorEaxRetNop, 0, kNoJumpTarget}, // xor eax,eax; ret; nop
        };
        // Entry 24: `sub esp,8; mov ecx,[imm32]; mov edx,[ecx+14]; lea eax,[esp]`.
        constexpr SkipLauncherWrite kSkipEntryWrites_24[] = {
            {0, 4, ops::kXorEaxRetNop, 0, kNoJumpTarget},
        };

        // ---- the main table (0x10045CE0) ----------------------------------

        // In the original's order. Entry 1 is the only row with no stores: entry
        // 9's E9 jumps to its match, so the handler keeps its address and writes
        // nothing into it. `std::size` keeps each count next to its array.
        constexpr SkipLauncherEntry kSkipLauncherEntries[] = {
            // 0: `test bl,bl; jne` launcher check; two EB hook sites
            {"84 DB 0F 85 43 01 00 00 8D 4C 24 28 8B C1", kSkipEntryWrites_0,
             std::size(kSkipEntryWrites_0)},
            // 1: target of entry 9's jump; no writes of its own
            {"68 ? ? ? ? 89 35 ? ? ? ? E8 ? ? ? ? 83 C4 04 84 C0 0F 84", nullptr, 0},
            // 2: `74 EC` / `74 E7` conditional launcher jumps
            {"74 EC 38 5E 06 74 E7 68", kSkipEntryWrites_2, std::size(kSkipEntryWrites_2)},
            // 3: `74 C4` leading conditional jump
            {"74 C4 8B 07 3B 46 18 75 BD 68", kSkipEntryWrites_3,
             std::size(kSkipEntryWrites_3)},
            // 4: `cmp edx,[esi+18]; jne rel32`
            {"3B 56 18 0F 85", kSkipEntryWrites_4, std::size(kSkipEntryWrites_4)},
            // 5: `cmp ecx,[esi+18]; jne rel32`
            {"3B 4E 18 0F 85", kSkipEntryWrites_5, std::size(kSkipEntryWrites_5)},
            // 6: leading `jne rel32` of an epilogue sequence
            {"0F 85 ? ? ? ? 8B 8C 24 ? ? ? ? 5F 5E 5B 33 CC C6", kSkipEntryWrites_6,
             std::size(kSkipEntryWrites_6)},
            // 7: `cmp eax,[esi+18]; jne -0x43` and a following store
            {"3B 46 18 75 BD", kSkipEntryWrites_7, std::size(kSkipEntryWrites_7)},
            // 8: `push edi; push ecx` + three `C7 44 24` immediate stores
            {"57 51 C7 44 24 ? ? ? ? ? C7 44 24 ? ? ? ? ? C7 44 24",
             kSkipEntryWrites_8, std::size(kSkipEntryWrites_8)},
            // 9: `mov edx,[esi+1C]; cmp edx,[esi+20]` -> xor eax,eax; jmp entry 1
            {"8B 56 1C 3B 56 20 ? ? 6A 00 6A 00", kSkipEntryWrites_9,
             std::size(kSkipEntryWrites_9)},
            // 10: `mov [imm32],esi; call; add esp,4; test al,al`
            {"89 35 ? ? ? ? E8 ? ? ? ? 83 C4 04 84 C0", kSkipEntryWrites_10,
             std::size(kSkipEntryWrites_10)},
            // 11: `mov edx,[eax+2C]; cmp edx,[eax+30]` -> eax = 0
            {"8B 50 2C 3B 50 30", kSkipEntryWrites_11, std::size(kSkipEntryWrites_11)},
            // 12: `mov ecx,[eax+2C]; sub esp,0x78` + body tail
            {"8B 48 2C 83 EC 78", kSkipEntryWrites_12, std::size(kSkipEntryWrites_12)},
            // 13: the same with `sub esp,0x74`
            {"8B 48 2C 83 EC 74", kSkipEntryWrites_13, std::size(kSkipEntryWrites_13)},
            // 14: `mov ecx,[eax+2C]; cmp ecx,[eax+30]; jz +3`
            {"8B 48 2C 3B 48 30 74 03", kSkipEntryWrites_14,
             std::size(kSkipEntryWrites_14)},
            // 15: the same compare followed by `push ebx`
            {"8B 48 2C 3B 48 30 53", kSkipEntryWrites_15, std::size(kSkipEntryWrites_15)},
            // 16: the same compare followed by `jz +0x11`
            {"8B 48 2C 3B 48 30 74 11", kSkipEntryWrites_16,
             std::size(kSkipEntryWrites_16)},
            // 17: `... jne -0x24; lea edx,[esp+18]`
            {"8B 48 2C 3B 48 30 75 DC 8D 54 24 18", kSkipEntryWrites_17,
             std::size(kSkipEntryWrites_17)},
            // 18: `... jne -0x24; lea edx,[esp+1C]`
            {"8B 48 2C 3B 48 30 75 DC 8D 54 24 1C", kSkipEntryWrites_18,
             std::size(kSkipEntryWrites_18)},
            // 19: `mov ecx,[imm32]; mov edx,[ecx+2C]`
            {"8B 0D ? ? ? ? 8B 51 2C", kSkipEntryWrites_19, std::size(kSkipEntryWrites_19)},
            // 20: prologue pushes + `mov edi,[imm32]; mov eax,[edi+2C]`
            {"51 53 55 56 57 8B 3D ? ? ? ? 8B 47 2C", kSkipEntryWrites_20,
             std::size(kSkipEntryWrites_20)},
            // 21: `cmp eax,edi; jne rel32; test eax,eax`
            {"3B C7 0F 85 ? ? ? ? 85 C0", kSkipEntryWrites_21,
             std::size(kSkipEntryWrites_21)},
            // 22: `jne rel32; test eax,eax; je rel32; call rel32; test edx,edx`
            {"0F 85 ? ? ? ? 85 C0 0F 84 ? ? ? ? E8 ? ? ? ? 85 D2", kSkipEntryWrites_22,
             std::size(kSkipEntryWrites_22)},
            // 23: `sub esp,0x24; mov eax,[imm32]; mov ecx,[eax+14]; push ...`
            {"83 EC 24 A1 ? ? ? ? 8B 48 14 53 55 56 57", kSkipEntryWrites_23,
             std::size(kSkipEntryWrites_23)},
            // 24: `sub esp,8; mov ecx,[imm32]; mov edx,[ecx+14]; lea eax,[esp]`
            {"83 EC 08 8B 0D ? ? ? ? 8B 51 14 8D 04 24 50 6A 00 52",
             kSkipEntryWrites_24, std::size(kSkipEntryWrites_24)},
        };

        static_assert(std::size(kSkipLauncherEntries) == 25);

        // ---- the multi-hit collectors --------------------------------------

        // `mov al,1; ret; nop` (B0 01 C3 90) forces a function to report success.
        // The original patches the first two matches of one pattern and the last
        // two of the other with it.
        constexpr SkipLauncherCollector kSkipLauncherCollectors[] = {
            // `mov eax,[imm32]; test eax,eax; mov ecx,[imm32]; jne`
            {"A1 ? ? ? ? 85 C0 8B 0D ? ? ? ? 75", SkipLauncherCollector::Target::first_two,
             ops::kMovAl1RetNop, kCollectorStubLength},
            // `xor eax,eax; cmp dword [imm32],1; sete al; ret`
            {"33 C0 83 3D ? ? ? ? 01 0F 94 C0 C3",
             SkipLauncherCollector::Target::last_two, ops::kMovAl1RetNop,
             kCollectorStubLength},
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

    std::span<const SkipLauncherEntry> SkipLauncherEntries() noexcept
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
        // null when the signature is absent on this image. Jump rows resolve their
        // target through the plan list, so nothing is scanned twice.
        struct EntryPlan
        {
            const SkipLauncherEntry* entry{};
            std::uint8_t* match{};
        };

        using EntryPlanList = std::vector<EntryPlan>;

        // True when every jump row's target entry matched. The original shares one
        // guard between the E9 and its 33 C0/rel32 rows, so an absent target skips
        // the whole entry, not just the jump.
        [[nodiscard]] bool JumpTargetsPresent(const SkipLauncherEntry& entry,
                                              const EntryPlanList& plans) noexcept
        {
            for (std::size_t index = 0; index < entry.writeCount; ++index)
            {
                const std::uint32_t targetEntry = entry.writes[index].jumpToEntry;
                if (targetEntry != kNoJumpTarget &&
                    (targetEntry >= plans.size() || plans[targetEntry].match == nullptr))
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
            return target == SkipLauncherCollector::Target::first_two ? hit < 2 : hit + 2 >= hits;
        }

        // Applies one write row:
        //   * jump row: rewrite the whole branch one byte before the rel32 (the
        //     preceding row wrote the E9) so the displacement is measured from the
        //     end of the instruction, not from the literal dword;
        //   * byte row: store the recovered bytes;
        //   * fill row: repeat the row's fill byte (NOP in the recovered data).
        PatchOutcome ApplyWriteRow(std::span<std::byte> image, std::uint8_t* match,
                                   const SkipLauncherWrite& write,
                                   const EntryPlanList& plans, SkipLauncherReport& report)
        {
            std::uint8_t* site = MatchAt(match, write.offset);

            if (write.jumpToEntry != kNoJumpTarget)
            {
                std::uint8_t* target = write.jumpToEntry < plans.size()
                                           ? plans[write.jumpToEntry].match
                                           : nullptr;
                if (target == nullptr)
                {
                    // The entry-level jump check already rejected this case; keep
                    // the guard because this is the only place the row's target is
                    // dereferenced.
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

            if (!InBounds(image, site, write.length))
            {
                return std::unexpected(PatchError{PatchErrorCode::out_of_bounds,
                                                  "site out of bounds"});
            }

            if (write.bytes != nullptr)
            {
                injector::WriteMemoryRaw(injector::raw_ptr(site),
                                         const_cast<std::uint8_t*>(write.bytes), write.length,
                                         true);
            }
            else
            {
                // The installer writes the row's own fill byte instead of assuming
                // 0x90; xla_table_parity rejects a non-NOP fill on these rows.
                injector::MemoryFill(injector::raw_ptr(site), write.fill, write.length, true);
            }

            ++report.writes;
            return {};
        }

        // Applies one matched entry. The rows are in the recovered order and share
        // the entry's single jump-target guard.
        PatchOutcome ApplyEntry(std::span<std::byte> image, const EntryPlan& plan,
                                const EntryPlanList& plans, SkipLauncherReport& report)
        {
            if (!JumpTargetsPresent(*plan.entry, plans))
            {
                return {};
            }

            for (std::size_t index = 0; index < plan.entry->writeCount; ++index)
            {
                const auto status =
                    ApplyWriteRow(image, plan.match, plan.entry->writes[index], plans, report);
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
            const std::span<const SkipLauncherEntry> entries = SkipLauncherEntries();
            EntryPlanList plans(entries.size());

            for (std::size_t index = 0; index < entries.size(); ++index)
            {
                const SkipLauncherEntry& entry = entries[index];
                plans[index].entry = &entry;

                hook::pattern pattern = Scan(image, entry.signature);
                if (pattern.empty())
                {
                    ++report.entriesMissing;
                    continue;
                }

                plans[index].match = pattern.get(0).get<std::uint8_t>();
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
        // ("mov al,1; ret; nop") is stored over the first/last matches, never
        // over the signature itself.
        PatchOutcome ApplyCollectors(std::span<std::byte> image, SkipLauncherReport& report)
        {
            for (const SkipLauncherCollector& collector : SkipLauncherCollectors())
            {
                hook::pattern pattern = Scan(image, collector.pattern);
                const std::size_t hits = pattern.size();
                if (hits == 0)
                {
                    continue;
                }

                ++report.collectorsFound;
                for (std::size_t hit = 0; hit < hits; ++hit)
                {
                    if (!CollectorTakes(collector.target, hit, hits))
                    {
                        continue;
                    }

                    std::uint8_t* site = pattern.get(hit).get<std::uint8_t>();
                    if (!InBounds(image, site, collector.length))
                    {
                        return std::unexpected(PatchError{PatchErrorCode::out_of_bounds,
                                                          "site out of bounds"});
                    }

                    injector::WriteMemoryRaw(injector::raw_ptr(site),
                                             const_cast<std::uint8_t*>(collector.bytes),
                                             collector.length, true);
                    ++report.collectorWrites;
                }
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
                report.createFileSlot = injector::ReadMemory<std::uint32_t>(
                    injector::raw_ptr(capture.get(0).get<std::uint8_t>() + kDfaCaptureSlotOffset));
            }

            PublishCreateFileSlot(report);
        }

        // Installs one stage's E8/E9 branches. A body the resolver does not know,
        // or a missing signature, counts as missing; a site outside the image is
        // the only failure.
        PatchOutcome InstallHooks(std::span<std::byte> image,
                                  std::span<const SkipLauncherInstall> installs,
                                  SkipHookResolver resolve, void* resolverUser,
                                  std::size_t& applied, std::size_t& missing)
        {
            for (const SkipLauncherInstall& install : installs)
            {
                const std::uintptr_t destination = resolve(install.hook, resolverUser);
                if (destination == 0)
                {
                    ++missing;
                    continue;
                }

                hook::pattern hookSite = Scan(image, install.signature);
                if (hookSite.empty())
                {
                    ++missing;
                    continue;
                }

                std::uint8_t* site = MatchAt(hookSite.get(0).get<std::uint8_t>(), install.offset);
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
                ++applied;
            }
            return {};
        }

        // Stage dfa, part 2: the six file-API hooks.
        PatchOutcome InstallDfaHooks(std::span<std::byte> image, SkipHookResolver resolve,
                                     void* resolverUser, SkipLauncherReport& report)
        {
            return InstallHooks(image, SkipLauncherDfaInstalls(), resolve, resolverUser,
                                report.dfaInstalls, report.dfaMissing);
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

                    injector::MakeJMP(
                        injector::raw_ptr(site),
                        injector::raw_ptr(targetPattern.get(0).get<std::uint8_t>()), true);
                    ++report.collectedInstalls;
                }
            }
            return {};
        }

        // Stage rom: the two message-window hooks.
        PatchOutcome InstallRomHooks(std::span<std::byte> image, SkipHookResolver resolve,
                                     void* resolverUser, SkipLauncherReport& report)
        {
            return InstallHooks(image, SkipLauncherRomInstalls(), resolve, resolverUser,
                                report.romInstalls, report.romMissing);
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

            // RomReset's object layout: [1] is the window handle, [4] the WM_ROM
            // id; [0], [2], [3] and [5..18] are cleared first.
            inline constexpr std::size_t kObjectWindow = 1;
            inline constexpr std::size_t kObjectMessage = 4;
            inline constexpr std::size_t kObjectClearFirst = 5;
            inline constexpr std::size_t kObjectClearLast = 18;

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

                constexpr std::size_t kStubAllocationBytes = 64; // one page, eleven used
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
            inline int __cdecl RomResetBody(std::uint32_t* object)
            {
                StartRomService();
                if (object == nullptr)
                {
                    return 0;
                }

                object[0] = 0;
                object[2] = 0;
                object[3] = 0;
                for (std::size_t index = kObjectClearFirst; index <= kObjectClearLast; ++index)
                {
                    object[index] = 0;
                }

                object[kObjectWindow] =
                    static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(gWindow.load()));
                object[kObjectMessage] = kRomMessage;
                return static_cast<int>(object[kObjectWindow]);
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
