// SPDX-License-Identifier: GPL-3.0-or-later
//
// xla.skip_launcher - the SkipLauncher=1 launcher/SecuROM bypass: the recovered
// ZolikaPatch tables and the hook bodies they jump to.
//
// Recovered from the original's handlers, in their order:
//   0x10045CE0  the 25-signature main table and the two multi-hit collectors
//   0x10004850  the DFA file-API hooks (6 installs) and the 2 collected jumps
//   0x10004620  the ROM message-window hooks (2 installs; bodies
//               0x10004570/0x10004610, service 0x100041A0..0x10004570)
//
// Behaviour and recovered data are ported from
// openprecepatch/xlivelessaddon/source/skip_launcher.ixx. Row order, bytes,
// offsets, lengths and fill values are data; the native suite pins the table
// shape, the shipped stage set, the bounds behaviour and the hook-body contracts.
//
// The two live DFA/ROM copies (this file for SkipLauncher=1, xla::dfa +
// xla::rom_window for SkipLauncher=0) are deliberately not merged: they differ in
// CreateFile forwarding, the CloseHandle fault answer, the ReadFile hook site and
// the DfaInit argument shape.

module;

#include <common.hxx>

export module skip_launcher;

import common;
import patch;

export namespace xla::skip_launcher
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
        std::int32_t offset{};
        std::span<const std::uint8_t> bytes{};
        std::uint16_t count{};
        std::uint8_t fill{};
        std::uint32_t target{};
    };

    [[nodiscard]] constexpr PatchOp WriteBytes(
        std::int32_t offset, std::span<const std::uint8_t> bytes) noexcept
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

    [[nodiscard]] constexpr PatchOp Jump(std::int32_t offset, std::uint32_t target) noexcept
    {
        return {.kind = PatchOp::Kind::jump, .offset = offset, .target = target};
    }

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

    struct EntryPatch
    {
        std::string_view signature;
        std::span<const PatchOp> ops;
    };

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

    struct SkipLauncherInstall
    {
        std::string_view signature;
        std::int32_t offset;
        Opcode opcode; // kCallRel32 or kJmpRel32
        SkipHook hook;
    };

    struct SkipLauncherCollectedTarget
    {
        std::string_view targetSignature;
        std::uint32_t index;
    };

    struct SkipLauncherCollectedInstall
    {
        std::string_view collector;
        const SkipLauncherCollectedTarget* targets;
        std::size_t targetCount;
    };

    struct SkipLauncherReport
    {
        std::size_t entriesFound{};
        std::size_t entriesMissing{};
        std::size_t writes{};
        std::size_t collectorsFound{};
        std::size_t collectorWrites{};
        bool jumpInstalled{};

        std::size_t dfaInstalls{};
        std::size_t dfaMissing{};
        std::size_t romInstalls{};
        std::size_t romMissing{};
        std::size_t collectedInstalls{};
        std::uint32_t createFileSlot{};
    };

    // The original's three passes as a bitmask. The shipping path applies only
    // `kShippedStages` (DFA + ROM): XLivelessAddon only ever ran those two, and
    // applying `main` after the add-on had hooked the launcher broke the GFWL
    // session. `main` stays available to callers that ask for it explicitly.
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

    [[nodiscard]] constexpr bool HasStage(SkipLauncherStage set,
                                          SkipLauncherStage stage) noexcept
    {
        return (static_cast<std::uint8_t>(set) & static_cast<std::uint8_t>(stage)) != 0;
    }

    inline constexpr SkipLauncherStage kShippedStages =
        SkipLauncherStage::dfa | SkipLauncherStage::rom;

    [[nodiscard]] std::string DescribeStages(SkipLauncherStage stages);

    std::span<const EntryPatch> SkipLauncherEntries() noexcept;
    std::span<const SkipLauncherCollector> SkipLauncherCollectors() noexcept;
    std::span<const SkipLauncherInstall> SkipLauncherDfaInstalls() noexcept;
    std::span<const SkipLauncherInstall> SkipLauncherRomInstalls() noexcept;
    std::span<const SkipLauncherCollectedInstall> SkipLauncherDfaCollected() noexcept;

    // The entry whose match feeds the jump install: the original reads the second
    // entry's match into its jump-target slot (entry 9 jumps here).
    inline constexpr std::uint32_t kSkipLauncherJumpTargetEntry = 1;

    // The one hard failure of the pass is a store outside the caller's image.
    struct PatchError
    {
        enum class Code : std::uint8_t
        {
            invalid_input,
            out_of_bounds,
        };
        Code code{Code::invalid_input};
        std::string_view detail{};
    };

    std::expected<SkipLauncherReport, PatchError> ApplySkipLauncher(
        const Image& image, SkipHookResolver resolve, void* resolverUser,
        SkipLauncherStage stages);

    void SetCreateFileSlot(std::uint32_t slotVa) noexcept;
    bool PublishCreateFileSlot(const SkipLauncherReport& report) noexcept;
    std::uintptr_t ResolveSkipHook(SkipHook hook, void* user) noexcept;
} // namespace xla::skip_launcher

namespace xla::skip_launcher
{
    namespace
    {
        constexpr std::size_t kBranchLength = 5; // E8/E9 <rel32>
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
        // The hook sites outside their matched window.
        constexpr std::int32_t kDfaReadFileSite = -165;
        constexpr std::int32_t kRomSetSite = -67;
        constexpr std::int32_t kRomResetCall = 6;

        inline constexpr std::int32_t kMaxPatchExtent = 0x200;

        // ---- the main table's inline patches (0x10045CE0) ------------------

        constexpr PatchOp kEntry0Ops[] = {
            WriteBytes(kEntry0Branch0, ops::kJmpRel8), // jz/jnz -> jmp
            WriteBytes(kEntry0Branch1, ops::kJmpRel8),
        };
        constexpr PatchOp kEntry2Ops[] = {
            WriteBytes(0, ops::kNop2),
            WriteBytes(kEntry2Branch1, ops::kNop2),
        };
        constexpr PatchOp kEntry3Ops[] = {
            WriteBytes(0, ops::kNop2),
        };
        constexpr PatchOp kEntry4Ops[] = {
            WriteBytes(kEntry4Jcc, ops::kNop6),
        };
        constexpr PatchOp kEntry5Ops[] = {
            WriteBytes(kEntry5Jcc, ops::kNop6),
        };
        constexpr PatchOp kEntry6Ops[] = {
            WriteBytes(0, ops::kNop6),
        };
        constexpr PatchOp kEntry7Ops[] = {
            ForceEaxZero(kEntry7Jcc),
            WriteBytes(kEntry7Store, ops::kNopMovMoffsEax),
        };
        constexpr PatchOp kEntry8Ops[] = {
            NopFill(kEntry8Memset, kEntry8MemsetLength),
        };
        constexpr PatchOp kEntry9Ops[] = {
            ForceEaxZero(0),
            WriteBytes(kEntry9JmpOpcode, ops::kJmpRel32),
            Jump(kEntry9JmpRel32, kSkipLauncherJumpTargetEntry),
        };
        constexpr PatchOp kEntry10Ops[] = {
            WriteBytes(0, ops::kNopMovMoffsEax),
        };
        constexpr PatchOp kEntry11Ops[] = {
            ForceEaxZero(0),
            WriteBytes(kEntry11Nop, ops::kNop4),
        };
        constexpr PatchOp kEntry12Ops[] = {
            WriteBytes(0, ops::kNop3),
            NopFill(kEntry12Tail, 11),
        };
        constexpr PatchOp kEntry13Ops[] = {
            WriteBytes(0, ops::kNop3),
            NopFill(kEntry13Tail, 11),
        };
        constexpr PatchOp kEntry14Ops[] = {
            WriteBytes(0, ops::kNop11),
        };
        constexpr PatchOp kEntry15Ops[] = {
            NopFill(0, 32),
        };
        constexpr PatchOp kEntry16Ops[] = {
            NopFill(0, 25),
        };
        constexpr PatchOp kEntry17Ops[] = {
            WriteBytes(0, ops::kNop8),
        };
        constexpr PatchOp kEntry18Ops[] = {
            WriteBytes(0, ops::kNop8),
        };
        constexpr PatchOp kEntry19Ops[] = {
            WriteBytes(0, ops::kNop14),
        };
        constexpr PatchOp kEntry20Ops[] = {
            ForceRet(0), // the whole function becomes `ret`
        };
        constexpr PatchOp kEntry21Ops[] = {
            NopFill(0, 16),
        };
        constexpr PatchOp kEntry22Ops[] = {
            WriteBytes(0, ops::kNop14),
        };
        constexpr PatchOp kEntry23Ops[] = {
            ForceEaxZeroRetNop(0), // xor eax,eax; ret; nop
        };
        constexpr PatchOp kEntry24Ops[] = {
            ForceEaxZeroRetNop(0),
        };

        // ---- the main table (0x10045CE0) ----------------------------------

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

        [[nodiscard]] constexpr std::int32_t PatchOpLength(const PatchOp& op) noexcept
        {
            switch (op.kind)
            {
            case PatchOp::Kind::write:
                return static_cast<std::int32_t>(op.bytes.size());
            case PatchOp::Kind::fill:
                return static_cast<std::int32_t>(op.count);
            case PatchOp::Kind::jump:
                return 4;
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

        constexpr SkipLauncherCollector kSkipLauncherCollectors[] = {
            {"A1 ? ? ? ? 85 C0 8B 0D ? ? ? ? 75", SkipLauncherCollector::Target::first_two,
             ops::kMovAl1RetNop},
            {"33 C0 83 3D ? ? ? ? 01 0F 94 C0 C3",
             SkipLauncherCollector::Target::last_two, ops::kMovAl1RetNop},
        };
        static_assert(std::size(kSkipLauncherCollectors) == 2);

        // ---- the CreateFile IAT capture ------------------------------------

        constexpr std::string_view kDfaCapturePattern = "FF 15 ? ? ? ? 8B F0 83 FE FF 74 24";
        constexpr std::int32_t kDfaCaptureSlotOffset = 2;

        // ---- the DFA hook installs (0x10004850) ----------------------------

        constexpr SkipLauncherInstall kSkipLauncherDfaInstalls[] = {
            {"E8 ? ? ? ? 83 C4 0C 83 F8 01 74 11 6A 00 6A 00", 0, Opcode::kCallRel32,
             SkipHook::dfa_init},
            {"55 8B EC 6A 00 E8", 0, Opcode::kJmpRel32, SkipHook::create_file},
            {"6A 00 E8 ? ? ? ? 83 F8 01 59 75 17 FF 15 ? ? ? ? 50 B9 ? ? ? ? E8 ? ? ? ? 8B "
             "40 08 FF 60 0C 33 C0 C3",
             0, Opcode::kJmpRel32, SkipHook::close_handle},
            {"6A 00 E8 ? ? ? ? 83 F8 01 59 75 17 FF 15 ? ? ? ? 50 B9 ? ? ? ? E8 ? ? ? ? 8B "
             "40 08 FF 60 ? 83 C8 FF C3",
             0, Opcode::kJmpRel32, SkipHook::set_file_pointer},
            {"56 8B 74 24 0C 8D 46 04 50 FF 74 24 0C E8 ? ? ? ? 59 59 33 C9 83 F8 FF 0F 95 "
             "C1 89 06 5E 8B C1 C3",
             0, Opcode::kJmpRel32, SkipHook::get_file_size_ex},
            {"FF 50 60 83 C4 14 39 75 F8 89 45 FC", kDfaReadFileSite,
             Opcode::kJmpRel32, SkipHook::read_file},
        };
        static_assert(std::size(kSkipLauncherDfaInstalls) == 6);

        // ---- the ROM hook installs (0x10004620) ----------------------------

        constexpr SkipLauncherInstall kSkipLauncherRomInstalls[] = {
            {"89 46 3C 89 4E 40 E8", kRomResetCall, Opcode::kCallRel32,
             SkipHook::rom_reset},
            {"0F 85 ? ? ? ? 68 03 01 00 00 68 ? ? ? ? 68 04 01 00 00", kRomSetSite,
             Opcode::kJmpRel32, SkipHook::rom_set},
        };
        static_assert(std::size(kSkipLauncherRomInstalls) == 2);

        // ---- the DFA collected jumps ---------------------------------------

        constexpr SkipLauncherCollectedTarget kDfaCollectedTargets_0[] = {
            {"80 BC 24 ? ? ? ? ? 6A 00", 0},
            {"6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 57", 1},
        };

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
} // namespace xla::skip_launcher

namespace xla::skip_launcher
{
    namespace
    {
        struct EntryPlan
        {
            const EntryPatch* entry{};
            std::uint8_t* match{};
        };
        using EntryPlanList = std::vector<EntryPlan>;

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

        [[nodiscard]] bool CollectorTakes(SkipLauncherCollector::Target target, std::size_t hit,
                                          std::size_t hits) noexcept
        {
            return target == SkipLauncherCollector::Target::first_two
                       ? hit < kCollectorWidth
                       : hit + kCollectorWidth >= hits;
        }

        std::expected<void, PatchError> ApplyPatchOp(const Image& image, std::uint8_t* match,
                                                     const PatchOp& op,
                                                     const EntryPlanList& plans,
                                                     SkipLauncherReport& report)
        {
            std::uint8_t* site = match + op.offset;

            switch (op.kind)
            {
            case PatchOp::Kind::jump:
            {
                std::uint8_t* target =
                    op.target < plans.size() ? plans[op.target].match : nullptr;
                if (target == nullptr)
                {
                    return {};
                }
                if (!patch::JumpAt(image, site - 1, target, "skipLauncher: jump"))
                {
                    return std::unexpected(
                        PatchError{PatchError::Code::out_of_bounds, "site out of bounds"});
                }
                report.jumpInstalled = true;
                ++report.writes;
                return {};
            }
            case PatchOp::Kind::write:
            {
                if (!patch::WriteRawAt(image, site, op.bytes, "skipLauncher: write"))
                {
                    return std::unexpected(
                        PatchError{PatchError::Code::out_of_bounds, "site out of bounds"});
                }
                ++report.writes;
                return {};
            }
            case PatchOp::Kind::fill:
            {
                if (!patch::FillAt(image, site, op.fill, op.count, "skipLauncher: fill"))
                {
                    return std::unexpected(
                        PatchError{PatchError::Code::out_of_bounds, "site out of bounds"});
                }
                ++report.writes;
                return {};
            }
            }

            return std::unexpected(
                PatchError{PatchError::Code::invalid_input, "unsupported patch op"});
        }

        std::expected<void, PatchError> ApplyEntry(const Image& image, const EntryPlan& plan,
                                                   const EntryPlanList& plans,
                                                   SkipLauncherReport& report)
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

        std::expected<void, PatchError> ApplyMainTable(const Image& image,
                                                       SkipLauncherReport& report)
        {
            const std::span<const EntryPatch> entries = SkipLauncherEntries();
            EntryPlanList plans(entries.size());

            for (std::size_t index = 0; index < entries.size(); ++index)
            {
                const EntryPatch& entry = entries[index];

                patch::Pattern pattern = patch::FindIn(image, entry.signature, 1);
                if (pattern.empty())
                {
                    ++report.entriesMissing;
                    Log::Trace("skipLauncher: entry {} missing", index);
                    continue;
                }

                const std::size_t hits = pattern.size();
                if (hits != 1)
                {
                    Log::Print("skipLauncher: entry {} matched {} site(s), expected 1", index,
                               hits);
                }

                plans[index] = {&entry, pattern.get<std::uint8_t>(0)};
                ++report.entriesFound;

                const auto status = ApplyEntry(image, plans[index], plans, report);
                if (!status)
                {
                    return status;
                }
            }
            return {};
        }

        std::expected<void, PatchError> ApplyCollectors(const Image& image,
                                                        SkipLauncherReport& report)
        {
            std::size_t collectorIndex = 0;
            for (const SkipLauncherCollector& collector : SkipLauncherCollectors())
            {
                patch::Pattern pattern = patch::FindIn(image, collector.pattern, 0);
                const std::size_t hits = pattern.size();
                if (hits == 0)
                {
                    ++collectorIndex;
                    continue;
                }

                ++report.collectorsFound;
                std::size_t applied = 0;
                for (std::size_t hit = 0; hit < hits; ++hit)
                {
                    if (!CollectorTakes(collector.target, hit, hits))
                    {
                        continue;
                    }
                    std::uint8_t* site = pattern.get<std::uint8_t>(hit);
                    if (!patch::WriteRawAt(image, site, collector.stub,
                                           "skipLauncher: collector"))
                    {
                        return std::unexpected(PatchError{
                            PatchError::Code::out_of_bounds, "site out of bounds"});
                    }
                    ++report.collectorWrites;
                    ++applied;
                }

                Log::Print("skipLauncher: collector {} matched {} site(s), patched {}",
                           collectorIndex, hits, applied);
                ++collectorIndex;
            }
            return {};
        }

        void CaptureCreateFileSlot(const Image& image, SkipLauncherReport& report)
        {
            patch::Pattern capture = patch::FindIn(image, kDfaCapturePattern, 1);
            if (!capture.empty())
            {
                report.createFileSlot = *capture.get_first<std::uint32_t>(kDfaCaptureSlotOffset);
            }

            PublishCreateFileSlot(report);
        }

        struct HookCounts
        {
            std::size_t installed{};
            std::size_t missing{};
        };

        std::expected<HookCounts, PatchError> InstallHooks(
            const Image& image, std::span<const SkipLauncherInstall> installs,
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

                patch::Pattern hookSite = patch::FindIn(image, install.signature, 1);
                if (hookSite.empty())
                {
                    ++counts.missing;
                    continue;
                }

                std::uint8_t* site = hookSite.get<std::uint8_t>(0) + install.offset;
                switch (install.opcode)
                {
                case Opcode::kCallRel32:
                    if (!patch::CallAt(image, site,
                                       reinterpret_cast<void*>(destination),
                                       "skipLauncher: hook call"))
                    {
                        return std::unexpected(PatchError{
                            PatchError::Code::out_of_bounds, "site out of bounds"});
                    }
                    break;
                case Opcode::kJmpRel32:
                    if (!patch::JumpAt(image, site, reinterpret_cast<std::uint8_t*>(destination),
                                       "skipLauncher: hook jump"))
                    {
                        return std::unexpected(PatchError{
                            PatchError::Code::out_of_bounds, "site out of bounds"});
                    }
                    break;
                default:
                    return std::unexpected(PatchError{PatchError::Code::invalid_input,
                                                      "unsupported branch opcode"});
                }
                ++counts.installed;
            }
            return counts;
        }

        std::expected<void, PatchError> InstallDfaHooks(const Image& image,
                                                        SkipHookResolver resolve,
                                                        void* resolverUser,
                                                        SkipLauncherReport& report)
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

        std::expected<void, PatchError> InstallCollectedJumps(const Image& image,
                                                              SkipLauncherReport& report)
        {
            for (const SkipLauncherCollectedInstall& install : SkipLauncherDfaCollected())
            {
                patch::Pattern anchor = patch::FindIn(image, install.collector, 0);
                for (std::size_t index = 0; index < install.targetCount; ++index)
                {
                    const SkipLauncherCollectedTarget& target = install.targets[index];
                    if (target.index >= anchor.size())
                    {
                        continue;
                    }

                    patch::Pattern targetPattern =
                        patch::FindIn(image, target.targetSignature, 1);
                    if (targetPattern.empty())
                    {
                        continue;
                    }

                    std::uint8_t* site = anchor.get<std::uint8_t>(target.index);
                    if (!patch::JumpAt(image, site,
                                       targetPattern.get_first<std::uint8_t>(),
                                       "skipLauncher: collected jump"))
                    {
                        return std::unexpected(PatchError{
                            PatchError::Code::out_of_bounds, "site out of bounds"});
                    }
                    ++report.collectedInstalls;
                }
            }
            return {};
        }

        std::expected<void, PatchError> InstallRomHooks(const Image& image,
                                                        SkipHookResolver resolve,
                                                        void* resolverUser,
                                                        SkipLauncherReport& report)
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
        const Image& image, SkipHookResolver resolve, void* resolverUser,
        SkipLauncherStage stages)
    {
        if (image.empty())
        {
            return std::unexpected(
                PatchError{PatchError::Code::invalid_input, "invalid skip launcher input"});
        }

        SkipLauncherReport report;

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

        if (HasStage(stages, SkipLauncherStage::dfa))
        {
            CaptureCreateFileSlot(image, report);
        }

        if (resolve)
        {
            if (HasStage(stages, SkipLauncherStage::dfa))
            {
                if (auto status = InstallDfaHooks(image, resolve, resolverUser, report);
                    !status)
                {
                    return std::unexpected(status.error());
                }
                if (auto status = InstallCollectedJumps(image, report); !status)
                {
                    return std::unexpected(status.error());
                }
            }

            if (HasStage(stages, SkipLauncherStage::rom))
            {
                if (auto status = InstallRomHooks(image, resolve, resolverUser, report);
                    !status)
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
        const auto append = [&](SkipLauncherStage stage, std::string_view name)
        {
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
} // namespace xla::skip_launcher

// ===========================================================================
// Hook bodies
// ===========================================================================
//
// The bodies the install rows jump to. They run inside the game process, so the
// ABI is part of the recovered contract:
//   * CreateFile, CloseHandle, SetFilePointer, GetFileSizeEx, ReadFile, DfaInit
//     and RomReset are __cdecl (plain `ret`): the patched site's caller pops the
//     arguments, exactly as it popped the original's.
//   * RomSet takes the object in ESI and returns with `ret 8` (the site pushed
//     two arguments the callee must pop). A C function cannot express a register
//     argument plus a callee stack pop, so its eleven opcode bytes are assembled
//     into an executable page at install time.
// The originals live at 0x10004720..0x1000484e (file API + DFA) and
// 0x100041A0..0x10004710 (WM_ROM service, RomReset, RomSet).

namespace xla::skip_launcher
{
    namespace
    {
        // The CreateFile IAT slot captured by the DFA stage; 0 means the body
        // calls CreateFileA directly (no slot captured yet, or none on this image).
        inline std::atomic<std::uint32_t> gCreateFileSlot{0};
    } // namespace

    namespace dfa
    {
        using CreateFileAFn = HANDLE(WINAPI*)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES,
                                              DWORD, DWORD, HANDLE);

        // 0x10004780: replaces the DFA init call so it reports success. ABI:
        // __cdecl, no arguments; the call site is `E8 rel32; 83 C4 0C`, so the
        // caller discards the three arguments itself.
        inline int __cdecl DfaInitBody()
        {
            return 1;
        }

        // 0x10004820: CreateFileA through the captured IAT slot, falling back to
        // the import when nothing was captured. The original trampoline is
        // __cdecl (plain ret; the caller pops the seven arguments).
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
                    return fn(fileName, desiredAccess, shareMode, security, creationDisposition,
                              flags, templateFile);
                }
            }

            return ::CreateFileA(fileName, desiredAccess, shareMode, security,
                                 creationDisposition, flags, templateFile);
        }

        // 0x10004790: the original wraps CloseHandle in SEH and returns -1
        // (its `or eax,-1` filter at 0x100047EC) when it faults.
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

        inline DWORD __cdecl SetFilePointerBody(HANDLE handle, LONG distance,
                                                PLONG distanceHigh, DWORD moveMethod)
        {
            return ::SetFilePointer(handle, distance, distanceHigh, moveMethod);
        }

        inline BOOL __cdecl GetFileSizeExBody(HANDLE handle, PLARGE_INTEGER size)
        {
            return ::GetFileSizeEx(handle, size);
        }

        inline BOOL __cdecl ReadFileBody(HANDLE handle, LPVOID buffer, DWORD toRead,
                                         LPDWORD read, LPOVERLAPPED overlapped)
        {
            return ::ReadFile(handle, buffer, toRead, read, overlapped);
        }
    } // namespace dfa

    namespace rom
    {
        inline constexpr UINT kRomMessage = 43858; // WM_ROM in the original
        inline constexpr char kClassName[] = "MessageWindow";
        inline constexpr char kClassFallback[] = "MessageWindow2";

        // xmmword_10104050..0x10104080: the table the ROM service hands to the
        // game (action 18 copies all 16 dwords).
        inline constexpr std::array<std::uint32_t, 16> kActionTable{
            8, 11, 241, 1, 240, 2, 7, 12, 3, 243, 9, 6, 10, 5, 4, 242,
        };

        inline constexpr std::size_t kPayloadAction = 4;
        inline constexpr std::size_t kPayloadArg0 = 5;
        inline constexpr std::size_t kPayloadArg1 = 6;

        inline constexpr std::uint32_t kActionCopyTable = 18;
        inline constexpr std::uint32_t kActionAdd = 51;
        inline constexpr std::uint32_t kActionSet = 100;

        // RomReset's object (0x10004570): 19 32-bit slots. The window handle sits
        // in slot 1 and the WM_ROM id in slot 4; the original zeroes slot 0, 2, 3
        // and 5..18 first, so a whole-object zero followed by the two publishes
        // ends in the same state.
        struct RomObject
        {
            std::uint32_t slot0{};
            std::uint32_t window{}; // slot 1
            std::uint32_t slot2{};
            std::uint32_t slot3{};
            std::uint32_t message{};                    // slot 4
            std::array<std::uint32_t, 14> tail{};       // slots 5..18
        };
        static_assert(offsetof(RomObject, window) == sizeof(std::uint32_t));
        static_assert(offsetof(RomObject, message) == 4 * sizeof(std::uint32_t));
        static_assert(sizeof(RomObject) == 19 * sizeof(std::uint32_t));

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
                    std::memcpy(
                        reinterpret_cast<void*>(
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

            ::CreateWindowExA(0,
                              reinterpret_cast<LPCSTR>(static_cast<std::uintptr_t>(atom)), "",
                              0, 0, 0, 0, 0, HWND_MESSAGE, nullptr, wc.hInstance, nullptr);

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

        // 0x10004610: the object arrives in ESI (the patched site keeps it there)
        // and the site pushed two arguments the callee must pop. The original is
        // `mov ecx,[esi+1c]; mov [esi+20],ecx; mov al,1; ret 8`; a C function
        // cannot express that, so the eleven opcode bytes are assembled into an
        // executable page once and cached.
        inline void* RomSetStub()
        {
            static std::atomic<void*> cached{nullptr};
            if (void* existing = cached.load(); existing != nullptr)
            {
                return existing;
            }

            constexpr std::size_t kStubAllocationBytes = 64;
            void* memory = ::VirtualAlloc(nullptr, kStubAllocationBytes,
                                          MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (memory == nullptr)
            {
                Log::Line("rom: cannot allocate the RomSet stub");
                return nullptr;
            }

            // 8B 4E 1C   mov ecx,[esi+0x1c]
            // 89 4E 20   mov [esi+0x20],ecx
            // B0 01      mov al,1
            // C2 08 00   ret 8
            constexpr std::uint8_t kCode[] = {
                Byte(Opcode::kMovR32Rm32), 0x4E, 0x1C,
                Byte(Opcode::kMovRm32R32), 0x4E, 0x20,
                Byte(Opcode::kMovAlImm8), 0x01,
                ops::kRet8[0], ops::kRet8[1], ops::kRet8[2],
            };
            static_assert(std::size(kCode) == 11);
            static_assert(std::size(ops::kRet8) == 3);
            std::memcpy(memory, kCode, sizeof(kCode));
            ::FlushInstructionCache(::GetCurrentProcess(), memory, sizeof(kCode));
            cached.store(memory);
            return memory;
        }

        // 0x10004570: start the ROM service, reset the object and publish the
        // window handle plus the WM_ROM id. ABI: __cdecl with one stack argument,
        // returning the window handle in eax (plain ret).
        inline int __cdecl RomResetBody(RomObject* object)
        {
            StartRomService();
            if (object == nullptr)
            {
                return 0;
            }

            *object = RomObject{};
            object->window = static_cast<std::uint32_t>(
                reinterpret_cast<std::uintptr_t>(gWindow.load()));
            object->message = kRomMessage;
            return static_cast<int>(object->window);
        }
    } // namespace rom

    void SetCreateFileSlot(std::uint32_t slotVa) noexcept
    {
        gCreateFileSlot.store(slotVa);
    }

    bool PublishCreateFileSlot(const SkipLauncherReport& report) noexcept
    {
        SetCreateFileSlot(report.createFileSlot);
        return report.createFileSlot != 0;
    }

    std::uintptr_t ResolveSkipHook(SkipHook hook, void*) noexcept
    {
        switch (hook)
        {
        case SkipHook::dfa_init:
            return reinterpret_cast<std::uintptr_t>(&dfa::DfaInitBody);
        case SkipHook::create_file:
            return reinterpret_cast<std::uintptr_t>(&dfa::CreateFileBody);
        case SkipHook::close_handle:
            return reinterpret_cast<std::uintptr_t>(&dfa::CloseHandleGuardedBody);
        case SkipHook::set_file_pointer:
            return reinterpret_cast<std::uintptr_t>(&dfa::SetFilePointerBody);
        case SkipHook::get_file_size_ex:
            return reinterpret_cast<std::uintptr_t>(&dfa::GetFileSizeExBody);
        case SkipHook::read_file:
            return reinterpret_cast<std::uintptr_t>(&dfa::ReadFileBody);
        case SkipHook::rom_reset:
            return reinterpret_cast<std::uintptr_t>(&rom::RomResetBody);
        case SkipHook::rom_set:
            return reinterpret_cast<std::uintptr_t>(rom::RomSetStub());
        }
        return 0;
    }
} // namespace xla::skip_launcher
