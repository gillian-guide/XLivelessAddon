// SPDX-License-Identifier: GPL-3.0-or-later
//
// xla.skip_launcher — the launcher/SecuROM bypass descended from
// XLivelessAddon and reimplemented from ZolikaPatch's handler at 0x10045ce0.
//
// The tables follow the original handler's order: the main signature table
// (0x10045CE0), the two multi-hit collectors, the DFA file-API hooks
// (0x10004850) and the ROM message-window patches (0x10004620). The tables are
// byte-identical to the recovered ones; only the wrapper is ours.
//
// Writes target a caller-owned image. The installers never guess: a missing
// signature is a logged skip, and a store outside the image is an error.

module;

#include "common.hxx"

export module xla.skip_launcher;

import xla.common;

export namespace xla
{
    // One store relative to a signature match: `bytes`, or `fill` repeated, and a
    // rel32 to another entry's match when `jumpToEntry` is set (the 33 C0 E9 rel32).
    struct SkipLauncherWrite
    {
        std::int32_t offset;
        std::uint16_t length;
        const std::uint8_t* bytes; // null when fill is used
        std::uint8_t fill;         // e.g. 0x90 for NOP fills
        std::uint32_t jumpToEntry;
    };

    inline constexpr std::uint32_t kNoJumpTarget = 0xFFFFFFFFu;

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
    // E8/E9 jumps from the game module into its own.
    enum class SkipHook : std::uint8_t
    {
        dfa_init,       // 0x10004780: return 1
        create_file,    // 0x10004820: CreateFileA through the captured slot
        close_handle,   // 0x10004790: CloseHandle with an exception guard
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
        std::uint8_t opcode; // 0xE8 call or 0xE9 jump
        SkipHook hook;
    };

    struct SkipLauncherCollectedTarget
    {
        std::string_view targetSignature;
        std::uint32_t index; // collected match index the jump is installed at
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
        std::size_t dfaInstalls{}; // DFA hook jumps written
        std::size_t dfaMissing{};  // DFA signatures absent this build
        std::size_t romInstalls{}; // ROM hook jumps written
        std::size_t romMissing{};
        std::size_t collectedInstalls{}; // DFA collected-site jumps
        std::uint32_t createFileSlot{};  // captured IAT slot VA (0 when absent)
    };

    // The original's stages: main writes, then DFA (0x10004850) under its
    // XLivelessAddon/GTAC.dll/EFLC/one-shot guards, then ROM (0x10004620) always;
    // MiscFixes calls DFA again (0x10024018).
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

    // Table accessors; the spans cover the recovered rows.
    std::span<const SkipLauncherEntry> SkipLauncherEntries() noexcept;
    std::span<const SkipLauncherCollector> SkipLauncherCollectors() noexcept;
    std::span<const SkipLauncherInstall> SkipLauncherDfaInstalls() noexcept;
    std::span<const SkipLauncherInstall> SkipLauncherRomInstalls() noexcept;
    std::span<const SkipLauncherCollectedInstall> SkipLauncherDfaCollected() noexcept;

    // The entry whose match feeds the jump install: the original reads the second
    // entry's match into its jump-target slot.
    inline constexpr std::uint32_t kSkipLauncherJumpTargetEntry = 1;

    // Applies the patches selected by `stages` to `image`. Missing signatures are
    // skipped, never guessed, exactly like the original; the hook stages need
    // `resolve` and do not run without it.
    std::expected<SkipLauncherReport, PatchError> ApplySkipLauncher(
        std::span<std::byte> image, SkipHookResolver resolve, void* resolverUser,
        SkipLauncherStage stages = SkipLauncherStage::all);

    // Records the CreateFile IAT slot captured from the game; 0 makes the hook
    // call CreateFileA directly.
    void SetCreateFileSlot(std::uint32_t slotVa) noexcept;

    // Publishes the slot captured into the create_file body so it forwards through
    // the game's IAT slot (and any detour another ASI installed there), like the
    // original trampoline at 0x10004820. Call it after ApplySkipLauncher, before
    // the game reaches the hooked DFA entry point.
    bool PublishCreateFileSlot(const SkipLauncherReport& report) noexcept;

    // Resolves a SkipHook to the reimplemented body; 0 for an unknown hook.
    std::uintptr_t ResolveSkipHook(SkipHook hook, void* user) noexcept;
} // namespace xla

namespace xla
{
    namespace
    {
        constexpr std::uint8_t kNopByte = 0x90;
        constexpr std::uint8_t kCallOpcode = 0xE8;
        constexpr std::uint8_t kJumpOpcode = 0xE9;
        constexpr std::size_t kDwordLength = 4;
        constexpr std::size_t kBranchLength = 5; // E8/E9 <rel32>
        constexpr std::uint16_t kCollectorStubLength = 4;

        constexpr std::uint8_t kSkipEntryBytes_0_0[] = {0xeb};              // jmp rel8
        constexpr std::uint8_t kSkipEntryBytes_0_1[] = {0xeb};              // jmp rel8
        constexpr std::uint8_t kSkipEntryBytes_2_0[] = {0x90, 0x90};        // nop 2
        constexpr std::uint8_t kSkipEntryBytes_2_1[] = {0x90, 0x90};        // nop 2
        constexpr std::uint8_t kSkipEntryBytes_3_0[] = {0x90, 0x90};        // nop 2
        constexpr std::uint8_t kSkipEntryBytes_4_0[] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
        constexpr std::uint8_t kSkipEntryBytes_5_0[] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
        constexpr std::uint8_t kSkipEntryBytes_6_0[] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
        constexpr std::uint8_t kSkipEntryBytes_7_0[] = {0x33, 0xc0};        // xor eax,eax
        constexpr std::uint8_t kSkipEntryBytes_7_1[] = {0x90, 0xa3};        // nop; mov [imm32],eax
        constexpr std::uint8_t kSkipEntryBytes_9_0[] = {0x33, 0xc0};        // xor eax,eax
        constexpr std::uint8_t kSkipEntryBytes_9_1[] = {0xe9};              // jmp rel32
        constexpr std::uint8_t kSkipEntryBytes_10_0[] = {0x90, 0xa3};       // nop; mov [imm32],eax
        constexpr std::uint8_t kSkipEntryBytes_11_0[] = {0x33, 0xc0};       // xor eax,eax
        constexpr std::uint8_t kSkipEntryBytes_11_1[] = {0x90, 0x90, 0x90, 0x90};
        constexpr std::uint8_t kSkipEntryBytes_12_0[] = {0x90, 0x90, 0x90};
        constexpr std::uint8_t kSkipEntryBytes_13_0[] = {0x90, 0x90, 0x90};
        constexpr std::uint8_t kSkipEntryBytes_14_0[] = {
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        };
        constexpr std::uint8_t kSkipEntryBytes_17_0[] = {0x90, 0x90, 0x90, 0x90,
                                                         0x90, 0x90, 0x90, 0x90};
        constexpr std::uint8_t kSkipEntryBytes_18_0[] = {0x90, 0x90, 0x90, 0x90,
                                                         0x90, 0x90, 0x90, 0x90};
        constexpr std::uint8_t kSkipEntryBytes_19_0[] = {
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        };
        constexpr std::uint8_t kSkipEntryBytes_20_0[] = {0xc3}; // ret
        constexpr std::uint8_t kSkipEntryBytes_22_0[] = {
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        };
        constexpr std::uint8_t kSkipEntryBytes_23_0[] = {0x33, 0xc0, 0xc3, 0x90}; // xor; ret; nop
        constexpr std::uint8_t kSkipEntryBytes_24_0[] = {0x33, 0xc0, 0xc3, 0x90}; // xor; ret; nop

        // The collectors' stub: "mov al,1; ret; nop" over each collected match.
        constexpr std::uint8_t kSkipCollectorBytes_0[] = {0xb0, 0x01, 0xc3, 0x90};
        constexpr std::uint8_t kSkipCollectorBytes_1[] = {0xb0, 0x01, 0xc3, 0x90};

        // Entry i's stores: {match-relative offset, length, bytes (null = fill),
        // fill byte, jump-target entry (kNoJumpTarget = not a jump)}.
        constexpr SkipLauncherWrite kSkipEntryWrites_0[] = {
            {34, 1, kSkipEntryBytes_0_0, 0, kNoJumpTarget},
            {223, 1, kSkipEntryBytes_0_1, 0, kNoJumpTarget},
        };
        constexpr SkipLauncherWrite kSkipEntryWrites_2[] = {
            {0, 2, kSkipEntryBytes_2_0, 0, kNoJumpTarget},
            {5, 2, kSkipEntryBytes_2_1, 0, kNoJumpTarget},
        };
        constexpr SkipLauncherWrite kSkipEntryWrites_3[] = {
            {0, 2, kSkipEntryBytes_3_0, 0, kNoJumpTarget},
        };
        constexpr SkipLauncherWrite kSkipEntryWrites_4[] = {
            {3, 6, kSkipEntryBytes_4_0, 0, kNoJumpTarget},
        };
        constexpr SkipLauncherWrite kSkipEntryWrites_5[] = {
            {3, 6, kSkipEntryBytes_5_0, 0, kNoJumpTarget},
        };
        constexpr SkipLauncherWrite kSkipEntryWrites_6[] = {
            {0, 6, kSkipEntryBytes_6_0, 0, kNoJumpTarget},
        };
        constexpr SkipLauncherWrite kSkipEntryWrites_7[] = {
            {3, 2, kSkipEntryBytes_7_0, 0, kNoJumpTarget},
            {10, 2, kSkipEntryBytes_7_1, 0, kNoJumpTarget},
        };
        constexpr SkipLauncherWrite kSkipEntryWrites_8[] = {
            {1, 447, nullptr, kNopByte, kNoJumpTarget},
        };
        constexpr SkipLauncherWrite kSkipEntryWrites_9[] = {
            {0, 2, kSkipEntryBytes_9_0, 0, kNoJumpTarget},
            {2, 1, kSkipEntryBytes_9_1, 0, kNoJumpTarget},
            {3, 4, nullptr, 0, kSkipLauncherJumpTargetEntry},
        };
        constexpr SkipLauncherWrite kSkipEntryWrites_10[] = {
            {0, 2, kSkipEntryBytes_10_0, 0, kNoJumpTarget},
        };
        constexpr SkipLauncherWrite kSkipEntryWrites_11[] = {
            {0, 2, kSkipEntryBytes_11_0, 0, kNoJumpTarget},
            {2, 4, kSkipEntryBytes_11_1, 0, kNoJumpTarget},
        };
        constexpr SkipLauncherWrite kSkipEntryWrites_12[] = {
            {0, 3, kSkipEntryBytes_12_0, 0, kNoJumpTarget},
            {6, 11, nullptr, kNopByte, kNoJumpTarget},
        };
        constexpr SkipLauncherWrite kSkipEntryWrites_13[] = {
            {0, 3, kSkipEntryBytes_13_0, 0, kNoJumpTarget},
            {6, 11, nullptr, kNopByte, kNoJumpTarget},
        };
        constexpr SkipLauncherWrite kSkipEntryWrites_14[] = {
            {0, 11, kSkipEntryBytes_14_0, 0, kNoJumpTarget},
        };
        constexpr SkipLauncherWrite kSkipEntryWrites_15[] = {
            {0, 32, nullptr, kNopByte, kNoJumpTarget},
        };
        constexpr SkipLauncherWrite kSkipEntryWrites_16[] = {
            {0, 25, nullptr, kNopByte, kNoJumpTarget},
        };
        constexpr SkipLauncherWrite kSkipEntryWrites_17[] = {
            {0, 8, kSkipEntryBytes_17_0, 0, kNoJumpTarget},
        };
        constexpr SkipLauncherWrite kSkipEntryWrites_18[] = {
            {0, 8, kSkipEntryBytes_18_0, 0, kNoJumpTarget},
        };
        constexpr SkipLauncherWrite kSkipEntryWrites_19[] = {
            {0, 14, kSkipEntryBytes_19_0, 0, kNoJumpTarget},
        };
        constexpr SkipLauncherWrite kSkipEntryWrites_20[] = {
            {0, 1, kSkipEntryBytes_20_0, 0, kNoJumpTarget},
        };
        constexpr SkipLauncherWrite kSkipEntryWrites_21[] = {
            {0, 16, nullptr, kNopByte, kNoJumpTarget},
        };
        constexpr SkipLauncherWrite kSkipEntryWrites_22[] = {
            {0, 14, kSkipEntryBytes_22_0, 0, kNoJumpTarget},
        };
        constexpr SkipLauncherWrite kSkipEntryWrites_23[] = {
            {0, 4, kSkipEntryBytes_23_0, 0, kNoJumpTarget},
        };
        constexpr SkipLauncherWrite kSkipEntryWrites_24[] = {
            {0, 4, kSkipEntryBytes_24_0, 0, kNoJumpTarget},
        };

        constexpr SkipLauncherEntry kSkipLauncherEntries[] = {
            {"84 DB 0F 85 43 01 00 00 8D 4C 24 28 8B C1", kSkipEntryWrites_0,
             std::size(kSkipEntryWrites_0)},
            {"68 ? ? ? ? 89 35 ? ? ? ? E8 ? ? ? ? 83 C4 04 84 C0 0F 84", nullptr, 0},
            {"74 EC 38 5E 06 74 E7 68", kSkipEntryWrites_2, std::size(kSkipEntryWrites_2)},
            {"74 C4 8B 07 3B 46 18 75 BD 68", kSkipEntryWrites_3,
             std::size(kSkipEntryWrites_3)},
            {"3B 56 18 0F 85", kSkipEntryWrites_4, std::size(kSkipEntryWrites_4)},
            {"3B 4E 18 0F 85", kSkipEntryWrites_5, std::size(kSkipEntryWrites_5)},
            {"0F 85 ? ? ? ? 8B 8C 24 ? ? ? ? 5F 5E 5B 33 CC C6", kSkipEntryWrites_6,
             std::size(kSkipEntryWrites_6)},
            {"3B 46 18 75 BD", kSkipEntryWrites_7, std::size(kSkipEntryWrites_7)},
            {"57 51 C7 44 24 ? ? ? ? ? C7 44 24 ? ? ? ? ? C7 44 24", kSkipEntryWrites_8,
             std::size(kSkipEntryWrites_8)},
            {"8B 56 1C 3B 56 20 ? ? 6A 00 6A 00", kSkipEntryWrites_9,
             std::size(kSkipEntryWrites_9)},
            {"89 35 ? ? ? ? E8 ? ? ? ? 83 C4 04 84 C0", kSkipEntryWrites_10,
             std::size(kSkipEntryWrites_10)},
            {"8B 50 2C 3B 50 30", kSkipEntryWrites_11, std::size(kSkipEntryWrites_11)},
            {"8B 48 2C 83 EC 78", kSkipEntryWrites_12, std::size(kSkipEntryWrites_12)},
            {"8B 48 2C 83 EC 74", kSkipEntryWrites_13, std::size(kSkipEntryWrites_13)},
            {"8B 48 2C 3B 48 30 74 03", kSkipEntryWrites_14, std::size(kSkipEntryWrites_14)},
            {"8B 48 2C 3B 48 30 53", kSkipEntryWrites_15, std::size(kSkipEntryWrites_15)},
            {"8B 48 2C 3B 48 30 74 11", kSkipEntryWrites_16, std::size(kSkipEntryWrites_16)},
            {"8B 48 2C 3B 48 30 75 DC 8D 54 24 18", kSkipEntryWrites_17,
             std::size(kSkipEntryWrites_17)},
            {"8B 48 2C 3B 48 30 75 DC 8D 54 24 1C", kSkipEntryWrites_18,
             std::size(kSkipEntryWrites_18)},
            {"8B 0D ? ? ? ? 8B 51 2C", kSkipEntryWrites_19, std::size(kSkipEntryWrites_19)},
            {"51 53 55 56 57 8B 3D ? ? ? ? 8B 47 2C", kSkipEntryWrites_20,
             std::size(kSkipEntryWrites_20)},
            {"3B C7 0F 85 ? ? ? ? 85 C0", kSkipEntryWrites_21, std::size(kSkipEntryWrites_21)},
            {"0F 85 ? ? ? ? 85 C0 0F 84 ? ? ? ? E8 ? ? ? ? 85 D2", kSkipEntryWrites_22,
             std::size(kSkipEntryWrites_22)},
            {"83 EC 24 A1 ? ? ? ? 8B 48 14 53 55 56 57", kSkipEntryWrites_23,
             std::size(kSkipEntryWrites_23)},
            {"83 EC 08 8B 0D ? ? ? ? 8B 51 14 8D 04 24 50 6A 00 52", kSkipEntryWrites_24,
             std::size(kSkipEntryWrites_24)},
        };

        constexpr SkipLauncherCollector kSkipLauncherCollectors[] = {
            {"A1 ? ? ? ? 85 C0 8B 0D ? ? ? ? 75", SkipLauncherCollector::Target::first_two,
             kSkipCollectorBytes_0, kCollectorStubLength},
            {"33 C0 83 3D ? ? ? ? 01 0F 94 C0 C3",
             SkipLauncherCollector::Target::last_two, kSkipCollectorBytes_1,
             kCollectorStubLength},
        };

        // `FF 15` is a call through an IAT slot; the slot VA is the operand at +2.
        constexpr std::string_view kDfaCapturePattern = "FF 15 ? ? ? ? 8B F0 83 FE FF 74 24";
        constexpr std::int32_t kDfaCaptureSlotOffset = 2;

        // DFA file-API hooks: the original installs these E8/E9 jumps from 0x10004850.
        constexpr SkipLauncherInstall kSkipLauncherDfaInstalls[] = {
            {"E8 ? ? ? ? 83 C4 0C 83 F8 01 74 11 6A 00 6A 00", 0, kCallOpcode,
             SkipHook::dfa_init},
            {"55 8B EC 6A 00 E8", 0, kJumpOpcode, SkipHook::create_file},
            {"6A 00 E8 ? ? ? ? 83 F8 01 59 75 17 FF 15 ? ? ? ? 50 B9 ? ? ? ? E8 ? ? ? ? 8B "
             "40 08 FF 60 0C 33 C0 C3",
             0, kJumpOpcode, SkipHook::close_handle},
            {"6A 00 E8 ? ? ? ? 83 F8 01 59 75 17 FF 15 ? ? ? ? 50 B9 ? ? ? ? E8 ? ? ? ? 8B "
             "40 08 FF 60 ? 83 C8 FF C3",
             0, kJumpOpcode, SkipHook::set_file_pointer},
            {"56 8B 74 24 0C 8D 46 04 50 FF 74 24 0C E8 ? ? ? ? 59 59 33 C9 83 F8 FF 0F 95 "
             "C1 89 06 5E 8B C1 C3",
             0, kJumpOpcode, SkipHook::get_file_size_ex},
            {"FF 50 60 83 C4 14 39 75 F8 89 45 FC", -165, kJumpOpcode, SkipHook::read_file},
        };

        // ROM message-window hooks: the original installs these from 0x10004620.
        constexpr SkipLauncherInstall kSkipLauncherRomInstalls[] = {
            {"89 46 3C 89 4E 40 E8", 6, kCallOpcode, SkipHook::rom_reset},
            {"0F 85 ? ? ? ? 68 03 01 00 00 68 ? ? ? ? 68 04 01 00 00", -67, kJumpOpcode,
             SkipHook::rom_set},
        };

        // The collector's two jump targets: index 0 of the first pattern, index 1 of
        // the second.
        constexpr SkipLauncherCollectedTarget kDfaCollectedTargets_0[] = {
            {"80 BC 24 ? ? ? ? ? 6A 00", 0},
            {"6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 57", 1},
        };

        constexpr SkipLauncherCollectedInstall kSkipLauncherDfaCollected[] = {
            {"A1 ? ? ? ? B9 A7 FA DC 5C F7 E1 8B 0D ? ? ? ? 33 F6", kDfaCollectedTargets_0,
             std::size(kDfaCollectedTargets_0)},
        };

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
        const std::span<const SkipLauncherEntry> entries = SkipLauncherEntries();
        std::vector<const std::uint8_t*> matches(entries.size(), nullptr);

        if (HasStage(stages, SkipLauncherStage::main))
        {
            for (std::size_t index = 0; index < entries.size(); ++index)
            {
                const SkipLauncherEntry& entry = entries[index];
                hook::pattern pattern = Scan(image, entry.signature);

                if (pattern.empty())
                {
                    ++report.entriesMissing;
                    continue;
                }

                auto* match = pattern.get(0).get<std::uint8_t>();
                matches[index] = match;
                ++report.entriesFound;

                // The jump-installing entry needs its target entry's match (from the
                // 0x10045CE0 scan); when it is absent the whole block is skipped, not
                // just the jump - 33 C0 + E9 + rel32 share one [ebp-0x1c] guard.
                bool targetAbsent = false;
                for (std::size_t w = 0; w < entry.writeCount; ++w)
                {
                    const std::uint32_t targetEntry = entry.writes[w].jumpToEntry;
                    if (targetEntry != kNoJumpTarget &&
                        (targetEntry >= matches.size() || matches[targetEntry] == nullptr))
                    {
                        targetAbsent = true;
                        break;
                    }
                }

                if (targetAbsent)
                {
                    continue;
                }

                for (std::size_t w = 0; w < entry.writeCount; ++w)
                {
                    const SkipLauncherWrite& write = entry.writes[w];
                    auto* site = match + write.offset;

                    if (write.jumpToEntry != kNoJumpTarget)
                    {
                        const std::uint8_t* target =
                            write.jumpToEntry < matches.size() ? matches[write.jumpToEntry]
                                                               : nullptr;
                        if (!target)
                        {
                            continue; // the original skips when the target entry was absent
                        }
                        if (!InBounds(image, site, kDwordLength))
                        {
                            return std::unexpected(PatchError{PatchErrorCode::out_of_bounds,
                                                              "site out of bounds"});
                        }

                        // The recorded site is the rel32 itself; the E9 opcode sits one
                        // byte before it, so the displacement is measured from the end
                        // of the dword.
                        injector::WriteMemory<std::uint32_t>(
                            site,
                            static_cast<std::uint32_t>(
                                reinterpret_cast<std::uintptr_t>(target) -
                                (reinterpret_cast<std::uintptr_t>(site) + kDwordLength)),
                            true);
                        report.jumpInstalled = true;
                    }
                    else
                    {
                        if (!InBounds(image, site, write.length))
                        {
                            return std::unexpected(PatchError{PatchErrorCode::out_of_bounds,
                                                              "site out of bounds"});
                        }

                        if (write.bytes)
                        {
                            injector::WriteMemoryRaw(
                                site, const_cast<std::uint8_t*>(write.bytes), write.length, true);
                        }
                        else
                        {
                            // Every fill row in the tables is kNopByte.
                            injector::MakeNOP(site, write.length, true);
                        }
                    }

                    ++report.writes;
                }
            }

            const std::span<const SkipLauncherCollector> collectors = SkipLauncherCollectors();
            for (const SkipLauncherCollector& collector : collectors)
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
                    // first_two keeps matches 0 and 1; last_two keeps the final two
                    // (a lone match is one site for either rule).
                    if (collector.target == SkipLauncherCollector::Target::first_two)
                    {
                        if (hit >= 2)
                        {
                            break;
                        }
                    }
                    else if (hit + 2 < hits)
                    {
                        continue;
                    }

                    auto* site = pattern.get(hit).get<std::uint8_t>();
                    if (!InBounds(image, site, collector.length))
                    {
                        return std::unexpected(PatchError{PatchErrorCode::out_of_bounds,
                                                          "site out of bounds"});
                    }

                    injector::WriteMemoryRaw(site, const_cast<std::uint8_t*>(collector.bytes),
                                             collector.length, true);
                    ++report.collectorWrites;
                }
            }
        }

        if (HasStage(stages, SkipLauncherStage::dfa))
        {
            // The create_file hook forwards through this IAT slot, so the capture must
            // happen before the installer writes the hook.
            hook::pattern capture = Scan(image, kDfaCapturePattern);
            if (!capture.empty())
            {
                report.createFileSlot = injector::ReadMemory<std::uint32_t>(
                    capture.get(0).get<std::uint8_t>() + kDfaCaptureSlotOffset);
            }

            // Publish (or clear) the captured slot as part of the pass, so the
            // create_file body can never read a stale slot from an earlier image.
            PublishCreateFileSlot(report);
        }

        if (resolve)
        {
            // Installs an opcode + rel32 to the reimplemented body. A body the resolver
            // does not know, or a missing signature, counts as missing.
            const auto installHooks = [&](std::span<const SkipLauncherInstall> installs,
                                          std::size_t& applied,
                                          std::size_t& missing) -> PatchOutcome {
                for (const SkipLauncherInstall& install : installs)
                {
                    const std::uintptr_t destination = resolve(install.hook, resolverUser);
                    if (!destination)
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

                    auto* site = hookSite.get(0).get<std::uint8_t>() + install.offset;
                    if (!InBounds(image, site, kBranchLength))
                    {
                        return std::unexpected(PatchError{PatchErrorCode::out_of_bounds,
                                                          "site out of bounds"});
                    }

                    injector::WriteMemory<std::uint8_t>(site, install.opcode, true);
                    injector::WriteMemory<std::uint32_t>(
                        site + 1,
                        static_cast<std::uint32_t>(destination - (reinterpret_cast<std::uintptr_t>(
                                                                       site) +
                                                                   kBranchLength)),
                        true);
                    ++applied;
                }
                return {};
            };

            if (HasStage(stages, SkipLauncherStage::dfa))
            {
                const auto dfaStatus =
                    installHooks(SkipLauncherDfaInstalls(), report.dfaInstalls,
                                 report.dfaMissing);
                if (!dfaStatus)
                {
                    return std::unexpected(dfaStatus.error());
                }

                // The collector tail of 0x10004850: each collected site jumps to another
                // pattern's match.
                for (const SkipLauncherCollectedInstall& install : SkipLauncherDfaCollected())
                {
                    hook::pattern hits = Scan(image, install.collector);
                    for (std::size_t t = 0; t < install.targetCount; ++t)
                    {
                        const SkipLauncherCollectedTarget& target = install.targets[t];
                        if (target.index >= hits.size())
                        {
                            continue;
                        }

                        hook::pattern targetPattern = Scan(image, target.targetSignature);
                        if (targetPattern.empty())
                        {
                            continue;
                        }

                        auto* site = hits.get(target.index).get<std::uint8_t>();
                        if (!InBounds(image, site, kBranchLength))
                        {
                            return std::unexpected(PatchError{PatchErrorCode::out_of_bounds,
                                                              "site out of bounds"});
                        }

                        injector::WriteMemory<std::uint8_t>(site, kJumpOpcode, true);
                        injector::WriteMemory<std::uint32_t>(
                            site + 1,
                            static_cast<std::uint32_t>(
                                reinterpret_cast<std::uintptr_t>(
                                    targetPattern.get(0).get<std::uint8_t>()) -
                                (reinterpret_cast<std::uintptr_t>(site) + kBranchLength)),
                            true);
                        ++report.collectedInstalls;
                    }
                }
            }

            if (HasStage(stages, SkipLauncherStage::rom))
            {
                const auto romStatus =
                    installHooks(SkipLauncherRomInstalls(), report.romInstalls,
                                 report.romMissing);
                if (!romStatus)
                {
                    return std::unexpected(romStatus.error());
                }
            }
        }

        return report;
    }
} // namespace xla

// ---------------------------------------------------------------------------
// Windows hook bodies
// ---------------------------------------------------------------------------

namespace xla
{
    namespace rom
    {
        // The originals live at 0x10004720..0x1000484e (the file API and DFA bodies)
        // and 0x100041A0..0x10004570 (the WM_ROM message-window service, ANSI variant).
        inline constexpr UINT kMessage = 43858; // WM_ROM in the original
        inline constexpr char kClassName[] = "MessageWindow";
        inline constexpr char kClassFallback[] = "MessageWindow2";

        // xmmword_10104050..0x10104080: the table the ROM service hands to the game.
        inline constexpr std::array<std::uint32_t, 16> kTable{
            8, 11, 241, 1, 240, 2, 7, 12, 3, 243, 9, 6, 10, 5, 4, 242,
        };

        // WM_ROM carries a word array: [4] is the action, [5] and [6] are its operands.
        inline constexpr std::size_t kPayloadAction = 4;
        inline constexpr std::size_t kPayloadArg0 = 5;
        inline constexpr std::size_t kPayloadArg1 = 6;

        inline constexpr std::uint32_t kActionCopyTable = 18;
        inline constexpr std::uint32_t kActionAdd = 51;
        inline constexpr std::uint32_t kActionSet = 100;

        // SkipRomReset's object layout: [1] is the window handle, [4] the WM_ROM id;
        // [0], [2], [3] and [5..18] are cleared first.
        inline constexpr std::size_t kObjectWindow = 1;
        inline constexpr std::size_t kObjectMessage = 4;
        inline constexpr std::size_t kObjectClearFirst = 5;
        inline constexpr std::size_t kObjectClearLast = 18;

        inline constexpr int kReadyPollLimit = 200;
        inline constexpr DWORD kReadyPollMs = 1;

        inline std::atomic<std::uint32_t> gCreateFileSlot{0};
        inline std::atomic<HWND> gWindow{nullptr};
        inline std::atomic<bool> gReady{false};
        inline std::atomic<bool> gStarted{false};

        using CreateFileAFn = HANDLE(WINAPI*)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD,
                                              DWORD, HANDLE);

        inline LRESULT CALLBACK WindowProc(HWND window, UINT message, WPARAM wparam, LPARAM lparam)
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
            else if (message == kMessage)
            {
                auto* payload = reinterpret_cast<std::uint32_t*>(lparam);
                switch (payload[kPayloadAction])
                {
                case kActionCopyTable:
                    std::memcpy(reinterpret_cast<void*>(
                                    static_cast<std::uintptr_t>(payload[kPayloadArg1])),
                                kTable.data(), sizeof(kTable));
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

        inline DWORD WINAPI Thread(LPVOID)
        {
            WNDCLASSEXA wc{};
            wc.cbSize = sizeof(wc);
            wc.lpfnWndProc = &WindowProc;
            wc.hInstance = ::GetModuleHandleA(nullptr);
            wc.lpszClassName = kClassName;

            ATOM atom = ::RegisterClassExA(&wc);
            if (!atom)
            {
                wc.lpszClassName = kClassFallback;
                atom = ::RegisterClassExA(&wc);
                if (!atom)
                {
                    return 1;
                }
            }

            ::CreateWindowExA(0, reinterpret_cast<LPCSTR>(static_cast<std::uintptr_t>(atom)), "",
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

        // 0x100043D0: start the ROM service once and wait until the window exists.
        inline void StartService()
        {
            if (gStarted.exchange(true))
            {
                return;
            }

            const HANDLE thread = ::CreateThread(nullptr, 0, &Thread, nullptr, 0, nullptr);
            if (thread)
            {
                ::CloseHandle(thread);
            }

            for (int i = 0; i < kReadyPollLimit && !gReady.load(); ++i)
            {
                ::Sleep(kReadyPollMs);
            }
        }

        // 0x10004780: replaces the DFA init call so it reports success.
        inline int __cdecl DfaInitBody()
        {
            return 1;
        }

        // 0x10004820: CreateFileA through the captured IAT slot. The original
        // trampoline is __cdecl (plain ret; the caller pops the seven arguments), so
        // the ABI must match - a stdcall body would corrupt the stack.
        inline HANDLE __cdecl CreateFileBody(LPCSTR fileName, DWORD desiredAccess, DWORD shareMode,
                                         LPSECURITY_ATTRIBUTES security,
                                         DWORD creationDisposition, DWORD flags,
                                         HANDLE templateFile)
        {
            const std::uint32_t slot = gCreateFileSlot.load();
            if (slot)
            {
                const auto* fn =
                    *reinterpret_cast<CreateFileAFn*>(static_cast<std::uintptr_t>(slot));
                if (fn)
                {
                    return fn(fileName, desiredAccess, shareMode, security,
                              creationDisposition, flags, templateFile);
                }
            }

            return ::CreateFileA(fileName, desiredAccess, shareMode, security,
                                 creationDisposition, flags, templateFile);
        }

        // 0x10004790: the original wraps CloseHandle in SEH and returns -1 (its
        // `or eax,-1` filter at 0x100047ec) when it faults. __cdecl like the
        // original trampoline; the SEH keywords are MSVC-only.
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

        inline DWORD __cdecl SetFilePointerBody(HANDLE handle, LONG distance, PLONG distanceHigh,
                                            DWORD moveMethod)
        {
            return ::SetFilePointer(handle, distance, distanceHigh, moveMethod);
        }

        inline BOOL __cdecl GetFileSizeExBody(HANDLE handle, PLARGE_INTEGER size)
        {
            return ::GetFileSizeEx(handle, size);
        }

        inline BOOL __cdecl ReadFileBody(HANDLE handle, LPVOID buffer, DWORD toRead, LPDWORD read,
                                     LPOVERLAPPED overlapped)
        {
            return ::ReadFile(handle, buffer, toRead, read, overlapped);
        }

        // 0x10004570: start the ROM service, reset the object and publish the window
        // handle plus the WM_ROM id. __cdecl with one stack argument, returning the
        // window handle in eax (plain ret).
        // 0x10004610: the object arrives in ESI (the patched site keeps it there) and
        // the site pushed two arguments the callee must pop - the original is
        // `mov ecx,[esi+1c]; mov [esi+20],ecx; mov al,1; ret 8`. A C function cannot
        // express that, so the eleven opcode bytes are assembled once, at install
        // time, into an executable page (MSVC rejects __declspec(naked) on a
        // namespace-scope function, which a module makes everything be).
        inline void* RomSetStub()
        {
            static std::atomic<void*> cached{nullptr};
            if (void* existing = cached.load(); existing != nullptr)
            {
                return existing;
            }

            void* memory = ::VirtualAlloc(nullptr, 64, MEM_COMMIT | MEM_RESERVE,
                                          PAGE_EXECUTE_READWRITE);
            if (memory == nullptr)
            {
                log::Write("rom: cannot allocate the RomSet stub");
                return nullptr;
            }

            constexpr std::uint8_t kCode[] = {
                0x8B, 0x4E, 0x1C, // mov ecx, [esi + 0x1c]
                0x89, 0x4E, 0x20, // mov [esi + 0x20], ecx
                0xB0, 0x01,       // mov al, 1
                0xC2, 0x08, 0x00, // ret 8
            };
            std::memcpy(memory, kCode, sizeof(kCode));
            ::FlushInstructionCache(::GetCurrentProcess(), memory, sizeof(kCode));
            cached.store(memory);
            return memory;
        }

        inline int __cdecl RomResetBody(std::uint32_t* object)
        {
            StartService();
            if (!object)
            {
                return 0;
            }

            object[0] = 0;
            object[2] = 0;
            object[3] = 0;
            for (std::size_t i = kObjectClearFirst; i <= kObjectClearLast; ++i)
            {
                object[i] = 0;
            }

            object[kObjectWindow] =
                static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(gWindow.load()));
            object[kObjectMessage] = kMessage;
            return static_cast<int>(object[kObjectWindow]);
        }

    } // namespace rom

    inline void SetCreateFileSlot(std::uint32_t slotVa) noexcept
    {
        rom::gCreateFileSlot.store(slotVa);
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
            return reinterpret_cast<std::uintptr_t>(&rom::DfaInitBody);
        case SkipHook::create_file:
            return reinterpret_cast<std::uintptr_t>(&rom::CreateFileBody);
        case SkipHook::close_handle:
            return reinterpret_cast<std::uintptr_t>(&rom::CloseHandleGuardedBody);
        case SkipHook::set_file_pointer:
            return reinterpret_cast<std::uintptr_t>(&rom::SetFilePointerBody);
        case SkipHook::get_file_size_ex:
            return reinterpret_cast<std::uintptr_t>(&rom::GetFileSizeExBody);
        case SkipHook::read_file:
            return reinterpret_cast<std::uintptr_t>(&rom::ReadFileBody);
        case SkipHook::rom_reset:
            return reinterpret_cast<std::uintptr_t>(&rom::RomResetBody);
        case SkipHook::rom_set:
            return reinterpret_cast<std::uintptr_t>(rom::RomSetStub());
        }
        return 0;
    }
} // namespace xla
