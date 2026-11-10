// SPDX-License-Identifier: GPL-3.0-or-later
//
// xla.skip_launcher - the SkipLauncher=1 launcher/SecuROM bypass.
//
// The file is laid out in reading order:
//
//   1. the small data model (Edit / Entry / Collector / Install);
//   2. the recovered main table, included from skip_launcher_recovered.inc
//      (data only, not shipped, kept for parity and the native suite);
//   3. the shipping data: the six DFA hooks, the two ROM hooks and the two
//      collected jumps;
//   4. the pass that applies the selected stage;
//   5. the ABI-exact hook bodies and the RomSet stub.
//
// Recovered from the original handlers:
//   0x10045CE0  the 25-entry main table and the two multi-hit collectors
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
    // ---------------------------------------------------------------------
    // 1. The data model
    // ---------------------------------------------------------------------
    //
    // A launcher row is an in-place instruction edit, not a callable hook: the
    // recovered handler overwrites the game's own check at the match (a NOP, an
    // xor, a one-byte branch, a short jump), so an edit has no ABI.

    struct Edit
    {
        enum class Kind : std::uint8_t
        {
            bytes,          // store `bytes` at match + offset
            nop,            // store `count` copies of `fill` (NOP in the data)
            jump_to_entry,  // rewrite the 5-byte branch ending at match + offset + 4
        };

        Kind kind{};
        std::int32_t offset{};
        std::span<const std::uint8_t> bytes{};
        std::uint16_t count{};
        std::uint8_t fill{};
        std::uint32_t target{};
    };

    template <std::size_t N>
    [[nodiscard]] constexpr Edit WriteBytes(std::int32_t offset,
                                            const std::uint8_t (&bytes)[N]) noexcept
    {
        return {.kind = Edit::Kind::bytes,
                .offset = offset,
                .bytes = std::span<const std::uint8_t>(bytes, N)};
    }

    [[nodiscard]] constexpr Edit Nop(std::int32_t offset, std::uint16_t count) noexcept
    {
        return {.kind = Edit::Kind::nop,
                .offset = offset,
                .count = count,
                .fill = Byte(Opcode::kNop)};
    }

    [[nodiscard]] constexpr Edit JumpTo(std::int32_t offset, std::uint32_t target) noexcept
    {
        return {.kind = Edit::Kind::jump_to_entry, .offset = offset, .target = target};
    }

    [[nodiscard]] constexpr Edit XorEax(std::int32_t offset) noexcept
    {
        return WriteBytes(offset, ops::kXorEaxEax);
    }

    [[nodiscard]] constexpr Edit XorEaxRetNop(std::int32_t offset) noexcept
    {
        return WriteBytes(offset, ops::kXorEaxRetNop);
    }

    [[nodiscard]] constexpr Edit Ret(std::int32_t offset) noexcept
    {
        return WriteBytes(offset, ops::kRet);
    }

    // One signature scan and the edits made at its first match. The label is
    // what the log prints, so a failure names the code, not a row index.
    struct Entry
    {
        std::string_view label;
        std::string_view signature;
        std::span<const Edit> edits;
    };

    // A multi-hit collector: the original patches the first two (or last two)
    // matches of one pattern with the same stub.
    struct Collector
    {
        enum class Target : std::uint8_t
        {
            first_two,
            last_two,
        };

        std::string_view label;
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

    // One E8/E9 branch a stage installs: the signature that finds the site, the
    // offset from the match, the branch opcode and the body.
    struct Install
    {
        std::string_view label;
        std::string_view signature;
        std::int32_t offset;
        Opcode opcode; // kCallRel32 or kJmpRel32
        SkipHook hook;
    };

    // A collected jump: the anchor match at `index` becomes a jump to the first
    // match of `signature`.
    struct CollectedTarget
    {
        std::string_view label;
        std::string_view signature;
        std::uint32_t index;
    };

    struct CollectedInstall
    {
        std::string_view label;
        std::string_view anchor;
        const CollectedTarget* targets;
        std::size_t count;
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

    std::span<const Entry> SkipLauncherEntries() noexcept;
    std::span<const Collector> SkipLauncherCollectors() noexcept;
    std::span<const Install> SkipLauncherDfaInstalls() noexcept;
    std::span<const Install> SkipLauncherRomInstalls() noexcept;
    std::span<const CollectedInstall> SkipLauncherDfaCollected() noexcept;

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
    inline constexpr std::int32_t kMaxPatchExtent = 0x200;
}

// ---------------------------------------------------------------------------
// 2. The recovered main table (data only; not shipped)
// ---------------------------------------------------------------------------
namespace xla::skip_launcher
{
    namespace recovered
    {
#include "skip_launcher_recovered.inc"
    } // namespace recovered
} // namespace xla::skip_launcher

// ---------------------------------------------------------------------------
// 3. The shipping data
// ---------------------------------------------------------------------------
namespace xla::skip_launcher
{
    namespace
    {
        constexpr std::size_t kBranchLength = 5; // E8/E9 <rel32>
        constexpr std::size_t kCollectorWidth = 2;

        // `FF 15 <rel32>` is `call [imm32]`; the operand at +2 is the IAT slot.
        constexpr std::string_view kDfaCapturePattern = "FF 15 ? ? ? ? 8B F0 83 FE FF 74 24";
        constexpr std::int32_t kDfaCaptureSlotOffset = 2;

        // The hook sites that are outside their matched window.
        constexpr std::int32_t kDfaReadFileSite = -165; // the enclosing function's prologue
        constexpr std::int32_t kRomSetSite = -67;       // the enclosing function's prologue
        constexpr std::int32_t kRomResetCall = 6;       // the E8 after the two object stores

        // The six DFA file-API hooks (0x10004850).
        constexpr Install kDfaHooks[] = {
            {"DFA init reports success",
             "E8 ? ? ? ? 83 C4 0C 83 F8 01 74 11 6A 00 6A 00", 0, Opcode::kCallRel32,
             SkipHook::dfa_init},
            {"CreateFile forwards through the captured IAT slot", "55 8B EC 6A 00 E8", 0,
             Opcode::kJmpRel32, SkipHook::create_file},
            {"CloseHandle is guarded and returns -1 on a fault",
             "6A 00 E8 ? ? ? ? 83 F8 01 59 75 17 FF 15 ? ? ? ? 50 B9 ? ? ? ? E8 ? ? ? ? 8B "
             "40 08 FF 60 0C 33 C0 C3",
             0, Opcode::kJmpRel32, SkipHook::close_handle},
            {"SetFilePointer forwards",
             "6A 00 E8 ? ? ? ? 83 F8 01 59 75 17 FF 15 ? ? ? ? 50 B9 ? ? ? ? E8 ? ? ? ? 8B "
             "40 08 FF 60 ? 83 C8 FF C3",
             0, Opcode::kJmpRel32, SkipHook::set_file_pointer},
            {"GetFileSizeEx forwards",
             "56 8B 74 24 0C 8D 46 04 50 FF 74 24 0C E8 ? ? ? ? 59 59 33 C9 83 F8 FF 0F 95 "
             "C1 89 06 5E 8B C1 C3",
             0, Opcode::kJmpRel32, SkipHook::get_file_size_ex},
            {"ReadFile forwards (hook the function prologue)", "FF 50 60 83 C4 14 39 75 F8 89 45 FC",
             kDfaReadFileSite, Opcode::kJmpRel32, SkipHook::read_file},
        };
        static_assert(std::size(kDfaHooks) == 6);

        // The two ROM hooks (0x10004620).
        constexpr Install kRomHooks[] = {
            {"RomReset starts the service and resets the object", "89 46 3C 89 4E 40 E8",
             kRomResetCall, Opcode::kCallRel32, SkipHook::rom_reset},
            {"RomSet copies the object field pair", "0F 85 ? ? ? ? 68 03 01 00 00 68 ? ? ? ? 68 04 01 00 00",
             kRomSetSite, Opcode::kJmpRel32, SkipHook::rom_set},
        };
        static_assert(std::size(kRomHooks) == 2);

        // The collected DFA jumps: anchor matches 0 and 1 become jumps to the
        // first match of each target signature.
        constexpr CollectedTarget kDfaCollectedTargets[] = {
            {"jump to the cmp/push sequence", "80 BC 24 ? ? ? ? ? 6A 00", 0},
            {"jump to the seven-push sequence",
             "6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 57", 1},
        };
        constexpr CollectedInstall kDfaCollected[] = {
            {"collected DFA sites", "A1 ? ? ? ? B9 A7 FA DC 5C F7 E1 8B 0D ? ? ? ? 33 F6",
             kDfaCollectedTargets, std::size(kDfaCollectedTargets)},
        };
        static_assert(std::size(kDfaCollected) == 1);
    } // namespace

    std::span<const Entry> SkipLauncherEntries() noexcept
    {
        return recovered::kEntries;
    }

    std::span<const Collector> SkipLauncherCollectors() noexcept
    {
        return recovered::kCollectors;
    }

    std::span<const Install> SkipLauncherDfaInstalls() noexcept
    {
        return kDfaHooks;
    }

    std::span<const Install> SkipLauncherRomInstalls() noexcept
    {
        return kRomHooks;
    }

    std::span<const CollectedInstall> SkipLauncherDfaCollected() noexcept
    {
        return kDfaCollected;
    }
} // namespace xla::skip_launcher

// ---------------------------------------------------------------------------
// 4. The pass
// ---------------------------------------------------------------------------
namespace xla::skip_launcher
{
    namespace
    {
        struct EntryPlan
        {
            const Entry* entry{};
            std::uint8_t* match{};
        };

        [[nodiscard]] bool JumpTargetsPresent(const Entry& entry,
                                              const std::vector<EntryPlan>& plans) noexcept
        {
            // The original shares one guard between the E9 and its 33 C0/rel32
            // ops, so an absent target skips the whole entry, not just the jump.
            for (const Edit& edit : entry.edits)
            {
                if (edit.kind == Edit::Kind::jump_to_entry &&
                    (edit.target >= plans.size() || plans[edit.target].match == nullptr))
                {
                    return false;
                }
            }
            return true;
        }

        [[nodiscard]] bool CollectorTakes(Collector::Target target, std::size_t hit,
                                          std::size_t hits) noexcept
        {
            return target == Collector::Target::first_two
                       ? hit < kCollectorWidth
                       : hit + kCollectorWidth >= hits;
        }

        std::expected<void, PatchError> ApplyEdit(const Image& image, std::uint8_t* match,
                                                  const Edit& edit,
                                                  const std::vector<EntryPlan>& plans,
                                                  SkipLauncherReport& report)
        {
            std::uint8_t* site = match + edit.offset;

            switch (edit.kind)
            {
            case Edit::Kind::bytes:
                if (!patch::WriteRawAt(image, site, edit.bytes, "skipLauncher: edit"))
                {
                    return std::unexpected(
                        PatchError{PatchError::Code::out_of_bounds, "edit out of bounds"});
                }
                ++report.writes;
                return {};

            case Edit::Kind::nop:
                if (!patch::FillAt(image, site, edit.fill, edit.count, "skipLauncher: nop"))
                {
                    return std::unexpected(
                        PatchError{PatchError::Code::out_of_bounds, "nop out of bounds"});
                }
                ++report.writes;
                return {};

            case Edit::Kind::jump_to_entry:
            {
                std::uint8_t* target =
                    edit.target < plans.size() ? plans[edit.target].match : nullptr;
                if (target == nullptr)
                {
                    return {};
                }
                // The preceding bytes edit wrote the E9; the row's offset is the
                // rel32, so the branch starts one byte earlier.
                if (!patch::JumpAt(image, site - 1, target, "skipLauncher: jump"))
                {
                    return std::unexpected(
                        PatchError{PatchError::Code::out_of_bounds, "jump out of bounds"});
                }
                report.jumpInstalled = true;
                ++report.writes;
                return {};
            }
            }

            return std::unexpected(
                PatchError{PatchError::Code::invalid_input, "unsupported edit"});
        }

        std::expected<void, PatchError> ApplyMainTable(const Image& image,
                                                       SkipLauncherReport& report)
        {
            const std::span<const Entry> entries = SkipLauncherEntries();
            std::vector<EntryPlan> plans(entries.size());

            for (std::size_t index = 0; index < entries.size(); ++index)
            {
                const Entry& entry = entries[index];

                // Scan every hit, like the recovered single-match finder's
                // `size()` call: the count is reported, never used as a gate. A
                // duplicate signature is still applied at the first match.
                patch::Pattern pattern = patch::FindIn(image, entry.signature, 0);
                if (pattern.empty())
                {
                    ++report.entriesMissing;
                    Log::Trace("skipLauncher: {}: signature missing", entry.label);
                    continue;
                }

                if (pattern.size() != 1)
                {
                    Log::Print("skipLauncher: {}: matched {} site(s), expected 1", entry.label,
                               pattern.size());
                }

                plans[index] = {&entry, pattern.get<std::uint8_t>(0)};
                ++report.entriesFound;

                if (!JumpTargetsPresent(entry, plans))
                {
                    Log::Trace("skipLauncher: {}: jump target absent, row skipped", entry.label);
                    continue;
                }

                for (const Edit& edit : entry.edits)
                {
                    const auto status = ApplyEdit(image, plans[index].match, edit, plans, report);
                    if (!status)
                    {
                        return status;
                    }
                }
            }
            return {};
        }

        std::expected<void, PatchError> ApplyCollectors(const Image& image,
                                                        SkipLauncherReport& report)
        {
            for (const Collector& collector : SkipLauncherCollectors())
            {
                patch::Pattern pattern = patch::FindIn(image, collector.pattern, 0);
                const std::size_t hits = pattern.size();
                if (hits == 0)
                {
                    Log::Trace("skipLauncher: {}: signature missing", collector.label);
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
                    if (!patch::WriteRawAt(image, pattern.get<std::uint8_t>(hit), collector.stub,
                                           "skipLauncher: collector"))
                    {
                        return std::unexpected(
                            PatchError{PatchError::Code::out_of_bounds, "collector out of bounds"});
                    }
                    ++report.collectorWrites;
                    ++applied;
                }

                Log::Print("skipLauncher: {}: {} site(s), patched {}", collector.label, hits,
                           applied);
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
            const Image& image, std::span<const Install> installs, SkipHookResolver resolve,
            void* resolverUser)
        {
            HookCounts counts;
            for (const Install& install : installs)
            {
                const std::uintptr_t destination = resolve(install.hook, resolverUser);
                if (destination == 0)
                {
                    ++counts.missing;
                    Log::Trace("skipLauncher: {}: body unavailable", install.label);
                    continue;
                }

                patch::Pattern hookSite = patch::FindIn(image, install.signature, 1);
                if (hookSite.empty())
                {
                    ++counts.missing;
                    Log::Trace("skipLauncher: {}: signature missing", install.label);
                    continue;
                }

                std::uint8_t* site = hookSite.get<std::uint8_t>(0) + install.offset;
                switch (install.opcode)
                {
                case Opcode::kCallRel32:
                    if (!patch::CallAt(image, site, reinterpret_cast<void*>(destination),
                                       "skipLauncher: hook"))
                    {
                        return std::unexpected(
                            PatchError{PatchError::Code::out_of_bounds, "hook out of bounds"});
                    }
                    break;
                case Opcode::kJmpRel32:
                    if (!patch::JumpAt(image, site, reinterpret_cast<std::uint8_t*>(destination),
                                       "skipLauncher: hook"))
                    {
                        return std::unexpected(
                            PatchError{PatchError::Code::out_of_bounds, "hook out of bounds"});
                    }
                    break;
                default:
                    return std::unexpected(
                        PatchError{PatchError::Code::invalid_input, "unsupported branch opcode"});
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
            const auto counts = InstallHooks(image, SkipLauncherDfaInstalls(), resolve,
                                             resolverUser);
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
            for (const CollectedInstall& install : SkipLauncherDfaCollected())
            {
                patch::Pattern anchor = patch::FindIn(image, install.anchor, 0);
                for (std::size_t index = 0; index < install.count; ++index)
                {
                    const CollectedTarget& target = install.targets[index];
                    if (target.index >= anchor.size())
                    {
                        continue;
                    }

                    patch::Pattern targetPattern =
                        patch::FindIn(image, target.signature, 1);
                    if (targetPattern.empty())
                    {
                        Log::Trace("skipLauncher: {}: target signature missing", target.label);
                        continue;
                    }

                    if (!patch::JumpAt(image, anchor.get<std::uint8_t>(target.index),
                                       targetPattern.get_first<std::uint8_t>(),
                                       "skipLauncher: collected jump"))
                    {
                        return std::unexpected(PatchError{PatchError::Code::out_of_bounds,
                                                          "collected jump out of bounds"});
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
            const auto counts = InstallHooks(image, SkipLauncherRomInstalls(), resolve,
                                             resolverUser);
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
                if (auto status = InstallDfaHooks(image, resolve, resolverUser, report); !status)
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

// ---------------------------------------------------------------------------
// 5. The hook bodies
// ---------------------------------------------------------------------------
//
// The ABI is the recovered contract:
//   * CreateFile, CloseHandle, SetFilePointer, GetFileSizeEx, ReadFile, DfaInit
//     and RomReset are __cdecl (plain `ret`): the patched site's caller pops the
//     arguments, exactly as it popped the original's.
//   * RomSet takes the object in ESI and returns with `ret 8` (the site pushed
//     two arguments the callee must pop). A C function cannot express a register
//     argument plus a callee stack pop, so its eleven opcode bytes are assembled
//     into an executable page at install time.
// The originals live at 0x10004720..0x1000484E (file API + DFA) and
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

        // 0x10004780: the DFA init call reports success. ABI: __cdecl, no
        // arguments; the site is `E8 rel32; 83 C4 0C`, so the caller discards the
        // three arguments itself.
        inline int __cdecl DfaInitBody()
        {
            return 1;
        }

        // 0x10004820: CreateFileA through the captured IAT slot, falling back to
        // the import. ABI: __cdecl (plain ret; the caller pops seven arguments).
        inline HANDLE __cdecl CreateFileBody(LPCSTR fileName, DWORD desiredAccess,
                                             DWORD shareMode, LPSECURITY_ATTRIBUTES security,
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

        // 0x10004790: CloseHandle with an exception guard; the original's
        // `or eax,-1; ret` filter returns -1 when the call faults.
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

        // xmmword_10104050..0x10104080: the table action 18 copies into the game.
        inline constexpr std::array<std::uint32_t, 16> kActionTable{
            8, 11, 241, 1, 240, 2, 7, 12, 3, 243, 9, 6, 10, 5, 4, 242,
        };

        inline constexpr std::size_t kPayloadAction = 4;
        inline constexpr std::size_t kPayloadArg0 = 5;
        inline constexpr std::size_t kPayloadArg1 = 6;

        inline constexpr std::uint32_t kActionCopyTable = 18;
        inline constexpr std::uint32_t kActionAdd = 51;
        inline constexpr std::uint32_t kActionSet = 100;

        // 0x10004570's object: 19 32-bit slots. The window handle is slot 1 and
        // the WM_ROM id slot 4; the original zeroes the rest first, so a
        // whole-object zero followed by the two publishes ends in the same state.
        struct RomObject
        {
            std::uint32_t slot0{};
            std::uint32_t window{}; // slot 1
            std::uint32_t slot2{};
            std::uint32_t slot3{};
            std::uint32_t message{};              // slot 4
            std::array<std::uint32_t, 14> tail{}; // slots 5..18
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

        // 0x10004610: the object arrives in ESI and the site pushed two arguments
        // the callee must pop. The original is
        // `mov ecx,[esi+1c]; mov [esi+20],ecx; mov al,1; ret 8`; a C function
        // cannot express that, so the eleven bytes are assembled once and cached.
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

            constexpr std::uint8_t kCode[] = {
                Byte(Opcode::kMovR32Rm32), 0x4E, 0x1C, // mov ecx,[esi+0x1c]
                Byte(Opcode::kMovRm32R32), 0x4E, 0x20, // mov [esi+0x20],ecx
                Byte(Opcode::kMovAlImm8), 0x01,        // mov al,1
                ops::kRet8[0], ops::kRet8[1], ops::kRet8[2], // ret 8
            };
            static_assert(std::size(kCode) == 11);
            static_assert(std::size(ops::kRet8) == 3);
            std::memcpy(memory, kCode, sizeof(kCode));
            ::FlushInstructionCache(::GetCurrentProcess(), memory, sizeof(kCode));
            cached.store(memory);
            return memory;
        }

        // 0x10004570: start the service, reset the object and publish the window
        // handle plus the WM_ROM id. ABI: __cdecl, one stack argument, returns
        // the handle in eax (plain ret).
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
