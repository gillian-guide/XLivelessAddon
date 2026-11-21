// SPDX-License-Identifier: GPL-3.0-or-later
//
// xla.core - the recovered GFWL/check fixes, one section per INI key:
// RemoveDataIntegrityChecks, SkipTokenActivation, SkipFirstTimePlayAsk (the "core"
// group) and SkipWebConnect, which owns the web-connect and health-check pair.
//
// The old XLivelessAddon ran the data-integrity/token/first-play rows
// unconditionally; this tree carries them under the three per-fix keys
// OpenPreCEPatch's legacy import maps an old `MiscFixes` value onto. Recovered rows,
// same bytes and offsets as the original ZolikaPatch 7.65 `MiscFixes` handler
// (`sub_10023DD0`) and the old addon's `InstallCore`: a branch turned into an
// unconditional jump, `jmp rel8` pairs, two-byte NOPs and the token `mov eax,1`.
// The rows are applied one signature at a time and a miss is a logged skip, exactly
// like the old addon.
//
// SkipWebConnect is the old add-on's single key for the two recovered sections of
// its `InstallWebConnectChecks`: the three `InternetGetConnectedState` branches
// (`SkipInternetConnectionCheck`) and the health check's entry (`SkipHealthCheck`).
// The two fine-grained keys stay as refinements, so an old INI's `SkipWebConnect=0`
// keeps both checks in place (the reference's outcome) while a user who wants one
// of the two skipped can still say so.
//
// The original's `MiscFixes` bundle had an eleventh literal -- a short jump in the
// DLC manager init -- which the old addon never applied and which sits inside the
// window LibertyCityPlates.asi scans for its first address lookup. It is not here:
// the reference never wrote it, and writing it made that plugin report
// "Addresses could not be determined".

module;

#include <common.hxx>

export module core;

import common;
import patch;

export namespace xla::core
{
    // The write a row performs at its site.
    enum class Shape : std::uint8_t
    {
        branchToJump,  // one byte: the `74`/`75` of a `jcc rel8` becomes `EB`
        shortJump,     // `EB rel8`: the opcode and `value` as the displacement
        nop2,          // two `90`s over the branch
        ret,           // the function's first byte becomes `C3`
        movEaxOne,     // `B8 01 00 00 00`
    };

    struct Row
    {
        std::string_view signature;
        Shape shape;
        std::ptrdiff_t offset;
        std::uint8_t value;  // the displacement of a shortJump row
    };

    // RemoveDataIntegrityChecks: the VDS102/VDS100 branch flips. Provenance: the
    // original handler's "data integrity checks" rows (0x10023DD0's first three
    // writes); the old addon's `PatchEfcRows` rows carry the same labels.
    std::span<const Row> DataIntegrityRows() noexcept;

    // SkipTokenActivation: the DLC token jump and its `mov eax,1`.
    std::span<const Row> TokenActivationRows() noexcept;

    // SkipFirstTimePlayAsk: the first-time-play branch.
    std::span<const Row> FirstTimePlayRows() noexcept;

    // SkipInternetConnectionCheck: the three GetProcAddress-style
    // `InternetGetConnectedState` branches, one per build family.
    std::span<const Row> InternetConnectionRows() noexcept;

    // SkipHealthCheck: the GFWL health check's entry.
    std::span<const Row> HealthCheckRows() noexcept;

    // The three per-fix keys of the "core" group.
    struct Options
    {
        bool dataIntegrity{true};
        bool tokenActivation{true};
        bool firstTimePlay{true};
    };

    // SkipWebConnect's two recovered sections, in the reference's order.
    struct WebConnectOptions
    {
        bool internetConnection{true};
        bool healthCheck{true};
    };

    struct Report
    {
        std::size_t applied{};
        std::size_t missing{};
    };

    // Applies one key's rows to `image`: one scan per row, a miss is a logged
    // skip. Exposed so the native suite can drive each row against a synthetic
    // image.
    Report Apply(const Image& image, std::span<const Row> rows, std::string_view key);

    // The three "core" fixes, each behind its key. Returns the summed report.
    Report Install(const Image& image, const Options& options);

    // [Options] SkipWebConnect: the reference add-on's `InstallWebConnectChecks`,
    // one section over the two recovered row sets.
    Report InstallWebConnectChecks(const Image& image, const WebConnectOptions& options);

    // ---------------------------------------------------------------------
    // GFWLProtectionDisabler - the xlive.dll protection byte patch
    // ---------------------------------------------------------------------
    //
    // The standalone GFWLProtectionDisabler2019.asi flips xlive.dll+0xF1605 from its
    // `jz`/`jmp` to a `jmp`, which disables the Games for Windows LIVE protection
    // check. No xlive image is available to scan, so the RVA is the only anchor and
    // the pre-image byte is the guard: a different xlive build is left untouched.
    //
    // This arm lives here, in the GFWL checks' module, because it is one byte at one
    // offset: a separate module would carry no second feature. (SteamAchievements is
    // the big one and has its own module, xla.steam.)
    inline constexpr std::size_t kGfwlProtectionSiteOffset = 988677; // 0xF1605
    inline constexpr std::uint8_t kGfwlProtectionBranch = 0x74;      // jz
    inline constexpr std::uint8_t kGfwlProtectionJump = 0xEB;        // jmp
    inline constexpr std::uint8_t kGfwlProtectionPatched = 0xEB;     // what it becomes

    // An offset in a module is only readable when it is inside the mapped image and
    // the containing page is committed and accessible. xlive.dll is also the common
    // filename of Ultimate ASI Loader's proxy, and patching the UAL proxy's image at
    // the GFWL RVA would corrupt the loader itself, so this guard is the arm's only
    // anchor. Exposed so the native suite can drive it.
    bool ModuleImageContains(std::uintptr_t module, std::size_t offset, std::size_t bytes) noexcept;

    // The arm's only write: `jz`/`jmp` becomes `jmp`, anything else is left alone.
    // Answers whether the byte was written. Exposed so the suite can pin the write
    // set (a synthetic byte, no module needed).
    bool ApplyGfwlProtectionByte(std::uint8_t* site);

    // The install: refuses a process without a real Games for Windows LIVE image, an
    // unreadable offset and a site that does not carry the protection branch. Answers
    // whether the byte was written; every refusal is a logged skip.
    bool InstallGfwlProtectionDisabler();
} // namespace xla::core

namespace xla::core
{
    namespace
    {
        // One row's write, in the shape the recovered handler used. The image's
        // range is checked by the caller's scan (the site came out of it), and
        // `WriteRawAt` refuses a window past the image.
        bool WriteRow(const Image& image, std::uint8_t* site, const Row& row,
                      std::string_view label)
        {
            std::uint8_t* target = site + row.offset;
            switch (row.shape)
            {
            case Shape::branchToJump:
            {
                const std::array<std::uint8_t, 1> bytes{0xEB};
                return patch::WriteRawAt(image, target, bytes, label);
            }
            case Shape::shortJump:
            {
                const std::array<std::uint8_t, 2> bytes{0xEB, row.value};
                return patch::WriteRawAt(image, target, bytes, label);
            }
            case Shape::nop2:
                return patch::FillAt(image, target, 0x90, 2, label);
            case Shape::ret:
            {
                const std::array<std::uint8_t, 1> bytes{0xC3};
                return patch::WriteRawAt(image, target, bytes, label);
            }
            case Shape::movEaxOne:
            {
                const std::array<std::uint8_t, 5> bytes{0xB8, 0x01, 0x00, 0x00, 0x00};
                return patch::WriteRawAt(image, target, bytes, label);
            }
            }
            return false;
        }
    } // namespace

    // ---------------------------------------------------------------------
    // RemoveDataIntegrityChecks
    // ---------------------------------------------------------------------
    namespace
    {
        constexpr Row kDataIntegrity[] = {
            // VDS102 [1.0.0.2 - 1.0.0.4]: the `74 19` after the store.
            {"C7 06 ? ? ? ? 74 19", Shape::branchToJump, 6, 0},
            // VDS102 [1.0.0.5 - 1.0.8.0]: five bytes past the seven-byte compare.
            {"83 C4 ? 3B 46 20", Shape::branchToJump, 12, 0},
            // VDS100 [1.0.6.0 - 1.0.8.0]: the pattern starts on the branch.
            {"75 28 6A 00 6A 00 68 ? ? ? ? E8 ? ? ? ? 83 C4 0C", Shape::branchToJump, 0, 0},
        };
    } // namespace

    std::span<const Row> DataIntegrityRows() noexcept
    {
        return kDataIntegrity;
    }

    // ---------------------------------------------------------------------
    // SkipTokenActivation
    // ---------------------------------------------------------------------
    namespace
    {
        constexpr Row kTokenActivation[] = {
            // `jmp +0xC9` over the token check.
            {"8B 54 24 04 52 A3", Shape::shortJump, 0, 0xC9},
            // the token value is forced to 1
            {"83 F8 01 75 30 A3", Shape::movEaxOne, 0, 1},
        };
    } // namespace

    std::span<const Row> TokenActivationRows() noexcept
    {
        return kTokenActivation;
    }

    // ---------------------------------------------------------------------
    // SkipFirstTimePlayAsk
    // ---------------------------------------------------------------------
    namespace
    {
        constexpr Row kFirstTimePlay[] = {
            // `jmp +0x0D` over the first-time-play ask.
            {"C7 05 ? ? ? ? 03 00 00 00 33 C0 5E 59 C3 C7", Shape::shortJump, 0, 0x0D},
        };
    } // namespace

    std::span<const Row> FirstTimePlayRows() noexcept
    {
        return kFirstTimePlay;
    }

    // ---------------------------------------------------------------------
    // SkipInternetConnectionCheck
    // ---------------------------------------------------------------------
    namespace
    {
        constexpr Row kInternetConnection[] = {
            {"FF 15 ? ? ? ? 85 C0 75 18", Shape::nop2, 8, 0},  // 1.0.0.0 / 1.0.1.0
            {"FF 15 ? ? ? ? 85 C0 75 04 32", Shape::nop2, 8, 0},  // 1.0.0.4 - 1.0.4.0
            {"FF 15 ? ? ? ? 85 C0 75 07 A0", Shape::nop2, 8, 0},  // 1.0.6.0 - 1.0.8.0
        };
    } // namespace

    std::span<const Row> InternetConnectionRows() noexcept
    {
        return kInternetConnection;
    }

    // ---------------------------------------------------------------------
    // SkipHealthCheck
    // ---------------------------------------------------------------------
    namespace
    {
        constexpr Row kHealthCheck[] = {
            // the GFWL health check's entry becomes `ret`
            {"81 EC ? ? ? ? A1 ? ? ? ? 33 C4 89 84 24 ? ? ? ? 53 ? 6A 3C 33 DB 8D 44 24 ? 53 50 E8",
             Shape::ret, 0, 0},
        };
    } // namespace

    std::span<const Row> HealthCheckRows() noexcept
    {
        return kHealthCheck;
    }

    // ---------------------------------------------------------------------
    // The shared pass
    // ---------------------------------------------------------------------
    Report Apply(const Image& image, std::span<const Row> rows, std::string_view key)
    {
        Report report;
        for (const Row& row : rows)
        {
            patch::Pattern pattern = patch::FindIn(image, row.signature, 1);
            if (pattern.empty())
            {
                ++report.missing;
                Log::Print("{}: row missing", key);
                continue;
            }
            auto* site = pattern.get_first<std::uint8_t>();
            if (WriteRow(image, site, row, key))
            {
                ++report.applied;
            }
            else
            {
                ++report.missing;
            }
        }
        Log::Print("{}: {}/{} row(s)", key, report.applied, report.applied + report.missing);
        return report;
    }

    Report Install(const Image& image, const Options& options)
    {
        Report total;
        const auto run = [&](bool enabled, std::span<const Row> rows, std::string_view key)
        {
            if (!enabled)
            {
                Log::Trace("{}: option off", key);
                return;
            }
            const Report report = Apply(image, rows, key);
            total.applied += report.applied;
            total.missing += report.missing;
        };
        run(options.dataIntegrity, kDataIntegrity, "RemoveDataIntegrityChecks");
        run(options.tokenActivation, kTokenActivation, "SkipTokenActivation");
        run(options.firstTimePlay, kFirstTimePlay, "SkipFirstTimePlayAsk");
        return total;
    }

    Report InstallWebConnectChecks(const Image& image, const WebConnectOptions& options)
    {
        Report total;
        // The reference's `InstallWebConnectChecks` order: the three web-connect
        // branches first, then the health check's entry.
        const auto run = [&](bool enabled, std::span<const Row> rows, std::string_view key)
        {
            if (!enabled)
            {
                Log::Trace("{}: option off", key);
                return;
            }
            const Report report = Apply(image, rows, key);
            total.applied += report.applied;
            total.missing += report.missing;
        };
        run(options.internetConnection, kInternetConnection, "SkipWebConnect (web-connect)");
        run(options.healthCheck, kHealthCheck, "SkipWebConnect (health check)");
        return total;
    }

    namespace
    {
        // The module-image guard's two probes: the mapped size (psapi) and the page's
        // state/protection (VirtualQuery). Neither writes anything.
        bool PageReadable(const void* address, std::size_t bytes) noexcept
        {
            if (address == nullptr || bytes == 0)
            {
                return false;
            }
            MEMORY_BASIC_INFORMATION region{};
            if (VirtualQuery(address, &region, sizeof(region)) != sizeof(region))
            {
                return false;
            }
            if (region.State != MEM_COMMIT ||
                (region.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0)
            {
                return false;
            }
            return bytes <= region.RegionSize;
        }
    } // namespace

    bool ModuleImageContains(std::uintptr_t module, std::size_t offset, std::size_t bytes) noexcept
    {
        if (module == 0 || bytes == 0)
        {
            return false;
        }

        MODULEINFO info{};
        if (!GetModuleInformation(GetCurrentProcess(), reinterpret_cast<HMODULE>(module), &info,
                                  sizeof(info)))
        {
            return false;
        }
        const auto size = static_cast<std::size_t>(info.SizeOfImage);
        if (offset > size || bytes > size - offset)
        {
            return false;
        }
        return PageReadable(reinterpret_cast<const std::uint8_t*>(module) + offset, bytes);
    }

    bool ApplyGfwlProtectionByte(std::uint8_t* site)
    {
        if (site == nullptr)
        {
            return false;
        }

        // The pre-image byte is the guard: only the protection branch is flipped.
        const std::uint8_t opcode = *site;
        if (opcode != kGfwlProtectionBranch && opcode != kGfwlProtectionJump)
        {
            Log::Print("gfwl: the protection site holds {:#x}, not the jz/jmp branch; skipped",
                       opcode);
            return false;
        }
        return patch::Write(patch::Site{site}, 0, kGfwlProtectionPatched,
                            "gfwl: xlive.dll protection byte");
    }

    bool InstallGfwlProtectionDisabler()
    {
        const HMODULE xlive = GetModuleHandleA("xlive.dll");
        if (xlive == nullptr)
        {
            Log::Line("gfwl: xlive.dll is not loaded; GFWLProtectionDisabler skipped");
            return false;
        }

        // Only a real Games for Windows LIVE image has this export; the Ultimate ASI
        // Loader proxy that shares the filename does not, and patching its image at
        // the GFWL RVA would corrupt the loader.
        if (GetProcAddress(xlive, "XLiveInitialize") == nullptr)
        {
            Log::Line("gfwl: xlive.dll is not Games for Windows LIVE; skipped");
            return false;
        }

        if (!ModuleImageContains(reinterpret_cast<std::uintptr_t>(xlive),
                                 kGfwlProtectionSiteOffset, 1))
        {
            Log::Print("gfwl: xlive.dll+0x{:X} is not readable; skipped",
                       kGfwlProtectionSiteOffset);
            return false;
        }

        return ApplyGfwlProtectionByte(reinterpret_cast<std::uint8_t*>(xlive) +
                                       kGfwlProtectionSiteOffset);
    }
} // namespace xla::core
