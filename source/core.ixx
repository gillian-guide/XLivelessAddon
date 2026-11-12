// SPDX-License-Identifier: GPL-3.0-or-later
//
// xla.core - the five "core fixes" families, one section per INI key:
// RemoveDataIntegrityChecks, SkipTokenActivation, SkipFirstTimePlayAsk,
// SkipInternetConnectionCheck and SkipHealthCheck.
//
// The old XLivelessAddon ran these unconditionally; this tree carries them under
// the five per-fix keys OpenPreCEPatch's legacy import maps an old `MiscFixes`
// value onto. Recovered rows, same bytes and offsets as the original ZolikaPatch
// 7.65 `MiscFixes` handler (`sub_10023DD0`) and the old addon's `InstallCore`: a
// branch turned into an unconditional jump, `jmp rel8` pairs, two-byte NOPs, a
// `ret` on the health check and the token `mov eax,1`. The rows are applied one
// signature at a time and a miss is a logged skip, exactly like the old addon.
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

    struct Options
    {
        bool dataIntegrity{true};
        bool tokenActivation{true};
        bool firstTimePlay{true};
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

    // The five fixes, each behind its key. Returns the summed report.
    Report Install(const Image& image, const Options& options);
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
        run(options.internetConnection, kInternetConnection, "SkipInternetConnectionCheck");
        run(options.healthCheck, kHealthCheck, "SkipHealthCheck");
        return total;
    }
} // namespace xla::core
