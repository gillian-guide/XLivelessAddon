// SPDX-License-Identifier: GPL-3.0-or-later
//
// xla.vram - [Options] VRAMFix: the VRAM detection fix, so the graphics settings
// are not locked out.
//
// Ported 1:1 from openprecepatch/xlivelessaddon/source/patches.ixx's
// `InstallVramFix` (the old add-on's `VRAMFix`): three recovered call sites are
// retargeted at `GetVidMemBody`, which forwards to the game's own query and turns
// a non-positive answer into INT_MAX. The rows, the offsets, the body and the write
// order are the recovered ones; a missing signature is a logged skip.
//
// The reference kept ONE "original destination" variable and every row overwrote
// it, so all three bodies forward through the last original that resolved and a
// missing row stores nullptr (the body then answers INT_MAX). That unconditional
// overwrite is recovered behaviour, not an oversight: unlike FusionFix's rewrite of
// grcDevice::GetAvailableVideoMemory (memory.ixx: a DXGI query and a 2 GB floor),
// the add-on only clamps the game's own answer, and this port keeps it that way.
//
// Measured on the imaged builds (read-only, game_refs/): the three rows match on
// 1.0.0.0, 1.0.0.4, 1.0.1.0, 1.0.4.0, 1.0.6.0, 1.0.7.0, EFLC 1.1.1.0 and EFLC
// 1.1.2.0, and all of them retarget the same game function (the D3D9
// `GetAvailableTextureMem` wrapper). 1.0.8.0 and EFLC 1.1.3.0 restructured that
// call sequence, so the recovered rows are logged skips there - the reference's own
// behaviour, left unfaked. FusionFix's separate implementation is not this fix and
// is not substituted for it.

module;

#include <common.hxx>

export module vram;

import common;
import patch;

export namespace xla::vram
{
    // One recovered call site: the signature starts on the `E8` the row retargets.
    struct Row
    {
        std::string_view signature;
        std::string_view label;
    };

    // The three recovered rows, in the original handler's order.
    std::span<const Row> Rows() noexcept;

    // The body the sites call: the game's own answer, clamped to INT_MAX when it is
    // not positive. The original is called only when a row resolved one.
    std::int32_t __cdecl GetVidMemBody() noexcept;

    // The original the body forwards to (the reference's single variable). A miss
    // clears it, which the suite pins through the body's answer.
    void SetVidMemOriginal(std::int32_t(__cdecl* original)()) noexcept;
    [[nodiscard]] bool HasVidMemOriginal() noexcept;

    // [Options] VRAMFix. Returns the number of call sites retargeted; the
    // reference's overwrite order is preserved, so a later miss clears the original.
    std::size_t Install(const Image& image);
} // namespace xla::vram

namespace xla::vram
{
    namespace
    {
        using VidMemQuery = std::int32_t(__cdecl*)();

        constexpr Row kRows[] = {
            {"E8 ? ? ? ? D9 E8 85 C0", "vram: call (1/3)"},
            {"E8 ? ? ? ? F3 0F 10 0D ? ? ? ? F3 0F 5C 0D", "vram: call (2/3)"},
            {"E8 ? ? ? ? F3 0F 10 05 ? ? ? ? 89 44 24 08 6A 01 8D 44 24",
             "vram: call (3/3)"},
        };

        VidMemQuery g_vidMemOriginal = nullptr;
    } // namespace

    std::span<const Row> Rows() noexcept
    {
        return kRows;
    }

    std::int32_t __cdecl GetVidMemBody() noexcept
    {
        const std::int32_t value = g_vidMemOriginal != nullptr ? g_vidMemOriginal() : 0;
        return value <= 0 ? INT_MAX : value;
    }

    void SetVidMemOriginal(VidMemQuery original) noexcept
    {
        g_vidMemOriginal = original;
    }

    bool HasVidMemOriginal() noexcept
    {
        return g_vidMemOriginal != nullptr;
    }

    std::size_t Install(const Image& image)
    {
        std::size_t applied = 0;
        for (const Row& row : kRows)
        {
            // The reference assigns the result unconditionally: a row that does not
            // match clears the original for every body already installed.
            patch::Pattern pattern = patch::FindIn(image, row.signature, 1);
            if (pattern.empty())
            {
                Log::Print("{}: signature missing", row.label);
                g_vidMemOriginal = nullptr;
                continue;
            }

            const void* previous = patch::RetargetCallAt(
                image, pattern.get_first<std::uint8_t>(), reinterpret_cast<void*>(&GetVidMemBody),
                row.label);
            if (previous == nullptr)
            {
                Log::Print("{}: call site outside the image", row.label);
                g_vidMemOriginal = nullptr;
                continue;
            }
            g_vidMemOriginal = reinterpret_cast<VidMemQuery>(const_cast<void*>(previous));
            ++applied;
        }

        const std::size_t total = std::size(kRows);
        Log::Print("VRAMFix: {}/{} call site(s) retargeted", applied, total);
        return applied;
    }
} // namespace xla::vram
