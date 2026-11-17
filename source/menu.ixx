// SPDX-License-Identifier: GPL-3.0-or-later
//
// xla.menu - the frontend family: [Options] SkipIntro and SkipMenu.
//
// Ported from GTAIV.EFLC.FusionFix/source/skipintro.ixx (GPL-3.0, ThirteenAG and
// the FusionFix contributors), which is this tree's reference for the pair: the
// inline Loadsc hook that shortens the intro screens (only the ones under
// 8000 ms) and the sub_7870A0 hook that skips the main menu unless SHIFT is held
// on startup. The code below is FusionFix's, line for line, with the settings
// reads mapped to this tree's `[Options]` keys and the globals it captured in its
// lambda hoisted to module state. Its two injection idioms stay behind patch.ixx,
// the only unit allowed to install:
//
//  - FusionFix's inline hook over the Loadsc window is `patch::InlineHookAt<Loadsc>`
//    - the vendored injector's `MakeInline(at, end)` call, behind that boundary;
//  - FusionFix's hook_back holder and its call retarget are `patch::HookBack` and
//    `patch::HookCallAt`, which return the call's previous destination the same
//    way.
//
// The old add-on shipped the same two options with a different mechanism (a -6
// detour into a body that scaled ECX by 400 and forced 300 ms, and a menu-state
// rewrite at the three menu call sites); FusionFix's is the maintained one and is
// what this companion follows. The behaviour is unchanged: the intro screens under
// the 8000 ms threshold are zeroed only while the intro is still needed, and the
// menu is skipped (a1 = 6) unless SHIFT is held, exactly once.
//
// FusionFix gate: when a GTAIV.EFLC.FusionFix ASI is present its own
// skipintro.ixx owns this subsystem, so [Options] SkipIntro and SkipMenu are
// switched off by config::ApplyFusionFixGates before this module is reached.

module;

#include <common.hxx>

export module menu;

import common;
import patch;

export namespace xla::menu
{
    // The recovered pattern variants, in FusionFix's order: `find_pattern` tries
    // them in turn and the first that matches wins (v1 is the pre-1.0.8.0 shape,
    // v2 is the one 1.0.8.0 and EFLC 1.1.3.0 carry).
    inline constexpr std::string_view kIntroPatternV1 =
        "8B 0D ? ? ? ? 8B 44 24 18 83 C4 0C 69 C9 ? ? ? ? 89 81 ? ? ? ? 8D 44 24 60 68 ? ? ? ? "
        "50 E8 ? ? ? ? 83 C4 08 85 C0 0F 85";
    inline constexpr std::string_view kIntroPatternV2 = "8B 0D ? ? ? ? 8B 54 24 1C 83 C4 0C";

    // The menu hook: FusionFix scans the five-hit call shape and, when the build
    // does not produce five hits, falls back to the single-hit shape. 1.0.8.0 has
    // four hits and takes the fallback (measured; the fallback's call is the same
    // site the old add-on patched at its pattern's +23).
    inline constexpr std::string_view kMenuCallPattern =
        "E8 ? ? ? ? 83 C4 04 8B 8C 24 ? ? ? ? 5F 5E 5D 5B 33 CC E8 ? ? ? ? 81 C4 ? ? ? ? C3";
    inline constexpr std::string_view kMenuFallbackPattern =
        "E8 ? ? ? ? 83 C4 04 5F 5E 5B 8B 8C 24 ? ? ? ? 33 CC E8 ? ? ? ? 8B E5 5D C3 83 F8 30";

    // The window the Loadsc hook replaces: `mov ecx, [screen id global]` (6 bytes)
    // and the load of the candidate duration (4 bytes).
    inline constexpr std::size_t kIntroHookLength = 10;
    inline constexpr std::ptrdiff_t kScreenIdGlobalOperand = 2;   // the `mov ecx` imm32
    inline constexpr std::ptrdiff_t kIntroArgumentModRmOffset = 7; // 0x44 = eax, 0x54 = edx
    inline constexpr std::uint8_t kEdxVariantModRm = 0x54;

    // FusionFix's threshold and menu state literals.
    inline constexpr std::int32_t kIntroMillisecondsThreshold = 8000;
    inline constexpr int kMenuStateSkip = 6;

    // FusionFix's `Loadsc` functor, unchanged in body: it reproduces the two
    // instructions the window held (reload the screen id into ECX, load the
    // candidate duration into EAX/EDX per the matched variant) and zeroes that
    // duration while the intro is still needed and it is under the threshold. The
    // injector saves and restores the register file around it, so `regs.esp` is the
    // game's stack pointer at the window.
    struct Loadsc
    {
        void operator()(patch::Registers& regs);
    };

    // [Options] SkipIntro: FusionFix's Loadsc hook. Returns false (and logs) when
    // its pattern is missing or the site is not writable.
    bool InstallIntro(const Image& image, bool skipIntro);

    // [Options] SkipMenu: FusionFix's sub_7870A0 hook. The install step also runs
    // when only SkipIntro is on, because the body's first call is what marks the
    // intro no longer needed; `skipMenu` only gates the `a1 = 6` rewrite.
    bool InstallMenu(const Image& image, bool skipMenu);

    // The menu body the hook calls, and the original it forwards to (FusionFix's
    // `hbsub_7870A0.fun`).
    void MenuBody(int value);
    void SetMenuOriginal(void(__cdecl* original)(int)) noexcept;

    // Test seams for the latch the body keeps.
    void ResetMenuState() noexcept;
    [[nodiscard]] bool IntroNotNeeded() noexcept;
} // namespace xla::menu

namespace xla::menu
{
    namespace
    {
        // GetAsyncKeyState's high bit means "down". FusionFix masks the whole top
        // nibble (the recovered constant) rather than 0x8000; kept as recovered.
        constexpr SHORT kKeyDownMask = static_cast<SHORT>(0xF000);
        // The first-boot state: the only argument the skip rewrites.
        constexpr int kMenuStateFirstBoot = 0;

        // FusionFix's `pattern.get_first<uint8_t>(7)` (`reg`) and the screen-id
        // global it read with `get_first<int32_t*>(2)`.
        std::uint8_t g_argumentRegister = 0;
        std::int32_t* g_screenId = nullptr;

        // FusionFix reads its settings in the bodies; the INI does not change
        // during a pass, so the values are captured when the hooks install.
        bool g_skipMenu = false;
        bool g_skipIntro = false;
        // FusionFix's `bSkipIntroNotNeeded`, set by the menu body's first call.
        bool g_skipIntroNotNeeded = false;
        // FusionFix's `bOnce`: set on the first first-boot call only.
        bool g_menuLatch = false;
        // FusionFix's `hbsub_7870A0`: the call's original destination.
        patch::HookBack<void(__cdecl*)(int)> g_menuOriginal;
    } // namespace

    void Loadsc::operator()(patch::Registers& regs)
    {
        bool less = false;
        *(std::int32_t*)&regs.ecx = *g_screenId;
        if (g_argumentRegister == kEdxVariantModRm)
        {
            *(std::int32_t*)&regs.edx = *(std::int32_t*)(regs.esp + 0x1C);
            less = *(std::int32_t*)&regs.edx < kIntroMillisecondsThreshold;
        }
        else
        {
            *(std::int32_t*)&regs.eax = *(std::int32_t*)(regs.esp + 0x18);
            less = *(std::int32_t*)&regs.eax < kIntroMillisecondsThreshold;
        }
        if (!g_skipIntroNotNeeded && g_skipIntro && less)
        {
            if (g_argumentRegister == kEdxVariantModRm)
            {
                regs.edx = 0;
            }
            else
            {
                regs.eax = 0;
            }
        }
    }

    bool InstallIntro(const Image& image, bool skipIntro)
    {
        // FusionFix: `find_pattern` over the two variants, then the two statics the
        // functor reads, then `MakeInline<Loadsc>(match, match + 10)`.
        patch::Pattern pattern = patch::FindIn(image, 1, kIntroPatternV1, kIntroPatternV2);
        if (pattern.empty())
        {
            Log::Line("skipIntro: load-screen pattern missing");
            return false;
        }

        g_skipIntro = skipIntro;
        g_skipIntroNotNeeded = false;
        g_argumentRegister = *pattern.get_first<std::uint8_t>(kIntroArgumentModRmOffset);
        // FusionFix's `*pattern.get_first<int32_t*>(2)`: the operand is the screen-id
        // global's address, so the pointer is that value, not the operand's address.
        g_screenId = *pattern.get_first<std::int32_t*>(kScreenIdGlobalOperand);
        if (!patch::InlineHookAt<Loadsc>(image, pattern.get_first<std::uint8_t>(0),
                                         pattern.get_first<std::uint8_t>(kIntroHookLength),
                                         "skipIntro"))
        {
            Log::Line("skipIntro: hook window outside the image; skipped");
            return false;
        }

        Log::Print("skipIntro: load screens under {} ms zeroed ({} variant)",
                   kIntroMillisecondsThreshold,
                   g_argumentRegister == kEdxVariantModRm ? "edx" : "eax");
        return true;
    }

    // FusionFix's sub_7870A0 hook. The first call marks the intro no longer
    // needed (so the Loadsc hook stops shortening screens after the menu), and a
    // first-boot call rewrites the menu state to 6 unless SHIFT is held. The
    // original call is then made with the value that survived, which is how the
    // game reaches the loaded game instead of its menu.
    void MenuBody(int value)
    {
        if (!g_menuLatch)
        {
            g_skipIntroNotNeeded = true;
            if (value == kMenuStateFirstBoot)
            {
                const bool keepMenu = (::GetAsyncKeyState(VK_SHIFT) & kKeyDownMask) != 0;
                if (!keepMenu && g_skipMenu)
                {
                    value = kMenuStateSkip;
                }
                g_menuLatch = true;
            }
        }

        if (g_menuOriginal.fun != nullptr)
        {
            g_menuOriginal.fun(value);
        }
    }

    void SetMenuOriginal(void(__cdecl* original)(int)) noexcept
    {
        g_menuOriginal.fun = original;
    }

    void ResetMenuState() noexcept
    {
        g_menuLatch = false;
        g_skipIntroNotNeeded = false;
    }

    bool IntroNotNeeded() noexcept
    {
        return g_skipIntroNotNeeded;
    }

    bool InstallMenu(const Image& image, bool skipMenu)
    {
        // FusionFix asks for the five-hit call shape first; a build that does not
        // produce five hits takes the single-hit fallback. The scan asks for every
        // hit (0) so a build with more than five is not mistaken for a five-hit one.
        std::uint8_t* site = nullptr;
        constexpr std::size_t kExpectedHits = 5;
        constexpr std::size_t kHookHit = 1;
        patch::Pattern pattern = patch::FindIn(image, 0, kMenuCallPattern);
        if (pattern.size() == kExpectedHits)
        {
            site = pattern.get<std::uint8_t>(kHookHit);
        }
        else
        {
            patch::Pattern fallback = patch::FindIn(image, 1, kMenuFallbackPattern);
            if (!fallback.empty())
            {
                site = fallback.get_first<std::uint8_t>();
            }
        }
        if (site == nullptr)
        {
            Log::Line("skipMenu: menu-state pattern missing");
            return false;
        }

        g_skipMenu = skipMenu;
        if (!patch::HookCallAt(image, site, &MenuBody, g_menuOriginal.fun, "skipMenu"))
        {
            Log::Line("skipMenu: hook site outside the image; skipped");
            return false;
        }

        if (skipMenu)
        {
            Log::Print("skipMenu: menu skip installed at {:08X} (SHIFT keeps the menu)",
                       reinterpret_cast<std::uintptr_t>(site));
        }
        else
        {
            Log::Print("skipMenu: menu-state hook installed at {:08X} for the intro latch",
                       reinterpret_cast<std::uintptr_t>(site));
        }
        return true;
    }
} // namespace xla::menu
