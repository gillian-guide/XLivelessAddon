// SPDX-License-Identifier: GPL-3.0-or-later
//
// xla.menu - the frontend family: [Options] SkipIntro and SkipMenu.
//
// Ported from GTAIV.EFLC.FusionFix/source/skipintro.ixx (GPL-3.0, ThirteenAG and
// the FusionFix contributors), which is this tree's reference for the pair: the
// inline Loadsc hook that shortens the intro screens (only the ones under
// 8000 ms) and the sub_7870A0 hook that skips the main menu unless SHIFT is held
// on startup. The old add-on shipped the same two options with a different
// mechanism (a -6 detour into a body that scales ECX by 400 and forces 300 ms, and
// a menu-state rewrite at the three menu call sites); FusionFix's is the
// maintained one and is what this companion follows.
//
// Shape difference, not a behaviour one: the companion pins injector's classic
// revision, which has no `MakeInline`/`reg_pack` and no `hook_back`, so
//  - the Loadsc window (two instructions the functor reproduced) is replaced by a
//    jump into an assembled stub. The stub reproduces both instructions, applies
//    FusionFix's test and jumps through the published resume;
//  - the menu call keeps the reference add-on's plumbing: `E8` retargeted at the
//    body, whose original target is captured first and called from the body
//    (FusionFix's `hbsub_7870A0.fun(a1)` tail call does the same through
//    safetyhook).
// The FusionFix behaviour itself is unchanged: the intro screens under the 8000 ms
// threshold are zeroed only while the intro is still needed, and the menu is
// skipped (a1 = 6) unless SHIFT is held, exactly once.
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

    // The intro stub is the Loadsc functor's register contract as bytes. It reads
    // four addresses, so the suite can pin the body on its own:
    //   [0]  pushfd
    //   [1]  pushad
    //   [2]  mov eax, [esp+0x3C]            (the game's [esp+0x18], eax variant)
    //        mov eax, [esp+0x40]            (the game's [esp+0x1C], edx variant)
    //   [6]  cmp eax, 8000
    //   [11] jge done
    //   [13] cmp byte [skipIntroFlag], 0
    //   [20] je done
    //   [22] cmp byte [skipIntroNotNeededFlag], 0
    //   [29] jne done
    //   [31] xor eax, eax
    //   [33] mov [esp+0x1C], eax           (the saved EAX popad restores)
    //        mov [esp+0x14], eax           (the saved EDX popad restores)
    //   [37] popad
    //   [38] popfd
    //   [39] mov ecx, [screenIdGlobal]     (the replaced instruction)
    //   [45] jmp [resumeSlot]              (the published resume)
    // After pushfd+pushad the game's stack starts at esp+0x24, which is why the eax
    // variant reads [esp+0x3C] (`[esp+0x18]` for the game) and the edx variant
    // [esp+0x40] (`[esp+0x1C]`). The argument is always adjusted in EAX: the edx
    // variant only stores it into EDX's saved slot, so the game's EAX survives the
    // popad untouched.
    struct IntroStubInputs
    {
        std::uint32_t screenIdGlobal{};
        std::uint32_t resumeSlot{};
        std::uint32_t skipIntroFlag{};
        std::uint32_t skipIntroNotNeededFlag{};
        bool edxVariant{};
    };
    inline constexpr std::size_t kIntroStubBytes = 51;

    // The stub's bytes; exposed for the register-contract test.
    std::array<std::uint8_t, kIntroStubBytes> BuildIntroStub(const IntroStubInputs& inputs);

    // [Options] SkipIntro: FusionFix's Loadsc hook. Returns false (and logs) when
    // its pattern is missing or the site is not writable.
    bool InstallIntro(const Image& image, bool skipIntro);

    // [Options] SkipMenu: FusionFix's sub_7870A0 hook. The install step also runs
    // when only SkipIntro is on, because the body's first call is what marks the
    // intro no longer needed; `skipMenu` only gates the `a1 = 6` rewrite.
    bool InstallMenu(const Image& image, bool skipMenu);

    // The menu body the hook calls, and the original it forwards to.
    void MenuBody(int value);
    void SetMenuOriginal(void(__cdecl* original)(int)) noexcept;

    // The Loadsc hook's published resume (0 until the hook installs). Exposed with
    // the stub builder for the register-contract test.
    [[nodiscard]] std::uint32_t IntroResume() noexcept;

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

        // The body's resume: the call's original target, captured before the site
        // is rewritten.
        void(__cdecl* g_menuOriginal)(int) = nullptr;
        // FusionFix's `bOnce`: set on the first first-boot call only.
        bool g_menuLatch = false;
        // FusionFix reads its settings in the bodies; the INI does not change
        // during a pass, so the values are captured when the hooks install.
        bool g_skipMenu = false;
        bool g_skipIntro = false;
        // FusionFix's `bSkipIntroNotNeeded`, set by the menu body's first call.
        bool g_skipIntroNotNeeded = false;
        // The Loadsc hook's resume, published before the window is replaced.
        std::uint32_t g_introResume = 0;
    } // namespace

    std::array<std::uint8_t, kIntroStubBytes> BuildIntroStub(const IntroStubInputs& inputs)
    {
        std::array<std::uint8_t, kIntroStubBytes> code{};
        const auto put8 = [&code](std::size_t at, std::uint8_t value) { code[at] = value; };
        const auto put32 = [&code, &put8](std::size_t at, std::uint32_t value)
        {
            put8(at, static_cast<std::uint8_t>(value & 0xFF));
            put8(at + 1, static_cast<std::uint8_t>((value >> 8) & 0xFF));
            put8(at + 2, static_cast<std::uint8_t>((value >> 16) & 0xFF));
            put8(at + 3, static_cast<std::uint8_t>((value >> 24) & 0xFF));
        };
        const auto rel8 = [](std::size_t from, std::size_t to) {
            return static_cast<std::uint8_t>(static_cast<std::ptrdiff_t>(to) -
                                             static_cast<std::ptrdiff_t>(from));
        };

        // The offsets are the layout the comment above documents; the suite pins
        // the same numbers as literals, so a change on either side breaks it.
        constexpr std::size_t kPushfd = 0;
        constexpr std::size_t kPushad = 1;
        constexpr std::size_t kLoadArgument = 2;
        constexpr std::size_t kCompare = 6;
        constexpr std::size_t kJumpIfNotShort = 11;
        constexpr std::size_t kCheckSkipIntro = 13;
        constexpr std::size_t kJumpIfIntroOff = 20;
        constexpr std::size_t kCheckNotNeeded = 22;
        constexpr std::size_t kJumpIfNotNeeded = 29;
        constexpr std::size_t kZero = 31;
        constexpr std::size_t kStoreArgument = 33;
        constexpr std::size_t kPopad = 37;
        constexpr std::size_t kPopfd = 38;
        constexpr std::size_t kLoadScreenId = 39;
        constexpr std::size_t kJumpResume = 45;
        constexpr std::size_t kDone = kStoreArgument;
        static_assert(kPushfd == 0 && kPushad == 1 && kLoadArgument == 2 && kCompare == 6);
        static_assert(kJumpIfNotShort == 11 && kCheckSkipIntro == 13 && kJumpIfIntroOff == 20);
        static_assert(kCheckNotNeeded == 22 && kJumpIfNotNeeded == 29 && kZero == 31);
        static_assert(kStoreArgument == 33 && kPopad == 37 && kPopfd == 38);
        static_assert(kLoadScreenId == 39 && kJumpResume == 45);
        static_assert(kJumpResume + 6 == kIntroStubBytes);

        put8(kPushfd, 0x9C); // pushfd
        put8(kPushad, 0x60); // pushad
        if (inputs.edxVariant)
        {
            put8(kLoadArgument, 0x8B);     // mov eax, [esp+0x40]
            put8(kLoadArgument + 1, 0x44); //   (the game's [esp+0x1C])
            put8(kLoadArgument + 2, 0x24);
            put8(kLoadArgument + 3, 0x40);
        }
        else
        {
            put8(kLoadArgument, 0x8B);     // mov eax, [esp+0x3C]
            put8(kLoadArgument + 1, 0x44); //   (the game's [esp+0x18])
            put8(kLoadArgument + 2, 0x24);
            put8(kLoadArgument + 3, 0x3C);
        }
        put8(kCompare, 0x3D); // cmp eax, 8000
        put32(kCompare + 1, static_cast<std::uint32_t>(kIntroMillisecondsThreshold));
        put8(kJumpIfNotShort, 0x7D); // jge done
        put8(kJumpIfNotShort + 1, rel8(kJumpIfNotShort + 2, kDone));
        put8(kCheckSkipIntro, 0x80); // cmp byte [skipIntroFlag], 0
        put8(kCheckSkipIntro + 1, 0x3D);
        put32(kCheckSkipIntro + 2, inputs.skipIntroFlag);
        put8(kCheckSkipIntro + 6, 0);
        put8(kJumpIfIntroOff, 0x74); // je done
        put8(kJumpIfIntroOff + 1, rel8(kJumpIfIntroOff + 2, kDone));
        put8(kCheckNotNeeded, 0x80); // cmp byte [skipIntroNotNeededFlag], 0
        put8(kCheckNotNeeded + 1, 0x3D);
        put32(kCheckNotNeeded + 2, inputs.skipIntroNotNeededFlag);
        put8(kCheckNotNeeded + 6, 0);
        put8(kJumpIfNotNeeded, 0x75); // jne done
        put8(kJumpIfNotNeeded + 1, rel8(kJumpIfNotNeeded + 2, kDone));
        put8(kZero, 0x33); // xor eax, eax
        put8(kZero + 1, 0xC0);
        if (inputs.edxVariant)
        {
            put8(kStoreArgument, 0x89);     // mov [esp+0x14], eax (saved EDX in the pushad frame)
            put8(kStoreArgument + 1, 0x44);
            put8(kStoreArgument + 2, 0x24);
            put8(kStoreArgument + 3, 0x14);
        }
        else
        {
            put8(kStoreArgument, 0x89);     // mov [esp+0x1C], eax (saved EAX in the pushad frame)
            put8(kStoreArgument + 1, 0x44);
            put8(kStoreArgument + 2, 0x24);
            put8(kStoreArgument + 3, 0x1C);
        }
        put8(kPopad, 0x61); // popad
        put8(kPopfd, 0x9D); // popfd
        put8(kLoadScreenId, 0x8B); // mov ecx, [screenIdGlobal]
        put8(kLoadScreenId + 1, 0x0D);
        put32(kLoadScreenId + 2, inputs.screenIdGlobal);
        put8(kJumpResume, 0xFF); // jmp dword ptr [resumeSlot]
        put8(kJumpResume + 1, 0x25);
        put32(kJumpResume + 2, inputs.resumeSlot);
        return code;
    }

    bool InstallIntro(const Image& image, bool skipIntro)
    {
        patch::Pattern pattern = patch::FindIn(image, 1, kIntroPatternV1, kIntroPatternV2);
        if (pattern.empty())
        {
            Log::Line("skipIntro: load-screen pattern missing");
            return false;
        }

        auto* match = pattern.get_first<std::uint8_t>();
        const bool edxVariant =
            *pattern.get_first<std::uint8_t>(kIntroArgumentModRmOffset) == kEdxVariantModRm;
        const auto screenId = *pattern.get_first<std::uint32_t>(kScreenIdGlobalOperand);

        g_skipIntro = skipIntro;
        g_skipIntroNotNeeded = false;
        g_introResume = static_cast<std::uint32_t>(
            reinterpret_cast<std::uintptr_t>(match) + kIntroHookLength);

        const IntroStubInputs inputs{
            .screenIdGlobal = screenId,
            .resumeSlot = static_cast<std::uint32_t>(
                reinterpret_cast<std::uintptr_t>(&g_introResume)),
            .skipIntroFlag = static_cast<std::uint32_t>(
                reinterpret_cast<std::uintptr_t>(&g_skipIntro)),
            .skipIntroNotNeededFlag = static_cast<std::uint32_t>(
                reinterpret_cast<std::uintptr_t>(&g_skipIntroNotNeeded)),
            .edxVariant = edxVariant,
        };
        const auto code = BuildIntroStub(inputs);
        void* stub = patch::MakeStub(code, "skipIntro");
        if (stub == nullptr)
        {
            return false;
        }
        if (!patch::InlineJumpAt(image, match, kIntroHookLength, stub, "skipIntro"))
        {
            Log::Line("skipIntro: hook window outside the image; skipped");
            return false;
        }

        Log::Print("skipIntro: load screens under {} ms zeroed ({} variant, resume {:08X})",
                   kIntroMillisecondsThreshold, edxVariant ? "edx" : "eax", g_introResume);
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

        if (g_menuOriginal != nullptr)
        {
            g_menuOriginal(value);
        }
    }

    void SetMenuOriginal(void(__cdecl* original)(int)) noexcept
    {
        g_menuOriginal = original;
    }

    std::uint32_t IntroResume() noexcept
    {
        return g_introResume;
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
        const void* original = patch::RetargetCallAt(
            image, site, reinterpret_cast<void*>(&MenuBody), "skipMenu");
        if (original == nullptr)
        {
            Log::Line("skipMenu: hook site outside the image; skipped");
            return false;
        }
        g_menuOriginal = reinterpret_cast<void(__cdecl*)(int)>(
            const_cast<void*>(original));
        if (!skipMenu)
        {
            Log::Print("skipMenu: menu-state hook installed for the intro latch (was {:08X})",
                       reinterpret_cast<std::uintptr_t>(original));
        }
        else
        {
            Log::Print("skipMenu: menu skip installed (was {:08X}, SHIFT keeps the menu)",
                       reinterpret_cast<std::uintptr_t>(original));
        }
        return true;
    }
} // namespace xla::menu
