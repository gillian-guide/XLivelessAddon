// SPDX-License-Identifier: GPL-3.0-or-later
//
// xla.patches — the signature table the original add-on ran after its launcher
// stage: GFWL/RGSC gating, file-integrity checks, DLC activation, the intro/menu
// skips, the legacy DefWindowProc shims and the VRAM detection fix.
//
// Signature strings, offsets and stored bytes are the recovered ones; only the
// wrapper is ours. Every row logs whether it applied, so a user log is a
// complete write-set report for their build.

module;

#include "common.hxx"

export module xla.patches;

import xla.common;
import xla.build;
import xla.patch;

export namespace xla::patches
{
    // The unconditional list, in the original handler's order. `build` gates the
    // two rows that differ between the 1.0.0.x and later builds.
    void InstallCore(const Image& image, build::Id build);

    // The GFWL web-connect and health checks.
    void InstallWebConnectChecks(const Image& image);

    // The 300 ms intro variant (`SkipIntro`).
    void InstallIntro(const Image& image);

    // The main-menu skip (`SkipMenu`); hold SHIFT at startup to keep the menu.
    void InstallMenu(const Image& image);

    // DoNotPauseOnMinimize: stop the game pausing when the window loses focus.
    void InstallDoNotPauseOnMinimize(const Image& image);

    // VRAM detection fix so the settings are not locked out.
    void InstallVramFix(const Image& image);
} // namespace xla::patches

namespace xla::patches
{
    namespace
    {
        // Recovered instruction windows the rows store (common.ixx names the
        // opcodes): "mov al,1; ret; nop" and "xor eax,eax; ret; nop".
        constexpr std::uint32_t kMovAl1RetNop = Dword(ops::kMovAl1RetNop);
        constexpr std::uint32_t kXorEaxRetNop = Dword(ops::kXorEaxRetNop);
        constexpr std::uint16_t kXorEaxEax = Word(ops::kXorEaxEax);
        constexpr std::uint16_t kNopMovMoffsEax = Word(ops::kNopMovMoffsEax);
        // The hex on the right of these asserts is the original's recovered
        // dword/word (byte order shown next to it, provenance only); the named
        // window on the left is what the code writes, so a change to either side
        // breaks the build.
        static_assert(kMovAl1RetNop == 0x90C301B0); // B0 01 C3 90
        static_assert(kXorEaxRetNop == 0x90C3C033); // 33 C0 C3 90
        static_assert(kXorEaxEax == 0xC033);        // 33 C0
        static_assert(kNopMovMoffsEax == 0xA390);   // 90 A3

        // Match-relative write offsets for rows whose site is not the pattern start.
        // Each call site names its signature; the comment decodes what sits there.
        constexpr std::ptrdiff_t kVds102JccOffset = 6;       // `74 19` at +6 -> EB
        constexpr std::ptrdiff_t kVds102LateJccOffset = 12;  // +12, 5 bytes past the 7-byte sig
        constexpr std::ptrdiff_t kVds100JccOffset = 0;       // pattern starts `75 28`
        constexpr std::ptrdiff_t kRgscInitSecondNopOffset = 5; // the `74 E7` after `74 EC 38 5E 06`
        constexpr std::ptrdiff_t kRgscResultJccOffset = 3;   // `75 BD` at +3 -> 33 C0
        constexpr std::ptrdiff_t kRgscResultStoreOffset = 10; // 5 bytes past the 5-byte sig
        constexpr std::ptrdiff_t kRgscEfcJumpOffset = 2;     // E9 over `8B 56 1C`
        constexpr std::ptrdiff_t kWebConnectBranchOffset = 8; // `75 ??` after `FF 15; 85 C0`
        constexpr std::ptrdiff_t kIntroHookBackBytes = 6;    // 6 bytes before the resume match
        constexpr std::ptrdiff_t kMenuCallOffsetV1002 = 23;  // E8 inside [1002-1008]
        constexpr std::ptrdiff_t kMenuCallOffsetEarly = 2;   // E8 inside [1000]/[1001]

        // ModRM of `mov [imm32], ebx` (89 1D): the original's 1.0.0.x/1.0.1.0
        // variant changes the `mov [imm32], esi` operand's register field to ebx.
        // (This is the ModRM byte of `89 /r`, not the A3/A1 moffs form.)
        constexpr std::uint8_t kStoreEbXModRm = 0x1D;

        // 447-byte NOP fill of the EFC20 row [v1003 - v1004] (the original's
        // 0x1BF; spelled as the byte count it is).
        constexpr std::size_t kEfc20NopBytes = 447;
        static_assert(kEfc20NopBytes == 0x1BF); // recovered: the original's NOP count

        // GetAsyncKeyState returns a SHORT whose high bit (0x8000) means "down".
        // The original masks with the whole top nibble 0xF000 instead; kept as
        // recovered so the SHIFT-held behaviour is byte-for-byte the original's.
        constexpr SHORT kKeyDownMask = static_cast<SHORT>(0xF000);

        // The JZ rel8 at +3 (`74 19`) in the [1002 - 1004] row: site + 3, two
        // bytes long, displacement 0x19 - so the continuation is at +0x1E.
        constexpr std::ptrdiff_t kJzOffset = 3;
        constexpr std::ptrdiff_t kJzLength = 2;
        constexpr std::int8_t kJzDisplacement = 0x19; // recovered `74 19` displacement
        constexpr std::ptrdiff_t kJzTarget = kJzOffset + kJzLength + kJzDisplacement;
        static_assert(kJzTarget == 0x1E); // derived: +3 + 2 + 0x19

        // The two recovered `EB rel8` pokes: the DLC token activation jumps over
        // the check (-0x37, recovered `EB C9`), the first-time-play ask skips it
        // (+0x0D, recovered `EB 0D`).
        constexpr std::int8_t kDlcTokenJump = -0x37; // recovered `EB C9`
        constexpr std::int8_t kFirstPlayJump = 0x0D; // recovered `EB 0D`
        static_assert(JmpShort(kDlcTokenJump) == 0xC9EB);  // recovered: EB C9
        static_assert(JmpShort(kFirstPlayJump) == 0x0DEB); // recovered: EB 0D

        // The intro skip's register contract: ecx *= 400 (ms per tick), then edx
        // is forced to 300 ms while it is below 8000 ms. The recovered immediates
        // are the asserts' right-hand side (provenance), the named values are used.
        enum : std::uint32_t
        {
            kIntroTickMilliseconds = 400,   // recovered: imul ecx,ecx,0x190
            kIntroFloorMilliseconds = 8000, // recovered: cmp edx,0x1f40
            kIntroForcedMilliseconds = 300, // recovered: mov edx,0x12c
        };
        static_assert(kIntroTickMilliseconds == 0x190);   // recovered: imul ecx,ecx,0x190
        static_assert(kIntroFloorMilliseconds == 0x1F40); // recovered: cmp edx,0x1f40
        static_assert(kIntroForcedMilliseconds == 0x12C); // recovered: mov edx,0x12c

        // ---- SkipIntro -------------------------------------------------------
        // Same contract as the original inline hook: ecx *= 400, edx is forced to
        // 300 ms below 8000, then resume at the hooked site.
        std::uint32_t g_skipIntroResume = 0;

        __declspec(naked) void SkipIntroBody()
        {
            __asm
            {
                imul ecx, ecx, kIntroTickMilliseconds
                cmp edx, kIntroFloorMilliseconds
                jge skip_intro_ok
                mov edx, kIntroForcedMilliseconds
                skip_intro_ok:
                jmp dword ptr [g_skipIntroResume]
            }
        }

        // ---- SkipMenu --------------------------------------------------------
        // The original's menu-state arguments: 0 is the first-boot state; 6 skips
        // straight into the loaded game (`a1 = 6` in dcc4f31 dllmain.cpp).
        constexpr int kMenuStateFirstBoot = 0;
        constexpr int kMenuStateSkip = 6;
        void(__cdecl* g_menuOriginal)(int) = nullptr;

        void __cdecl SkipMenuBody(int value)
        {
            static bool once = false;
            if (!once)
            {
                if (value == kMenuStateFirstBoot)
                {
                    // Latches only on the first-boot value; SHIFT keeps the menu.
                    const bool keepMenu = (::GetAsyncKeyState(VK_SHIFT) & kKeyDownMask) != 0;
                    if (!keepMenu)
                    {
                        value = kMenuStateSkip;
                    }
                    once = true;
                }
            }

            if (g_menuOriginal != nullptr)
            {
                g_menuOriginal(value);
            }
        }

        // ---- VRAMFix ---------------------------------------------------------
        std::int32_t(__cdecl* g_vidMemOriginal)() = nullptr;

        std::int32_t __cdecl GetVidMemBody()
        {
            const std::int32_t value = g_vidMemOriginal != nullptr ? g_vidMemOriginal() : 0;
            return value <= 0 ? INT_MAX : value;
        }
    } // namespace

    // Section index for the 290-line body (all one recovered sequence; do not
    // reorder): files.txt/integrity checks -> RGSC gating -> EFC20 -> fixed
    // sequences -> missing-test rows (v1005 and neighbours) -> DLC token/first-play
    // -> intro/menu/do-not-pause/VRAM (separate functions below). The signature
    // golden pins the scan order; the write plan is reviewed section by section.
    void InstallCore(const Image& image, build::Id build)
    {
        (void)image;

        // The one pointer several later rows jump through (the EFC skip).
        hook::pattern efcPattern{"68 ? ? ? ? 89 35 ? ? ? ? E8 ? ? ? ? 83 C4 04 84 C0 0F 84"};
        void* efc = efcPattern.empty() ? nullptr : efcPattern.get(0).get<void>();
        if (efc == nullptr)
        {
            log::Write("core: EFC anchor pattern missing");
        }

        // disable sleep [v1002 - v1008]
        patch::WriteDword("68 88 13 00 00 FF 15", 1, 1, "core: disable sleep");

        // RETN - enable debugger in error menu (don't load WER.dll) [v1000 - v1008]
        patch::WriteByte(
            "81 EC ? ? ? ? A1 ? ? ? ? 33 C4 89 84 24 ? ? 00 00 53 56 8B 35 ? ? ? ? 68", 0,
            Byte(Opcode::kRet), "core: debugger in error menu");

        // RETN 8 - certificates check [v1002 - v1008]
        patch::RetFirst(
            "81 EC ? ? ? ? A1 ? ? ? ? 33 C4 89 84 24 ? ? ? ? 53 8B 9C 24 ? ? ? ? 55 8B AC ? ? ? "
            "? ? 8B 45 00",
            0, 8, "core: certificates check");

        // RETN - skip files.txt hash check [v1002 - v1005]
        patch::RetFirst(
            "81 EC ? ? ? ? A1 ? ? ? ? 33 C4 89 84 24 ? ? ? ? 83 3D ? ? ? ? ? 56 57 0F 85 ? ? ? ? "
            "83 3D",
            0, 0, "core: files.txt hash [1002-1005]");

        // RETN - skip files.txt hash check [v1000 - v1001]
        patch::RetFirst(
            "81 EC ? ? ? ? A1 ? ? ? ? 33 C4 89 84 24 ? ? ? ? 83 3D ? ? ? ? ? 0F 85 ? ? ? ? 83 3D",
            0, 0, "core: files.txt hash [1000-1001]");

        // RETN - skip files.txt hash check [v1000 - v1001]
        patch::RetFirst(
            "81 EC ? ? ? ? A1 ? ? ? ? 33 C4 89 84 24 ? ? ? ? 56 68 ? ? ? ? 68 ? ? ? ? 68", 0, 0,
            "core: files.txt hash (third variant)");

        // JMP [v1002 - v1004]
        {
            hook::pattern pattern{"3B 56 20 74 19"};
            if (!pattern.empty())
            {
                auto* site = pattern.get(0).get<std::uint8_t>();
                // The JZ rel8 at +3 (`74 19`) continues at +0x1E. An E9 keeps the same
                // destination, so the literal +0x16 the original stored is derived here.
                injector::MakeJMP(injector::raw_ptr(site + 3), injector::raw_ptr(site + kJzTarget),
                                  true);
                log::Write("core: branch rewrite [1002-1004] applied");
            }
            else
            {
                log::Write("core: branch rewrite [1002-1004] missing");
            }
        }

        // NOP - another files.txt hash check [v1000 - v1001]
        patch::NopFirst("74 F7 8B CE", 0, 2, "core: files.txt hash nop");

        // RETN - remove connect to the RGSC [v1000 - v1001]
        patch::RetFirst(
            "83 EC 68 A1 ? ? ? ? 33 C4 89 44 24 60 53 56 57 8B F1 68 ? ? ? ? 8D 44 24 2C 8D 4C 24 "
            "3C 68",
            0, 0, "core: RGSC connect [1000-1001]");

        // RETN 4 - remove connect to the RGSC [v1002 - v1005]
        patch::RetFirst(
            "83 EC 64 A1 ? ? ? ? 33 C4 89 44 24 60 8B 44 24 68 53 56 8B F1 8B 08 3B 4E 0C 57 0F 85",
            0, 4, "core: RGSC connect [1002-1005]");

        // data integrity checks VDS102 [v1002 - v1004]
        patch::WriteByte("C7 06 ? ? ? ? 74 19", kVds102JccOffset, Byte(Opcode::kJmpRel8),
                         "core: VDS102 [1002-1004]");

        // data integrity checks VDS102 [v1005 - v1008]
        patch::WriteByte("83 C4 ? 3B 46 20", kVds102LateJccOffset, Byte(Opcode::kJmpRel8),
                         "core: VDS102 [1005-1008]");

        // data integrity checks VDS100 [v1006 - v1008]
        patch::WriteByte("75 28 6A 00 6A 00 68 ? ? ? ? E8 ? ? ? ? 83 C4 0C", kVds100JccOffset,
                         Byte(Opcode::kJmpRel8), "core: VDS100 [1006-1008]");

        // NOP - RGSC initialization check [v1000 - v1001]
        {
            hook::pattern pattern{"74 EC 38 5E 06 74 E7 68"};
            if (!pattern.empty())
            {
                auto* site = pattern.get(0).get<std::uint8_t>();
                injector::MakeNOP(injector::raw_ptr(site), 2, true);
                injector::MakeNOP(injector::raw_ptr(site + kRgscInitSecondNopOffset), 2, true);
                log::Write("core: RGSC init [1000-1001] nops applied");
            }
            else
            {
                log::Write("core: RGSC init [1000-1001] missing");
            }
        }

        // NOP - RGSC initialization check [v1002 - v1004]
        patch::NopFirst("74 C4 8B 07 3B 46 18 75 BD 68", 0, 2, "core: RGSC init [1002-1004]");

        // NOP - last RGSC init check [v1002 - v1004]
        patch::NopFirst("3B 56 18 0F 85", 3, 6, "core: last RGSC init [1002-1004]");

        // NOP - last RGSC init check [v1005]
        patch::NopFirst("3B 4E 18 0F 85", 3, 6, "core: last RGSC init [1005]");

        // NOP - last RGSC init check [v1006 - v1008]
        patch::NopFirst("0F 85 ? ? ? ? 8B 8C 24 ? ? ? ? 5F 5E 5B 33 CC C6", 0, 6,
                        "core: last RGSC init [1006-1008]");

        // RGSC initialization check [v1002 - v1004]
        {
            hook::pattern pattern{"3B 46 18 75 BD"};
            if (!pattern.empty())
            {
                auto* site = pattern.get(0).get<std::uint8_t>();
                injector::WriteMemory<std::uint16_t>(
                    injector::raw_ptr(site + kRgscResultJccOffset), kXorEaxEax,
                    true); // xor eax,eax
                injector::WriteMemory<std::uint16_t>(
                    injector::raw_ptr(site + kRgscResultStoreOffset), kNopMovMoffsEax,
                    true); // nop; mov [],eax
                log::Write("core: RGSC result reset [1002-1004] applied");
            }
            else
            {
                log::Write("core: RGSC result reset [1002-1004] missing");
            }
        }

        // EFC20 [v1003 - v1004]
        patch::NopFirst("57 51 C7 44 24 ? ? ? ? ? C7 44 24 ? ? ? ? ? C7 44 24", 1, kEfc20NopBytes,
                        "core: EFC20 [1003-1004]");

        // fix messed sequences (the original patches the first two matches)
        // 0xBAC160 / 0xBAC190: `mov al,1; retn` (dcc4f31 dllmain.cpp).
        {
            hook::pattern pattern{"A1 ? ? ? ? 85 C0 8B 0D ? ? ? ? 75"};
            if (pattern.size() >= 2)
            {
                injector::WriteMemory<std::uint32_t>(injector::raw_ptr(pattern.get(0).get<void>()),
                                                     kMovAl1RetNop, true);
                injector::WriteMemory<std::uint32_t>(injector::raw_ptr(pattern.get(1).get<void>()),
                                                     kMovAl1RetNop, true);
                log::Write("core: fixed sequences patched (two matches)");
            }
            else
            {
                log::Write("core: fixed sequences missing");
            }
        }

        // fix messed sequences (the original patches the last two matches)
        // 0xBAC180 / 0xBAC1C0: `mov al,1; retn` (dcc4f31 dllmain.cpp).
        {
            hook::pattern pattern{"33 C0 83 3D ? ? ? ? 01 0F 94 C0 C3"};
            if (pattern.size() >= 2)
            {
                injector::WriteMemory<std::uint32_t>(
                    injector::raw_ptr(pattern.get(pattern.size() - 2).get<void>()), kMovAl1RetNop,
                    true);
                injector::WriteMemory<std::uint32_t>(
                    injector::raw_ptr(pattern.get(pattern.size() - 1).get<void>()), kMovAl1RetNop,
                    true);
                log::Write("core: fixed sequences patched (last two matches)");
            }
            else
            {
                log::Write("core: fixed sequences (second table) missing");
            }
        }

        // skip RGSC connect and EFC checks [v1005 - v1008]
        {
            hook::pattern pattern{"8B 56 1C 3B 56 20 ? ? 6A 00 6A 00"};
            if (!pattern.empty() && efc != nullptr)
            {
                auto* site = pattern.get(0).get<std::uint8_t>();
                injector::WriteMemory<std::uint16_t>(injector::raw_ptr(site), kXorEaxEax,
                                                     true); // xor eax,eax
                injector::MakeJMP(injector::raw_ptr(site + kRgscEfcJumpOffset),
                                  injector::raw_ptr(efc), true);
                log::Write("core: RGSC/EFC skip [1005-1008] applied");
            }
            else
            {
                log::Write("core: RGSC/EFC skip [1005-1008] missing");
            }
        }

        // NOP; MOV [g_rgsc], eax [v1000 - v1008]
        {
            hook::pattern pattern{"89 35 ? ? ? ? E8 ? ? ? ? 83 C4 04 84 C0"};
            if (!pattern.empty())
            {
                auto* site = pattern.get(0).get<std::uint8_t>();
                if (!build::Is(build, {build::Id::v1000, build::Id::v1010}))
                {
                    injector::WriteMemory<std::uint16_t>(injector::raw_ptr(site), kNopMovMoffsEax,
                                                         true);
                }
                else
                {
                    injector::WriteMemory<std::uint8_t>(injector::raw_ptr(site + 1),
                                                        kStoreEbXModRm, true);
                }
                log::Write("core: RGSC store neutralised");
            }
            else
            {
                log::Write("core: RGSC store pattern missing");
            }
        }

        // skip missing tests [v1005]
        {
            hook::pattern pattern{"8B 50 2C 3B 50 30"};
            if (!pattern.empty())
            {
                auto* site = pattern.get(0).get<std::uint8_t>();
                injector::WriteMemory<std::uint16_t>(injector::raw_ptr(site), kXorEaxEax, true);
                injector::MakeNOP(injector::raw_ptr(site + 2), 4, true);
                log::Write("core: missing-test skip [v1005] (1/9) applied");
            }
            else
            {
                log::Write("core: missing-test skip [v1005] (1/9) missing");
            }
        }
        // (2/9) and (3/9) each need two NOPs from ONE scan: the 3-byte head NOP
        // overwrites the start of the signature, so a second scan of the same
        // string would miss and silently drop the 11-byte tail NOP.
        constexpr std::array<std::pair<std::string_view, std::string_view>, 2>
            kMissingTestSites{{
                {"8B 48 2C 83 EC 78", "core: missing-test [v1005] (2/9)"},
                {"8B 48 2C 83 EC 74", "core: missing-test [v1005] (3/9)"},
            }};
        for (const auto& [signature, label] : kMissingTestSites)
        {
            const patch::Site site = patch::Find(signature, label);
            patch::Nop(site, 0, 3, label);
            patch::Nop(site, 6, 11, label);
        }
        patch::NopFirst("8B 48 2C 3B 48 30 74 03", 0, 11, "core: missing-test [v1005] (4/9)");
        patch::NopFirst("8B 48 2C 3B 48 30 53", 0, 32, "core: missing-test [v1005] (5/9)");
        patch::NopFirst("8B 48 2C 3B 48 30 74 11", 0, 25, "core: missing-test [v1005] (6/9)");
        patch::NopFirst("8B 48 2C 3B 48 30 75 DC 8D 54 24 18", 0, 8,
                        "core: missing-test [v1005] (7/9)");
        patch::NopFirst("8B 48 2C 3B 48 30 75 DC 8D 54 24 1C", 0, 8,
                        "core: missing-test [v1005] (8/9)");
        patch::NopFirst("8B 0D ? ? ? ? 8B 51 2C", 0, 14, "core: missing-test [v1005] (9/9)");

        // skip missing tests [v1003 - v1005]
        patch::RetFirst("51 53 55 56 57 8B 3D ? ? ? ? 8B 47 2C", 0, 0,
                        "core: missing-test [1003-1005] ret");

        // skip missing tests [v1005 - v1008]
        patch::NopFirst("3B C7 0F 85 ? ? ? ? 85 C0", 0, 16, "core: missing-test [1005-1008] (1/2)");
        patch::NopFirst("0F 85 ? ? ? ? 85 C0 0F 84 ? ? ? ? E8 ? ? ? ? 85 D2", 0, 14,
                        "core: missing-test [1005-1008] (2/2)");

        // skip missing tests [v1006 - v1007]
        patch::WriteDword("83 EC 24 A1 ? ? ? ? 8B 48 14 53 55 56 57", 0, kXorEaxRetNop,
                          "core: missing-test [1006-1007] (1/2)");
        patch::WriteDword("83 EC 08 8B 0D ? ? ? ? 8B 51 14 8D 04 24 50 6A 00 52", 0, kXorEaxRetNop,
                          "core: missing-test [1006-1007] (2/2)");

        // DLC token activation [v1006 - v1007]
        patch::WriteWord("8B 54 24 04 52 A3", 0, JmpShort(kDlcTokenJump),
                         "core: DLC token activation (1/2)");
        {
            hook::pattern pattern{"83 F8 01 75 30 A3"};
            if (!pattern.empty())
            {
                auto* site = pattern.get(0).get<std::uint8_t>();
                injector::WriteMemory<std::uint8_t>(injector::raw_ptr(site),
                                                    Byte(Opcode::kMovEaxImm32),
                                                    true); // mov eax, ...
                injector::WriteMemory<std::uint32_t>(injector::raw_ptr(site + 1), 1, true);
                log::Write("core: DLC token activation (2/2) applied");
            }
            else
            {
                log::Write("core: DLC token activation (2/2) missing");
            }
        }

        // skip first-time play ask [v1006 - v1008]
        patch::WriteWord("C7 05 ? ? ? ? 03 00 00 00 33 C0 5E 59 C3 C7", 0,
                         JmpShort(kFirstPlayJump), "core: first-time play ask");
    }

    void InstallWebConnectChecks(const Image& image)
    {
        (void)image;

        // [v1000 - v1001]
        patch::NopFirst("FF 15 ? ? ? ? 85 C0 75 18", kWebConnectBranchOffset, 2,
                        "web: InternetGetConnectedState [1000]");
        // [v1002 - v1005]
        patch::NopFirst("FF 15 ? ? ? ? 85 C0 75 04 32", kWebConnectBranchOffset, 2,
                        "web: InternetGetConnectedState [1002-1005]");
        // [v1006 - v1008]
        patch::NopFirst("FF 15 ? ? ? ? 85 C0 75 07 A0", kWebConnectBranchOffset, 2,
                        "web: InternetGetConnectedState [1006-1008]");

        // health check [v1003 - v1008]
        patch::WriteByte(
            "81 EC ? ? ? ? A1 ? ? ? ? 33 C4 89 84 24 ? ? ? ? 53 ? 6A 3C 33 DB 8D 44 24 ? 53 50 "
            "E8",
            0, Byte(Opcode::kRet), "web: health check");
    }

    void InstallIntro(const Image& image)
    {
        (void)image;

        // IV hangs with the jump-to-menu variant; shorten the load screens instead.
        // The 6 bytes before the match are replaced by a jump into the body above,
        // which reproduces the original inline hook's register contract.
        hook::pattern pattern{"89 91 ? ? ? ? 8D 44 24 ? 68 ? ? ? ? 50"};
        if (!pattern.empty())
        {
            g_skipIntroResume = static_cast<std::uint32_t>(
                reinterpret_cast<std::uintptr_t>(pattern.get(0).get<void>()));
            injector::MakeJMP(injector::raw_ptr(pattern.get_first(-kIntroHookBackBytes)),
                              injector::raw_ptr(reinterpret_cast<void*>(&SkipIntroBody)), true);
            log::Info("intro: 300 ms body installed (resume {:08X})", g_skipIntroResume);
        }
        else
        {
            log::Write("intro: load-screen pattern missing");
        }
    }

    void InstallMenu(const Image& image)
    {
        (void)image;

        hook::pattern pattern{
            "83 F8 03 75 ? A1 ? ? ? ? 80 88 ? ? ? ? ? 84 DB 74 0A 6A 00 E8 ? ? ? ? 83 C4 04 5F 5E"};
        if (!pattern.empty())
        {
            g_menuOriginal = reinterpret_cast<void(__cdecl*)(int)>(
                injector::MakeCALL(injector::raw_ptr(pattern.get(0).get<void>(kMenuCallOffsetV1002)),
                                   injector::raw_ptr(reinterpret_cast<void*>(&SkipMenuBody)), true)
                    .get<void*>());
            log::Write("menu: skip installed [1002-1008]");
            return;
        }

        pattern = hook::pattern{
            "6A 00 E8 ? ? ? ? 83 C4 04 8B 8C 24 ? ? ? ? 5F 5E 5D 5B 33 CC E8 ? ? ? ? 81 C4 ? ? ? "
            "? C3"};
        if (!pattern.empty())
        {
            g_menuOriginal = reinterpret_cast<void(__cdecl*)(int)>(
                injector::MakeCALL(injector::raw_ptr(pattern.get(0).get<void>(kMenuCallOffsetEarly)),
                                   injector::raw_ptr(reinterpret_cast<void*>(&SkipMenuBody)), true)
                    .get<void*>());
            log::Write("menu: skip installed [1000]");
            return;
        }

        pattern = hook::pattern{
            "6A 00 E8 ? ? ? ? 83 C4 04 8B 8C 24 ? ? ? ? 5F 5E 5B 33 CC E8 ? ? ? ? 8B E5 5D C3"};
        if (!pattern.empty())
        {
            g_menuOriginal = reinterpret_cast<void(__cdecl*)(int)>(
                injector::MakeCALL(injector::raw_ptr(pattern.get(0).get<void>(kMenuCallOffsetEarly)),
                                   injector::raw_ptr(reinterpret_cast<void*>(&SkipMenuBody)), true)
                    .get<void*>());
            log::Write("menu: skip installed [1001]");
            return;
        }

        log::Write("menu: skip pattern missing");
    }

    void InstallDoNotPauseOnMinimize(const Image& image)
    {
        (void)image;

        // NOP the `75 ?` branch; original site 0x402D5A (dcc4f31 dllmain.cpp).
        patch::NopFirst("75 ? 8B 0D ? ? ? ? 51 FF 15 ? ? ? ? 85 C0 75 ? 8B 15", 0, 2,
                        "input: do not pause on minimize");
    }

    void InstallVramFix(const Image& image)
    {
        (void)image;

        // Each site is a call to the game's VRAM query; the body clamps non-positive
        // answers to INT_MAX. The original stored the last resolved original in one
        // variable and every site forwards through it; that behaviour is kept.
        g_vidMemOriginal = reinterpret_cast<std::int32_t(__cdecl*)()>(
            patch::CallFirst("E8 ? ? ? ? D9 E8 85 C0", 0,
                             reinterpret_cast<void*>(&GetVidMemBody), "vram: call (1/3)"));
        g_vidMemOriginal = reinterpret_cast<std::int32_t(__cdecl*)()>(
            patch::CallFirst("E8 ? ? ? ? F3 0F 10 0D ? ? ? ? F3 0F 5C 0D", 0,
                             reinterpret_cast<void*>(&GetVidMemBody), "vram: call (2/3)"));
        g_vidMemOriginal = reinterpret_cast<std::int32_t(__cdecl*)()>(
            patch::CallFirst("E8 ? ? ? ? F3 0F 10 05 ? ? ? ? 89 44 24 08 6A 01 8D 44 24", 0,
                             reinterpret_cast<void*>(&GetVidMemBody), "vram: call (3/3)"));
    }
} // namespace xla::patches
