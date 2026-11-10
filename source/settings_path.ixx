// SPDX-License-Identifier: GPL-3.0-or-later
//
// xla.settings_path - CustomSettingsPath, closing the old add-on's "parsed but
// not hooked" gap.
//
// Ported from InstallCustomSettingsPath in
// openprecepatch/xlivelessaddon/source/patches.ixx.
//
// The recovered XLivelessAddon body is a register-contract inline hook at two of
// four matched sites: the site's `mov ecx, <global>` is replaced by a 5-byte call
// to a stub that preserves every register and EFLAGS, calls the C helper that
// composes and creates the settings folder, then restores ECX from the original
// global and returns to the next instruction.
//
// The stub is assembled into an executable page at install time. The helper's
// copy into the game's buffer keeps the original's unbounded `buffer[size] = 0`
// (a configured path longer than the game buffer writes past it); that inherited
// fault is preserved and documented in docs/parity.md.

module;

#include <common.hxx>

export module settings_path;

import common;
import patch;

export namespace xla::settings_path
{
    // The path the original body composes. `gameDirectory` prefixes a relative
    // configured path (the INI's rule); an absolute configured path is used
    // as-is.
    [[nodiscard]] std::string ComposeSettingsPath(std::string_view gameDirectory,
                                                  std::string_view configured,
                                                  std::string_view subfolder);

    // Builds the 30-byte call body; exposed for the register-contract test.
    [[nodiscard]] void* MakeSettingsStub(std::uint32_t buffer, std::uint32_t global,
                                         std::uint32_t helper);

    // Installs the two recovered sites. Empty `customSettingsPath` = the option is
    // off (the caller also gates it on the INI key).
    void InstallCustomSettingsPath(const Image& image, std::string_view customSettingsPath);
} // namespace xla::settings_path

namespace xla::settings_path
{
    namespace
    {
        // Recovered XLivelessAddon pattern [v1001-v1008]. The original asserts
        // four hits; matches 1 and 2 are patched at +5 (the `mov ecx, <global>`
        // after the pushed settings-path buffer operand).
        constexpr std::string_view kSettingsPathPattern =
            "68 ? ? ? ? B9 ? ? ? ? E8 ? ? ? ? 8D 4C 24 04 E8 ? ? ? ? 5B 83 C4 08 C3";
        constexpr std::size_t kSettingsPathSites = 4;
        constexpr std::size_t kSettingsPatchCount = 2;
        constexpr std::size_t kSettingsPatchOffset = 5;      // the `mov ecx, imm32` opcode
        constexpr std::size_t kSettingsCallLength = 5;       // E8 + rel32 replaces it
        constexpr std::ptrdiff_t kSettingsBufferOperand = 1; // pushed settings-path buffer
        constexpr std::ptrdiff_t kSettingsGlobalOperand = 6; // the original ECX global
        constexpr std::uint16_t kSettingsCopyLimit = 256;

        std::string g_customSettingsPath;

        // Runs in the game process at the patched site (cdecl, called from the
        // assembled body below): fills the game's settings-path buffer. The
        // try/catch is required because the call frame is assembly; an exception
        // must never unwind through it.
        void __cdecl BuildCustomSettingsPath(char* buffer, const char* subfolder)
        {
            if (buffer == nullptr || subfolder == nullptr)
            {
                return;
            }
            try
            {
                // A relative CustomSettingsPath is relative to the game folder,
                // not to the ASI's folder.
                const std::string path = ComposeSettingsPath(
                    Game::Get().ExecutableDirectory().string(), g_customSettingsPath,
                    subfolder);
                if (::GetFileAttributesA(path.c_str()) == INVALID_FILE_ATTRIBUTES)
                {
                    ::CreateDirectoryA(path.c_str(), nullptr);
                }
                // The original checks the attribute without re-testing the error:
                // INVALID_FILE_ATTRIBUTES (-1) still has the directory bit set, so
                // a failed CreateDirectory copies too. Kept 1:1.
                if ((::GetFileAttributesA(path.c_str()) & FILE_ATTRIBUTE_DIRECTORY) != 0)
                {
                    // Original: memmove(buffer, path, min(256, size)); then
                    // buffer[size] = 0. A path longer than 255 bytes writes past
                    // the game buffer; that inherited fault is preserved here.
                    path.copy(buffer, kSettingsCopyLimit);
                    buffer[path.size()] = '\0';
                }
            }
            catch (...)
            {
            }
        }

        // The body the patched site calls. After `pushfd; pushad` the saved frame
        // is, low to high: EDI, ESI, EBP, original ESP, EBX, EDX, ECX, EAX. Saved
        // EBX (the game's per-profile folder name) is at [esp+0x10] and saved ECX
        // at [esp+0x18]; the recovered thunk's helper reads frame+16 and writes
        // frame+24, matching those offsets.
        inline constexpr std::size_t kStubBytes = 30;
        inline constexpr std::size_t kStubBufferOperand = 7;  // imm32 of `push buffer`
        inline constexpr std::size_t kStubCallRel32 = 12;     // rel32 of `call helper`
        inline constexpr std::size_t kStubGlobalOperand = 23; // imm32 of `mov [esp+..], global`
        inline constexpr std::size_t kStubCallEnd = 16;       // end of `call rel32`
        inline constexpr std::size_t kStubAllocationBytes = 64;
    } // namespace

    std::string ComposeSettingsPath(std::string_view gameDirectory,
                                    std::string_view configured,
                                    std::string_view subfolder)
    {
        // The recovered order: a relative configured path is prefixed with the
        // game folder, then the configured part, the per-profile folder name the
        // game passes in EBX, and a trailing separator. The original called
        // s.back() on an empty string when the configured path was absolute
        // (undefined); the documented intent (start at the configured path) is
        // used for that case.
        std::string path;
        if (configured.find(':') == std::string_view::npos)
        {
            path.assign(gameDirectory);
            if (!path.empty() && path.back() != '\\')
            {
                path += '\\';
            }
        }
        path.append(configured);
        if (path.empty() || path.back() != '\\')
        {
            path += '\\';
        }
        path.append(subfolder);
        path += '\\';
        return path;
    }

    void* MakeSettingsStub(std::uint32_t buffer, std::uint32_t global, std::uint32_t helper)
    {
        void* memory = ::VirtualAlloc(nullptr, kStubAllocationBytes,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (memory == nullptr)
        {
            Log::Line("settings: cannot allocate the CustomSettingsPath stub");
            return nullptr;
        }
        std::array<std::uint8_t, kStubBytes> code{
            0x9C,                                           // pushfd
            0x60,                                           // pushad
            0xFF, 0x74, 0x24, 0x10,                         // push [esp+0x10]
            0x68, 0x00, 0x00, 0x00, 0x00,                   // push buffer
            0xE8, 0x00, 0x00, 0x00, 0x00,                   // call helper
            0x83, 0xC4, 0x08,                               // add esp, 8
            0xC7, 0x44, 0x24, 0x18, 0x00, 0x00, 0x00, 0x00, // mov [esp+0x18], global
            0x61,                                           // popad
            0x9D,                                           // popfd
            0xC3,                                           // ret
        };
        static_assert(code.size() == kStubBytes);
        std::memcpy(code.data() + kStubBufferOperand, &buffer, sizeof(buffer));
        const auto callEnd = reinterpret_cast<std::uintptr_t>(memory) + kStubCallEnd;
        const auto displacement =
            static_cast<std::int32_t>(static_cast<std::uintptr_t>(helper) - callEnd);
        std::memcpy(code.data() + kStubCallRel32, &displacement, sizeof(displacement));
        std::memcpy(code.data() + kStubGlobalOperand, &global, sizeof(global));
        std::memcpy(memory, code.data(), code.size());
        ::FlushInstructionCache(::GetCurrentProcess(), memory, code.size());
        return memory;
    }

    void InstallCustomSettingsPath(const Image& image, std::string_view customSettingsPath)
    {
        if (customSettingsPath.empty())
        {
            return;
        }
        g_customSettingsPath.assign(customSettingsPath);

        // Scan every hit, then require exactly four: the old body asserted the
        // count before patching, so an image with extra hits is a logged skip, not
        // a partial install.
        patch::Pattern pattern = patch::FindIn(image, kSettingsPathPattern, 0);
        if (pattern.size() != kSettingsPathSites)
        {
            Log::Print("settings: CustomSettingsPath pattern matched {} site(s), expected {}; "
                       "keeping the game default",
                       pattern.size(), kSettingsPathSites);
            return;
        }

        std::size_t installed = 0;
        const auto install = [&](std::size_t index)
        {
            auto* match = pattern.get<std::uint8_t>(index);
            auto* site = match + kSettingsPatchOffset;
            if (!image.contains(site, kSettingsCallLength))
            {
                Log::Line("settings: CustomSettingsPath site outside the image; skipped");
                return;
            }
            const std::uint32_t buffer = *pattern.get<std::uint32_t>(
                index, static_cast<std::ptrdiff_t>(kSettingsBufferOperand));
            const std::uint32_t global = *pattern.get<std::uint32_t>(
                index, static_cast<std::ptrdiff_t>(kSettingsGlobalOperand));
            void* stub = MakeSettingsStub(
                buffer, global,
                static_cast<std::uint32_t>(
                    reinterpret_cast<std::uintptr_t>(&BuildCustomSettingsPath)));
            if (stub == nullptr)
            {
                return;
            }
            if (patch::CallAt(image, site, stub, "settings: custom settings path"))
            {
                ++installed;
            }
        };
        install(1);
        install(2);
        if (installed == kSettingsPatchCount)
        {
            Log::Print("settings: CustomSettingsPath installed ({}, two sites)",
                       customSettingsPath);
        }
        else
        {
            Log::Print("settings: CustomSettingsPath installed at {}/2 sites ({})",
                       installed, customSettingsPath);
        }
    }
} // namespace xla::settings_path
