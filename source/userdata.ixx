// SPDX-License-Identifier: GPL-3.0-or-later
//
// xla.userdata - LocalSettingsPath, implemented the FusionFix way
// (GTAIV.EFLC.FusionFix/source/userdata.ixx): redirect the shell user-data
// folders (CSIDL_APPDATA/PERSONAL/...) to <game>\saves instead of rewriting the
// game's path buffers. One hook covers saves and settings.
//
// Ported from openprecepatch/xlivelessaddon/source/userdata.ixx, itself adapted
// from FusionFix's userdata.ixx (GPL-3.0, ThirteenAG and contributors).
//
// DIVERGENCE FROM THE OLD ADDON: this option is not switched off when FusionFix is
// installed. It works on the game build and its own INI key alone. See
// docs/parity.md for the reason (the FusionFix gate misbehaves on 1.0.8.0).

module;

#include <common.hxx>

export module userdata;

import common;
import patch;

export namespace xla::userdata
{
    // True when the add-on redirects this CSIDL to <game>\saves.
    bool ShouldRedirect(int csidl) noexcept;

    // <game>\saves for the running game (the executable's folder, not the ASI's).
    std::filesystem::path SavesDirectory();

    // Replaces the two SHGetFolderPath import slots. Exposed so the native test
    // can drive it against a synthetic import table; returns how many slots were
    // replaced.
    std::size_t ReplaceShellFolderImports(HMODULE module, void* hookA, void* hookW);

    // The mechanism: creates <game>\saves, publishes it and replaces the two
    // import slots of `module`. The live installer below adds the "only ever the
    // real game module" policy; the native test calls this with a synthetic
    // module to prove the redirect itself is independent of FusionFix.
    bool InstallLocalSettingsPathForModule(HMODULE module) noexcept;

    // Creates <game>\saves and replaces the SHGetFolderPath A/W import slots.
    // Returns false (and logs) when this is not the live game module, the folder
    // cannot be created or neither import is present.
    bool InstallLocalSettingsPath(const Image& image) noexcept;
} // namespace xla::userdata

namespace xla::userdata
{
    namespace
    {
        using ShGetFolderPathAFn = HRESULT(WINAPI*)(HWND, int, HANDLE, DWORD, LPSTR);
        using ShGetFolderPathWFn = HRESULT(WINAPI*)(HWND, int, HANDLE, DWORD, LPWSTR);

        std::string g_profilePath;
        std::wstring g_profilePathW;
        ShGetFolderPathAFn g_shellFolderA = nullptr;
        ShGetFolderPathWFn g_shellFolderW = nullptr;

        // SHGetFolderPath's caller buffer is MAX_PATH by contract.
        constexpr std::size_t kShellPathCapacity = MAX_PATH;

        // Writes the redirect target into the caller's buffer, truncated (and
        // always terminated) to the shell's buffer size. One body: the A/W
        // difference is the character type only.
        template <typename CharT>
        HRESULT CopyProfilePath(const std::basic_string<CharT>& path, CharT* buffer) noexcept
        {
            if (buffer == nullptr)
            {
                return E_INVALIDARG;
            }
            const std::size_t length = (std::min)(path.size(), kShellPathCapacity - 1);
            std::copy_n(path.data(), length, buffer);
            buffer[length] = 0;
            return S_OK;
        }

        HRESULT WINAPI ShellFolderPathA(HWND window, int csidl, HANDLE token, DWORD flags,
                                        LPSTR path)
        {
            if (ShouldRedirect(csidl))
            {
                return CopyProfilePath(g_profilePath, path);
            }
            return g_shellFolderA != nullptr
                       ? g_shellFolderA(window, csidl, token, flags, path)
                       : E_FAIL;
        }

        HRESULT WINAPI ShellFolderPathW(HWND window, int csidl, HANDLE token, DWORD flags,
                                        LPWSTR path)
        {
            if (ShouldRedirect(csidl))
            {
                return CopyProfilePath(g_profilePathW, path);
            }
            return g_shellFolderW != nullptr
                       ? g_shellFolderW(window, csidl, token, flags, path)
                       : E_FAIL;
        }
    } // namespace

    bool ShouldRedirect(int csidl) noexcept
    {
        switch (csidl)
        {
        case CSIDL_APPDATA:
        case CSIDL_COMMON_APPDATA:
        case CSIDL_COMMON_DOCUMENTS:
        case CSIDL_LOCAL_APPDATA:
        case CSIDL_PERSONAL:
            return true;
        default:
            return false;
        }
    }

    std::filesystem::path SavesDirectory()
    {
        return Game::Get().ExecutableDirectory() / "saves";
    }

    std::size_t ReplaceShellFolderImports(HMODULE module, void* hookA, void* hookW)
    {
        const auto originals = patch::ReplaceImports(
            module, "SHELL32.DLL",
            {{"SHGetFolderPathA", hookA}, {"SHGetFolderPathW", hookW}});

        const auto ansi = originals.find("SHGetFolderPathA");
        if (ansi != originals.end())
        {
            g_shellFolderA = reinterpret_cast<ShGetFolderPathAFn>(ansi->second);
        }
        const auto wide = originals.find("SHGetFolderPathW");
        if (wide != originals.end())
        {
            g_shellFolderW = reinterpret_cast<ShGetFolderPathWFn>(wide->second);
        }
        return originals.size();
    }

    bool InstallLocalSettingsPathForModule(HMODULE module) noexcept
    {
        std::error_code error;
        const std::filesystem::path directory = SavesDirectory();
        if (directory.empty())
        {
            Log::Line("userdata: game directory unavailable");
            return false;
        }

        std::filesystem::create_directories(directory, error);
        if (error || !std::filesystem::exists(directory))
        {
            Log::Print("userdata: cannot create {} ({})", directory.string(),
                       error.message());
            return false;
        }

        g_profilePath = directory.string();
        g_profilePathW = directory.wstring();

        const std::size_t replaced = ReplaceShellFolderImports(
            module, reinterpret_cast<void*>(&ShellFolderPathA),
            reinterpret_cast<void*>(&ShellFolderPathW));

        Log::Print("userdata: profile={} ({} slot(s) replaced)", g_profilePath, replaced);
        return replaced != 0;
    }

    bool InstallLocalSettingsPath(const Image& image) noexcept
    {
        // Only ever inside the real game module: a parity dump that maps a private
        // copy must not hook its own process.
        if (::GetModuleHandleW(nullptr) != reinterpret_cast<HMODULE>(image.base))
        {
            return false;
        }
        return InstallLocalSettingsPathForModule(::GetModuleHandleW(nullptr));
    }
} // namespace xla::userdata
