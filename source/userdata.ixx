// SPDX-License-Identifier: GPL-3.0-or-later
//
// xla.userdata — LocalSettingsPath, implemented the FusionFix way (userdata.ixx):
// redirect the shell user-data folders (CSIDL_APPDATA/PERSONAL/...) to
// <game>\saves instead of rewriting the game's path buffers. One hook covers
// saves and settings, which is why the INI documents it as an alternative to the
// custom paths.

module;

#include "common.hxx"

export module xla.userdata;

import xla.common;

export namespace xla::userdata
{
    // True when the add-on redirects this CSIDL to <game>\saves.
    bool ShouldRedirect(int csidl) noexcept;

    // Creates <game>\saves and replaces the SHGetFolderPath A/W import slots.
    // Returns false (and logs) when the folder cannot be created or the import is
    // not present.
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

        // Writes the redirect target into the caller's buffer, truncated (and always
        // terminated) to the shell's buffer size. One body: the A/W difference is
        // the character type only.
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
            return g_shellFolderA != nullptr ? g_shellFolderA(window, csidl, token, flags, path)
                                             : E_FAIL;
        }

        HRESULT WINAPI ShellFolderPathW(HWND window, int csidl, HANDLE token, DWORD flags,
                                        LPWSTR path)
        {
            if (ShouldRedirect(csidl))
            {
                return CopyProfilePath(g_profilePathW, path);
            }
            return g_shellFolderW != nullptr ? g_shellFolderW(window, csidl, token, flags, path)
                                             : E_FAIL;
        }

        // Replaces one shell32 IAT slot and returns the value it held (the function
        // the game keeps calling), or nullopt when there is no such slot. The value
        // can be null, so the optional says whether the slot was replaced. The walk
        // is FusionFix's IATHook; the map lookup is the "was it present" answer.
        [[nodiscard]] std::optional<void*> ReplaceShellImport(const Image& image,
                                                              const char* function,
                                                              void* replacement) noexcept
        {
            if (image.empty() || function == nullptr || replacement == nullptr ||
                NtHeaders(image.base) == nullptr)
            {
                return std::nullopt;
            }

            auto originals = IATHook::Replace(
                reinterpret_cast<HMODULE>(image.base), "SHELL32.DLL",
                std::pair<const char*, void*>{function, replacement});
            const auto found = originals.find(function);
            if (found == originals.end())
            {
                return std::nullopt;
            }
            return found->second.get();
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

    bool InstallLocalSettingsPath(const Image& image) noexcept
    {
        // Only ever inside the real game module: a parity dump that maps a private
        // copy must not hook its own process.
        if (::GetModuleHandleW(nullptr) != reinterpret_cast<HMODULE>(image.base))
        {
            return false;
        }

        // <game>\saves, not <ASI folder>\saves: the redirect is documented as a
        // saves folder inside the game folder, so a plugins\ install keeps the
        // game's own tree.
        std::error_code error;
        const std::filesystem::path directory =
            std::filesystem::path(paths::GameDirectory(error)) / "saves";
        if (error)
        {
            log::Write("userdata: game directory unavailable");
            return false;
        }

        std::filesystem::create_directories(directory, error);
        if (error || !std::filesystem::exists(directory))
        {
            log::Info("userdata: cannot create {} ({})", directory.string(),
                      error.message());
            return false;
        }

        g_profilePath = directory.string();
        g_profilePathW = directory.wstring();

        const auto ansi = ReplaceShellImport(image, "SHGetFolderPathA",
                                             reinterpret_cast<void*>(&ShellFolderPathA));
        if (ansi)
        {
            g_shellFolderA = reinterpret_cast<ShGetFolderPathAFn>(*ansi);
        }
        const auto wide = ReplaceShellImport(image, "SHGetFolderPathW",
                                             reinterpret_cast<void*>(&ShellFolderPathW));
        if (wide)
        {
            g_shellFolderW = reinterpret_cast<ShGetFolderPathWFn>(*wide);
        }

        log::Info("userdata: profile={} (A={} W={})", g_profilePath, ansi ? 1 : 0,
                  wide ? 1 : 0);
        return ansi.has_value() || wide.has_value();
    }
} // namespace xla::userdata
