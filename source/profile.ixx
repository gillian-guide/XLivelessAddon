// SPDX-License-Identifier: GPL-3.0-or-later
//
// xla.profile - [USERPROFILE] CustomUserProfilePath: the one user-data redirect.
//
// This is the user-data family. The SavegameFix CRC32 bypass is the separate
// xla.savegames family; the save folder is one of the roots this redirect
// answers, not a second save-game patch.
//
// The shell's profile folders (CSIDL_PERSONAL and the roaming/local app-data
// ones) answer the configured root, so the game's own path builders put
// everything under it: saves, settings, user music, videos and benchmarks. There
// is no second hook: GTA IV 1.0.8.0 resolves those roots through
// SHGetFolderPathA/W in its startup path initialiser (`__initalizePaths`,
// 0x856BF0) and the savegame resolver `sub_61E770` (0x61E770) asks
// SHGetFolderPathA for CSIDL_PERSONAL on every save and appends
// "Rockstar Games\GTA IV\savegames\user_<xuid>".
//
// Ported from GTAIV.EFLC.FusionFix/source/userdata.ixx (GPL-3.0, ThirteenAG and
// contributors) and made to work on 1.0.8.0:
//
//  * FusionFix installs the hook from `onInitEventAsync`, which on 1.0.8.0 runs
//    after `__initalizePaths` has already resolved and cached the startup roots
//    in globals -- the custom folder never reaches them. This module installs
//    from DllMain, before the game's entry point, so the cached roots are the
//    custom ones.
//  * A relative value is resolved against the game folder (not the working
//    directory, which is elsewhere when the launcher starts the game) and
//    created recursively; a value with a leading separator means "under the game
//    folder", which is how the old keys were written.
//
// Replaces LocalSettingsPath, CustomSavePath and CustomSettingsPath.

module;

#include <common.hxx>

export module profile;

import common;
import patch;

export namespace xla::profile
{
    // True when `csidl` is answered with the custom root. The set is FusionFix's:
    // the game asks for the personal folder (saves, settings), the roaming and
    // local app data (profiles, user music) and the common ones.
    [[nodiscard]] bool ShouldRedirect(int csidl) noexcept;

    // The configured value as a full path. Empty value = feature off (empty
    // result). A path with a drive/UNC root is used as-is; anything else is
    // relative to `gameDirectory`; a leading separator is treated as relative.
    [[nodiscard]] std::filesystem::path ResolveProfilePath(
        const std::filesystem::path& gameDirectory, std::string_view configured);

    // Replaces the two SHGetFolderPath import slots of `module` and keeps the
    // originals for the pass-through. Exposed so the native test can drive it
    // against a synthetic import table; returns how many slots were replaced.
    std::size_t ReplaceShellFolderImports(HMODULE module, void* hookA, void* hookW);

    // Creates `root` recursively, publishes it to the hooks and replaces
    // `module`'s shell imports. The live installer below adds the "only ever the
    // real game module" policy; the native test calls this directly.
    bool InstallForModule(HMODULE module, const std::filesystem::path& root) noexcept;

    // The live install: resolves the configured value against the game folder and
    // redirects the game module's shell imports. Returns false (and logs) when
    // this is not the live game module, the value is empty, the folder cannot be
    // created or neither import is present.
    bool Install(const Image& image, std::string_view configured) noexcept;
} // namespace xla::profile

namespace xla::profile
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

    std::filesystem::path ResolveProfilePath(const std::filesystem::path& gameDirectory,
                                             std::string_view configured)
    {
        // The INI parser keeps the value's leading/trailing spaces (they are part
        // of it, as everywhere else in this add-on), so trim them here: a path
        // cannot start or end with one.
        while (!configured.empty() &&
               (configured.front() == ' ' || configured.front() == '\t'))
        {
            configured.remove_prefix(1);
        }
        while (!configured.empty() &&
               (configured.back() == ' ' || configured.back() == '\t'))
        {
            configured.remove_suffix(1);
        }
        if (configured.empty())
        {
            return {};
        }

        std::string text{configured};
        std::filesystem::path resolved{text};

        // "D:\Saves", "\\server\share" keep their own root.
        if (!resolved.has_root_name())
        {
            // A leading separator means "under the game folder": "\Savefiles" and
            // "./Savefiles" both resolve to <game>\Savefiles, which is how the
            // replaced keys were written.
            std::size_t first = text.find_first_not_of("\\/");
            if (first == std::string::npos)
            {
                return {};
            }
            text.erase(0, first);
            resolved = gameDirectory / std::filesystem::path{text};
        }
        return resolved.lexically_normal();
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

    bool InstallForModule(HMODULE module, const std::filesystem::path& root) noexcept
    {
        if (module == nullptr || root.empty())
        {
            Log::Line("profile: no module or no root; shell folders unchanged");
            return false;
        }

        std::error_code error;
        std::filesystem::create_directories(root, error);
        if (error || !std::filesystem::exists(root))
        {
            Log::Print("profile: cannot create {} ({})", root.string(), error.message());
            return false;
        }

        g_profilePath = root.string();
        g_profilePathW = root.wstring();

        const std::size_t replaced = ReplaceShellFolderImports(
            module, reinterpret_cast<void*>(&ShellFolderPathA),
            reinterpret_cast<void*>(&ShellFolderPathW));

        Log::Print("profile: root={} ({} slot(s) replaced)", g_profilePath, replaced);
        return replaced != 0;
    }

    bool Install(const Image& image, std::string_view configured) noexcept
    {
        // Only ever inside the real game module: a parity dump that maps a private
        // copy must not hook its own process.
        if (::GetModuleHandleW(nullptr) != reinterpret_cast<HMODULE>(image.base))
        {
            return false;
        }

        const std::filesystem::path root =
            ResolveProfilePath(Game::Get().ExecutableDirectory(), configured);
        if (root.empty())
        {
            Log::Line("profile: CustomUserProfilePath is empty; shell folders unchanged");
            return false;
        }
        return InstallForModule(::GetModuleHandleW(nullptr), root);
    }
} // namespace xla::profile
