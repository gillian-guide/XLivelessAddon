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

        // Replaces one shell32 IAT slot in the game module and hands back the
        // original. Near-copy of windowed::ReplaceImport (HMODULE vs Image) and
        // registry's walker; this one trusts the PE, registry's is bounds-checked.
        bool ReplaceShellImport(const Image& image, const char* function, void* replacement,
                                void** original) noexcept
        {
            if (image.empty() || function == nullptr || replacement == nullptr)
            {
                return false;
            }

            auto* base = reinterpret_cast<std::uint8_t*>(image.base);
            const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            {
                return false;
            }

            const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE)
            {
                return false;
            }

            const auto& directory =
                nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
            if (directory.VirtualAddress == 0)
            {
                return false;
            }

            auto* descriptor =
                reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + directory.VirtualAddress);
            for (; descriptor->Name != 0; ++descriptor)
            {
                const char* module = reinterpret_cast<const char*>(base + descriptor->Name);
                if (_stricmp(module, "SHELL32.DLL") != 0)
                {
                    continue;
                }

                auto* thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(
                    base + (descriptor->OriginalFirstThunk != 0 ? descriptor->OriginalFirstThunk
                                                                : descriptor->FirstThunk));
                auto* slot = reinterpret_cast<IMAGE_THUNK_DATA*>(base + descriptor->FirstThunk);
                for (; thunk->u1.AddressOfData != 0; ++thunk, ++slot)
                {
                    if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal))
                    {
                        continue;
                    }

                    const auto* import = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(
                        base + thunk->u1.AddressOfData);
                    if (std::strcmp(reinterpret_cast<const char*>(import->Name), function) != 0)
                    {
                        continue;
                    }

                    DWORD previous = 0;
                    if (!::VirtualProtect(&slot->u1.Function, sizeof(void*), PAGE_READWRITE,
                                          &previous))
                    {
                        return false;
                    }
                    *original = reinterpret_cast<void*>(slot->u1.Function);
                    slot->u1.Function = reinterpret_cast<ULONG_PTR>(replacement);
                    ::VirtualProtect(&slot->u1.Function, sizeof(void*), previous, &previous);
                    return true;
                }
            }
            return false;
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

        std::error_code error;
        const std::filesystem::path directory =
            std::filesystem::path(paths::ModuleDirectory(error)) / "saves";
        if (error)
        {
            log::Write("userdata: module directory unavailable");
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

        const bool ansi = ReplaceShellImport(
            image, "SHGetFolderPathA", reinterpret_cast<void*>(&ShellFolderPathA),
            reinterpret_cast<void**>(&g_shellFolderA));
        const bool wide = ReplaceShellImport(
            image, "SHGetFolderPathW", reinterpret_cast<void*>(&ShellFolderPathW),
            reinterpret_cast<void**>(&g_shellFolderW));

        log::Info("userdata: profile={} (A={} W={})", g_profilePath, ansi ? 1 : 0,
                  wide ? 1 : 0);
        return ansi || wide;
    }
} // namespace xla::userdata
