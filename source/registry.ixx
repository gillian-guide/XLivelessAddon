// SPDX-License-Identifier: GPL-3.0-or-later
//
// xla.registry — remove the "Rockstar Games" registry path dependency.
//
// The original patched the game's ADVAPI32 import slots so that opening the
// Rockstar Games key succeeds, and answers InstallFolder with the game's own
// directory. The replacement is unchanged; the IAT walk is now bounds-checked and
// the captured key is closed.

module;

#include "common.hxx"

export module xla.registry;

import xla.common;

export namespace xla::registry
{
    // True when the sub-key is the Rockstar Games one the game expects to find.
    // Test hook: the hooks call the internal ContainsRockstarGames directly.
    bool IsRockstarSubKey(std::string_view subKey) noexcept;

    // True when the value the game asks for is the install folder.
    bool IsInstallFolderValue(std::string_view valueName) noexcept;

    // The install folder answer: the game executable's directory, trailing
    // separator included (the original's `strrchr(path, '\\') + 1 = '\0'`).
    std::string InstallFolderAnswer();

    // Replaces every matching ADVAPI32 import slot. Returns the number replaced.
    std::size_t Install(const Image& image);
} // namespace xla::registry

namespace xla::registry
{
    namespace
    {
        HKEY g_key = nullptr;
        std::string g_subKey;

        bool ContainsRockstarGames(std::string_view text) noexcept
        {
            return text.find("Rockstar Games") != std::string_view::npos;
        }

        std::string GameDirectoryWithSeparator()
        {
            std::error_code error;
            const auto directory = paths::ModuleDirectory(error);
            if (error)
            {
                return {};
            }
            std::string text = directory.string();
            if (!text.empty() && text.back() != '\\')
            {
                text += '\\';
            }
            return text;
        }

        // The fake open shared by both open hooks: remember the real key/sub-key and
        // answer success with a null handle (the query hook then forwards to the
        // remembered key). Returns false when the call is not the Rockstar Games one,
        // so the caller forwards to the real API.
        bool AnswerRockstarKey(HKEY key, LPCSTR subKey, PHKEY result) noexcept
        {
            if (subKey == nullptr || result == nullptr || !ContainsRockstarGames(subKey))
            {
                return false;
            }
            g_key = key;
            g_subKey = subKey;
            *result = nullptr;
            return true;
        }

        LSTATUS WINAPI RegOpenKeyAHook(HKEY key, LPCSTR subKey, PHKEY result)
        {
            if (AnswerRockstarKey(key, subKey, result))
            {
                return ERROR_SUCCESS;
            }
            return ::RegOpenKeyA(key, subKey, result);
        }

        LSTATUS WINAPI RegOpenKeyExAHook(HKEY key, LPCSTR subKey, DWORD options, REGSAM access,
                                         PHKEY result)
        {
            if (AnswerRockstarKey(key, subKey, result))
            {
                return ERROR_SUCCESS;
            }
            return ::RegOpenKeyExA(key, subKey, options, access, result);
        }

        LSTATUS WINAPI RegQueryValueExAHook(HKEY key, LPCSTR valueName, LPDWORD reserved,
                                            LPDWORD type, LPBYTE data, LPDWORD size)
        {
            if (key != nullptr)
            {
                return ::RegQueryValueExA(key, valueName, reserved, type, data, size);
            }

            if (valueName == nullptr || !IsInstallFolderValue(valueName))
            {
                // Not the value the add-on fakes: forward to the captured key, exactly
                // like the original's `RegOpenKeyExA(Key, SubKey, ...)` tail.
                HKEY opened = nullptr;
                if (g_key == nullptr || g_subKey.empty())
                {
                    return ERROR_FILE_NOT_FOUND;
                }
                if (::RegOpenKeyExA(g_key, g_subKey.c_str(), 0, KEY_READ, &opened) !=
                    ERROR_SUCCESS)
                {
                    return ERROR_FILE_NOT_FOUND;
                }
                const LSTATUS status =
                    ::RegQueryValueExA(opened, valueName, reserved, type, data, size);
                ::RegCloseKey(opened);
                return status;
            }

            const std::string answer = InstallFolderAnswer();
            if (size == nullptr)
            {
                return ERROR_INVALID_PARAMETER;
            }

            if (data == nullptr)
            {
                // The original reports the length without its terminator; keep that.
                *size = static_cast<DWORD>(answer.size());
                return ERROR_SUCCESS;
            }

            // Never write past the caller's buffer, and always terminate.
            const auto capacity = static_cast<std::size_t>(*size);
            if (capacity == 0)
            {
                *size = 0;
                return ERROR_SUCCESS;
            }

            const std::size_t copy = (std::min)(answer.size(), capacity - 1);
            std::memcpy(data, answer.data(), copy);
            data[copy] = '\0';
            *size = static_cast<DWORD>(copy);
            return ERROR_SUCCESS;
        }
    } // namespace

    bool IsRockstarSubKey(std::string_view subKey) noexcept
    {
        return ContainsRockstarGames(subKey);
    }

    bool IsInstallFolderValue(std::string_view valueName) noexcept
    {
        return valueName.find("InstallFolder") != std::string_view::npos;
    }

    std::string InstallFolderAnswer()
    {
        return GameDirectoryWithSeparator();
    }

    std::size_t Install(const Image& image)
    {
        if (image.empty())
        {
            return 0;
        }

        HMODULE advapi = ::GetModuleHandleA("advapi32.dll");
        if (advapi == nullptr)
        {
            log::Write("registry: advapi32.dll is not loaded; nothing replaced");
            return 0;
        }

        // Match a slot by the loader's own answer for the export, not by name: the
        // slot value is what the game calls, and a name would need a second parse
        // of the import table for no extra safety.
        const auto exportAddress = [advapi](const char* name) {
            return reinterpret_cast<std::uintptr_t>(::GetProcAddress(advapi, name));
        };
        const auto openKey = exportAddress("RegOpenKeyA");
        const auto openKeyEx = exportAddress("RegOpenKeyExA");
        const auto queryValueEx = exportAddress("RegQueryValueExA");
        if (openKey == 0 || openKeyEx == 0 || queryValueEx == 0)
        {
            log::Write("registry: advapi32 exports not found; nothing replaced");
            return 0;
        }

        auto* base = reinterpret_cast<std::uint8_t*>(image.base);
        const IMAGE_NT_HEADERS* nt = NtHeaders(base);
        if (nt == nullptr)
        {
            return 0;
        }
        const auto& directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (directory.VirtualAddress == 0)
        {
            return 0;
        }

        // Bounds-checked copy of the import walker used by windowed/userdata (those
        // trust the PE headers); keep the descriptor/thunk/slot checks here.
        std::size_t replaced = 0;
        auto* descriptor =
            reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + directory.VirtualAddress);
        for (; descriptor->Name != 0; ++descriptor)
        {
            if (!image.contains(descriptor, sizeof(*descriptor)))
            {
                break;
            }

            const auto* module = reinterpret_cast<const char*>(base + descriptor->Name);
            if (!image.contains(module, 1) || _stricmp(module, "ADVAPI32.DLL") != 0)
            {
                continue;
            }

            auto* thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(
                base + (descriptor->OriginalFirstThunk != 0 ? descriptor->OriginalFirstThunk
                                                            : descriptor->FirstThunk));
            auto* slot = reinterpret_cast<std::uintptr_t*>(base + descriptor->FirstThunk);
            for (; thunk->u1.AddressOfData != 0; ++thunk, ++slot)
            {
                if (!image.contains(thunk, sizeof(*thunk)) || !image.contains(slot, sizeof(*slot)))
                {
                    break;
                }
                if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal))
                {
                    continue;
                }

                void* replacement = nullptr;
                if (*slot == openKey)
                {
                    replacement = reinterpret_cast<void*>(&RegOpenKeyAHook);
                }
                else if (*slot == openKeyEx)
                {
                    replacement = reinterpret_cast<void*>(&RegOpenKeyExAHook);
                }
                else if (*slot == queryValueEx)
                {
                    replacement = reinterpret_cast<void*>(&RegQueryValueExAHook);
                }

                if (replacement == nullptr)
                {
                    continue;
                }

                DWORD previous = 0;
                if (!::VirtualProtect(slot, sizeof(*slot), PAGE_READWRITE, &previous))
                {
                    log::Info("registry: cannot unprotect slot {:08X}",
                              reinterpret_cast<std::uintptr_t>(slot));
                    continue;
                }
                *slot = reinterpret_cast<std::uintptr_t>(replacement);
                ::VirtualProtect(slot, sizeof(*slot), previous, &previous);
                ++replaced;
            }
        }

        log::Info("registry: replaced {} import slot(s)", replaced);
        return replaced;
    }
} // namespace xla::registry
