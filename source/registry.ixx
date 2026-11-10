// SPDX-License-Identifier: GPL-3.0-or-later
//
// xla.registry - remove the "Rockstar Games" registry path dependency.
//
// The original patched the game's ADVAPI32 import slots so that opening the
// Rockstar Games key succeeds, and answers InstallFolder with the game's own
// directory. The replacement is unchanged; the IAT walk is now the shared
// patch::ReplaceImports, and the captured key is closed after the forwarded query.

module;

#include <common.hxx>

export module registry;

import common;
import patch;

export namespace xla::registry
{
    bool IsRockstarSubKey(std::string_view subKey) noexcept;
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
            // The game's install folder, not the ASI's folder: the registry
            // answer must stay <game>\ even for a plugins\ install.
            const auto directory = Game::Get().ExecutableDirectory();
            if (directory.empty())
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

        // The fake open shared by both open hooks: remember the real key/sub-key
        // and answer success with a null handle (the query hook then forwards to
        // the remembered key). Returns false when the call is not the Rockstar
        // Games one, so the caller forwards to the real API.
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
                // Not the value the add-on fakes: forward to the captured key,
                // exactly like the original's tail.
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

        const HMODULE module = ::GetModuleHandleA("advapi32.dll");
        if (module == nullptr)
        {
            Log::Line("registry: advapi32.dll is not loaded; nothing replaced");
            return 0;
        }

        const auto originals = patch::ReplaceImports(
            ::GetModuleHandleW(nullptr), "ADVAPI32.DLL",
            {{"RegOpenKeyA", reinterpret_cast<void*>(&RegOpenKeyAHook)},
             {"RegOpenKeyExA", reinterpret_cast<void*>(&RegOpenKeyExAHook)},
             {"RegQueryValueExA", reinterpret_cast<void*>(&RegQueryValueExAHook)}});

        Log::Print("registry: replaced {} import slot(s)", originals.size());
        return originals.size();
    }
} // namespace xla::registry
