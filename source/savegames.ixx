// SPDX-License-Identifier: GPL-3.0-or-later
//
// xla.savegames — the custom savegame folder (and the save-file CRC32 bypass),
// descended from XLivelessAddon's getSavefilePath replacement.
//
// The original replaced the game's path builder and copied 256 bytes into the
// caller's buffer. The transport is unchanged; the copy is now bounded and
// NUL-terminated, so an over-long custom path truncates instead of writing past
// the game's buffer.

module;

#include "common.hxx"

export module xla.savegames;

import xla.common;
import xla.patch;

export namespace xla::savegames
{
    // The game hands the hook a 256-byte buffer (the original's assumption).
    inline constexpr std::size_t kGamePathCapacity = 256;

    // The savegame directory the game would use, redirected when the INI sets a
    // custom folder. Exposed for tests.
    std::string BaseSavePath(std::string_view gameDefaultPath, std::string_view customPath);

    // BaseSavePath plus "\<save name>" when a name is given. Exposed for tests.
    std::string JoinSaveName(std::string_view basePath, std::string_view saveName);

    // Installs the CRC32 bypass (always, as the original did) and the path
    // redirect. Logs which signatures were found.
    void Install(const Image& image, std::string_view customSavePath);

    // Reads a NUL-terminated string out of the game image without running past
    // `limit` bytes. Exposed for tests.
    std::string ReadCString(const Image& image, const void* address, std::size_t limit);
} // namespace xla::savegames

namespace xla::savegames
{
    namespace
    {
        std::string g_gameDefaultSavePath;
        std::string g_customSavePath;

        // ABI: __cdecl, (unused int, char* buffer, char* saveName), plain ret. The
        // game's path builder is tail-jumped here with its 256-byte caller buffer;
        // the copy below is bounded but keeps that buffer contract.
        void __cdecl GetSavefilePath(int /*unused*/, char* buffer, char* saveName)
        {
            if (buffer == nullptr)
            {
                return;
            }

            const std::string base = BaseSavePath(g_gameDefaultSavePath, g_customSavePath);
            const std::string_view name = saveName != nullptr ? std::string_view{saveName} : "";

            const DWORD attributes = ::GetFileAttributesA(base.c_str());
            if (attributes == INVALID_FILE_ATTRIBUTES)
            {
                if (!::CreateDirectoryA(base.c_str(), nullptr))
                {
                    log::Info("savegames: cannot create {} (error {})", base, ::GetLastError());
                }
            }
            else if ((attributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
            {
                // A file sits where the folder belongs: keep the game's own name.
                if (!name.empty())
                {
                    ::strncpy_s(buffer, kGamePathCapacity, std::string{name}.c_str(), _TRUNCATE);
                }
                return;
            }

            const std::string path = JoinSaveName(base, name);
            if (::strncpy_s(buffer, kGamePathCapacity, path.c_str(), _TRUNCATE) != 0)
            {
                log::Info("savegames: path truncated to {} characters", kGamePathCapacity - 1);
            }
        }
    } // namespace

    std::string BaseSavePath(std::string_view gameDefaultPath, std::string_view customPath)
    {
        if (!customPath.empty())
        {
            return std::string{customPath};
        }

        std::string path{gameDefaultPath};
        path += "savegames"; // the game's default already ends in a backslash
        return path;
    }

    std::string JoinSaveName(std::string_view basePath, std::string_view saveName)
    {
        std::string path{basePath};
        if (!saveName.empty())
        {
            if (!path.empty() && path.back() != '\\')
            {
                path += '\\';
            }
            path += saveName;
        }
        return path;
    }

    std::string ReadCString(const Image& image, const void* address, std::size_t limit)
    {
        if (address == nullptr || limit == 0)
        {
            return {};
        }

        const auto* text = static_cast<const char*>(address);
        std::size_t length = 0;
        while (length < limit && image.contains(text + length, 1) && text[length] != '\0')
        {
            ++length;
        }
        return std::string{text, length};
    }

    void Install(const Image& image, std::string_view customSavePath)
    {
        g_customSavePath = customSavePath;

        // The path buffer lives in a helper around the third match; the original
        // scanned back 0x80 bytes from it (128 - a byte count, not a mask).
        constexpr std::uintptr_t kPathScanBackBytes = 128;
        hook::pattern anchor{
            "8A 10 83 C0 01 84 D2 75 F7 56 57 BF ? ? ? ? 2B C1 8B F1 83 C7 FF 8A 4F 01 83 C7 01"};
        if (anchor.size() >= 3)
        {
            const auto rangeEnd = reinterpret_cast<std::uintptr_t>(anchor.get(2).get<void>());
            hook::pattern redirect = hook::make_range_pattern(
                rangeEnd - kPathScanBackBytes, rangeEnd,
                "8A 88 ? ? ? ? 88 88 ? ? ? ? 83 C0 01");
            if (!redirect.empty())
            {
                const auto* slot = redirect.get(0).get<const char*>(2);
                if (slot != nullptr && image.contains(slot, sizeof(void*)))
                {
                    g_gameDefaultSavePath = ReadCString(image, *slot, kGamePathCapacity);
                }
                log::Info("savegames: game default path = \"{}\"", g_gameDefaultSavePath);
            }
            else
            {
                log::Write("savegames: path pattern not found; using the game default");
            }
        }
        else
        {
            log::Write("savegames: anchor pattern not found; using the game default");
        }

        patch::NopFirst("75 ? 83 C1 01 83 C0 01 83 F9 04", 0, 2, "savegames: crc32 bypass");
        patch::JumpFirst("55 8B EC 83 E4 F8 83 EC 4C 56", 0,
                         reinterpret_cast<const void*>(&GetSavefilePath),
                         "savegames: path redirect");
    }
} // namespace xla::savegames
