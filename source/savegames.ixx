// SPDX-License-Identifier: GPL-3.0-or-later
//
// xla.savegames - the custom savegame folder and the save-file CRC32 bypass,
// descended from XLivelessAddon's getSavefilePath replacement.
//
// Ported from openprecepatch/xlivelessaddon/source/savegames.ixx.
//
// The original replaced the game's path builder and copied 256 bytes into the
// caller's buffer. The transport is unchanged; the copy is bounded and
// NUL-terminated here, so an over-long custom path truncates instead of writing
// past the game's buffer.

module;

#include <common.hxx>

export module savegames;

import common;
import patch;

export namespace xla::savegames
{
    // The game hands the hook a 256-byte buffer (the original's assumption).
    inline constexpr std::size_t kGamePathCapacity = 256;

    std::string BaseSavePath(std::string_view gameDefaultPath, std::string_view customPath);
    std::string JoinSaveName(std::string_view basePath, std::string_view saveName);
    std::string ReadCString(const Image& image, const void* address, std::size_t limit);

    // Installs the CRC32 bypass and the path redirect. The caller gates it on the
    // SavegameFix INI key. Logs which signatures were found; a missing signature
    // is a logged skip, never a fault.
    void Install(const Image& image, std::string_view customSavePath);
} // namespace xla::savegames

namespace xla::savegames
{
    namespace
    {
        std::string g_gameDefaultSavePath;
        std::string g_customSavePath;

        // Copies into the game's fixed-size buffer: truncated and always
        // terminated, like the original's memmove+terminator but without its
        // overrun. Logs when the value did not fit.
        void CopyToGameBuffer(std::string_view text, char* buffer, std::string_view what)
        {
            const std::size_t length = (std::min)(text.size(), kGamePathCapacity - 1);
            std::copy_n(text.data(), length, buffer);
            buffer[length] = '\0';
            if (length < text.size())
            {
                Log::Print("savegames: {} truncated to {} characters", what, length);
            }
        }

        // ABI: __cdecl, (unused int, char* buffer, char* saveName), plain ret.
        // The game's path builder is tail-jumped here with its 256-byte caller
        // buffer; the copies below keep that buffer contract.
        void __cdecl GetSavefilePath(int /*unused*/, char* buffer, char* saveName)
        {
            if (buffer == nullptr)
            {
                return;
            }

            const std::string base = BaseSavePath(g_gameDefaultSavePath, g_customSavePath);
            const std::string_view name =
                saveName != nullptr ? std::string_view{saveName} : std::string_view{};

            const DWORD attributes = ::GetFileAttributesA(base.c_str());
            if (attributes == INVALID_FILE_ATTRIBUTES)
            {
                if (!::CreateDirectoryA(base.c_str(), nullptr))
                {
                    Log::Print("savegames: cannot create {} (error {})", base,
                               ::GetLastError());
                }
            }
            else if ((attributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
            {
                // A file sits where the folder belongs: keep the game's own name.
                if (!name.empty())
                {
                    CopyToGameBuffer(name, buffer, "save name");
                }
                return;
            }

            const std::string path = JoinSaveName(base, name);
            CopyToGameBuffer(path, buffer, "custom save path");
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
        constexpr std::size_t kPathAnchorMatch = 2;
        constexpr std::ptrdiff_t kRedirectOperand = 2;

        patch::Pattern anchor = patch::FindIn(
            image,
            "8A 10 83 C0 01 84 D2 75 F7 56 57 BF ? ? ? ? 2B C1 8B F1 83 C7 FF 8A 4F 01 83 C7 01",
            0);
        if (anchor.size() > kPathAnchorMatch)
        {
            const auto rangeEnd =
                reinterpret_cast<std::uintptr_t>(anchor.get(kPathAnchorMatch));
            const Image tail{reinterpret_cast<std::byte*>(rangeEnd - kPathScanBackBytes),
                             kPathScanBackBytes};
            patch::Pattern redirect = patch::FindIn(
                tail, "8A 88 ? ? ? ? 88 88 ? ? ? ? 83 C0 01", 1);
            if (!redirect.empty())
            {
                const auto* slot = redirect.get<const char*>(0, kRedirectOperand);
                if (slot != nullptr && image.contains(slot, sizeof(void*)))
                {
                    g_gameDefaultSavePath = ReadCString(image, *slot, kGamePathCapacity);
                }
                Log::Print("savegames: game default path = \"{}\"", g_gameDefaultSavePath);
            }
            else
            {
                Log::Line("savegames: path pattern not found; using the game default");
            }
        }
        else
        {
            Log::Line("savegames: anchor pattern not found; using the game default");
        }

        // The two install sites are scanned in the same caller-owned image, so the
        // pass is testable against a synthetic image and the live game view uses
        // exactly the same code.
        patch::Pattern crc = patch::FindIn(image, "75 ? 83 C1 01 83 C0 01 83 F9 04", 1);
        if (!crc.empty())
        {
            patch::Nop(patch::Site{crc.get_first<std::uint8_t>()}, 0, 2,
                       "savegames: crc32 bypass");
        }
        else
        {
            Log::Line("savegames: crc32 pattern missing; bypass skipped");
        }

        patch::Pattern redirectSite =
            patch::FindIn(image, "55 8B EC 83 E4 F8 83 EC 4C 56", 1);
        if (!redirectSite.empty())
        {
            patch::Jump(patch::Site{redirectSite.get_first<std::uint8_t>()}, 0,
                        reinterpret_cast<const void*>(&GetSavefilePath),
                        "savegames: path redirect");
        }
        else
        {
            Log::Line("savegames: path redirect pattern missing; skipped");
        }
    }
} // namespace xla::savegames
