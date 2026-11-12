// SPDX-License-Identifier: GPL-3.0-or-later
//
// xla.savegames - [Options] SavegameFix: the save-file CRC32 bypass.
//
// This is the savegame family: the CRC32 bypass. The save path itself is the
// user-data family ([USERPROFILE] CustomUserProfilePath, xla.profile): the
// shell's profile folders are redirected there, and the game's own savegame
// resolver (`sub_61E770`, 0x61E770) builds `<profile>\Rockstar Games\GTA IV\
// savegames\user_<xuid>\<name>` from it. The CRC32 branch is orthogonal to where
// the file lives, so it stays here.

module;

#include <common.hxx>

export module savegames;

import common;
import patch;

export namespace xla::savegames
{
    // Installs the CRC32 bypass. Logs whether the recovered signature was found;
    // a missing signature is a logged skip, never a fault.
    void Install(const Image& image);
} // namespace xla::savegames

namespace xla::savegames
{
    void Install(const Image& image)
    {
        patch::Pattern crc = patch::FindIn(image, "75 ? 83 C1 01 83 C0 01 83 F9 04", 1);
        if (crc.empty())
        {
            Log::Line("savegames: crc32 pattern missing; bypass skipped");
            return;
        }
        patch::Nop(patch::Site{crc.get_first<std::uint8_t>()}, 0, 2,
                   "savegames: crc32 bypass");
    }
} // namespace xla::savegames
