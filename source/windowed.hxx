// SPDX-License-Identifier: GPL-3.0-or-later

//

// Improved borderless-window and focus-loss handling, ported from

// GTAIV.EFLC.FusionFix's windowed.ixx (GPL-3.0, ThirteenAG and contributors).

//

// The original ZolikaPatch code only strips the window styles once from the

// DefWindowProc shims. The port additionally keeps the style in sync when the

// window is created/resized, centres it on the monitor and suppresses game

// input while a borderless window is unfocused. The original writes still run;

// the IAT hooks are additive and can be disabled with OPCEP_IMPROVEMENTS.



#pragma once



#include "xla_common.hxx"



namespace opp

{

    // Installs the CreateWindowEx/MoveWindow/AdjustWindowRect/SetWindowPos/

    // SetWindowLongA/SetRect import hooks. Returns true when at least the

    // creation hooks were installed.

    bool InstallBorderlessHooks(GameImage image) noexcept;



    // Hooks the game's per-frame input call and skips it while a borderless

    // window is unfocused. Returns false when the pattern/globals are missing.

    bool InstallFocusLossInputHook(GameImage image) noexcept;

} // namespace opp

