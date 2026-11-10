# XLivelessAddon — FusionFix-style reimplementation

A clean reimplementation of the XLivelessAddon companion for **GTA IV / EFLC**,
built in the shape of [GTAIV.EFLC.FusionFix](https://github.com/ThirteenAG/GTAIV.EFLC.FusionFix).
It is a companion to [OpenPreCEPatch](https://github.com/OpenZDecomp/OpenPreCEPatch):
the two ASIs load side by side and nothing links them.

The repository is `xlivelessaddon-fusion/`; the shipped artifact keeps the name
users know, `XLivelessAddon.asi`.

## Features

- Read `XLivelessAddon.ini` next to the ASI, with the legacy `ZolikaPatch.ini`
  fallback (the ASI folder, then `<game>\plugins`, `scripts`, `update`).
- Detect the ASI loader and warn when it is older than Ultimate ASI Loader 6.9.0.
- Exit with an explanation on an unsupported game build and when the ASI was
  loaded twice.
- Reconstruct the game's savegame folder, or redirect it with `CustomSavePath`,
  and apply the save-file CRC32 bypass (the original's unconditional core fix).
- Remove the Rockstar Games registry path dependency
  (`RemoveRegistryPathDependency`).
- Move the shell user-data folders into `<game>\saves` (`LocalSettingsPath`).
- Redirect the settings folder (`CustomSettingsPath`).
- Skip the launcher/DRM checks (`SkipLauncher`): the recovered DFA/ROM stages, or
  the legacy DFA file-API + WM_ROM message window when `SkipLauncher=0`.
- Borderless window and keep rendering while unfocused
  (`BorderlessWindowed`, `DoNotPauseOnMinimize`).
- Startup warnings as FusionFix-style task dialogs, with a message-box fallback.

## Install

1. Install [Ultimate ASI Loader](https://github.com/ThirteenAG/Ultimate-ASI-Loader/releases/latest)
   6.9.0 or newer.
2. Put `XLivelessAddon.asi` and `XLivelessAddon.ini` in the game folder, `plugins\`,
   `scripts\` or `update\`.
3. Start the game and edit the INI. `XLivelessAddon.log` next to the ASI records
   every applied or skipped install, with the first line naming the build.

The ASI links the C runtime statically, so no Visual C++ redistributable is
needed. It is a 32-bit PE with image base `0x10000000`, like FusionFix.

## The deliberate divergence from the old addon

`LocalSettingsPath`, `CustomSavePath`, `CustomSettingsPath` and anything else that
redirects into the game folder work on their own detection — the game build and
their own INI key — and are **never switched off just because FusionFix is
installed**. The old addon gated them on a FusionFix check, and that misbehaves
with FusionFix on 1.0.8.0 (the two redirects fight over the same shell/import
slots). The windowed options are still gated, because FusionFix owns that
subsystem. `docs/parity.md` has the full statement and the tests.

## Build

Requirements: Windows 10/11, Visual Studio 18 2026 with the **x86** C++ toolset,
CMake 3.28+.

```bat
cmake --preset win-x86
cmake --build --preset release
ctest --preset release

cmake --build --preset trace
ctest --preset trace
```

The artifact is `build/win-x86/Release/XLivelessAddon.asi` (or `Trace\`). `ctest`
runs the native suite, loads the built ASI as an image, checks the PE headers,
fails if any module other than `source/patch.ixx` installs anything, and checks
the module layout.

## Supported game builds

The add-on recognises the original addon's compact build ids (the classification
dword at RVA `0x208C34`): 1.0.0.0, 1.0.1.0, 1.0.2.0, 1.0.3.0, 1.0.4.0, 1.0.0.4,
1.0.6.0, 1.0.7.0, 1.0.8.0, 1.1.0.0, 1.1.1.0, 1.1.2.0, 1.1.3.0. Any other build
is logged and exits with the unsupported-version dialog; nothing is installed.

## Layout

```
external/        pinned, committed vendor libraries (injector, Hooking.Patterns, IniReader)
source/common.ixx    Event tiers, Log, Game context, Image, opcode catalogue
source/patch.ixx     the only installer: scans, stores, branches, IAT, image unprotect
source/config.ixx    INI defaults/load/legacy fallback/FusionFix gates
source/build.ixx     classification table and detect
source/warnings.ixx  loader probe, single-instance, dialogs, FusionFix notice
source/probe.ixx     game probe and its one retry
source/savegames.ixx source/registry.ixx source/userdata.ixx source/settings_path.ixx
source/skip_launcher.ixx  SkipLauncher=1 recovered DFA/ROM tables and bodies
source/dfa.ixx source/rom_window.ixx  SkipLauncher=0 legacy stage
source/windowed.ixx  borderless/focus-loss hooks
source/startup.ixx   registration order and the synchronous pass
source/dllmain.cpp   the only plain TU and the entry point
docs/parity.md       feature-by-feature provenance, divergence and verification
```

## Credits and licence

GPL-3.0-or-later. The add-on is a derivative work of XLivelessAddon, ZolikaPatch,
GTAIV.EFLC.FusionFix, injector, Hooking.Patterns and IniReader; see `NOTICE` and
`CREDITS.md`. No game assets are shipped.
