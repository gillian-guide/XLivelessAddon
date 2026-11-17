# XLivelessAddon

[![Build](https://github.com/gillian-guide/XLivelessAddon/actions/workflows/build.yml/badge.svg)](https://github.com/gillian-guide/XLivelessAddon/actions/workflows/build.yml)

XLivelessAddon is an open-source successor to the XLivelessAddon, rewritten in the shape of
[GTAIV.EFLC.FusionFix](https://github.com/ThirteenAG/GTAIV.EFLC.FusionFix). It modernises the
loader, hooking and configuration layers around the same recovered signature data.

Its scope is the original add-on's whole option surface — the loader/launcher family, the
save/registry/userdata paths, the frontend skips, the GFWL checks, the VRAM fix, the windowed
options and the startup warnings — rebuilt in FusionFix's shape and reusing ZolikaPatch/FusionFix
code where that is the reference (the intro/menu pair is FusionFix's own mechanism).

It is meant to be used with [OpenPreCEPatch](https://github.com/gillian-guide/IV.EFLC.OpenPreCEPatch) as a companion, because some features belong there; it also works on its own.

## Features

The source modules are grouped by the INI families in `data/XLivelessAddon.ini`.

- `SkipLauncher`/`LegacyLauncher` — skip the launcher/DRM checks with the recovered DFA and
  ROM stages, and run the legacy DFA file-API + WM_ROM stage when the launcher skip is off.
- `LaunchWithPlayGTAIV` — rewrite the game's `LaunchGTAIV.exe` name slots to `PlayGTAIV.exe`
  while a live `PlayGTAIV.exe` is present, so a game started through the launcher passes the
  DRM's launcher check. The companion owns this key itself, so it starts a
  `PlayGTAIV.exe`-launched game without OpenPreCEPatch.
- `SavegameFix` — bypass the save-file CRC32 check and harden the save-path close, copy, mutex
  and "no savegame" call sites with the recovered helpers.
- `[USERPROFILE] CustomUserProfilePath` — ported from FusionFix with some improvements for
  1.0.8.0.
- `RemoveDataIntegrityChecks`, `SkipTokenActivation`, `SkipFirstTimePlayAsk` — skip the recovered
  "core" checks: the data-integrity (VDS) branches, the DLC token activation and the
  first-time-play ask.
- `SkipWebConnect` — skip the GFWL web-connect and health checks. The old add-on's single key
  covers both recovered sections; `SkipInternetConnectionCheck` and `SkipHealthCheck` refine it
  (each can keep one of the two in place).
- `SkipIntro`/`SkipMenu` — shorten the intro screens (the ones under 8000 ms) and skip the main
  menu, with SHIFT held on startup to reach it. FusionFix's mechanism, ported from its
  `skipintro.ixx`; FusionFix's own copy owns these keys when its ASI is installed.
- `VRAMFix` — fix the VRAM detection so the graphics settings are not locked out, in the two
  generations the game has: the old add-on's recovered call-site clamp on the builds whose
  queries it can retarget, and FusionFix's `GetAvailableVideoMemory` replacement (DXGI budget,
  d3d9 texture memory and its 2 GB floor) on 1.0.8.0/EFLC 1.1.3.0. The log names the path that
  ran.
- `RemoveRegistryPathDependency` — remove the Rockstar Games registry path dependency.
- `BorderlessWindowed`/`DoNotPauseOnMinimize` — add borderless windowed mode and keep
  rendering while the borderless window is unfocused.

With a FusionFix ASI installed, `SkipIntro`, `SkipMenu`, `BorderlessWindowed` and
`DoNotPauseOnMinimize` are switched off (FusionFix owns those subsystems) and the log records
which key was gated.

## Installation

1. Install [Ultimate ASI Loader](https://github.com/ThirteenAG/Ultimate-ASI-Loader/releases/latest)
   6.9.0 or newer.
2. Extract the archive anywhere the ASI loader loads from: the game folder, `plugins\`,
   `scripts\` or `update\`.
3. Start the game and edit `XLivelessAddon.ini`; `XLivelessAddon.log` records what was applied.

## Building

Requirements: Windows 10/11, Visual Studio 18 2026 (or newer) with the **x86** C++ toolchain,
and CMake 3.28+. The three vendor libraries are committed under `external/`; there are no
submodules to initialise.

```bat
cmake --preset win-x86
cmake --build --preset release
ctest --preset release

cmake --build --preset trace
ctest --preset trace
```

The output is `build/win-x86/Release/XLivelessAddon.asi` (or `Trace\XLivelessAddon.asi`) and its
INI. `ctest` runs the native suite (456 checks), the ASI image load, the PE checks, the
no-install guard, the module-layout guard and the recovered SkipLauncher table parity check.

`win-x86` names the **Visual Studio 18 2026** generator and builds Win32; the ASI is 32-bit
only.

## Credits

- **GTAmodding / XLivelessAddon contributors** — the original add-on: the launcher bypass,
  the save-file path redirect, the WM_ROM message window, the borderless window patches, the
  intro/menu skips, the VRAM-detection fix and the GFWL web-connect skip. Released into the
  public domain.
- **Zolika1351** — ZolikaPatch, whose recovered SkipLauncher tables, DFA file-API behaviour
  and legacy launcher stage this module reimplements.
- **ThirteenAG and the FusionFix contributors** — GTAIV.EFLC.FusionFix, which supplied the
  windowed/focus-loss implementation, the `SkipIntro`/`SkipMenu` mechanism (its
  `skipintro.ixx`), the SHGetFolderPath user-data redirect, the task-dialog shape and the
  overall module conventions.

Licensed under the GNU General Public License, version 3 or later; see `LICENSE` and `NOTICE`.
