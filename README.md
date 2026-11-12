# XLivelessAddon

[![Build](https://github.com/gillian-guide/XLivelessAddon/actions/workflows/build.yml/badge.svg)](https://github.com/gillian-guide/XLivelessAddon/actions/workflows/build.yml)

XLivelessAddon is an open-source successor to the XLivelessAddon, rewritten in the shape of
[GTAIV.EFLC.FusionFix](https://github.com/ThirteenAG/GTAIV.EFLC.FusionFix). It modernises the
loader, hooking and configuration layers around the same recovered signature data.

It is meant to be used with [OpenPreCEPatch](https://github.com/gillian-guide/IV.EFLC.OpenPreCEPatch) as a companion, because some features belong there; it also works on its own.

## Features

The source modules are grouped by the INI families in `data/XLivelessAddon.ini`.

- `SkipLauncher`/`LegacyLauncher` — skip the launcher/DRM checks with the recovered DFA and
  ROM stages, and run the legacy DFA file-API + WM_ROM stage when the launcher skip is off.
- `SavegameFix` — apply the save-file CRC32 bypass.
- `[USERPROFILE] CustomUserProfilePath` — ported from FusionFix with some improvements for
  1.0.8.0.
- `RemoveDataIntegrityChecks`, `SkipTokenActivation`, `SkipFirstTimePlayAsk`,
  `SkipInternetConnectionCheck`, `SkipHealthCheck` — skip the extra GFWL checks.
- `RemoveRegistryPathDependency` — remove the Rockstar Games registry path dependency.
- `BorderlessWindowed`/`DoNotPauseOnMinimize` — add borderless windowed mode and keep
  rendering while the borderless window is unfocused.

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
INI. `ctest` runs the native suite, the ASI image load, the PE checks, the no-install guard, the
module-layout guard and the recovered SkipLauncher table parity check.

`win-x86` names the **Visual Studio 18 2026** generator and builds Win32; the ASI is 32-bit
only.

## Credits

- **GTAmodding / XLivelessAddon contributors** — the original add-on: the launcher bypass,
  the save-file path redirect, the WM_ROM message window and the borderless window patches.
  Released into the public domain.
- **Zolika1351** — ZolikaPatch, whose recovered SkipLauncher tables, DFA file-API behaviour
  and legacy launcher stage this module reimplements.
- **ThirteenAG and the FusionFix contributors** — GTAIV.EFLC.FusionFix, which supplied the
  windowed/focus-loss implementation, the SHGetFolderPath user-data redirect, the task-dialog
  shape and the overall module conventions.

Licensed under the GNU General Public License, version 3 or later; see `LICENSE` and `NOTICE`.
