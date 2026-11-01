# XLivelessAddon

[![Build](https://github.com/gillian-guide/XLivelessAddon/actions/workflows/build.yml/badge.svg)](https://github.com/gillian-guide/XLivelessAddon/actions/workflows/build.yml)

XLivelessAddon is an open-source successor to the XLivelessAddon. It modernises the loader,
hooking and configuration layers around the same recovered signature data.

It is meant to be used with [OpenPreCEPatch](https://github.com/gillian-guide/IV.EFLC.OpenPreCEPatch) as a companion, because some features belong there; it also works on its own.

## Features

- Skip the launcher/DRM checks.
- Set custom savegame and settings folders, or move both into a saves folder inside the game folder.
- Remove the Rockstar Games registry path dependency.
- Skip the GFWL web-connect and health checks.
- Shorten the intro screens to 300 ms and skip the main menu (hold SHIFT on startup to reach it).
- Add borderless windowed mode and keep rendering while the borderless window is unfocused.
- Fix the VRAM detection so the settings are not locked out.

## Installation

1. Install [Ultimate ASI Loader](https://github.com/ThirteenAG/Ultimate-ASI-Loader/releases/latest).
2. Extract the archive next to `GTAIV.exe` and `EFLC.exe`.
3. Start the game and edit `XLivelessAddon.ini`; `XLivelessAddon.log` records what was applied.

The ASI links the C runtime statically, so no Visual C++ redistributable is needed.

## Building

Requirements: Windows 10/11, Visual Studio 2022 17.10+ (or newer) with the **x86** C++ toolchain,
CMake 3.28+, and the submodules checked out.

```bat
git clone --recursive https://github.com/gillian-guide/XLivelessAddon
cd XLivelessAddon
cmake --preset win-x86
cmake --build --preset release
ctest --preset release
```

The output is `build/win-x86/bin/XLivelessAddon.asi` and its INI. CI publishes a single
`XLivelessAddon.zip` containing just those two files; `--build --preset package` produces the
CPack zip, which also carries `README.md`, `LICENSE`, `NOTICE` and `CREDITS.md`.

`win-x86` names the **Visual Studio 18 2026** generator. On VS 2022 use
`cmake --preset win-x86-vs2022` with `cmake --build --preset release-vs2022` and
`ctest --preset release-vs2022`.

## Credits

- **ThirteenAG** — the original add-on: the launcher bypass, the save-file path redirect, the WM_ROM message window and the borderless window patches.
- **Zolika1351** — ZolikaPatch, whose recovered SkipLauncher tables and GFWL bypasses this module reimplements.
- **ThirteenAG and the FusionFix contributors** — GTAIV.EFLC.FusionFix, which supplied
  the windowed/focus-loss implementation, the 300 ms intro-skip variant, the per-feature FusionFix
  compatibility gates and the overall module layout conventions.

Licensed under the GNU General Public License, version 3 or later; see `LICENSE` and `NOTICE`.
