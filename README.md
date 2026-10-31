# XLivelessAddon

[![Build](https://github.com/gillian-guide/XLivelessAddon/actions/workflows/build.yml/badge.svg)](https://github.com/gillian-guide/XLivelessAddon/actions/workflows/build.yml)

XLivelessAddon is an open-source successor to [XLivelessAddon](https://github.com/GTAmodding/XLivelessAddon),
the GTA IV / Episodes from Liberty City loader add-on. It keeps the original's launcher bypass,
save/settings handling and windowing fixes, rewrites them as readable, maintainable C++23, and
modernises the loader, hooking and configuration layers around the same recovered signature data.

It is meant to be used with [OpenPreCEPatch](https://github.com/gillian-guide/IV.EFLC.OpenPreCEPatch)
as a companion, as some features belong there; it also works on its own.

## Features

- Launcher/SecuROM bypass (`SkipLauncher`), including the recovered DFA and ROM stages.
- Save and settings redirection (`CustomSavePath`, `LocalSettingsPath`) and the save-file CRC32 bypass.
- Rockstar Games registry path dependency removal and GFWL web-connect/health-check skips.
- Intro shortening (`SkipIntro`) and main-menu skip (`SkipMenu`, hold SHIFT to keep it).
- Borderless window, focus-loss handling and the VRAM detection fix.
- Every option is INI-gated and logged, and is gated off when FusionFix owns the same subsystem.

## Installation

1. Install [Ultimate ASI Loader](https://github.com/ThirteenAG/Ultimate-ASI-Loader/releases/latest).
2. Extract the archive next to `GTAIV.exe` and `EFLC.exe`.
3. Start the game and edit `XLivelessAddon.ini`; `XLivelessAddon.log` records what applied.

## Supported game versions

| compact | version | status |
| ---: | --- | --- |
| 1000 | 1.0.0.0 | supported |
| 1040 | 1.0.4.0 | supported |
| 1060 | 1.0.6.0 | supported |
| 1070 | 1.0.7.0 | supported |
| 1080 | 1.0.8.0 | supported |
| 1100 | 1.1.0.0 (EFLC) | supported |
| 1110 | 1.1.1.0 (TLAD) | supported |
| 1120 | 1.1.2.0 (TBoGT) | supported |
| 1130 | 1.1.3.0 (EFLC) | supported |

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
`XLivelessAddon.zip` containing just those two files.

## Credits

- Original add-on by the **GTAmodding / XLivelessAddon** contributors.
- Original mod behaviour recovered from **ZolikaPatch** by Zolika1351.
- **GTAIV.EFLC.FusionFix** by ThirteenAG and contributors.
- `injector` by LINK/2012 and ThirteenAG
- `Hooking.Patterns` by CitizenFX and ThirteenAG
- `IniReader` by ThirteenAG.

Licensed under the GNU General Public License, version 3 or later; see `LICENSE` and `NOTICE`.
