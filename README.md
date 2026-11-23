# XLivelessAddon

[![Build](https://github.com/gillian-guide/XLivelessAddon/actions/workflows/build.yml/badge.svg)](https://github.com/gillian-guide/XLivelessAddon/actions/workflows/build.yml)

XLivelessAddon is an open-source successor to the XLivelessAddon, rewritten in the shape of
[GTAIV.EFLC.FusionFix](https://github.com/ThirteenAG/GTAIV.EFLC.FusionFix). It modernises the
loader, hooking and configuration layers around the same recovered signature data.

Its scope is the original add-on's whole option surface — the loader/launcher family, the
save/registry/userdata paths, the frontend skips, the GFWL checks, the VRAM fix, the windowed
options and the startup warnings — rebuilt in FusionFix's shape and reusing ZolikaPatch/FusionFix
code where that is the reference, plus a few extra features from ZolikaPatch with improvements.

It is meant to be used with [OpenPreCEPatch](https://github.com/gillian-guide/IV.EFLC.OpenPreCEPatch) as a companion, because some features belong there; this mod also works on its own.

## Features

The source modules are grouped by the INI families in `data/XLivelessAddon.ini`.

- DRM and launcher check bypasses: the full ZolikaPatch `SkipLauncher` pass (main table, DFA
  file-API hooks and the ROM message window), including the two multi-hit collectors that keep
  the `SECUROM_SPOT_CHECK1/2/3/4` script natives answering true (mission scripts such as
  `vlad3.sco`, Clean Getaway, gate on `SECUROM_SPOT_CHECK3`), and the `LaunchWithPlayGTAIV`
  launcher-name rewrite that gets a `PlayGTAIV.exe`-started 1.0.8.0 past the startup check.
  EFLC ships the main and ROM stages only; its DFA handler refuses those product versions and
  the DFA path faults there (0x00426440), so the build's stage set is `main|rom`.
- Bypass the save-file CRC32 check.
- `CustomUserProfilePath` ported from FusionFix with some improvements for 1.0.8.0.
- Unnecessary GFWL and Social Club checks removal 
- Skip Intro and Skip Menu
- Fix the VRAM detection so the graphics settings are not locked out
- Borderless Windowed
- Allow `script.img` and `radiohud` from newer versions to work on an older executable
- Allow newer savefiles to load without downgrading them first, by converting the file when the game loads it (`1.0.6.0`-`1.0.8.0` only).
- Fix the crash after the benchmark ends (every build except `1.0.8.0` and `1.1.3.0`).
- Fix the freeze after Concrete Jungle with the 3 EFLC exclusive radio stations installed.
- Load TBoGT and TLAD from the EFLC or CE folders, plus addon episodes named `Episode3`, `Episode4`, etc. (`1.0.6.0`-`1.0.8.0` only).
- Mirror the achievements to Steam

With a FusionFix ASI installed, `SkipIntro`, `SkipMenu`, `BorderlessWindowed` and `DoNotPauseOnMinimize` are switched off.

## Installation

1. Install [Ultimate ASI Loader](https://github.com/ThirteenAG/Ultimate-ASI-Loader/releases/latest).
2. Extract the archive anywhere the ASI loader loads from: the game folder, `plugins\`,
   `scripts\` or `update\`.
3. Start the game and edit `XLivelessAddon.ini`; `XLivelessAddon.log` records what was applied.

## Building

Requirements: Windows 10/11, Visual Studio 18 2026 (or newer) with the **x86** C++ toolchain,
and CMake 3.28+. The dependencies are pinned upstream submodules under `external/`, so a fresh clone starts with:

```bat
git submodule update --init --recursive
```

```bat
cmake --preset win-x86
cmake --build --preset release
ctest --preset release

cmake --build --preset trace
ctest --preset trace
```

The output is `build/win-x86/Release/XLivelessAddon.asi` (or `Trace\XLivelessAddon.asi`) and its
INI. `ctest` runs tests.

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
- **OpenPreCEPatch** — the recovered `[COMPATIBILITY]` arms moved here from that project:
  the NewFiles/NewSaves bodies, anchors and save-file converter, the GFWL protection site and
  the Steam achievement table/bridge; also the `LoadDLCs` discovery pass and the two
  recovered crash fixes (`BenchmarkFix`, `CombinedRadioFreezeFix`).

Licensed under the GNU General Public License, version 3 or later; see `LICENSE` and `NOTICE`.
