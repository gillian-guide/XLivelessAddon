# XLivelessAddon

[![Build](https://github.com/gillian-guide/XLivelessAddon/actions/workflows/build.yml/badge.svg)](https://github.com/gillian-guide/XLivelessAddon/actions/workflows/build.yml)

XLivelessAddon is an open-source successor to the XLivelessAddon, rewritten in the shape of
[GTAIV.EFLC.FusionFix](https://github.com/ThirteenAG/GTAIV.EFLC.FusionFix). It modernises the
loader, hooking and configuration layers around the same recovered signature data.

Its scope is the original add-on's whole option surface — the loader/launcher family, the
save/registry/userdata paths, the frontend skips, the GFWL checks, the VRAM fix, the windowed
options and the startup warnings — rebuilt in FusionFix's shape and reusing ZolikaPatch/FusionFix
code where that is the reference (the intro/menu pair is FusionFix's own mechanism), plus the
pieces that belong to the companion: `LaunchWithPlayGTAIV` and the recovered `[COMPATIBILITY]`
set (`NewFilesCompatibility`, `NewSavesCompatibility`, `GFWLProtectionDisabler`,
`SteamAchievements`), which moved here from OpenPreCEPatch.

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
  queries it can retarget, and FusionFix's `GetAvailableVideoMemory` replacement (copied from
  its `memory.ixx`: the d3d9-matched DXGI budget, the d3d9 texture memory and the 2 GB floor,
  installed with safetyhook, with the device/COM calls guarded and every stage logged) on
  1.0.8.0/EFLC 1.1.3.0. The log names the path that ran and, if the copied code cannot
  finish, the stage it died in.
- `RemoveRegistryPathDependency` — remove the Rockstar Games registry path dependency.
- `BorderlessWindowed`/`DoNotPauseOnMinimize` — add borderless windowed mode and keep
  rendering while the borderless window is unfocused.
- `NewFilesCompatibility` — allow `script.img` and `radiohud` from newer versions to work on an
  older executable (the recovered registrar and the two file-type update calls). Skipped when
  `GTAC.dll` or `JacksIVFixes.asi` is loaded, because both install the same feature.
- `NewSavesCompatibility` — allow newer savefiles to load without downgrading them first, by
  converting the file when the game loads it (`1060`-`1080` only, the builds the newer layout
  belongs to).
- `GFWLProtectionDisabler` — flip the GFWL `xlive.dll` protection branch to a jump. The offset
  is guarded by the mapped image and the pre-image byte, so another xlive build (and Ultimate
  ASI Loader's `xlive.dll` proxy) is left untouched.
- `SteamAchievements` — mirror the GFWL achievements to Steam at the `xlive.dll` import
  boundary: the GFWL store still runs first, and `steam_api.dll` is loaded lazily on the first
  achievement write. Without `steam_api.dll` the game keeps its GFWL-only behaviour.

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
and CMake 3.28+. The dependencies are pinned upstream submodules under `external/` (the injector
tree with safetyhook, MinHook, bddisasm, kananlib and its in-tree Zydis amalgamation,
Hooking.Patterns and IniReader), so a fresh clone starts with:

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
INI. `ctest` runs the native suite (555 checks), the ASI image load, the PE checks, the
no-install guard, the module-layout guard and the recovered SkipLauncher table parity check.

The compatibility arms' asm tail is proved against the original ASI, not assumed: with the
oracle at hand,

```bat
python tools/verify_compat_bodies.py --original ..\game_refs\ZolikaPatch_original.asi.off ^
    --built build\win-x86\Release\XLivelessAddon.asi ^
    --map build\win-x86\Release\XLivelessAddon.map
```

decodes both sides and compares every transcribed body instruction by instruction (needs
`capstone`).

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
- **OpenPreCEPatch** — the recovered `[COMPATIBILITY]` arms moved here from that project:
  the NewFiles/NewSaves bodies, anchors and save-file converter, the GFWL protection site and
  the Steam achievement table/bridge.

Licensed under the GNU General Public License, version 3 or later; see `LICENSE` and `NOTICE`.
