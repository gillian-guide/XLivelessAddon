# XLivelessAddon

[![Build](https://github.com/gillian-guide/XLivelessAddon/actions/workflows/build.yml/badge.svg)](https://github.com/gillian-guide/XLivelessAddon/actions/workflows/build.yml)

XLivelessAddon is an open-source successor to the community XLivelessAddon, the GTA IV / Episodes
from Liberty City loader add-on. It keeps the original's launcher bypass, save/settings redirection
and windowing fixes, rewrites them as readable, maintainable C++23, and modernises the loader,
hooking and configuration layers around the same recovered signature data.

It is meant to be used with [OpenPreCEPatch](https://github.com/gillian-guide/IV.EFLC.OpenPreCEPatch)
as a companion, because some features belong there; it also works on its own. Every entry below is
an option in `XLivelessAddon.ini`, which records the default and whether FusionFix owns the
subsystem.

## Features

- Skip the launcher and its recovered DFA and ROM checks.
- Redirect savegames and settings, and bypass the savegame CRC32 check.
- Remove the Rockstar Games registry path dependency.
- Skip the GFWL web-connect and health checks.
- Shorten the intro screens to 300 ms and skip the main menu (hold SHIFT on startup to keep it).
- Add borderless windowed mode and keep rendering while the window is unfocused.
- Fix the VRAM detection so the settings are not locked out.
- Gate every optional install on its INI key, log it, and disable options that FusionFix owns.

`CustomSettingsPath` is implemented with a reconstructed 5-byte call body: the pinned injector's
`MakeInline` is SafetyHook-based and this build compiles no SafetyHook. The recovered path logic is
unit-tested, but the hook has not been validated in-game; an absolute path (one with a drive
letter) uses the documented intent rather than the original's undefined empty-string check. Prefer
`LocalSettingsPath` or FusionFix's `userdata.ixx` if the hook does not fit.

## Installation

1. Install [Ultimate ASI Loader](https://github.com/ThirteenAG/Ultimate-ASI-Loader/releases/latest).
2. Extract the archive next to `GTAIV.exe` and `EFLC.exe`.
3. Start the game and edit `XLivelessAddon.ini`; `XLivelessAddon.log` records what was applied.

The ASI links the C runtime statically, so no Visual C++ redistributable is needed.

## Supported game versions

The ids are the original add-on's classification ids (the values in `build.ixx`), not the game's
patch numbers; `1.0.0.4` is classified as `1050`, for example. 1.0.5.0 is not in the table, so no
patch applies there. The version names for `1020` and `1030` (and EFLC `1100`) follow the original
table's order; those three executables were not available to test against.

| id | version | status |
| ---: | --- | --- |
| 1000 | 1.0.0.0 | supported |
| 1010 | 1.0.1.0 | supported |
| 1020 | 1.0.2.0 | supported |
| 1030 | 1.0.3.0 | supported |
| 1040 | 1.0.4.0 | supported |
| 1050 | 1.0.0.4 | supported |
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
`XLivelessAddon.zip` containing just those two files; `--build --preset package` produces the
CPack zip, which also carries `README.md`, `LICENSE`, `NOTICE` and `CREDITS.md`.

`win-x86` names the **Visual Studio 18 2026** generator. On VS 2022 use
`cmake --preset win-x86-vs2022` with `cmake --build --preset release-vs2022` and
`ctest --preset release-vs2022`.

## Credits

- **GTAmodding / XLivelessAddon contributors** — the original add-on: the launcher bypass, the
  save-file path redirect, the WM_ROM message window and the borderless window patches.
- **Zolika1351** — ZolikaPatch, whose recovered SkipLauncher tables, GFWL bypasses and intro/menu
  behaviour this module reimplements.
- **ThirteenAG and the FusionFix contributors** — GTAIV.EFLC.FusionFix (GPL-3.0), which supplied
  the windowed/focus-loss implementation, the 300 ms intro-skip variant, the per-feature FusionFix
  compatibility gates and the overall module layout conventions.
- **LINK/2012 and ThirteenAG** — the `injector` memory-patching library.
- **cursey** — `safetyhook`, `kananlib`; **Bitdefender** — `bddisasm`; **Tsuda Kageyu** —
  `minhook` (nested `injector` submodules).
- **CitizenFX / NTAuthority** — `Hooking.Patterns`.
- **ThirteenAG** — `IniReader`.

Licensed under the GNU General Public License, version 3 or later; see `LICENSE` and `NOTICE`.
