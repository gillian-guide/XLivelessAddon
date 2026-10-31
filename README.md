# XLivelessAddon

A maintained, modernised fork of [XLivelessAddon](https://github.com/GTAmodding/XLivelessAddon)
for **GTA IV** and **Episodes from Liberty City** (1.0.0.0 – 1.0.8.0, 1.1.0.0 – 1.1.3.0).

It is a **companion** to [OpenPreCEPatch](https://github.com/OpenZDecomp/OpenPreCEPatch): install
it next to that ASI, or on its own. It is its own repository and build; OpenPreCEPatch neither
builds nor requires it.

## Features

| INI key | What it does |
| --- | --- |
| `SkipLauncher` | Bypasses the launcher/SecuROM checks (the recovered DFA and ROM stages) so the game starts without `PlayGTAIV.exe`. |
| `RemoveRegistryPathDependency` | Removes the `Rockstar Games` registry path dependency; the install folder is answered from the game's own directory. |
| `SkipWebConnect` | Skips the GFWL web-connect and health checks. |
| `SkipIntro` | Shortens the intro/load screens to 300 ms. |
| `SkipMenu` | Skips the main menu. Hold **SHIFT** while starting to keep it. |
| `CustomSavePath` | Redirects savegames to a folder of your choice. |
| `LocalSettingsPath` | Moves saves and settings to `<game>\saves`. |
| `DoNotPauseOnMinimize` | Keeps rendering while the borderless window is unfocused. |
| `BorderlessWindowed` | Borderless window, centred on the monitor, style kept in sync on resize. |
| `VRAMFix` | Fixes the VRAM detection so the settings are not locked out. |

Everything is logged: `XLivelessAddon.log` next to the game executable records the detected
build and every patch that applied or was skipped, so a bug report can say exactly which binary
ran and what it did.

## Install

1. Copy `XLivelessAddon.asi` and `XLivelessAddon.ini` into the game folder (next to `GTAIV.exe`
   or `EFLC.exe`).
2. Start the game through `PlayGTAIV.exe` (or directly when `SkipLauncher` is off).
3. Edit `XLivelessAddon.ini` to taste; the file is created with defaults when missing.

No other files are needed. `XLivelessAddon.log` and the optional `saves/` folder are created at
runtime.

## Compatibility

* **OpenPreCEPatch** – designed to run alongside it; the two modules do not overlap.
* **GTAIV.EFLC.FusionFix** – when a `*FusionFix*.asi` is present, the options whose subsystem
  FusionFix owns (`SkipIntro`, `SkipMenu`, `BorderlessWindowed`, `DoNotPauseOnMinimize`,
  `VRAMFix`, `LocalSettingsPath`, `CustomSavePath`, `CustomSettingsPath`) are switched off and
  the log says why. Never run two modules that patch the same code.
* **Other ASIs** – install-time patches are INI-gated and each install is logged; the
  `CreateFile` hook forwards through the game's IAT slot, so a detour another ASI installed
  there keeps working.

See [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md) for the details.

## Build

Requirements: Windows, Visual Studio 2022 or newer with the **Win32/x86** C++ tools, CMake 3.28+,
and Git (for the submodules).

```bat
git clone --recursive https://github.com/OpenZDecomp/XLivelessAddon.git
cd XLivelessAddon
cmake --preset win-x86
cmake --build --preset release
ctest --preset release
```

Outputs:

* `build/win-x86/bin/XLivelessAddon.asi`
* `build/win-x86/bin/XLivelessAddon.ini`
* `build/win-x86/bin/XLivelessAddon.map` (linker map, for debugging)

To copy the result into a game folder after every build:

```bat
cmake --preset win-x86 -DXLA_GAME_DIR="D:/Games/GTA IV"
cmake --build --preset release
```

or use the `win-x86-deploy` preset with `GTAIV_DIR` set in the environment.

To build the release zip (`XLivelessAddon-<version>.zip` with the ASI, INI, README and licences):

```bat
cmake --build --preset package
```

Already have Visual Studio 2022 instead of 2026? Use `--preset win-x86-vs2022` and
`--preset release-vs2022`.

### Submodules

The build needs the three pinned libraries under `external/`:

| Path | Project |
| --- | --- |
| `external/injector` | [ThirteenAG/injector](https://github.com/ThirteenAG/injector) (with its nested `safetyhook`, `bddisasm`, `kananlib`, `minhook` submodules) |
| `external/hooking` | [ThirteenAG/Hooking.Patterns](https://github.com/ThirteenAG/Hooking.Patterns) |
| `external/IniReader` | [ThirteenAG/IniReader](https://github.com/ThirteenAG/IniReader) (with its vendored `mINI`) |

Always initialise recursively: `git submodule update --init --recursive`. The nested
`injector` submodules are needed for the checkout to be complete even though this build only
uses injector's header-only patching helpers. See [docs/DEPENDENCIES.md](docs/DEPENDENCIES.md).

## Layout

```
source/            C++23 module interface units (.ixx) and common.hxx
  common.ixx       image view, error type, logger, module paths
  build.ixx        build recognition
  config.ixx       INI defaults/loading and FusionFix gates
  ini_file.cpp     plain-TU INI wrapper over IniReader/mINI
  patch.ixx        find/store helpers over Hooking.Patterns + injector
  skip_launcher.ixx  recovered launcher tables + hook bodies
  dfa.ixx          legacy DFA file-API hooks
  rom_window.ixx   legacy WM_ROM message window
  savegames.ixx    custom save path + CRC32 bypass
  registry.ixx     registry path dependency removal
  userdata.ixx     LocalSettingsPath shell-folder redirect
  windowed.ixx     borderless window, focus loss, DefWindowProc shims
  patches.ixx      the recovered signature table (GFWL/RGSC/DLC/intro/VRAM)
  addon.ixx        the init pipeline
  dllmain.cpp      DLL entry point
data/              the shipped XLivelessAddon.ini
tests/             native test suite (runs without the game)
tools/             helper scripts (PE verification)
external/          pinned git submodules
cmake/             version header template
res/               PE version resource template
docs/              build, INI, compatibility, architecture and testing notes
```

The module layout follows GTAIV.EFLC.FusionFix: every feature is a `.ixx` module, `common.hxx`
holds the includes, and only `dllmain.cpp`/`ini_file.cpp` are plain translation units.

## Status

* The code builds with MSVC 19.4x/19.5x in C++23 mode, Win32 only (the game is 32-bit).
* The native tests cover the INI loader, the build table, the patch primitives and the recovered
  SkipLauncher tables/bodies; they need no game files.
* `CustomSettingsPath` is read and logged but **not hooked** in this build (the original's
  inline hook was not ported). Use `LocalSettingsPath`, `CustomSavePath`, or FusionFix's
  `userdata.ixx` instead.

## Licence

GPL-3.0-or-later. See `LICENSE`, `NOTICE` and `CREDITS.md` for the attribution of the code this
fork descends from.
