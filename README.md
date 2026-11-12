# XLivelessAddon

`xlivelessaddon-fusion` is an open-source reimplementation of XLivelessAddon for
GTA IV / Episodes from Liberty City, written in the shape of
[GTAIV.EFLC.FusionFix](https://github.com/ThirteenAG/GTAIV.EFLC.FusionFix). It
keeps the artifact name users know, `XLivelessAddon.asi`, and modernises the
loader, hooking and configuration layers around the same recovered signature
data.

It is meant to be used with [OpenPreCEPatch](https://github.com/OpenZDecomp/OpenPreCEPatch)
as a companion; it also works on its own.

## Features

- Skip the launcher/DRM checks (`SkipLauncher`; `LegacyLauncher` selects the
  legacy DFA + WM_ROM stage when `SkipLauncher=0`).
- Put the game's user data — saves, settings, user music, videos and benchmarks —
  under one folder (`[USERPROFILE] CustomUserProfilePath`, default
  `./Savefiles`), and apply the save-file CRC32 bypass (`SavegameFix`).
- Remove the Rockstar Games registry path dependency
  (`RemoveRegistryPathDependency`).
- Add borderless windowed mode and keep rendering while the borderless window is
  unfocused (`BorderlessWindowed`, `DoNotPauseOnMinimize`).
- Every install has its own INI toggle. With every feature at `0` and the path
  empty the add-on makes no game changes at all — see
  [Switching everything off](#switching-everything-off).
- Startup warnings as FusionFix-style task dialogs (`StartupWarnings` gates the
  non-fatal ones).

`CustomUserProfilePath` replaces the old add-on's `LocalSettingsPath`,
`CustomSavePath` and `CustomSettingsPath`; it is the same one redirect for all of
them. The key is FusionFix's (same section and name); see
[docs/parity.md](docs/parity.md) for why FusionFix's own copy of it does not take
effect on 1.0.8.0 and why this one does.

The port covers the feature set requested for this tree. The old addon's
`SkipIntro`, `SkipMenu`, `VRAMFix`, `SkipWebConnect` and its unconditional
RGSC/integrity/DLC list are not ported; [docs/parity.md](docs/parity.md) names
them with their old sources.

## Startup warnings

The add-on shows FusionFix-style task dialogs (comctl32 6.0 activated from its own
embedded manifest; a plain message box if that cannot be activated), always on a
worker thread because it initializes from `DllMain`:

- **Old ASI Loader detected!** — the loader is not Ultimate ASI Loader 6.9.0 or
  newer (the first release that exports `IsUltimateASILoader`, the marker
  FusionFix's own compatibility check trusts). The dialog has a button for the
  download page.
- **Unsupported game version.** — the executable's classification dword is not
  one of the supported builds; the game exits when the dialog is closed.
- **XLivelessAddon was loaded twice!** — a second copy of the ASI initialized in
  the same process (for example two loader files each with their own copy); the
  game exits.
- **FusionFix is installed.** — `XLivelessAddon.fusionfix-notice.txt` lists the
  options that were switched off because FusionFix owns them. The file is
  rewritten on every launch and the dialog is shown only while it does not
  exist; delete it to show the dialog again.

`StartupWarnings=0` suppresses the first and last warnings. The unsupported
version and loaded-twice dialogs are safety checks, not features, and always run.

## Installation

1. Install [Ultimate ASI Loader](https://github.com/ThirteenAG/Ultimate-ASI-Loader/releases/latest)
   6.9.0 or newer.
2. Extract the archive anywhere the ASI loader loads from: the game folder, `plugins\`,
   `scripts\` or `update\`.
3. Start the game and edit `XLivelessAddon.ini`; `XLivelessAddon.log` records what was applied.

The add-on resolves its own directory, so `XLivelessAddon.ini`, `XLivelessAddon.log` and the
FusionFix notice are always next to the ASI. Options documented as relative to the game folder
(`CustomUserProfilePath`, the registry install-folder answer) use the executable's folder
instead. A legacy `ZolikaPatch.ini` is read from the ASI's folder or from the loader folders
under the game folder (`plugins`, `scripts`, `update`).

The ASI links the C runtime statically, so no Visual C++ redistributable is needed.

## Switching everything off

Set every boolean to `0` and leave `[USERPROFILE] CustomUserProfilePath` empty:

- no save-file CRC32 bypass (`SavegameFix=0`),
- no launcher work (`SkipLauncher=0` and `LegacyLauncher=0`),
- no registry or user-data redirect,
- no borderless/focus-loss hooks,
- no non-fatal startup dialogs or FusionFix notice.

The image's page protections are left untouched too: the driver skips the
unprotect when no install is enabled. The ASI still writes its log and checks the
build; the fatal safety checks remain.

## Building

Requirements: Windows 10/11, Visual Studio 18 2026 (or newer) with the **x86** C++
toolchain, and CMake 3.28+. The three vendor libraries are committed under
`external/`; there are no submodules to initialise.

```bat
cmake --preset win-x86
cmake --build --preset release
ctest --preset release

cmake --build --preset trace
ctest --preset trace
```

The output is `build/win-x86/Release/XLivelessAddon.asi` (or `Trace\`) and its
INI. `ctest` runs the native suite, the ASI image load, the PE checks, the
no-install guard, the module-layout guard and the recovered SkipLauncher table
parity check.

## Credits

- **GTAmodding / XLivelessAddon contributors** — the original add-on: the launcher bypass,
  the save-file path redirect, the WM_ROM message window and the borderless window patches.
  Released into the public domain.
- **Zolika1351** — ZolikaPatch, whose recovered SkipLauncher tables and DFA file-API
  behaviour this module reimplements. ZolikaPatch shipped as a compiled ASI; no original
  source is redistributed.
- **ThirteenAG and the FusionFix contributors** — GTAIV.EFLC.FusionFix, which supplied the
  windowed/focus-loss implementation, the SHGetFolderPath user-data redirect, the task-dialog
  shape and the overall module conventions.
- **LINK/2012 and ThirteenAG** — the `injector` memory-patching library.
- **CitizenFX / NTAuthority** — `Hooking.Patterns`.
- **ThirteenAG** — `IniReader` and `mINI`.

Licensed under the GNU General Public License, version 3 or later; see `LICENSE` and `NOTICE`.
