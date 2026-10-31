# Changelog

All notable changes to XLivelessAddon. Versions follow the repository tags.

## 1.1.0 — 2026-10-31

### Added

- Standalone repository: own CMake build, presets, packaging, CI and docs; the module no longer
  reads anything from the OpenPreCEPatch tree. The three dependencies are pinned submodules
  under `external/` (injector with its nested submodules, Hooking.Patterns, IniReader).
- Native test suite (`ctest`): INI precedence/defaults and FusionFix gating, build recognition,
  patch primitives, savegame path building, registry helpers, user-data redirection, windowed
  guards, the recovered SkipLauncher table shape/bounds and the CreateFile slot forwarding.
- A PE verification test that asserts the built artifact is a 32-bit Windows DLL based at
  `0x10000000` with the GUI subsystem and a `USER32` import.
- A `package` target that produces `XLivelessAddon-<version>.zip` with the ASI, INI, README and
  licence files at the archive root.
- `XLivelessAddon.ini` is created from the embedded defaults when missing, so a fresh install
  never runs with an empty config.
- The log now starts with the add-on version and git SHA, and every patch logs whether it applied
  or was skipped (signature missing / image not writable).

### Changed

- The code is C++23 and organised as module interface units (`common.ixx`, `build.ixx`,
  `config.ixx`, `patch.ixx`, `skip_launcher.ixx`, `dfa.ixx`, `rom_window.ixx`, `savegames.ixx`,
  `registry.ixx`, `userdata.ixx`, `windowed.ixx`, `patches.ixx`, `addon.ixx`), following the
  GTAIV.EFLC.FusionFix layout. `dllmain.cpp` and `ini_file.cpp` are the only plain TUs.
- The patcher uses `Hooking.Patterns` for every scan and `injector` for every store, with one
  helper per action (`WriteByte/Word/Dword`, `Nop`, `Ret`, `Jump`, `Call`).
- The recovered signature strings, offsets and stored bytes are unchanged; a parity check
  compares the old monolithic table with the new modules (all 66 scans present, same order) and
  the SkipLauncher tables are structurally identical.

### Fixed

- `SkipIntro`'s body sets the 300 ms value it documents (it previously had a comment saying
  "zeroed" while setting `0x12C`).
- `getSavefilePath` no longer copies a whole 256-byte buffer with uninitialised tail bytes; the
  path is NUL-terminated and truncated safely.
- The registry `InstallFolder` answer never writes past the caller's buffer.
- An LF-only `XLivelessAddon.ini`/`ZolikaPatch.ini` is normalised to CRLF before parsing; mINI
  would otherwise read such a file as a single line and silently ignore every option but the
  first.
- INI paths are resolved to absolute paths before `CIniReader` sees them (it re-bases relative
  paths on the module directory).
- An unwritable or unrecognised game image aborts the install with a log line instead of
  terminating the process, and an unsupported build installs nothing.
- `SkipMenu` and the VRAM/borderless hook bodies tolerate a missing original pointer instead of
  calling through null.

## 1.0.0 — 2026-10-26

- First standalone successor: recovered SkipLauncher (DFA/ROM) tables, GFWL/RGSC patches,
  save/settings redirects, borderless window, focus-loss input, VRAM fix, FusionFix gates and an
  INI-driven loader. Split out of the OpenPreCEPatch tree.
