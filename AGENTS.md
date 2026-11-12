# AGENTS.md — XLivelessAddon (FusionFix-style reimplementation)

## What this is

A clean reimplementation of the XLivelessAddon companion for GTA IV / EFLC, in
the shape of GTAIV.EFLC.FusionFix. It is its **own repository**; it is loaded
next to OpenPreCEPatch and never links it.

The behavioural reference is `../openprecepatch/xlivelessaddon/`; the
shape/feature reference is `../GTAIV.EFLC.FusionFix/`; the build/layout template
is `../fusionfix-skeleton/`. Those three trees are read-only: copy from them and
cite, never edit them.

The invariants the tree is built around:

- **`source/patch.ixx` is the only unit allowed to install.** It owns signature
  scanning, the injector stores/branches, the IAT replacement and the image
  unprotect. A feature module calls `patch::...`; it never names `injector::`,
  `safetyhook::`, `Make*`, `WriteMemory`, `VirtualProtect` or `IATHook`.
  `tools/check_no_installs.py` (CTest `xla_no_installs`) enforces it.
- **`source/dllmain.cpp` is the only plain TU in `source/`** and owns startup.
  `source/startup.ixx` owns the registration order and the synchronous pass.
- **Startup is synchronous in `DllMain`.** The only deferred activity is the
  probe retry (the DRM may not have rewritten the image at attach time), which
  re-runs the same pass on one worker after the first pass has returned.
- **Every install is INI-gated, and all-off is inert.** `SavegameFix`,
  `SkipLauncher`, `LegacyLauncher`, `RemoveRegistryPathDependency`,
  `RemoveDataIntegrityChecks`, `SkipTokenActivation`, `SkipFirstTimePlayAsk`,
  `SkipInternetConnectionCheck`, `SkipHealthCheck`, `BorderlessWindowed`,
  `DoNotPauseOnMinimize` and a non-empty `[USERPROFILE] CustomUserProfilePath`
  cover the installs; `StartupWarnings` only
  gates the non-fatal dialogs/notice. With every install key `0` and the path
  empty, `startup::AnyInstallEnabled()` is false, no install runs and the image
  unprotect is skipped; `TestAllOff` pins it.
- **The user-data divergence is intentional.** `CustomUserProfilePath` is never
  switched off because FusionFix is present; only the windowed options are gated.
  Do not "restore" the old gate. It replaces the old addon's
  `LocalSettingsPath`, `CustomSavePath` and `CustomSettingsPath` with one redirect
  of the shell profile folders, and it installs from `DllMain` because the game
  caches its roots in `__initalizePaths` (`0x856BF0`) before FusionFix's async
  hook would run.
- **Recovered tables are data.** Signature strings, offsets, stored bytes, fill
  values and the stage order are 1:1 with the old addon. Renaming is free;
  changing a number or a scan is a behaviour change.

## Layout

- `source/*.ixx` — one C++23 module interface unit per feature family, plus the
  infrastructure units (`common`, `patch`, `build`, `config`, `probe`, `startup`)
  and the feature families `warnings`, `savegames`, `registry`, `profile`,
  `core`, `launcher`, `windowed`. They are listed in the `CXX_MODULES` file set.
  A module is one feature family, not one original handler: `launcher` owns both
  launcher stages, and `core` owns the five core fixes.
- `source/common.hxx` — the one include header; included in each module's
  `module;` global fragment. It is includes only.
- `source/dllmain.cpp` — the entry point and the only plain TU in `source/`.
- `source/patch.ixx` — the primitive scan/store/branch/IAT helpers; the only
  installer.
- `source/config.ixx` — the INI defaults, load, legacy fallback and the
  FusionFix windowed gates. `Load`/`Publish` are out of line: `IniReader` is
  all-inline and MSVC 19.51 crashes when that body is imported into another
  module interface unit.
- `source/startup.ixx` — `Game` initialisation, the registration order, the
  synchronous pass, `AnyInstallEnabled` and the all-off path.
- `source/launcher.ixx` — the whole launcher family: the `SkipLauncher=1`
  recovered DFA + ROM stage (main table, ABI-exact bodies, the CreateFile slot
  and the ROM message window) and the `SkipLauncher=0` legacy DFA file-API +
  WM_ROM stage under `legacy::dfa`/`legacy::rom`. `source/launcher_recovered.inc`
  is the recovered main table (data only, not shipped), included inside the
  module.
- `source/savegames.ixx` — `[Options] SavegameFix`: the save-file CRC32 bypass.
- `source/profile.ixx` — `[USERPROFILE] CustomUserProfilePath`: the shell-folder
  user-data redirect. The save folder is one of the roots it redirects; the
  CRC32 bypass is the separate SavegameFix family.
- `source/core.ixx` — the recovered "core" fixes in one section per key: VDS/
  data-integrity, DLC token, first-time-play ask, Internet check, health check.
- `source/registry.ixx` — `RemoveRegistryPathDependency`.
- `source/windowed.ixx` — `BorderlessWindowed`/`DoNotPauseOnMinimize`: the
  FusionFix-shaped borderless/focus-loss hooks and the legacy DefWindowProc
  shims.
- `source/warnings.ixx` — `StartupWarnings`: the ASI loader probe, the
  single-instance guard and the FusionFix notice.
- `external/` — committed, pinned vendor trees: injector (classic), Hooking.Patterns,
  IniReader + mINI; licences next to each.
- `tests/` — the native suite, the ASI image load and the PE checks; also the
  recovered SkipLauncher table golden.
- `tools/` — `check_no_installs.py`, `check_module_layout.py` and
  `check_skip_launcher_tables.py`.
- `README.md` — features, startup warnings, install, credits and the build.

### FusionFix overlap

**Mirrored:**

- the borderless window, centring and focus-loss input (`windowed.ixx`);
- the `SHGetFolderPath` user-data redirect and its `[USERPROFILE]
  CustomUserProfilePath` key (`profile.ixx`);
- the `Event<Args...>` tiers, `Log`, `Game` context and `find_pattern` idiom
  (`common.ixx`, `patch.ixx`);
- the task-dialog/FusionFix-notice shape (`warnings.ixx`).

**Deliberately not FusionFix-gated:** `[USERPROFILE] CustomUserProfilePath`. The
old addon's gate misbehaves with FusionFix on 1.0.8.0 and can clear a path the
user configured. The windowed options stay gated.

**No FusionFix counterpart / recovered:** the SkipLauncher main table, the DFA
and ROM stages, the WM_ROM service, the save-file CRC install, the registry
path and the legacy launcher stage.

## Build and test

```
cmake --preset win-x86
cmake --build --preset release
ctest --preset release

cmake --build --preset trace
ctest --preset trace
```

Win32/MSVC only, static CRT, image base `0x10000000`, windowed subsystem. Both
Release and Trace must stay green. The artifact is
`build/win-x86/Release/XLivelessAddon.asi`.

`ctest` runs the native suite (checks + the ASI image load), the PE header check,
`xla_no_installs`, `xla_module_layout` and `xla_skip_tables` (the recovered
SkipLauncher table against the old addon's golden).

## Rules learned the hard way

1. **Hook bodies are ABI contracts.** `CreateFile` is `__cdecl` (plain `ret`),
   `RomSet` is `ret 8` with the object in `ESI`, and resumes are tail-jumped
   (`jmp`), never called. A naked body is `static` in the interface unit or lives
   in an implementation unit; MSVC rejects an exported naked member (C2488).
2. **Standard headers and the vendored headers belong in the `module;` global
   fragment.** Do not include a standard header after an `import`.
3. **`IniReader.h` is all-inline.** Do not move a function body that instantiates
   `CIniReader` into another module's interface; keep `config::Load`/`Publish`
   out of line.
4. **`hook::pattern` wildcards are one `?` per byte; `??` is two bytes.** The
   scanner caches hits per signature string, so one string cannot be scanned
   twice with different counts; a multi-hit row asks for its count up front
   (`0` asks for all).
5. **The classic injector's `MakeRET` writes four bytes for both forms.**
   `patch::Ret` writes the one-/three-byte form itself; the suite pins both
   widths and the untouched byte after them.
6. **Every install logs its applied/missing state.** A missing signature is a
   logged skip, never a fault; the log's first line names the build and the ASI
   version.
7. **All-off is a supported state.** Do not add an install outside the
   `AnyInstallEnabled()` predicate; `TestAllOff` flips each key and expects the
   predicate to become true again.

## Dependency policy

`external/` is committed, pinned and unmodified. A vendored defect is adapted to
in `source/` (the classic `MakeRET` width and the all-inline `IniReader` are the
two examples) or upstreamed; never commit inside the vendor tree. Do not copy a
vendor's code into `source/` without attribution and licence compatibility.

## Git

Commit coherent checkpoints on `master`; never push, tag or publish without the
user asking. A commit that changes behaviour says why in its message. Message
style: `area: summary` (e.g. `fix: write ret at its exact width`).

## Docs

The README describes the current code, the INI keys and the startup warnings.
Update it in the same commit as a behaviour change; no session narration.
