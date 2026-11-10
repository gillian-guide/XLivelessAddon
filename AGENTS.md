# AGENTS.md — XLivelessAddon (FusionFix-style reimplementation)

## What this is

A clean reimplementation of the XLivelessAddon companion for GTA IV / EFLC, in
the shape of GTAIV.EFLC.FusionFix. It is a standalone repository; it is loaded
next to OpenPreCEPatch and never links it.

The behavioural reference is `../openprecepatch/xlivelessaddon/`; the shape/feature
reference is `../GTAIV.EFLC.FusionFix/`; the build/layout template is
`../fusionfix-skeleton/`. Those three trees are read-only: copy from them and
cite, never edit them.

## Invariants

- **`source/patch.ixx` is the only unit allowed to install.** It owns signature
  scanning, the injector stores/branches, the IAT replacement and the image
  unprotect. A feature module calls `patch::...`; it must never name
  `injector::`, `safetyhook::`, `Make*`, `WriteMemory`, `VirtualProtect` or
  `IATHook`. `tools/check_no_installs.py` (CTest `xla_no_installs`) enforces it.
- **`source/dllmain.cpp` is the only plain TU in `source/`** and owns startup.
  `source/startup.ixx` owns the registration order and the synchronous pass.
- **Startup is synchronous in `DllMain`.** The only deferred activity is the
  probe retry (the DRM may not have rewritten the image at attach time), which
  re-runs the same pass on one worker after the first pass has returned.
- **Hook bodies are ABI contracts.** `CreateFile` is `__cdecl` (plain `ret`),
  `RomSet` is `ret 8` with the object in `ESI`, resumes are tail-jumped (`jmp`),
  never called. A naked body is `static` in the interface unit or lives in an
  implementation unit; MSVC rejects an exported naked member (C2488).
- **Every optional install is INI-gated.** A missing signature is a logged skip,
  never a fault. `CustomSettingsPath` is gated by being non-empty; `SkipLauncher=0`
  selects the legacy DFA/ROM stage. The savegame path reconstruction and CRC32
  bypass are the original's one unconditional core install (the old addon's
  `AGENTS.md` says so); `CustomSavePath` only chooses the folder and is never
  FusionFix-gated.
- **The local-path divergence is intentional.** `LocalSettingsPath`,
  `CustomSavePath`, `CustomSettingsPath` are never switched off because FusionFix
  is present. Only `BorderlessWindowed` and `DoNotPauseOnMinimize` are gated.
  See `docs/parity.md`; do not "restore" the old gate.
- **Recovered tables are data.** Signature strings, offsets, stored bytes, fill
  values and the stage order are 1:1 with the old addon. Renaming is free;
  changing a number or a scan is a behaviour change and needs the parity doc and
  the tests updated.

## Layout

```
external/            committed, pinned vendor trees (injector classic, Hooking.Patterns, IniReader)
source/common.ixx    Event tiers, Log, Game, Image, opcode catalogue, path/string helpers
source/patch.ixx     the only installer
source/build.ixx     the classification table/detect
source/config.ixx    INI defaults/load/legacy fallback/gates
source/warnings.ixx  loader probe, single instance, dialogs, FusionFix notice
source/probe.ixx     game probe + retry
source/savegames.ixx source/registry.ixx source/userdata.ixx source/settings_path.ixx
source/skip_launcher.ixx  SkipLauncher=1 recovered tables and bodies
source/dfa.ixx source/rom_window.ixx  SkipLauncher=0 legacy stage
source/windowed.ixx  borderless/focus-loss
source/startup.ixx   registration order and the pass
source/dllmain.cpp   entry point (only plain TU)
tests/               native suite + ASI load + PE checks
tools/               no-install and module-layout guards
docs/parity.md       provenance, divergence, verification
```

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

## Module rules learned here

1. Standard headers and the vendored headers belong in the `module;` global
   fragment. Do not include a standard header after an `import`.
2. `IniReader.h` is all-inline. MSVC 19.51's CL.exe crashes when a function body
   that instantiates `CIniReader` is imported into another module interface unit;
   `config::Load`/`config::Publish` are therefore out-of-line. Do not move the
   reader into a header included by `startup.ixx` or another module.
3. `hook::pattern`'s wildcard is one `?` per byte. The scanner caches hits per
   signature string, so one string cannot be scanned twice with different counts;
   a multi-hit row asks for its count up front (`0` asks for all).
4. The classic injector's `MakeRET` writes four bytes for both forms; `patch::Ret`
   writes the one-/three-byte form itself and the suite pins both widths.
5. Never include a standard header in a module's purview and then export a type
   that uses it without exporting the header; keep the public surface in
   `common.ixx` and `patch.ixx`.

## Git and docs

Commit coherent checkpoints locally; never push, tag or publish. Message style:
`area: summary` (e.g. `fix: write ret at its exact width`). Update
`docs/parity.md` and `README.md` in the same commit as a behaviour change. The
chat is not permanent context: record findings in `docs/parity.md` and the commit
message.
