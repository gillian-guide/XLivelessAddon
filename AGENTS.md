# AGENTS.md — XLivelessAddon (FusionFix-style reimplementation)

## What this is

A clean reimplementation of the XLivelessAddon companion for GTA IV / EFLC, in
the shape of GTAIV.EFLC.FusionFix. It is its **own repository**; it is loaded
next to OpenPreCEPatch and never links it.

Its scope is **the original XLivelessAddon's whole option surface**, rebuilt in
FusionFix shape and reusing ZolikaPatch/FusionFix code wherever that is the
reference (the frontend pair is FusionFix's `skipintro.ixx`; the launcher, the
VRAM fix and the GFWL checks are the old add-on's recovered rows). It is not a
subset: an old INI's keys keep their meaning here.

The behavioural reference is `../openprecepatch/xlivelessaddon/`; the
shape/feature reference is `../GTAIV.EFLC.FusionFix/`; the build/layout template
is `../fusionfix-skeleton/`. Those three trees are read-only: copy from them and
cite, never edit them.

The invariants the tree is built around:

- **`source/patch.ixx` is the only unit allowed to install.** It owns signature
  scanning, the injector stores/branches, the IAT replacement and the inline-hook
  factories; every store goes through the injector with its unprotect flag and the
  tree keeps no protection code of its own. A feature module calls `patch::...`;
  it never names `injector::`, `safetyhook::`, `Make*`, `WriteMemory`,
  `VirtualProtect` or `IATHook`. `tools/check_no_installs.py` (CTest
  `xla_no_installs`) enforces it.
- **`source/dllmain.cpp` is the only plain TU in `source/`** and owns startup.
  `source/startup.ixx` owns the registration order and the synchronous pass.
- **Startup is synchronous in `DllMain`.** The only deferred activity is the
  probe retry (the DRM may not have rewritten the image at attach time), which
  re-runs the same pass on one worker after the first pass has returned.
- **Every install is INI-gated, and all-off is inert.** `SavegameFix`,
  `SkipLauncher`, `LaunchWithPlayGTAIV`, `LegacyLauncher`,
  `RemoveRegistryPathDependency`, `RemoveDataIntegrityChecks`,
  `SkipTokenActivation`, `SkipFirstTimePlayAsk`, `SkipWebConnect` (with
  `SkipInternetConnectionCheck`/`SkipHealthCheck` refining it), `SkipIntro`,
  `SkipMenu`, `VRAMFix`, `BorderlessWindowed`,
  `DoNotPauseOnMinimize` and a non-empty `[USERPROFILE] CustomUserProfilePath`
  cover the installs; `StartupWarnings` only
  gates the non-fatal dialogs/notice. With every install key `0` and the path
  empty, `startup::AnyInstallEnabled()` is false and no store runs; `TestAllOff`
  pins it.
- **The user-data divergence is intentional.** `CustomUserProfilePath` is never
  switched off because FusionFix is present; only the windowed options are gated.
  Do not "restore" the old gate. It replaces the old addon's
  `LocalSettingsPath`, `CustomSavePath` and `CustomSettingsPath` with one redirect
  of the shell profile folders, and it installs from `DllMain` because the game
  caches its roots in `__initalizePaths` (`0x856BF0`) before FusionFix's async
  hook would run.
- **`LaunchWithPlayGTAIV` is a deliberate companion-side divergence.** The key is
  ZolikaPatch's `[COMPATIBILITY]` surface (and OpenPreCEPatch's), not the old
  add-on's. The companion owns it because a standalone companion must start a
  `PlayGTAIV.exe`-launched 1.0.8.0 without OpenPreCEPatch: GTA IV's SecuROM
  initialisation lowercases its parent process's module path and searches it for
  `LaunchGTAIV.exe\0`, fails for `PlayGTAIV.exe`, and leaves through
  `lmsgboxExit("SRLC10")` (the "Game needs to be launched using LaunchGTAIV.exe"
  dialog). Without this arm `SkipLauncher` looks inert. Do not fold the rewrite
  back into `SkipLauncher`: it is its own key and its own install step, and the
  recovered process gate (a live `PlayGTAIV.exe`) stays its own.
- **Recovered tables are data.** Signature strings, offsets, stored bytes, fill
  values and the stage order are 1:1 with the old addon. Renaming is free;
  changing a number or a scan is a behaviour change.

## Layout

- `source/*.ixx` — one C++23 module interface unit per feature family, plus the
  infrastructure units (`common`, `patch`, `build`, `config`, `probe`, `startup`)
  and the feature families `warnings`, `savegames`, `registry`, `profile`,
  `core`, `launcher`, `menu`, `vram`, `windowed`. They are listed in the
  `CXX_MODULES` file set.
  A module is one feature family, not one original handler: `launcher` owns every
  launcher stage (both SkipLauncher stages and the `LaunchWithPlayGTAIV` arm),
  `core` owns the recovered check fixes (the three "core" rows and the
  SkipWebConnect family), `menu` owns the frontend pair, and `vram` owns the VRAM
  detection fix.
- `source/common.hxx` — the one include header; included in each module's
  `module;` global fragment. It is includes only.
- `source/dllmain.cpp` — the entry point and the only plain TU in `source/`.
- `source/patch.ixx` — the primitive scan/store/branch/IAT helpers; the only
  installer.
- `source/config.ixx` — the INI defaults, load, legacy fallback and the
  FusionFix gates (the frontend pair and the windowed options). `Load`/`Publish`
  are out of line: `IniReader` is all-inline and MSVC 19.51 crashes when that
  body is imported into another module interface unit.
- `source/startup.ixx` — `Game` initialisation, the registration order, the
  synchronous pass, `AnyInstallEnabled` and the all-off path.
- `source/launcher.ixx` — the whole launcher family: the `SkipLauncher=1`
  recovered DFA + ROM stage (main table, ABI-exact bodies, the CreateFile slot
  and the ROM message window), the `SkipLauncher=0` legacy DFA file-API +
  WM_ROM stage under `legacy::dfa`/`legacy::rom`, and the `LaunchWithPlayGTAIV`
  arm (the recovered `.rdata` name-slot rewrite: handler `0x100441B0`, the
  per-build slot table, the `PlayGTAIV.exe` process walk and its own install
  step). `source/launcher_recovered.inc` is the recovered main table (data only,
  not shipped), included inside the module.
- `source/savegames.ixx` — `[Options] SavegameFix`: the save-file CRC32 bypass
  **and** the hardened save-path call sites. The ported OpenPreCEPatch arm (chosen
  because it is the more robust of the two implementations) retargets the ten
  recovered close/copy/mutex/null call sites at the four ABI-exact bodies
  (`0x10038570`, `0x10045580`, `0x100455A0`, `0x100455E0`) and NOPs the two-byte
  CRC32 branch, in the original handler's write order.
- `source/profile.ixx` — `[USERPROFILE] CustomUserProfilePath`: the shell-folder
  user-data redirect. The save folder is one of the roots it redirects; the
  CRC32 bypass is the separate SavegameFix family.
- `source/core.ixx` — the recovered check fixes in one section per key: the three
  "core" rows (VDS/data-integrity, DLC token, first-time-play ask) and
  `SkipWebConnect`, the old add-on's single key for the web-connect and health
  check pair (`SkipInternetConnectionCheck`/`SkipHealthCheck` refine it).
- `source/menu.ixx` — `SkipIntro`/`SkipMenu`: FusionFix's `skipintro.ixx`
  mechanism, ported as-is (the Loadsc window that zeroes the screens under
  8000 ms, and the `sub_7870A0` body with its `bOnce`/`bSkipIntroNotNeeded` latch,
  the SHIFT escape and `a1 = 6`). The installs are FusionFix's two idioms behind
  the only-installer boundary: `patch::InlineHook<Loadsc>` is the injector's
  `MakeInline(at, end)` behind a bounds check, and `patch::RetargetCallAt` is its
  call store returning the previous destination, which the body forwards to. The
  suite drives the functor's register contract directly.
- `source/vram.ixx` — `VRAMFix`, the two build generations of the same fix under one
  key: the old add-on's recovered `InstallVramFix` (three call sites retargeted at
  a body that clamps a non-positive answer to INT_MAX, including the reference's
  one-variable overwrite order) for the builds its rows match, and FusionFix's
  VRAM code copied verbatim from `GTAIV.EFLC.FusionFix/source/memory.ixx`
  (`GetProcessPreferredGPUMemory`, lines 14-201: the dynamic
  `CreateDXGIFactory2`/`CreateDXGIFactory` ladder, the d3d9-matched adapter
  selection, `GetDesc`/`GetDesc2`, `IDXGIAdapter3::QueryVideoMemoryInfo`, the
  release order, the 2 GB floor and the half-system-RAM cap; and
  `grcDevice::GetAvailableVideoMemory`, lines 203-221, with its `SafetyHookInline`
  original) for the builds where the rows no longer match. The install is
  FusionFix's own: safetyhook's inline hook at the pattern's first byte, through
  `patch::CreateInline`. The d3d9 device slot is FusionFix's `comvars.ixx` pattern
  set. No trampoline, no probe, no opt-in key; exactly one path installs per build
  and `vram: <path> ...` says which. The copied code's calls are guarded because a
  wrong pattern resolution must never become an arbitrary call (the 08:21 crash:
  `0xC0000005` at an unmapped private page): the device slot is only called when its
  vtable lies inside a loaded module (`IsModuleRange`), every COM pointer is null- or
  `SUCCEEDED`-checked, and each stage logs (factory, adapters with LUIDs, adapter3
  `QueryVideoMemoryInfo`, the d3d9 texture answer, the final max/cap) so the last log
  line names where a failure died.
- `source/registry.ixx` — `RemoveRegistryPathDependency`.
- `source/windowed.ixx` — `BorderlessWindowed`/`DoNotPauseOnMinimize`: the
  FusionFix-shaped borderless/focus-loss hooks and the legacy DefWindowProc
  shims.
- `source/warnings.ixx` — `StartupWarnings`: the ASI loader probe, the
  single-instance guard and the FusionFix notice.
- `external/` — pinned upstream submodules (see Dependencies): the injector tree
  (with safetyhook/minhook/bddisasm/kananlib and the in-tree Zydis amalgamation),
  Hooking.Patterns and IniReader + mINI; a fresh clone needs
  `git submodule update --init --recursive`.
- `tests/` — the native suite, the ASI image load and the PE checks; also the
  recovered SkipLauncher table golden.
- `tools/` — `check_no_installs.py`, `check_module_layout.py` and
  `check_skip_launcher_tables.py`.
- `README.md` — features, startup warnings, install, credits and the build.

### FusionFix overlap

**Mirrored:**

- the borderless window, centring and focus-loss input (`windowed.ixx`);
- the `SkipIntro`/`SkipMenu` mechanism (`menu.ixx`, taken from FusionFix's
  `skipintro.ixx`: the Loadsc window, the `sub_7870A0` body and its latch);
- the `grcDevice::GetAvailableVideoMemory` replacement and its value contract
  (`vram.ixx`, FusionFix's `memory.ixx`), on the builds where it applies;
- the `SHGetFolderPath` user-data redirect and its `[USERPROFILE]
  CustomUserProfilePath` key (`profile.ixx`);
- the `Event<Args...>` tiers, `Log`, `Game` context and `find_pattern` idiom
  (`common.ixx`, `patch.ixx`);
- the task-dialog/FusionFix-notice shape (`warnings.ixx`).

**Deliberately not FusionFix-gated:** `[USERPROFILE] CustomUserProfilePath`. The
old addon's gate misbehaves with FusionFix on 1.0.8.0 and can clear a path the
user configured. `VRAMFix` and `SkipWebConnect` stay ungated: the VRAM fix has
its own generation split (the old add-on's rows on the builds they match,
FusionFix's `GetAvailableVideoMemory` replacement on 1.0.8.0/EFLC 1.1.3.0) so
FusionFix's copy must not switch it off, and FusionFix has no GFWL. The frontend
pair and the windowed options are gated.

**No FusionFix counterpart / recovered:** the SkipLauncher main table, the DFA
and ROM stages, the WM_ROM service, the `LaunchWithPlayGTAIV` name-slot rewrite,
the SavegameFix CRC bypass and its hardened save-path call sites, the
`SkipWebConnect` family, the VRAM reference generation's call-site rows, the
registry path and the legacy launcher stage.

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
`build/win-x86/Release/XLivelessAddon.asi`; the native suite currently reports
**471 checks**.

`ctest` runs the native suite (checks + the ASI image load), the PE header check,
`xla_no_installs`, `xla_module_layout` and `xla_skip_tables` (the recovered
SkipLauncher table against the old addon's golden). The native suite now also
pins the launcher arm (`TestLaunchWithPlayGTAIV`: the two recovered slots on a
synthetic image of the right shape, the 16-byte payload, the short/long/off-RVA
refusals, the one-row-per-classified-build switch and the probe override), the
savegame arm (`TestSavegames`: the four recovered body VAs, the ten call
retargets with their destinations and order, the two-byte NOP, and the
missing-anchor and short-view skips), the frontend pair (`TestMenu`: FusionFix's
pattern strings, the inline window and NOP fill, the Loadsc functor's register
contract on a synthetic frame, the five-hit and fallback menu installs, the
body's latch/SHIFT/a1 = 6 behaviour and the missing-pattern skips), the VRAM fix
(`TestVram`: the reference generation's three call retargets, its clamp answers
and overwrite quirk, FusionFix's value contract through
`ReplacementValue`/`PreferredGpuValue`, the `safetyhook` install on a synthetic
page, the generation split and the no-pattern skips) and the web-connect family
(`TestWebConnect`: the two recovered sections, their exact writes and the
fine-grained keys).

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
5. **`injector::MakeRET` emits `ret`/`ret N` at their exact width.** The owner's
   injector fork fixed upstream's four-byte write, so the tree calls it directly
   and keeps no width workaround; the suite still pins both widths and the
   untouched byte after them.
6. **Every install logs its applied/missing state.** A missing signature is a
   logged skip, never a fault; the log's first line names the build and the ASI
   version.
7. **All-off is a supported state.** Do not add an install outside the
   `AnyInstallEnabled()` predicate; `TestAllOff` flips each key and expects the
   predicate to become true again.
8. **The frontend pair is FusionFix's mechanism, ported.** Keep the Loadsc window
   (two instructions, 10 bytes), the 8000 ms test and the zeroing of the screen
   time: do not substitute the old add-on's `-6` detour or its 300 ms literal.
   The `SkipMenu` hook must stay installed while `SkipIntro` is on, because its
   first call sets the `bSkipIntroNotNeeded` latch; the two install steps are
   separate only so each key has its own log line.
9. **`VRAMFix` has two generation paths under one key, and only one installs per
   build.** The old add-on's recovered rows run first (the builds they match);
   when they all miss, FusionFix's `GetAvailableVideoMemory` replacement installs
   instead (1.0.8.0 / EFLC 1.1.3.0). The hook is safetyhook's inline hook, created
   through `patch::CreateInline` and kept as FusionFix's `SafetyHookInline`, whose
   `.call<uint64_t>()` is the original; never hand-roll a trampoline. Keep
   FusionFix's value contract (2 GB pass-through/floor, `max(preferred, texture,
   2 GB)`, half-system-RAM ceiling, `static` once-per-process caching), the d3d9
   device slot from its `comvars.ixx` patterns, and the guards that make a wrong
   pattern resolution a logged skip: the device's vtable must be inside a loaded
   module before any method call, every COM pointer is checked, and each stage logs
   so the last line names the stage. The log line must name the path that ran; do
   not make the two paths install together.

## Dependencies

`external/injector`, `external/hooking` and `external/inireader` are pinned
upstream submodules, never committed copies. A fresh clone needs
`git submodule update --init --recursive`; CI checks them out recursively for the
same reason, and a configure without them fails on the required-file check.

| path | URL | pin |
| --- | --- | --- |
| `external/injector` | https://github.com/SandeMC/injector | `c196f90` |
| `external/injector/safetyhook` | https://github.com/cursey/safetyhook | `f44cc07` |
| `external/injector/minhook` | https://github.com/TsudaKageyu/minhook | `8af6b4a` |
| `external/injector/bddisasm` | https://github.com/bitdefender/bddisasm | `709fd97` |
| `external/injector/kananlib` | https://github.com/cursey/kananlib | `114de17` |
| `external/injector/zydis` | vendored inside the injector tree | Zydis amalgamation |
| `external/hooking` | https://github.com/ThirteenAG/Hooking.Patterns | `460a47b` |
| `external/inireader` | https://github.com/ThirteenAG/IniReader | `a0a5973` |

The injector pin is the owner's fork; upstream's `MakeRET` writes four bytes for
both forms, the fork writes the exact width, so `injector::MakeRET` is called
directly. `CMakeLists.txt` compiles safetyhook's sources and the injector's Zydis
amalgamation into `xla_safetyhook` (no `add_subdirectory`: safetyhook's own
CMakeLists fetches Zydis over the network, while FusionFix's premake compiles the
in-tree amalgamation), with `external/injector/include`,
`external/injector/safetyhook/include` and `external/injector/zydis` on the
include path. safetyhook at this pin embeds its x86 mid-hook thunk as data in
`mid_hook.cpp`, so there is no MASM step.

Do not write a primitive the submodules already provide: signature scanning is
Hooking.Patterns, stores/branches/`MakeInline`/`MakeRET`/IAT-slot writes are the
injector's (with its unprotect flag), and entry hooks that call their original
are safetyhook's `create_inline`. `source/patch.ixx` keeps only thin forwarding
wrappers for the image-bounds contract, the logging and the only-installer rule.

## Git

Commit coherent checkpoints on `master`; never push, tag or publish without the
user asking. A commit that changes behaviour says why in its message. Message
style: `area: summary` (e.g. `fix: write ret at its exact width`).

## Docs

The README describes the current code, the INI keys and the startup warnings.
Update it in the same commit as a behaviour change; no session narration.
