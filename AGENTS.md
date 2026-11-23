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

On top of that surface it owns the pieces that belong to the companion:
`LaunchWithPlayGTAIV` and, since the compatibility move, **the whole recovered
`[COMPATIBILITY]` set** (`NewFilesCompatibility`, `NewSavesCompatibility`,
`GFWLProtectionDisabler`, `SteamAchievements`), with OpenPreCEPatch's shipped
defaults. OpenPreCEPatch no longer ships those keys; their implementations were
ported 1:1 from the fork's `source/compatibility.ixx` before it was stripped.

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
  `DoNotPauseOnMinimize`, `NewFilesCompatibility`, `NewSavesCompatibility`,
  `GFWLProtectionDisabler`, `SteamAchievements`, `LoadDLCs`, `BenchmarkFix`,
  `CombinedRadioFreezeFix`
  and a non-empty `[USERPROFILE] CustomUserProfilePath`
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
  recovered process gate (a live `PlayGTAIV.exe`) stays its own. The name-slot
  rewrite only gets the game past the startup launcher check; it does **not**
  satisfy the SecuROM spot-check natives (see the next paragraph), so the two
  mechanisms are both required and are not substitutes.
- **`SkipLauncher` ships ZolikaPatch's full three-stage pass (`main|dfa|rom`).**
  The main stage is not optional: it runs the two multi-hit collectors from
  handler `0x10045CE0`, and those are the SecuROM spot-check bypass. The first
  collector matches `A1 ? ? ? ? 85 C0 8B 0D ? ? ? ? 75` at game
  `0xB4FAA0`/`0xB4FAD0` and writes `B0 01 C3 90` (`mov al,1; ret; nop`) over
  them; the second patches the last two matches of its own pattern. The game
  registers those bodies as `SECUROM_SPOT_CHECK1/2/3/4`
  (`NativeHashes.h`: `0x63576E53`, `0x1F40505C`, `0x5D1C0A6A`, `0x764236CE`),
  and mission scripts gate on them: `vlad3.sco` (Clean Getaway) only runs its
  garage/carwash state when `SECUROM_SPOT_CHECK3()` returns true, so a pass
  that omits `main` leaves the mission stuck before the garage door opens.
  XLivelessAddon applied these same rows in its unconditional process-patch
  block; the old note that `main` "broke the GFWL session" was about applying
  the table a second time after the add-on had already patched the same sites,
  which this tree does not do. On EFLC the shipped set is `main|rom`: the
  original DFA handler returns for product versions 10–13 (0x100048A2) and the
  DFA path faults at `0x00426440`; `ShippedStagesFor` is the one place that
  mask lives.
- **Recovered tables are data.** Signature strings, offsets, stored bytes, fill
  values and the stage order are 1:1 with the ZolikaPatch handlers and the old
  addon. Renaming is free; changing a number or a scan is a behaviour change.

## Layout

- `source/*.ixx` — one C++23 module interface unit per feature family, plus the
  infrastructure units (`common`, `patch`, `build`, `config`, `probe`, `startup`)
  and the feature families `warnings`, `savegames`, `registry`, `profile`,
  `core`, `compatibility`, `steam`, `episodes`, `stability`, `launcher`, `menu`,
  `vram`, `windowed`. They
  are listed in the `CXX_MODULES` file set.
  A module is one feature family, not one original handler: `launcher` owns every
  launcher stage (both SkipLauncher stages and the `LaunchWithPlayGTAIV` arm),
  `core` owns the recovered check fixes (the three "core" rows, the
  SkipWebConnect family and the GFWLProtectionDisabler byte patch),
  `compatibility` owns the two file/save path arms, `steam` owns the achievement
  bridge, `episodes` owns the DLC/episode discovery arm, `stability` owns the two
  recovered crash fixes, `menu` owns the frontend pair, and `vram` owns the VRAM
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
  recovered main + DFA + ROM pass (main table, the two SecuROM-spot-check
  collectors, ABI-exact bodies, the CreateFile slot and the ROM message window),
  the `SkipLauncher=0` legacy DFA file-API + WM_ROM stage under
  `legacy::dfa`/`legacy::rom`, and the `LaunchWithPlayGTAIV` arm (the recovered
  `.rdata` name-slot rewrite: handler `0x100441B0`, the per-build slot table, the
  `PlayGTAIV.exe` process walk and its own install step).
  `source/launcher_recovered.inc` is the recovered main table, shipped by
  `kShippedStages` and included inside the module.
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
  check pair (`SkipInternetConnectionCheck`/`SkipHealthCheck` refine it). Its last
  section is `GFWLProtectionDisabler` — the xlive.dll protection byte patch
  (`xlive.dll+0xF1605`, `jz`/`jmp` becomes `jmp`). It lives here rather than in a
  module of its own because it is one byte at one offset; the module-image guard
  (the offset must be inside the mapped, committed image, and the module must export
  `XLiveInitialize` **by name**) and the pre-image-byte rule are its whole footprint.
  Measured 2026-11-21: the packed system client has no named exports, so the name
  guard skips it, while Ultimate ASI Loader's 9.7.4 xlive does export
  `XLiveInitialize` (@5000) - there the pre-image byte is what prevents a write (the
  last log's `the protection site holds 0x0` line).
- `source/compatibility.ixx` — `[Options] NewFilesCompatibility` and
  `NewSavesCompatibility`, ported 1:1 from the fork's `source/compatibility.ixx`
  before it was stripped: the two publish steps (the registrar's call operand and
  the save-name buffer/load continuation), the two install steps (the two file-type
  update calls plus the registrar tail, and the savegame-load entry's trampoline),
  the savegame-load trampoline and the save-format converter with its three site
  patches. The transcription's asm tail is proved against the original ASI by
  `tools/verify_compat_bodies.py`. NewFiles is skipped when `GTAC.dll` or
  `JacksIVFixes.asi` is loaded (both install the same feature); NewSaves is gated
  on the original's own `[1060-1080]` build mask.
- `source/steam.ixx` — `[Options] SteamAchievements`: the achievement mirror, ported
  whole (the recovered id -> Steam name table, the lazy `SteamAPI_Init` on the first
  achievement write, the queued/replayed ids). The hook is the game's own
  `xlive.dll!XUserWriteAchievements` ordinal-5278 import slot, so it installs **with
  or without a GFWL client**: the loaded xlive is classified from its export directory
  (absent / GFWL client / xliveless proxy, `ProbeXliveExports`/`ClassifyXlive`). The
  slot is replaced through `patch::ReplaceImports` with `includeUnbound`, so a slot
  xliveless left null is still hooked, and one forwarding decision
  (`DecideForwarding`, shared with the suite) calls the previous value only when it is
  a validated code pointer inside a loaded module and either the module is the GFWL
  client or the pointer is that module's own ordinal-5278 export (a real bound thunk).
  Otherwise the hook answers `0` (what a completed write answers) and never calls it.
  Only two refusals remain: not the game image, and no `steam_api.dll`.
- `source/episodes.ixx` — `[Options] LoadDLCs`, ported 1:1 from the fork's
  `source/episodic.ixx` (the publish step, the per-build write table, the two
  transcribed bodies and the C++ discovery pass the struct-fixup body calls). The
  key replaces the game's DLC-manager tail with a body that clears the five
  request slots and, for a not-yet-initialised manager, runs the game's load
  callback and then the discovery pass: `\dlc\tlad\content\` or `\TLAD\`,
  `\dlc\TBoGT\content\` or `\TBoGT\`, and addon episodes
  `\Episode3\`...`\Episode254\` (folder `EpisodeN` registers as id `2*N`, its
  `setup2.xml` id). The build mask is the original's `[1060,1070,1080]`; the
  module-path buffer bound (`0x104` bytes) is the arm's own first refusal. The
  bodies are proved by `tools/verify_port_bodies.py`; the discovery pass is a
  rebuild (the fork carries no proof row for it either) and the suite drives it
  with fake register/apply entries.
- `source/stability.ixx` — `[Options] BenchmarkFix` and
  `[Options] CombinedRadioFreezeFix`, ported 1:1 from the fork's
  `source/stability.ixx`: the benchmark arm publishes each of its two sites' own
  `+0xD` continuation before it jumps, and refuses a scan that does not find
  exactly two (a shared resume would send the second body to the first one's
  continuation); the radio arm replaces the game's radio-update call with the
  two-instruction `mov eax,19; ret` body. The masks are the fork's option rows:
  BenchmarkFix is every classified build except 1.0.8.0/1.1.3.0,
  CombinedRadioFreezeFix is the original's all-builds mask. The five bodies are
  proved by `tools/verify_port_bodies.py`.
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
- `tools/` — `check_no_installs.py`, `check_module_layout.py`,
  `check_skip_launcher_tables.py`, `verify_compat_bodies.py` and
  `verify_port_bodies.py` (the manual proofs: they decode a module's asm tail and
  the original ASI's bodies at their recovered VAs and compare them instruction by
  instruction; `verify_compat_bodies.py` covers the compatibility family,
  `verify_port_bodies.py` the episodes/stability bodies. Both need the oracle, so
  neither is a ctest target).
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
**674 checks**.

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
page, the generation split and the no-pattern skips), the web-connect family
(`TestWebConnect`: the two recovered sections, their exact writes and the
fine-grained keys) and the recovered `[COMPATIBILITY]` family:

- `TestCompatibility`: the missing-anchor pass first (the scanner caches hits per
  signature string), then the recovered anchors and body VAs, the NewFiles write
  set on a synthetic image (two retargeted update calls and the registrar tail's
  jump, and nothing else), its `GTAC.dll`/`JacksIVFixes.asi` gate, the NewSaves
  published slots, its `[1060-1080]` build gate, the trampoline jump, and the
  converter's three site patches in both layouts (the branch opcode, the pushed
  read size, the branch word and the two call retargets, with the published
  original targets).
- `TestNewSavesWalk`: the converter's own walk and patch choice over synthetic
  saves, older/newer/mixed: the three chunk-size flags, the three chosen values,
  and every rejection path (short header, no `SAVE` at +0xC, a chunk size below
  nine, a header with no chunk table, a missing file).
- `TestGfwl`: the module-image guard (start/last byte, one past the end, a read
  crossing the end, a null module) and the byte rule (`jz`/`jmp` becomes `jmp`,
  idempotent, `jnz` and an unrelated byte untouched, a null site refused), plus
  the install's refusal without xlive.
- `TestSteam`: the 65-row recovered table (size, id order, five spot checks, ids
  0/66 absent), the ordinal constants, the two real refusals through
  `RefuseInstall` and the live refusal without `steam_api.dll` (twice, so it is
  stable); the export-table classification on synthetic PE32 export tables (the
  GFWL shape, the packed client's no-name/ordinal-only shape, the UAL xliveless
  shape with its `IsUltimateASILoader` marker, a module without the ordinal, an
  unparseable image, and this process's real absent xlive); the one forwarding
  decision (a GFWL bound thunk, a null slot, the hook itself, a non-module
  pointer, no module, a proxy's own ordinal export versus a foreign stub); and the
  hook driven through synthetic `xlive.dll` import tables: a bound GFWL slot calls
  the original first and mirrors after it (`OM`) and returns the original's answer,
  an unbound slot is never called, mirrors and answers `0`, an absent xlive still
  installs and never calls, and a proxy's real bound thunk forwards while its
  foreign stub does not. The suite cannot load a real GFWL client or a real
  `steam_api.dll`; those paths are pinned through the shared decision functions and
  the measured export tables the classification was built from.

The ported fixes have their own tests:

- `TestLoadDLCs`: the three recovered rows byte for byte (the register/apply/load-callback
  RVAs and all six writes each, including the 12-byte NOP tail), the literals, the request
  layout and the `0x104` path bound, the body VAs, the `[1060,1070,1080]` mask, the publish
  step's four slots, the exact write set on one synthetic image per build (the branch bytes,
  the jump/call destinations, and "only these six sites changed"), and the two refusals (a
  build outside the mask and a view too short for any fixed-RVA site).
- `TestLoadDLCsDiscovery`: the discovery pass driven through its own seam with fake
  register/apply entries (`__thiscall`: manager in ECX, request on the stack, `ret 4`) and
  folders created next to the test executable - the `TLAD`/`TBoGT`/`Episode3` paths and ids
  2/4/6, the request's flag/mode bytes, the manager's `0xA4`/`0x166` markers, the `0x40` EDX
  answer and the `\Episode254\` EDX forward (id 508), and the rejections: a missing folder,
  `Episode2` (a reserved id) and a non-numeric episode name are not registered, and a build
  with no published entry registers nothing.
- `TestStability`: the two anchors, both masks (inside and outside, plus the unclassified
  builds), the three body VAs, the missing-anchor, one-hit-scan and short-view refusals
  (nothing written, nothing published), the two benchmark sites with their own `+0xD`
  continuations and body targets, the radio call replacement, and the exact write set of
  both arms.

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
10. **The `[COMPATIBILITY]` arms are the fork's port, and the transcription is
    proved, not assumed.** `NewFilesCompatibility`/`NewSavesCompatibility` come from
    OpenPreCEPatch's `source/compatibility.ixx` (the whole section, with its shipped
    defaults): the anchors, the offsets inside them and the stored bytes are
    byte-identical, and the asm tail is compared instruction by instruction with the
    original ASI's own bodies by `tools/verify_compat_bodies.py`. The converter's
    walk and its value choice each have one implementation, used by the production
    path and by the suite (`WalkSaveFile` runs `WalkSaveFileInto` and
    `ChoosePatchValues`), so a test cannot agree with a copy of a bug. Keep
    `GFWLProtectionDisabler` in `core` (one byte, one offset) and `SteamAchievements`
    in `steam` (its table and its bridge): that is the size of each arm, and a module
    per key would be an empty shell.
    The achievement mirror is **not GFWL-gated**: the hook is the game's ordinal-5278
    import slot, the loaded xlive is classified from its export directory only, and
    the previous value is called only when `DecideForwarding` validates it (GFWL
    client, or the module's own ordinal export). Do not bring back a path/size/name
    test, and do not refuse because GFWL is absent: the old `ProtectedSystemXlive`
    path check refused the system GFWL client - the very layout the mirror is for -
    while letting UAL's xliveless stand-in through (measured 2026-11-21: the
    15,453,904 B system client has 5,377 ordinal exports and **no** named exports;
    UAL 9.7.4's 2,407,648 B xlive exports the same ABI with local emulation plus
    `IsUltimateASILoader`). `patch::ReplaceImports`'s `includeUnbound` is the
    steam-only flag that hooks a slot the loader left null; every other caller keeps
    the default. The suite drives the classification, the decision and the hook
    through synthetic PE32 export/import tables, and it cannot load a real client or
    a real `steam_api.dll`; that limit is stated in `TestSteam`.

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
