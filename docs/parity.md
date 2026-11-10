# Parity and verification

This document records, feature by feature, what was ported into
`xlivelessaddon-fusion/`, where it came from, how it is verified, the one
deliberate behavioural divergence from the old addon, and what remains
unverified without a live game.

Reference trees (never modified):

- `openprecepatch/xlivelessaddon/` — the old companion. Its source is the
  behavioural reference for the ported features and the source of the recovered
  tables and hook-body contracts.
- `GTAIV.EFLC.FusionFix/` — the shape/behaviour reference. Its `common.ixx`,
  `windowed.ixx` and `userdata.ixx` are the originals of the corresponding parts
  here.
- `fusionfix-skeleton/` — the build/layout/guard template (CMake, module file set,
  PE checks, no-install guard).

The new tree's artifact is still `XLivelessAddon.asi`, so it is a drop-in for the
old companion.

## Feature table

| Feature | Old addon source | FusionFix source | New unit | Verification |
| --- | --- | --- | --- | --- |
| INI defaults, load, legacy fallback, section order, flag grammar, CRLF normalisation | `source/config.ixx` | `common.ixx` / settings shape | `source/config.ixx` | `TestConfigGrammar`, `TestConfigDefaultsAndIni`, `TestConfigPrecedenceAndLegacy`, `TestConfigLegacySearch`, `TestConfigWhitespaceCommentsQuotes`, `TestConfigLineEndings` |
| ASI loader probe (Ultimate ASI Loader >= 6.9.0) | `source/warnings.ixx` | the compatibility marker FusionFix trusts (`IsUltimateASILoader`) | `source/warnings.ixx` | `TestWarnings` (`LoaderVersionAccepted`), the loader dialog text is pinned by the source |
| Game-executable probe and its one retry | `source/addon.ixx` (probe step) | — | `source/probe.ixx` | `TestProbe` (signature/spin constants), the retry path is source-reviewed, not drivable in a test process |
| Unsupported game build exit | `source/build.ixx`, `source/addon.ixx`, `source/warnings.ixx` | — | `source/build.ixx`, `source/startup.ixx`, `source/warnings.ixx` | `TestBuild`, `TestWarnings` (dialog), startup order pins the Build step |
| Loaded-twice exit | `source/warnings.ixx`, `source/addon.ixx` | — | `source/warnings.ixx`, `source/startup.ixx` | `TestWarnings` (`ClaimSingleInstance` twice) |
| Savegame path redirect + CRC32 bypass | `source/savegames.ixx` | — | `source/savegames.ixx` | `TestSavegames` (path composition, NUL-bounded read, synthetic anchor/redirect scan, CRC NOP, redirect jump) |
| Rockstar Games registry path dependency | `source/registry.ixx` | — | `source/registry.ixx` | `TestRegistry` (key/value predicates, install-folder answer), `TestIatReplacement` (the shared IAT walker) |
| `LocalSettingsPath` (shell user-data redirect) | `source/userdata.ixx` | `source/userdata.ixx` | `source/userdata.ixx` | `TestUserdata` (`ShouldRedirect`, saves folder, synthetic SHELL32 replacement, end-to-end `CSIDL_APPDATA` answer), `TestFusionFixPresenceAndDivergence` |
| `SkipLauncher=1`: recovered DFA + ROM stages | `source/skip_launcher.ixx` | — (ZolikaPatch recovered data) | `source/skip_launcher.ixx` | `TestSkipLauncherTable`, `TestSkipLauncherPass`, `TestSkipLauncherCreateFileSlot`, `TestSkipLauncherStub` |
| `SkipLauncher=0`: legacy DFA file-API stage | `source/dfa.ixx` | — | `source/dfa.ixx` | `TestDfaAndRomWindow` (init ABI), the six install patterns are source-reviewed against the old addon |
| `SkipLauncher=0`: legacy WM_ROM message window | `source/rom_window.ixx` | — | `source/rom_window.ixx` | `TestDfaAndRomWindow` (message id, action table, payload layout, window creation, all three actions, synthetic install) |
| Windowed mode: borderless, centring, focus-loss input, DefWindowProc shims, pause-branch NOP | `source/windowed.ixx` | `source/windowed.ixx` | `source/windowed.ixx` | `TestWindowed` (foreign-image guards), `TestIatReplacement` (the shared import walker), the hook bodies are source-reviewed against FusionFix |
| Startup warnings (TaskDialog, activation context, message-box fallback, FusionFix notice) | `source/warnings.ixx` | FusionFix's task-dialog/notice shape | `source/warnings.ixx` | `TestWarnings` (notice write/content, dialog shapes, single instance) |
| `CustomSettingsPath` (the old "parsed but not hooked" gap) | `source/patches.ixx` (`InstallCustomSettingsPath`) | — | `source/settings_path.ixx` | `TestSettingsPath` (composition, four-site install, stub bytes), `TestSettingsStubContract` (executes the real body and checks EBX/ECX/EFLAGS preservation) |
| Recovered opcode/byte catalogue | `source/common.ixx` | FusionFix byte helpers | `source/common.ixx` | `TestPatchPrimitives`, `TestSettingsPath`, `TestSkipLauncherTable` |
| Scanning and install primitives | `source/patch.ixx` | FusionFix `find_pattern` idiom | `source/patch.ixx` | `TestPatchScan`, `TestPatchPrimitives`, `TestIatReplacement` |

## The deliberate divergence: local-directory features are not FusionFix-gated

### Old behaviour

`openprecepatch/xlivelessaddon/source/config.ixx`'s `ApplyFusionFixGates` switches
off six options when FusionFix is present: `SkipIntro`, `SkipMenu`,
`BorderlessWindowed`, `DoNotPauseOnMinimize`, `VRAMFix`, **`LocalSettingsPath`**,
and it clears **`CustomSavePath`** and **`CustomSettingsPath`**. The gate is
applied by the `FusionFix` startup step as soon as a FusionFix ASI is detected.

### New behaviour

Only the two windowed options are gated:

```cpp
constexpr std::array<Gate, 2> gates{{
    {"BorderlessWindowed", &Options::borderlessWindowed, "windowed.ixx"},
    {"DoNotPauseOnMinimize", &Options::doNotPauseOnMinimize, "windowed.ixx"},
}};
```

`LocalSettingsPath`, `CustomSavePath` and `CustomSettingsPath` are never switched
off. They are installed on this add-on's own detection: the game build (already
gated by `build::Detect`) and their own INI key.

### Reason

With FusionFix on **1.0.8.0** the gate misbehaves: FusionFix's `userdata.ixx`
redirects the same shell/import slots, the two `SHGetFolderPath` hook chains are
installed in an order neither mod controls, and the old gate can clear a path the
user explicitly configured for this companion. The result is a save/settings path
that silently does not exist where the INI says. A companion feature must be
usable without another mod being installed; a local-directory redirect is exactly
the kind of feature that must not depend on someone else's presence.

### Tests that prove it

- `TestFusionFixPresenceAndDivergence` creates a temp install, writes an INI with
  all three local options and both windowed options, and asserts:
  - with **no** FusionFix module or file: all local paths and the windowed
    options survive, and the published `Game` context carries them;
  - after creating a dummy `GTAIV.EFLC.FusionFix.asi` next to the module: the
    local paths still survive, the two windowed options are gated, and the
    published context still carries the local paths.
- `TestUserdata` drives the real `LocalSettingsPath` mechanism against a
  synthetic SHELL32 import table and calls the installed `SHGetFolderPathA`
  hook: `CSIDL_APPDATA` is answered with `<game>\saves`. No FusionFix module is
  involved.
- `TestSavegames` drives the savegame anchor/redirect scan and both install
  sites on a synthetic image; the path composition is checked independently of
  FusionFix.

### Trade-off

When FusionFix is installed and its `CustomUserProfilePath` is configured, both
mods redirect user data. This tree does not try to arbitrate between them; the
user must configure one. The old gate avoided that by disabling this add-on's
redirect, which is precisely the behaviour that broke on 1.0.8.0.

## Recovered data and hook-body contracts

The SkipLauncher tables are data, not code. The new tree was diffed against the
old addon's table extraction: all 25 entry rows, the two collectors, the six DFA
installs, the two ROM installs, the collected-jump table and all 32 patch ops are
token-for-token identical. The native suite additionally pins:

- `entries[0]` offsets `+34`/`+223`, `entries[8]`'s 447-byte NOP fill, entry 9's
  jump target (`kSkipLauncherJumpTargetEntry == 1`);
- the shipped stage set is `dfa|rom` and never `main`;
- a main-stage store at `+34` is `EB`; the shipped stages do not touch it; a
  store past the caller's image fails with `out_of_bounds`;
- `RomSet` is `8B 4E 1C 89 4E 20 B0 01 C2 08 00` (`mov ecx,[esi+1c]; mov
  [esi+20],ecx; mov al,1; ret 8`);
- the CreateFile body forwards through the captured IAT slot and falls back to
  `CreateFileA` when the slot is cleared;
- the CustomSettingsPath stub is 30 bytes, with the buffer/global operands and
  the fixed opcodes pinned, and an executed instance preserves
  EBX/ESI/EDX/EAX, restores ECX from the recovered global and preserves carry.

The bodies keep the recovered ABIs: `CreateFile` and the other DFA bodies are
`__cdecl` (plain `ret`), `RomSet` takes the object in `ESI` and returns with
`ret 8`, and every resume is a tail jump (`jmp`), never a call.

## Vendored-code adaptation (not an edit)

The tree is pinned to the **classic** `injector` revision
`fdd277056a9b12e209d58c35a269277391cf955a`. That revision's `MakeRET` writes
`pop ? 0xC2 : 0xC3` through a deduced `int`, i.e. four bytes for both forms; the
maintained fork fixed it. `source/patch.ixx` writes `C3`/`C2 imm16` itself and the
suite pins both widths and the untouched byte after them. The vendored header is
not modified.

`IniReader` is all-inline. MSVC 19.51 crashes (C1001-style CL.exe access
violation) when `config::Load`'s body, which instantiates `CIniReader`, is
imported into another module interface unit. `config::Load` and
`config::Publish` are therefore out-of-line; the INI reader stays in
`config.ixx` and no extra plain TU is needed. This is why `source/dllmain.cpp`
can remain the only plain TU, as the brief requires.

## Verification summary

Commands (both must be green):

```bat
cmake --preset win-x86
cmake --build --preset release
ctest --preset release

cmake --build --preset trace
ctest --preset trace
```

- `xla_tests` — 279 native checks: event tiers, INI grammar/precedence/defaults/
  legacy/line endings, build table, patch primitives and widths, IAT walker,
  savegame path/install, registry helpers, userdata redirect, settings path and
  stub register contract, SkipLauncher tables/pass/bodies, DFA/ROM window,
  windowed guards, warnings, probe constants, startup order, and the
  local-path divergence.
- `xla_asi_load` — maps the built ASI as an image (DllMain is not executed: in a
  test process the executable is an unsupported build by design) and checks its
  version resource identity.
- `xla_pe_check` — PE32/i386, DLL, base `0x10000000`, windowed subsystem, static
  CRT, and the USER32/SHELL32/ADVAPI32/VERSION imports.
- `xla_no_installs` — every `injector::`/`safetyhook::`/`Make*`/`WriteMemory`/
  `VirtualProtect`/`IATHook` use is confined to `source/patch.ixx`.
- `xla_module_layout` — one `.ixx` per feature, `dllmain.cpp` the only plain TU,
  the CMake module file set complete.

## What remains unverified without a live game

These need the real executable (1.0.8.0 and the other supported builds) and a
user-run session; the offline suite cannot prove them:

- the actual `DllMain` pass in `GTAIV.exe`/`EFLC.exe`: probe timing under the
  DRM, the one retry, and the unsupported-build dialog/exit;
- every signature hit at the real addresses, and the `SkipLauncher` DFA/ROM
  branches against the running image;
- the loader probe's real `Ultimate ASI Loader` detection and the task dialogs
  (they need a desktop session);
- the borderless window/focus-loss sequence and the DefWindowProc shims on a real
  message loop;
- the save/settings/user-data redirects as the game actually queries them
  (including the `CustomSettingsPath` inline call sites and the inherited
  unbounded copy for a path longer than 255 bytes);
- the save-file CRC32 bypass against real save data;
- interaction with FusionFix installed at the same time, for the local-path
  divergence and the windowed gates.

Nothing above is claimed as verified in the final report.
