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
| Save-file CRC32 bypass (`SavegameFix`) | `source/savegames.ixx` (the CRC half) | — | `source/savegames.ixx` | `TestSavegames` (the recovered branch is NOPed, only its two bytes, and a missing signature is a clean skip) |
| Rockstar Games registry path dependency | `source/registry.ixx` | — | `source/registry.ixx` | `TestRegistry` (key/value predicates, install-folder answer), `TestIatReplacement` (the shared IAT walker) |
| `[USERPROFILE] CustomUserProfilePath` (shell user-data redirect; replaces `LocalSettingsPath`, `CustomSavePath`, `CustomSettingsPath`) | `source/userdata.ixx`, `source/savegames.ixx`, `source/patches.ixx` (`InstallCustomSettingsPath`) | `source/userdata.ixx` (the same key and the same SHGetFolderPath A/W redirect) | `source/profile.ixx` | `TestProfile` (`ShouldRedirect`, path resolution, synthetic SHELL32 replacement, end-to-end `CSIDL_PERSONAL`/`CSIDL_APPDATA` answers, foreign-image refusal), `TestFusionFixPresenceAndDivergence` |
| `SkipLauncher=1`: recovered DFA + ROM stages | `source/skip_launcher.ixx` | — (ZolikaPatch recovered data) | `source/skip_launcher.ixx`, `source/skip_launcher_recovered.inc` | `xla_skip_tables` (71 records), `TestSkipLauncherTable`, `TestSkipLauncherPass`, `TestSkipLauncherCreateFileSlot`, `TestSkipLauncherStub` |
| `SkipLauncher=0`: legacy DFA file-API stage (`LegacyLauncher`) | `source/dfa.ixx` | — | `source/dfa.ixx` | `TestDfaAndRomWindow` (init ABI), the six install patterns are source-reviewed against the old addon |
| `SkipLauncher=0`: legacy WM_ROM message window (`LegacyLauncher`) | `source/rom_window.ixx` | — | `source/rom_window.ixx` | `TestDfaAndRomWindow` (message id, action table, payload layout, window creation, all three actions, synthetic install) |
| Windowed mode: borderless, centring, focus-loss input, DefWindowProc shims, pause-branch NOP | `source/windowed.ixx` | `source/windowed.ixx` | `source/windowed.ixx` | `TestWindowed` (foreign-image guards), `TestIatReplacement` (the shared import walker), the hook bodies are source-reviewed against FusionFix |
| Startup warnings (`StartupWarnings` for the non-fatal ones; TaskDialog, activation context, message-box fallback, FusionFix notice) | `source/warnings.ixx` | FusionFix's task-dialog/notice shape | `source/warnings.ixx` | `TestWarnings` (notice write/content, dialog shapes, single instance) |
| Recovered opcode/byte catalogue | `source/common.ixx` | FusionFix byte helpers | `source/common.ixx` | `TestPatchPrimitives`, `TestSkipLauncherTable` |
| Scanning and install primitives | `source/patch.ixx` | FusionFix `find_pattern` idiom | `source/patch.ixx` | `TestPatchScan`, `TestPatchPrimitives`, `TestIatReplacement` |

## The one deliberate divergence: the user-data redirect is not FusionFix-gated

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

`[USERPROFILE] CustomUserProfilePath` is never switched off. It is installed on
this add-on's own detection: the game build (already gated by `build::Detect`) and
its own INI value. `LegacyLauncher` and `StartupWarnings` are ordinary independent
keys, not FusionFix gates either. The three old keys it replaces are gone.

### Reason

With FusionFix on **1.0.8.0** the gate misbehaves: FusionFix's `userdata.ixx`
redirects the same shell/import slots, the two `SHGetFolderPath` hook chains are
installed in an order neither mod controls, and the old gate can clear a path the
user explicitly configured for this companion. The result is a save/settings path
that silently does not exist where the INI says. A companion feature must be
usable without another mod being installed; a user-data redirect is exactly the
kind of feature that must not depend on someone else's presence.

### Why the ported key works on 1.0.8.0 and FusionFix's own copy does not

GTA IV 1.0.8.0 resolves its startup roots once, in `__initalizePaths` (`0x856BF0`):
three `SHGetFolderPathA` and three `SHGetFolderPathW` calls fill globals that the
settings, user-music, video and benchmark writers then read. The savegame resolver
`sub_61E770` (`0x61E770`) asks `SHGetFolderPathA` for `CSIDL_PERSONAL` on every
save and appends `Rockstar Games\GTA IV\savegames\user_<xuid>`.

FusionFix installs its `SHGetFolderPath` hook from `onInitEventAsync`, which runs
after that init pass; the startup roots are already cached from the default
answer, so a configured `CustomUserProfilePath` never reaches them. `profile.ixx`
installs from `DllMain`, before the game's entry point, so the cached roots and the
save-time answer are the custom ones. It also resolves a relative value against
the game folder (not the working directory) and trims the spaces a hand-written
INI line carries, neither of which FusionFix's path handling does.

### Tests that prove it

- `TestFusionFixPresenceAndDivergence` creates a temp install, writes an INI with
  `CustomUserProfilePath` and both windowed options, and asserts:
  - with **no** FusionFix module or file: the profile path and the windowed
    options survive, and the published `Game` context carries them;
  - after creating a dummy `GTAIV.EFLC.FusionFix.asi` next to the module: the
    profile path still survives, the two windowed options are gated, and the
    published context still carries the path.
- `TestProfile` drives the real redirect against a synthetic SHELL32 import table
  and calls the installed `SHGetFolderPathA`/`W` hooks: `CSIDL_PERSONAL` and
  `CSIDL_APPDATA` are answered with the configured root, the root is created, and
  a foreign image is refused. No FusionFix module is involved.

### Trade-off

When FusionFix is installed and its own `CustomUserProfilePath` is configured as
well, both mods redirect user data. FusionFix's hook installs later and takes the
import slot, so its value wins for the redirected CSIDLs; configure one of the two
keys, not both. This tree does not try to arbitrate between them. The old gate
avoided that by disabling this add-on's redirect, which is precisely the behaviour
that broke on 1.0.8.0.

### Added toggles for otherwise-unconditional behaviour

Three pieces of the old addon had no independent enable/disable key. They now do,
all defaulting to the old behaviour:

| Key | Default | Gates |
| --- | --- | --- |
| `SavegameFix` | `1` | the save-file CRC32 bypass (old addon: always installed) |
| `LegacyLauncher` | `1` | the legacy DFA + WM_ROM stage, only consulted when `SkipLauncher=0` (old addon: always installed on that path) |
| `StartupWarnings` | `1` | the non-fatal old-loader dialog and the FusionFix compatibility notice |

The defaults preserve the old addon exactly. `StartupWarnings` does not gate the
fatal unsupported-version and loaded-twice dialogs: those are safety checks, not
features. `TestConfigDefaultsAndIni` pins all three defaults and the shipped file.

### All-off behaviour

Every install is behind an INI key. With `SavegameFix=0`, `SkipLauncher=0`,
`LegacyLauncher=0`, `RemoveRegistryPathDependency=0`, `DoNotPauseOnMinimize=0`,
`BorderlessWindowed=0`, `StartupWarnings=0` and an empty
`[USERPROFILE] CustomUserProfilePath`, the driver's `startup::AnyInstallEnabled()`
is false: no hook or store runs, and the `Writable` step skips the image unprotect
so the image is not even made writable. The ASI still opens its log and checks the
build; the fatal safety dialogs remain.

`TestAllOff` loads exactly that INI, asserts the predicate is false, then flips
each install key on its own and asserts it becomes true again. It also checks that
a non-empty `CustomUserProfilePath` is an install and that `StartupWarnings` alone
is not.

## Recovered data and hook-body contracts

The SkipLauncher tables are data, not code. The readable rewrite keeps the
25-entry main table in `source/skip_launcher_recovered.inc` (data only, not
shipped) and the shipping rows in `source/skip_launcher.ixx`. `xla_skip_tables`
resolves every named offset and `ops::` window and compares 71 records with the
old addon's committed golden: all 25 entries, all 32 edits, the two collectors,
the capture pattern/offset, the eight installs, the two collected targets and the
collected install. The native suite additionally pins:

- `entries[0]` offsets `+34`/`+223`, `entries[8]`'s 447-byte NOP fill, entry 9's
  jump target (`kSkipLauncherJumpTargetEntry == 1`);
- the shipped stage set is `dfa|rom` and never `main`;
- a main-stage store at `+34` is `EB`; the shipped stages do not touch it; a
  store past the caller's image fails with `out_of_bounds`;
- `RomSet` is `8B 4E 1C 89 4E 20 B0 01 C2 08 00` (`mov ecx,[esi+1c]; mov
  [esi+20],ecx; mov al,1; ret 8`);
- the CreateFile body forwards through the captured IAT slot and falls back to
  `CreateFileA` when the slot is cleared;

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

## Not ported in this scope

The brief's feature list is the scope of this tree. These old-addon features are
deliberately **not** in it; they are named here so the omission is not silent.
They can be added later without changing the architecture (one module each, with
its own install arms through `patch.ixx`):

| Feature | Old addon source | Why it is not here |
| --- | --- | --- |
| `SkipIntro` (300 ms load screens) | `source/patches.ixx` (`InstallIntro`), `source/addon.ixx` | It is a different mechanism from FusionFix's `skipintro.ixx` and a different INI key (`SkipIntro` vs `PREF_SKIP_INTRO`); the brief's list does not include it, and adding it needs a decision about which mechanism this companion owns. |
| `SkipMenu` (hold SHIFT to keep the menu) | `source/patches.ixx` (`InstallMenu`) | Same as `SkipIntro`; the recovered three call sites are in the old file if it is added. |
| `VRAMFix` | `source/patches.ixx` (`InstallVramFix`) | FusionFix's `memory.ixx` implements the same feature with a different hook site; the brief's list does not include it, so this tree does not duplicate FusionFix's subsystem. |
| `SkipWebConnect` (GFWL web-connect/health checks) | `source/patches.ixx` (`InstallWebConnectChecks`) | Not in the brief's list; FusionFix owns the GFWL compatibility surface in a co-install. |
| The "core" recovered list (RGSC connect/init gating, files.txt/certificate/integrity checks, DLC token/first-play) | `source/patches.ixx` (`InstallCore`) | Not in the brief's list. It is a separate unconditional patch list, not part of the SkipLauncher DFA/ROM stage. |

Everything above is still in the old addon tree and in
`../GTAIV.EFLC.FusionFix/`; nothing was deleted or weakened. The new tree's
`SkipLauncher` is the recovered DFA + ROM stage the old addon shipped, not the
separate core list.

## Verification summary

Commands (both must be green):

```bat
cmake --preset win-x86
cmake --build --preset release
ctest --preset release

cmake --build --preset trace
ctest --preset trace
```

- `xla_tests` — 281 native checks: event tiers, INI grammar/precedence/defaults/
  legacy/line endings, build table, patch primitives and widths, IAT walker,
  save-file CRC32 bypass, registry helpers, the `CustomUserProfilePath` resolution
  and shell redirect, SkipLauncher tables/pass/bodies, DFA/ROM window, windowed
  guards, warnings, probe constants, startup order, and the user-data divergence.
- `xla_asi_load` — maps the built ASI as an image (DllMain is not executed: in a
  test process the executable is an unsupported build by design) and checks its
  version resource identity.
- `xla_pe_check` — PE32/i386, DLL, base `0x10000000`, windowed subsystem, static
  CRT, and the USER32/SHELL32/ADVAPI32/VERSION imports.
- `xla_no_installs` — every `injector::`/`safetyhook::`/`Make*`/`WriteMemory`/
  `VirtualProtect`/`IATHook` use is confined to `source/patch.ixx`.
- `xla_module_layout` — one `.ixx` per feature, `dllmain.cpp` the only plain TU,
  the CMake module file set complete.
- `xla_skip_tables` — the readable SkipLauncher rewrite's 71 recovered records
  against the old addon's golden (`tests/skip_launcher_tables.tsv`).

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
- the user-data redirect as the game actually queries it: the timing of the
  `DllMain` install against `__initalizePaths` (`0x856BF0`) and the savegame
  resolver (`0x61E770`), and the resulting `Savefiles\Rockstar Games\GTA IV\{savegames,Settings,
  User Music}` layout;
- the save-file CRC32 bypass against real save data;
- interaction with FusionFix installed at the same time, for the user-data
  divergence and the windowed gates.

Nothing above is claimed as verified in the final report.
