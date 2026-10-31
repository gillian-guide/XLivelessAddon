# INI reference

`XLivelessAddon.ini` lives next to `XLivelessAddon.asi` (the game folder). It is created with
defaults if missing, so a fresh install never runs with an empty configuration.

## Precedence

1. `XLivelessAddon.ini` (any of the sections below).
2. `ZolikaPatch.ini`, if present (legacy users migrating from ZolikaPatch).
3. The code default.

Both INIs are searched section by section, in this order:
`[MAIN]`, `[Options]`, `[COMPATIBILITY]`, `[INPUT]`, `[LOADING]`, `[XLIVELESS]`, `[STABILITY]`,
`[FIXES]`, `[PERFORMANCE]`, `[GRAPHICS]`, `[VEHICLES]`, `[MULTIPLAYER]`, `[EPISODIC]`, `[MISC]`,
`[INTERFACE]`. The first present key wins; a key present with an empty value wins over the
default too.

Boolean values are parsed like the original: `atoi(value) != 0`, so `1`, `2` and `-1` are true,
`0` and any non-numeric text are false. String values may be quoted; the quotes are stripped.

An INI saved with Unix (LF) line endings is rewritten with CRLF once on first load, because the
INI parser splits on CRLF on Windows. If the file is read-only, the options from the LF file are
not parsed and the log records `cannot read ...; using defaults`.

## Keys

| Key | Default (code) | Default (shipped INI) | Notes |
| --- | --- | --- | --- |
| `CustomSavePath` | `""` | `""` | Folder that receives the savegames. Empty keeps the game default. The folder is created when missing. |
| `CustomSettingsPath` | `""` | `""` | **Not hooked in this build.** Parsed and logged; use `LocalSettingsPath` or FusionFix's `userdata.ixx`. |
| `SkipLauncher` | `1` | `1` | Runs the recovered DFA and ROM launcher stages. With `0`, the legacy DFA file-API hooks and the WM_ROM window are installed instead. |
| `RemoveRegistryPathDependency` | `1` | `1` | Answers the `Rockstar Games` install-folder query from the game's own directory. |
| `SkipWebConnect` | `0` | `1` | Skips the GFWL web-connect and health checks. |
| `SkipIntro` | `0` | `1` | Shortens the load screens to 300 ms (never jumps straight to the menu; that hangs IV). |
| `SkipMenu` | `0` | `0` | Skips the main menu. Hold **SHIFT** during startup to reach it. |
| `DoNotPauseOnMinimize` | `0` | `1` | Suppresses the game's pause while the borderless window is unfocused. |
| `BorderlessWindowed` | `0` | `1` | Borderless window kept in sync when the window is created or resized. |
| `VRAMFix` | `1` | `1` | Clamps a non-positive VRAM answer to `INT_MAX` so the settings are not locked out. |
| `LocalSettingsPath` | `0` | `0` | Redirects the shell user-data folders to `<game>\saves` (one redirect covers saves and settings). |

The *code defaults* are the original add-on's defaults. The shipped INI enables the windowed and
intro options explicitly, which is why a fresh install behaves like the original distribution.

## FusionFix gating

When a `*FusionFix*.asi` is present next to the game executable, the following keys are forced
off and the log names the FusionFix module that owns the subsystem:

| Key | FusionFix module |
| --- | --- |
| `SkipIntro` | `skipintro.ixx` |
| `SkipMenu` | `skipintro.ixx` |
| `BorderlessWindowed` | `windowed.ixx` |
| `DoNotPauseOnMinimize` | `windowed.ixx` |
| `VRAMFix` | `memory.ixx` |
| `LocalSettingsPath` | `userdata.ixx` |
| `CustomSavePath` | `userdata.ixx` |
| `CustomSettingsPath` | `userdata.ixx` |

The gating runs before any patch is installed, so two modules never write the same code.

## Log

`XLivelessAddon.log` is appended to on every launch. The first line is the add-on version and git
SHA, followed by the INI paths, the effective options, the FusionFix gate decisions, the detected
build, and one line per patch (`name: wrote ... at VA`, `name: signature missing`, ...).
