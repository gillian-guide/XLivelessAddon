# Compatibility

## GTA IV / EFLC builds

The add-on recognises the executable by the classification dword the original read at
`0x608C34 + base - 0x400000`:

| id | build |
| --- | --- |
| 1000 | 1.0.0.0 |
| 1010 | 1.0.0.0 (the original's intermediate id) |
| 1020 | 1.0.0.x (the original's intermediate id) |
| 1030 | 1.0.3.0 (the original's intermediate id) |
| 1040 | 1.0.4.0 |
| 1050 | 1.0.5.0 (the original's intermediate id) |
| 1060 | 1.0.6.0 |
| 1070 | 1.0.7.0 |
| 1080 | 1.0.8.0 |
| 1100 | 1.1.0.0 (EFLC) |
| 1110 | 1.1.1.0 (TLAD) |
| 1120 | 1.1.2.0 (TBoGT) |
| 1130 | 1.1.3.0 (EFLC) |

The ids are the original add-on's compact ids. An unrecognised build installs **nothing** and the
log says so. The per-patch comments in `source/patches.ixx` keep the original's build ranges
(`[v1002 - v1008]`, ...); signatures missing on the running build are skipped, never guessed.

## GTAIV.EFLC.FusionFix

FusionFix owns several subsystems this add-on also implements. When a `*FusionFix*.asi` is
present the add-on switches the overlapping options off before installing anything:

| Option | FusionFix module | Why |
| --- | --- | --- |
| `SkipIntro` | `skipintro.ixx` | Two intro-duration hooks would fight over the same value. |
| `SkipMenu` | `skipintro.ixx` | FusionFix's menu skip is newer and has a savegame guard. |
| `BorderlessWindowed` | `windowed.ixx` | Two window managers would fight over styles and position. |
| `DoNotPauseOnMinimize` | `windowed.ixx` | Same focus-loss handling. |
| `VRAMFix` | `memory.ixx` | FusionFix owns the VRAM detection. |
| `LocalSettingsPath` | `userdata.ixx` | Both redirect the shell user-data folders. |
| `CustomSavePath` | `userdata.ixx` | Overlaps `CustomUserProfilePath`. |
| `CustomSettingsPath` | `userdata.ixx` | Overlaps `CustomUserProfilePath` (and is not hooked here anyway). |

`XLivelessAddon.log` records each gate (`fusionfix: gating SkipIntro (FusionFix skipintro.ixx)`),
so "the option did nothing" always has an explanation.

## OpenPreCEPatch

OpenPreCEPatch is a separate ASI with a separate INI and write set. The two modules can be
installed together: neither patches the other's sites, and the add-on's `CreateFile` hook
forwards through the game's IAT slot, so an IAT detour OpenPreCEPatch installed keeps working.

OpenPreCEPatch does not build, ship or require XLivelessAddon.

## Other ASIs / xliveless

* `SkipLauncher` replaces the launcher/SecuROM checks; do not combine it with another launcher
  bypass (the old `xlive.dll` wrapper, another XLivelessAddon build, Steam's own shim).
* The add-on patches the game module only; it does not hook other ASIs.
* IAT replacements (`CreateWindowEx*`, `MoveWindow`, `AdjustWindowRect`, `SetWindowPos`,
  `SetWindowLongA`, `SetRect`, `SHGetFolderPath*`, registry imports) are installed only for the
  game module's own import table and remember the previous slot value, so a detour installed
  before it is preserved.

## Load order

The add-on installs everything synchronously in `DLL_PROCESS_ATTACH`, like the original: the DRM
has already rewritten the game's import-time code by then, and signatures must be matched against
the final image. ASIs that defer their scans can still be installed first; nothing here depends
on another ASI's writes.
