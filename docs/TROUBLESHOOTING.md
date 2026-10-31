# Troubleshooting

Start with `XLivelessAddon.log` in the game folder. It is append-only and records the version, the
INI paths, the effective options, the FusionFix gate decisions, the detected build and one line per
patch.

## The game does not start / hangs on a black screen

* `SkipMenu=0` still skipped the menu? Check the log for `menu: skip installed`; if it is there
  while the INI says `0`, you have a stale ASI. The first log line carries the version/SHA.
* `init: probe never appeared` – the executable is not one the add-on knows (or another tool
  already modified its code). Nothing was installed.
* `init: unsupported build` – the build-classification dword is unknown. Nothing was installed.
* `init: image is not writable` – `VirtualProtect` failed on `.text`/`.rdata`; the module installed
  nothing (the original terminated the process instead).

## An option does nothing

Search the log for the option's patch name. Typical lines:

* `fusionfix: gating <Option> (FusionFix <module>)` – FusionFix is installed and owns that
  subsystem; uninstall it or disable its feature.
* `...: signature missing` – the pattern is not present on this build (expected on builds the
  original did not support for that row).
* `skipLauncher: failed with code ...` – the recovered stage rejected the image; the detail says
  which store was out of bounds.

## Saves or settings go to the wrong place

* `CustomSavePath` is applied by replacing the game's path builder; the log line
  `savegames: game default path = "..."` shows what was captured.
* `CustomSettingsPath` is **not hooked** in this build. Use `LocalSettingsPath` (moves both saves
  and settings to `<game>\saves`) or FusionFix's `userdata.ixx`.
* When FusionFix is present, both custom paths are gated off on purpose.

## The borderless window is not centred / has a frame

FusionFix also patches `windowed.ixx`; with FusionFix installed the add-on's window options are
gated off by design. Without FusionFix, check `window: borderless=1` in the log. `borderless=0`
means the USER32 import slots were not found (for example because another tool resolved them
earlier).

## The INI is ignored after editing it with an editor that saves LF

The loader rewrites an LF-only INI to CRLF on first use and logs `config: normalized ... to CRLF`.
If the file is read-only, the rewrite cannot happen; the log then says `cannot read ...; using
defaults` and the embedded defaults are used.

## Antivirus / Windows Defender

The ASI patches the game's executable in memory and replaces a few imports. False positives are
possible; the binary is built from this repository's source in CI, so verify the hash against the
release notes if in doubt.

## Diagnosing a crash

* The last line before the crash names the installer.
* `build/win-x86/bin/XLivelessAddon.map` maps addresses to functions.
* A debug ASI (built with `--preset debug`) drops `XLivelessAddon.pdb` next to it; a debugger can
  then symbolise the crash. Do not ship the debug ASI.
