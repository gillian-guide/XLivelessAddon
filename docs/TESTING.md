# Testing

## Native test suite

`ctest --preset release` runs two tests:

1. **`xla_tests`** — a console executable importing the add-on's modules. It needs no game files
   and no network.
2. **`xla_asi_headers`** — a PowerShell PE check of the built ASI
   (`tools/verify_asi.ps1`).

### What the unit tests cover

| Area | Checks |
| --- | --- |
| Default INI | the embedded defaults match `data/XLivelessAddon.ini` key for key (the shipped file is the source of truth for a fresh install) |
| Config precedence | own `XLivelessAddon.ini` wins over a legacy `ZolikaPatch.ini`; absent keys fall back; the code defaults are the original's |
| EnsureIni | the file is created once and never rewritten afterwards |
| LF normalisation | an LF-only INI is parsed after the one-time CRLF rewrite |
| FusionFix gates | all six options plus both custom paths are switched off and reported, and the second pass is a no-op |
| Build table | all 13 recovered signatures round-trip; unknown values and truncated images are rejected |
| Patch primitives | byte/word/nop/ret/jump/call stores land at the right offsets, the jump displacement is measured correctly, `Call` returns the previous target, an empty `Site` is a no-op |
| Savegame paths | default vs custom base, name joining, bounded C-string reads |
| Registry helpers | `Rockstar Games`/`InstallFolder` matching, install-folder answer form |
| User data | the CSIDL set that `LocalSettingsPath` redirects |
| Windowed guards | the IAT hooks refuse to run outside the real game module |
| ROM stub | the assembled `ret 8` bytes match the original instruction |
| SkipLauncher tables | 25 entries, the known write rows/fills/jump target, the collector and DFA/ROM row counts |
| SkipLauncher install | missing signatures are skipped and reported; an empty image is invalid input; an out-of-bounds store is an error; the main rows apply at the right offsets; the CreateFile slot is captured, published, forwarded through and cleared by a later capture-less pass |

### Running a single test binary by hand

```bat
build\win-x86\bin\xla_tests.exe data build\win-x86\test-work
```

`argv[1]` is the `data/` directory (the shipped INI), `argv[2]` the work directory for temporary
files (absolute or relative; defaults to `./xla-test-work`). The test prints each case name before
running it, so a crash points at the last printed line.

The tests intentionally avoid `%TEMP%`: it can be locked down on hardened machines and the
workspace contract keeps scratch files under the build tree.

## Continuous integration

`.github/workflows/build.yml` on `windows-latest`:

1. checks out with `submodules: recursive`;
2. configures `-A Win32 -G "Visual Studio 17 2022"`;
3. builds Release;
4. runs `ctest`;
5. builds the CPack zip and uploads `dist/*.zip`, the ASI and the map as artifacts;
6. on a version tag, attaches the zip to a GitHub release.

## Live test checklist

The unit tests cannot launch the game. When changing anything that installs a patch, verify in
game and read `XLivelessAddon.log`:

1. Copy `XLivelessAddon.asi` and `XLivelessAddon.ini` into the game folder (game closed).
2. Delete the old `XLivelessAddon.log`.
3. Start the game (through `PlayGTAIV.exe` when `SkipLauncher=1`).
4. Check the log:
   * first line has the new version/SHA;
   * `build=1080` (or your build);
   * `ini=...` points at the INI you edited;
   * `skipLauncher: ...` shows `dfa=6/0 rom=2/0` on a supported build;
   * each enabled option has `applied` lines; missing signatures are expected on other builds;
   * `init complete` is the last line.
5. Spot-check the features: launcher skipped, intro short, menu skipped (and SHIFT keeps it),
   borderless window centred, saves land in the configured folder.

If the game crashes, the log's last line identifies the installer that faulted; the map file
(`build/win-x86/bin/XLivelessAddon.map`) turns the crash address into a function name.
