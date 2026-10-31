# Building

## Requirements

* Windows 10/11.
* Visual Studio 2022 (v17.10 or newer) or Visual Studio 2026, with the **Desktop development
  with C++** workload and the **x86** toolset. The ASI is a 32-bit DLL because the game is 32-bit.
* CMake 3.28 or newer.
* Git, for the pinned submodules.
* PowerShell (the PE verification test uses it; `pwsh` or Windows PowerShell 5.1).

## First build

```bat
git clone --recursive https://github.com/OpenZDecomp/XLivelessAddon.git
cd XLivelessAddon
cmake --preset win-x86
cmake --build --preset release
ctest --preset release
```

`cmake --preset win-x86` configures `build/win-x86` with the "Visual Studio 18 2026" generator and
`-A Win32`. On a machine with VS 2022 use `--preset win-x86-vs2022` and
`--preset release-vs2022` instead; CMake picks the matching toolset.

Artifacts are written to `build/win-x86/bin/`:

| File | Purpose |
| --- | --- |
| `XLivelessAddon.asi` | the add-on |
| `XLivelessAddon.ini` | the INI copied from `data/XLivelessAddon.ini` |
| `XLivelessAddon.map` | linker map (symbol addresses, useful for crash reports) |

## Configuring by hand

Presets are a convenience; the underlying commands are:

```bat
cmake -S . -B build/win-x86 -G "Visual Studio 18 2026" -A Win32
cmake --build build/win-x86 --config Release
ctest --test-dir build/win-x86 -C Release --output-on-failure
```

CMake options:

| Option | Default | Effect |
| --- | --- | --- |
| `XLA_BUILD_TESTS` | `ON` | build `xla_tests` and register the CTest tests |
| `XLA_GAME_DIR` | empty | copy the ASI and INI into this folder after every build |

## Deploying to the game folder

```bat
cmake --preset win-x86 -DXLA_GAME_DIR="D:/Games/GTA IV"
cmake --build --preset release
```

or with the environment variable when using the deploy preset:

```bat
set GTAIV_DIR=D:\Games\GTA IV
cmake --preset win-x86-deploy
cmake --build --preset release
```

`tools/deploy.ps1` does the same for an already-built ASI:

```powershell
powershell -ExecutionPolicy Bypass -File tools/deploy.ps1 -GameDir "D:\Games\GTA IV"
```

Close the game before replacing the ASI; Windows keeps the DLL loaded otherwise.

## Packaging

```bat
cmake --build --preset package
```

produces `build/win-x86/XLivelessAddon-<version>.zip` (CPack, ZIP generator) with the ASI, the INI,
the README, the changelog and the licence files at the archive root, ready to drag into the game
folder. `CPACK_PACKAGE_CHECKSUM SHA256` also emits a `.sha256` next to the archive.

## Debug build

`cmake --build --preset debug` builds the same targets with the debug runtime and symbols
(`build/win-x86/bin/XLivelessAddon.pdb`). Debug and release use the same static CRT policy
(`/MT`), so a debug ASI can coexist with the release one but should not be installed at the same
time as the release ASI.

## Versioning

`project(XLivelessAddon VERSION 1.1.0 ...)` in `CMakeLists.txt` drives the version string, the
generated `xla/version.hpp` and the PE version resource. When building from a git checkout the
short SHA is appended (`1.1.0-abc1234`) and logged at startup, so a log always identifies the
exact binary.

## Troubleshooting the build

* *"Missing external/... Initialise the submodules"* – run
  `git submodule update --init --recursive` (recursive matters: injector contains its own
  submodules).
* *"Configure for Win32"* – the generator was not given `-A Win32`; delete the build directory
  and reconfigure with the preset.
* *"naked can only be applied to non-member function"* – a `__declspec(naked)` body leaked into a
  module; the ROM `ret 8` body is assembled as opcode bytes in `skip_launcher.ixx` for exactly
  this reason.
* *`istream`/`sentry` errors* – a standard header was included after an `import`. Include
  `common.hxx` first, then import.
