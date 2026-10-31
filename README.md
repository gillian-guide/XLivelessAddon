# XLivelessAddon (successor)

A maintained fork of [XLivelessAddon](https://github.com/GTAmodding/XLivelessAddon) for GTA IV / EFLC. Adds improved implementations from [FusionFix](https://github.com/ThirteenAG/GTAIV.EFLC.FusionFix/) and [ZolikaPatch](https://github.com/gillian-guide/ZolikaPatch). Made to be used as a companion to [OpenPreCEPatch](https://github.com/gillian-guide/OpenPreCEPatch).

## Features

* Custom save path and custom settings path
* Remove registry path dependency
* Skip web connect / GFWL gating checks
* Skip intro and skip menu
* Do not pause on minimize
* Borderless windowed
* VRAM detection fix
* GFWL checks disabler

## Improvements

- Improved SkipLauncher from ZolikaPatch
- Improved SkipIntro, SkipMenu and LocalSettingsPath from FusionFix
- Compatibility with FusionFix and OpenPreCEPatch
- Better codebase with improved stability and readability in FusionFix's style

## Build

From the OpenPreCEPatch repository root:

```bat
cmake -S . -B build -A Win32
cmake --build build --config Release
```

Outputs `build/Release/XLivelessAddon.asi` and `XLivelessAddon.ini`.

Premake also defines the `XLivelessAddon` project; build it with the same Win32 Release configuration.

## Modernisation status

The code compiles against the modern submodules and uses CMake/premake. The
inline hooks that required safetyhook/C++23 (`CustomSettingsPath`, the intro
duration hook) were rewritten or deferred; the rest is the original pattern
set. Improvements are tracked in the repository history and should be applied
here first, then mirrored into OpenPreCEPatch only when they are not
XLivelessAddon-specific.

