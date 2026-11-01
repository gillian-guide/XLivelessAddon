# AGENTS.md — XLivelessAddon (standalone companion to OpenPreCEPatch)

## What this is

A maintained fork of **XLivelessAddon** for GTA IV / EFLC: launcher/SecuROM bypass, save/settings
redirects, GFWL gating, intro/menu skips, borderless window, focus-loss handling and the VRAM
fix. It is its **own repository and build**. It is a *companion* to
[OpenPreCEPatch](https://github.com/OpenZDecomp/OpenPreCEPatch): installed next to it, but never
built, shipped or required by it. Do not add a dependency on the OpenPreCEPatch tree, its INIs or
its sources.

## Layout

- `source/*.ixx` — one C++23 module interface unit per feature (FusionFix layout); `common.hxx`
  is the shared include header. They are listed in the `XLA_MODULES` `CXX_MODULES` file set;
  `tools/module_layout.py` (CTest `xla_module_layout`) fails if a file drifts out of the shape.
- `source/dllmain.cpp` — the entry point. `source/ini_file.cpp` is the plain-TU boundary
  around the all-inline vendored IniReader; those are the only two plain TUs in `source/`.
  The vendored libraries compile their own TUs under `external/` (`Hooking.Patterns.cpp`).
- `source/patch.ixx` — the primitive store helpers (Hooking.Patterns for scans, injector for
  writes); every helper logs applied/missing.
- `source/patches.ixx` — the recovered patch list, in the original handler's order; its scan
  sequence is pinned by `tests/signature_golden.tsv` (CTest `xla_signature_parity`).
- `source/addon.ixx` — the entry pipeline: one `constexpr` registration table of
  `{phase, name, callback}` rows (probe, config, install, post). The runner executes the phases
  in order and the rows in table order; the 25-name golden test pins the effective sequence.
  There is no dependency graph — the publish-before-install contracts are commented at their rows.
- `source/skip_launcher.ixx` — the recovered launcher tables and hook bodies. **Do not "clean
  up" the tables**: signature strings, offsets, stored bytes and stage order are recovered data.
  The main table is a typed patch DSL (`WriteBytes`/`NopFill`/`Jump`); the rows are in-place
  instruction-window patches, not callable bodies.
- `source/windowed.ixx` — the borderless window is **FusionFix's implementation** (`windowed.ixx`
  in GTAIV.EFLC.FusionFix): the User32 import hook chain, style-0 creation, `SwitchWindowStyle`
  (strip style, AdjustWindowRect, SetWindowLong, MoveWindow, ShowWindow) and the MoveWindow
  centring, plus the focus-loss input body (`sub_69F0C0`) and the original add-on's DefWindowProc
  A/W shims. Keep it in step with FusionFix rather than "improving" the sequence.
- `external/` — pinned submodules (injector + its nested safetyhook/bddisasm/kananlib/minhook,
  Hooking.Patterns, IniReader). Init recursively.
- `tests/test_main.cpp` — native tests; no game files needed. `tests/signature_golden.tsv` is the
  recovered scan list (CTest `xla_signature_parity`), and `tools/module_layout.py` checks the
  `.ixx` layout (CTest `xla_module_layout`).
- `README.md` — install, features, supported builds and the build commands.

### FusionFix overlap (what is mirrored, what stays recovered)

`GTAIV.EFLC.FusionFix/source/` implements some of the same features. Mirror its implementation
only where it can be the same one; every overlapping option is already switched off when a
FusionFix ASI is present (`ApplyFusionFixGates`), so the two never hook the same subsystem
together.

- **Mirrored:** the borderless window and centring (`windowed.ixx`, FusionFix's
  `windowed.ixx`), the focus-loss input body (`FocusLossInput` = `sub_69F0C0`) and
  `LocalSettingsPath` (the `SHGetFolderPathA/W` redirect = FusionFix's `userdata.ixx`, with a
  fixed `<game>\saves` folder behind the boolean key).
- **Stays the original add-on's recovered behaviour** (FusionFix's version is a different
  mechanism or hook site, so replacing it would replace a recovered row): `SkipIntro` (300 ms at
  the recovered inline-hook site; FusionFix zeroes the load-screen time at another site and stops
  after the first menu), `SkipMenu` (same `a1 == 0` / SHIFT / `a1 = 6` algorithm; the recovered
  install sites are pinned by `tests/signature_golden.tsv`), `DoNotPauseOnMinimize` (the
  recovered pause-branch NOP plus the mirrored input skip; FusionFix's `ms_bNoBlockOnLostFocus`
  write needs a scan outside the golden), `VRAMFix` (recovered call-site clamp vs FusionFix's
  `grcDevice::GetAvailableVideoMemory` return rewrite, which needs a new scan and D3D/DXGI) and
  `CustomSavePath`/`CustomSettingsPath` (the add-on's path-builder hooks; FusionFix redirects the
  whole user profile instead).
- **No FusionFix counterpart:** `SkipLauncher` (the recovered DFA/ROM tables), `SkipWebConnect`
  and `RemoveRegistryPathDependency`.

## Build and test

```
cmake --preset win-x86
cmake --build --preset release
ctest --preset release
```

Win32 only (the game is 32-bit; the hook bodies assume x86). `ctest` runs the native suite plus
four checks: the recovered signature list/order (`xla_signature_parity`), the recovered launcher
tables and `[v1005]` NOP plan (`xla_table_parity`), the `.ixx` layout (`xla_module_layout`; all
three need Python 3) and the PE test (`xla_asi_headers`). The PE test asserts the
artifact is a 32-bit DLL based at `0x10000000` with the GUI subsystem, a USER32 import and the
static CRT (`/MT`; an MSVCP140/VCRUNTIME140 import is a failure, so the game folder needs no
Visual C++ redistributable).

Rules learned the hard way:

1. **Modules:** standard headers belong in `common.hxx`; include it in the `module;` global
   fragment, then `import`. Including a std header after an `import` breaks MSVC's `istream`.
2. **The vendored IniReader is header-only and all-inline upstream.** mINI crashed when that
   inline code was instantiated in module purview (reproduced in a probe module and in
   `xla.config`), so the reader lives behind `source/ini_file.h` and is compiled only by
   `source/ini_file.cpp` (a plain TU). Module code includes `ini_file.h`, never
   `<IniReader.h>`. Do not move the reader back into module purview; adjust the caller instead.
3. **`__declspec(naked)` on an exported module member is rejected by MSVC.** Assemble the opcodes
   instead (`skip_hooks::RomSetStub`) or use a plain TU. The one internal-linkage naked body
   (`SkipIntroBody` in `patches.ixx`) does compile in module purview on MSVC 2026; do not add new
   ones.
4. **Hook bodies are ABI contracts**: `CreateFile` is `__cdecl` (plain `ret`), `RomSet` is
   `ret 8` with the object in `ESI`, `SkipIntro` tail-jumps through `g_skipIntroResume` (never a
   `call`). Do not add parameters or change calling conventions.
5. **Recovered rows are 1:1.** Keep the signature comments' build ranges and the original order.
   New rows/guards are allowed only as documented fail-safes (log instead of fault).
6. **Log everything.** Every installer and every store logs, so a bug report names the build and
   the failing patch. The log's first line carries the version + git SHA.
7. **Every optional install is INI-gated** (and FusionFix-owned options are gated off before
   installing). The core patch list and the savegame CRC32 bypass are unconditional, as in the
   original.

## Dependency policy

Submodules stay pinned and unmodified. Bumping one = update `NOTICE` (revision + licence),
rebuild, run the tests, and commit `deps: bump <name> to <sha>`. A defect in a vendored library
is either upstreamed (fork + PR) or adapted to in our own code — never committed inside the
submodule. `source/ini_file.cpp` is the example: the all-inline IniReader is kept out of module
purview instead of patching the header. Don't copy a submodule's code into `source/` without
attribution and licence compatibility.

## Git

Commit coherent checkpoints on `master`; never push, tag or publish without the user asking. A
commit that changes behaviour says why in its message. Message style: `area: summary`
(e.g. `fix: never write past the caller's buffer`).

## Docs

The README describes the current code. When behaviour or the build changes, update it in the same
commit; no session narration.
