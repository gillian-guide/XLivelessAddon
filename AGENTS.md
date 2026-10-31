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
- `source/dllmain.cpp`, `source/ini_file.cpp` — the only plain translation units.
- `source/patch.ixx` — the primitive store helpers (Hooking.Patterns for scans, injector for
  writes); every helper logs applied/missing.
- `source/patches.ixx` — the recovered patch list, in the original handler's order; its scan
  sequence is pinned by `tests/signature_golden.tsv` (CTest `xla_signature_parity`).
- `source/addon.ixx` — the entry pipeline: it executes the order that
  `source/order.ixx` declares (phases + named `after`/`prerequisites` edges, a
  deterministic topological sort with cycle detection).
- `source/skip_launcher.ixx` — the recovered launcher tables and hook bodies. **Do not "clean
  up" the tables**: signature strings, offsets, stored bytes and stage order are recovered data.
- `external/` — pinned submodules (injector + its nested safetyhook/bddisasm/kananlib/minhook,
  Hooking.Patterns, IniReader). Init recursively.
- `tests/test_main.cpp` — native tests; no game files needed. `tests/signature_golden.tsv` is the
  recovered scan list (CTest `xla_signature_parity`), and `tools/module_layout.py` checks the
  `.ixx` layout (CTest `xla_module_layout`).
- `README.md` — install, features, supported builds and the build commands.

## Build and test

```
cmake --preset win-x86
cmake --build --preset release
ctest --preset release
```

Win32 only (the game is 32-bit; the hook bodies assume x86). `ctest` runs the native suite plus
three checks: the recovered signature list/order (`xla_signature_parity`), the `.ixx` layout
(`xla_module_layout`, needs Python 3) and the PE test (`xla_asi_headers`). The PE test asserts the
artifact is a 32-bit DLL based at `0x10000000` with the GUI subsystem, a USER32 import and the
static CRT (`/MT`; an MSVCP140/VCRUNTIME140 import is a failure, so the game folder needs no
Visual C++ redistributable).

Rules learned the hard way:

1. **Modules:** standard headers belong in `common.hxx`; include it in the `module;` global
   fragment, then `import`. Including a std header after an `import` breaks MSVC's `istream`.
2. **mINI/IniReader must stay in a plain TU** (`ini_file.cpp`). In module purview MSVC's
   serialisation of its stream internals is unreliable (it crashes at runtime).
3. **`__declspec(naked)` on an exported module member is rejected by MSVC.** Assemble the opcodes
   instead (`rom::RomSetStub`) or use a plain TU. The one internal-linkage naked body
   (`SkipIntroBody` in `patches.ixx`) does compile in module purview on MSVC 2026; do not add new
   ones.
4. **Hook bodies are ABI contracts**: `CreateFile` is `__cdecl` (plain `ret`), `RomSet` is
   `ret 8` with the object in `ESI`, `SkipIntro` tail-jumps through `g_skipIntroResume` (never a
   `call`). Do not add parameters or change calling conventions.
5. **Recovered rows are 1:1.** Keep the signature comments' build ranges and the original order.
   New rows/guards are allowed only as documented fail-safes (log instead of fault).
6. **Log everything.** Every installer and every store logs, so a bug report names the build and
   the failing patch. The log's first line carries the version + git SHA.
7. **Every install is INI-gated**, and FusionFix-owned options are gated off before installing.

## Dependency policy

Submodules stay pinned. Bumping one = update `NOTICE` (revision + licence), rebuild, run the
tests, and commit `deps: bump <name> to <sha>`. Don't import code from a submodule into `source/`
without attribution and licence compatibility.

## Git

Commit coherent checkpoints on `master`; never push, tag or publish without the user asking. A
commit that changes behaviour says why in its message. Message style: `area: summary`
(e.g. `fix: never write past the caller's buffer`).

## Docs

The README describes the current code. When behaviour or the build changes, update it in the same
commit; no session narration.
