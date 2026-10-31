# Dependencies

All third-party code is pinned as a git submodule under `external/`. Always initialise
recursively: **`git submodule update --init --recursive`**.

## Pinned libraries

| Path | Project | Revision | Licence | Used for |
| --- | --- | --- | --- | --- |
| `external/injector` | [ThirteenAG/injector](https://github.com/ThirteenAG/injector) (LINK/2012) | `1f7c3f9` (master, 2026-10-26) | zlib | `injector::WriteMemory`, `MakeNOP`, `MakeRET`, `MakeJMP`, `MakeCALL`, `ReadMemory` — all header-only (`injector/injector.hpp`). |
| `external/hooking` | [ThirteenAG/Hooking.Patterns](https://github.com/ThirteenAG/Hooking.Patterns) (CitizenFX, NTAuthority) | `460a47b` (master, 2025-03-06) | MIT | All signature scans (`hook::pattern`, `hook::make_range_pattern`). Compiled once into `xla_core`. |
| `external/IniReader` | [ThirteenAG/IniReader](https://github.com/ThirteenAG/IniReader) | `206c4b3` (master, 2026-10-06) | MIT | `CIniReader` for the INI loader, wrapped by `source/ini_file.cpp`. |

## Submodules inside the submodules

`injector` carries four nested submodules. They are checked out by the recursive init and are part
of a complete checkout, even though this build only compiles injector's header-only patching
helpers:

| Path | Project | Licence | Why it is there |
| --- | --- | --- | --- |
| `external/injector/safetyhook` | [cursey/safetyhook](https://github.com/cursey/safetyhook) | Boost 1.0 | Backs injector's `assembly.hpp` (`MakeInline`, `reg_pack`). Not included by this build. |
| `external/injector/bddisasm` | [bitdefender/bddisasm](https://github.com/bitdefender/bddisasm) | Apache-2.0 | Disassembler used by injector's hook helpers. Not compiled. |
| `external/injector/kananlib` | [cursey/kananlib](https://github.com/cursey/kananlib) | Boost 1.0 | Allocator/utility support for safetyhook. Not compiled. |
| `external/injector/minhook` | [TsudaKageyu/minhook](https://github.com/TsudaKageyu/minhook) | BSD-2-Clause | Alternative hook backend. Not compiled. |

`IniReader` vendors `mINI` (MIT, Danijel Durakovic) directly in its tree, so no extra submodule is
involved.

**Why the build avoids `injector/assembly.hpp`:** it requires safetyhook, which fetches Zydis at
configure time (network access) and needs MASM for its x86 mid-hook. A standalone build must work
offline from a plain clone, so inline hooks that need `reg_pack` are not used; the two bodies
that need inline semantics (`SkipIntro`, `RomSet`) are implemented as the original did (a naked
jump body and an assembled-opcode stub).

## Updating a dependency

```bat
git -C external/injector fetch origin
git -C external/injector checkout <new-sha>
git -C external/injector submodule update --init --recursive
git add external/injector
git commit -m "deps: bump injector to <new-sha>"
```

Then rebuild and run `ctest --preset release`; the signature scans and the PE test catch API
breakage immediately. Update the table above (revision and licence) in the same commit.

## Licences

This repository is GPL-3.0-or-later. `NOTICE` lists every dependency and its licence; the full
licence texts stay inside their submodule trees (`external/*/LICENSE*`). Do not copy code out of a
submodule into `source/` without keeping the attribution and the licence compatible.
