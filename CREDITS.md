# Credits

XLivelessAddon is a modernised reimplementation of the community XLivelessAddon
add-on for GTA IV / Episodes from Liberty City. It is meant to run next to
[OpenPreCEPatch](https://github.com/OpenZDecomp/OpenPreCEPatch) and
[GTAIV.EFLC.FusionFix](https://github.com/ThirteenAG/GTAIV.EFLC.FusionFix).

- **GTAmodding / XLivelessAddon contributors** — the original add-on: the
  launcher bypass, the save-file path redirect, the WM_ROM message window and the
  borderless window patches. Released into the public domain.
- **Zolika1351** — ZolikaPatch, whose recovered SkipLauncher tables, DFA
  file-API behaviour and legacy launcher stage this module reimplements.
  ZolikaPatch was distributed as a closed ASI; no original source is
  redistributed.
- **ThirteenAG and the FusionFix contributors** — GTAIV.EFLC.FusionFix
  (GPL-3.0), which supplied the windowed/focus-loss implementation, the
  SHGetFolderPath user-data redirect, the FusionFix notice shape, the
  `SkipIntro`/`SkipMenu` mechanism (`source/skipintro.ixx`, copied into
  `source/menu.ixx`), the `grcDevice::GetAvailableVideoMemory` replacement and
  its value contract (`source/memory.ixx`, copied into `source/vram.ixx`) and
  the overall module layout conventions.
- **LINK/2012 and ThirteenAG** — the `injector` memory-patching library.
- **CitizenFX / NTAuthority** — `Hooking.Patterns`.
- **ThirteenAG** — `IniReader`; **Danijel Durakovic** — `mINI`.

The signature tables, the hook bodies and the write behaviour were recovered
from the shipped binaries; `source/launcher.ixx`,
`source/launcher_recovered.inc`, `source/core.ixx` and `source/vram.ixx` carry
the provenance comments.
