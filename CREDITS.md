# Credits

XLivelessAddon is a maintained, modernised continuation of the community
XLivelessAddon add-on for GTA IV / Episodes from Liberty City. It is meant to
run next to [OpenPreCEPatch](https://github.com/OpenZDecomp/OpenPreCEPatch) and
[GTAIV.EFLC.FusionFix](https://github.com/ThirteenAG/GTAIV.EFLC.FusionFix).

- **GTAmodding / XLivelessAddon contributors** — the original add-on: the
  launcher bypass, the save-file path redirect, the WM_ROM message window and
  the borderless window patches. Released into the public domain.
- **Zolika1351** — ZolikaPatch, whose recovered SkipLauncher tables, GFWL
  bypasses and intro/menu behaviour this module reimplements. ZolikaPatch was
  distributed as a closed ASI; no original source is redistributed.
- **ThirteenAG and the FusionFix contributors** — GTAIV.EFLC.FusionFix
  (GPL-3.0), which supplied the windowed/focus-loss implementation, the 300 ms
  intro-skip variant, the per-feature FusionFix compatibility gates and the
  overall module layout conventions.
- **LINK/2012 and ThirteenAG** — the `injector` memory-patching library.
- **cursey** — `safetyhook`, `kananlib`; **Bitdefender** — `bddisasm`;
  **Tsuda Kageyu** — `minhook` (nested `injector` submodules).
- **CitizenFX / NTAuthority** — `Hooking.Patterns`.
- **ThirteenAG** — `IniReader`.

The signature tables, the hook bodies and the write behaviour were recovered
from the shipped binaries; `source/skip_launcher.ixx` and `source/patches.ixx`
carry the provenance comments.
