# Vendored dependencies

These are committed copies, not submodules, so a checkout is complete and the
build is reproducible offline. Do not edit them; adapt in `source/` or upstream
the change.

| Directory | Project | Revision | Licence |
| --- | --- | --- | --- |
| `injector/` | ThirteenAG/injector (classic, header-only) | `fdd277056a9b12e209d58c35a269277391cf955a` | zlib (`injector/LICENSE`) |
| `hooking/` | ThirteenAG/Hooking.Patterns | `460a47bc813085b66c79768531caab1ed5ea96fc` | MIT (`hooking/LICENSE.md`) |
| `inireader/` | ThirteenAG/IniReader | `206c4b343d3cb0d2ca83afd1fccbe71331137a37` | MIT (`inireader/LICENSE`) |
| `inireader/mINI/` | metayeti/mINI | bundled by the above | MIT (`inireader/mINI/LICENSE`) |

The injector is the classic 2017 revision requested by the port's design: it is
header-only and has no nested submodules. `source/patch.ixx` is its only
consumer; every feature module goes through that unit.
