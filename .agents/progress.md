# Progress log

Newest last. One dated entry per work round.

## 2026-11-23: the three ported ZolikaPatch keys (LoadDLCs, BenchmarkFix, CombinedRadioFreezeFix)

Ported from `readable-fusion-opcep/` into this companion: `source/episodes.ixx` (LoadDLCs:
the per-build write table, the publish step, the two transcribed bodies and the C++ discovery
pass the struct-fixup body calls) and `source/stability.ixx` (BenchmarkFix's two sites with
their own `+0xD` continuations, and CombinedRadioFreezeFix's `mov eax,19; ret` body). Keys,
defaults and masks are the fork's: LoadDLCs `0x380` [1060,1070,1080], BenchmarkFix `0x49DE2`
(all builds except 1.0.8.0/1.1.3.0), CombinedRadioFreezeFix `0x4BFE2` (all builds). The
original's build ids are mapped once in `xla.common` (`OriginalBuildId`/`BuildInMask`), so the
recovered masks stay verbatim; builds the original mod did not classify (1.0.1.0-1.0.3.0) have
no bit and the keys stay inert there.

Config/INI/startup: three `[Options]` keys (shipped on), the options log line, three
registration steps after the `[COMPATIBILITY]` family, and `AnyInstallEnabled`. The built-in
default INI text in `config.ixx` was reconciled with `data/XLivelessAddon.ini` (it had drifted
after the owner's trim, which was a pre-existing red check in the native suite).

Tests: `TestLoadDLCs`, `TestLoadDLCsDiscovery`, `TestStability` (the recovered rows/masks/body
VAs, the exact write sets on synthetic images, the refusals, and the discovery pass's folder
resolution, id rule and rejections). 672 checks.

Proof: `tools/verify_port_bodies.py` compares the five transcribed bodies with the original
ASI's own bodies at their recovered VAs - 5/5, plus `verify_compat_bodies.py` still 5/5.
`ctest --preset release` 6/6 and `ctest --preset trace` 6/6.

Note for the next round: the discovery pass sets its EDX second return value *after* every
non-trivial local is destroyed. The fork's rebuild sets it before its own `std::string`
destructor, whose `free` clobbers EDX; nothing in the fork observes EDX, which is why the
defect was invisible there.
