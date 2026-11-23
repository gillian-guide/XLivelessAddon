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

## 2026-11-23: SkipLauncher main stage restored (Clean Getaway / SECUROM spot checks)

Root cause of the "Clean Getaway garage door never opens / no carwash call" symptom: the
companion shipped `SkipLauncher` as `dfa|rom` only. The main table (handler `0x10045CE0`) is
where the two multi-hit collectors run, and those collectors are the SecuROM spot-check bypass.
Pattern `A1 ? ? ? ? 85 C0 8B 0D ? ? ? ? 75` matches the game's `SECUROM_SPOT_CHECK1`/`3` bodies
at `0xB4FAA0`/`0xB4FAD0`; the second pattern's last two matches are `0xB4FAC0`/`0xB4FB00`. The
collectors write `B0 01 C3 90` (`mov al,1; ret; nop`). The mission script proves the gate:
`vlad3.sco` (decompiled `vlad3.txt`, line 100) calls `SECUROM_SPOT_CHECK3()` and only then runs
`sub_25982()`, which opens garage `bs3MG` (lines 3293-3295) and advances `l_U556` (3297). The
native is registered at game `0xB527D9` (`push 0xB51380; push 0x5D1C0A6A; call 0x625620`), its
handler `0xB51380` calls `0xB4FAD0`; unpatched, that check reads the SecuROM counter/guards and
returns false, so state 3 is skipped. `LaunchWithPlayGTAIV` is unrelated: it only passes the
startup launcher-name check (SRLC10).

Fix: `kShippedStages` is `main|dfa|rom`; `ShippedStagesFor(build)` is `main|rom` on EFLC
(the original DFA handler returns for product versions 10-13 at `0x100048A2`; the DFA path
faults at `0x00426440`). The collector log now names the applied site and bytes, and the install
line reports entries/writes/collectors/collectorWrites. The old "main broke the GFWL session"
note described applying the table a second time after the addon's own process patches; this tree
applies it once (the fork's pre-removal launcher also skipped main/DFA when an `XLivelessAddon.asi`
was present, so there was never a double main/DFA install).

1.0.8.0 write set of the shipped launcher pass (game base 0x400000): main `0x49017D` <- 90*6;
`0x48FE8D` <- `33 C0 E9 4A 02 00 00` (to `0x4900DE`); `0x4900E3` <- `90 A3`; `0x4905C5` <- 90*16;
`0x4903C2` <- 90*14; collectors `0xB4FAA0`/`0xB4FAC0`/`0xB4FAD0`/`0xB4FB00` <- `B0 01 C3 90`;
DFA branches `0x455EFC`, `0xD17CD3`, `0xD17E6B`, `0xD17E92`, `0xD17EE1`, `0xD17D38`; collected
jumps `0x4701B7`/`0x47031B` -> `0x470278`/`0x4703DC`; ROM `0x48FE46`/`0x490A20`. Tables vs the
old addon golden: 71/71 records. Both presets: 6/6 ctest, 674 native checks.

## 2026-11-23: the StartupWarnings key is gone; the shipped INI is the owner's live file

`StartupWarnings` is no longer an option: it is out of the options struct/table, the built-in
and shipped INI, the `options:` log line, `TestAllOff`'s key list and the two config checks that
asserted its default/all-off state (672 native checks now, down from 674). The behaviour is
unchanged because the key's shipped default was on: the old-loader dialog and the FusionFix
notice now run unconditionally in the same `FusionFix` step, and the fatal loader/version/loaded-
twice checks were already unconditional (`source/startup.ixx` still registers the warnings step).
`data/XLivelessAddon.ini` and `config::kDefaultIni` were resynced to the owner's live
`game_refs/XLivelessAddon.ini`: same order, comments and values (including
`CustomUserProfilePath=./Savefiles`), plus the three ported fixes after the `[COMPATIBILITY]`
marker, and with the warning key removed. The two defaults are byte-identical (the native suite
compares them). README gained the startup-warnings section in its always-on wording. Release and
Trace: 6/6 ctest, 672 checks each.

