# Differential dump (650df11 -> current)

The refactor passes claim that `ApplySkipLauncher`'s behaviour is unchanged. This harness is the
evidence: it replaces `tests/test_main.cpp`, prints every launcher table row and the exact
changed-byte ranges for every scenario, and was run against two builds.

## Files

- `dump_650df11.cpp` — harness for the pre-refactor tree (`650df11`), using the old
  `SkipLauncherEntry`/`SkipLauncherWrite` API.
- `dump_650df11.txt` — its 354-line output.
- `dump_head.cpp` — the same harness against the current typed `EntryPatch`/`PatchOp` API; every
  other line is identical.
- `dump_head.txt` — its output, re-run on 2026-10-31 after the B1/B2 settings fix; comparable
  byte-for-byte with `dump_650df11.txt` (`Compare-Object`/`fc` report no differences).

## Method

1. Copy one `.cpp` over `tests/test_main.cpp`.
2. `cmake --build --preset release --target xla_tests`.
3. `build/win-x86/bin/xla_tests.exe data build/test-work > <out>.txt` (use `cmd /c` so the file is
   raw UTF-8, not PowerShell's UTF-16 redirection).
4. Restore `tests/test_main.cpp` with `git checkout -- tests/test_main.cpp`.

The `650df11` side is built from a temporary worktree:

```
git worktree add .scratch/base-tree 650df11
# junction/copy external/ into the worktree (submodules are not initialised by worktree add)
cmake --preset win-x86 -B build/win-x86      # from the worktree root
copy tests/differential/dump_650df11.cpp tests/test_main.cpp
cmake --build --preset release --target xla_tests
build/win-x86/bin/xla_tests.exe data build/test-work > dump_650df11.txt
```

`dump_head.cpp` is built the same way in this tree. The two outputs are identical.

## What it covers

- all 25 main-table entries, each in isolation and all together;
- the two collectors with 1, 2, 3 and 5 hits each;
- every stage combination with and without a resolver (`main`, `dfa`, `rom`, `dfa|rom`, `all`);
- the DFA capture/publication, the six DFA installs, the collected jumps and the two ROM installs;
- the bounds failures (entry 0 at the image tail, `read_file`/`rom_set` before the image) and the
  empty-image error;
- the resolved hook bodies: CreateFile forwarding (slot and direct), DfaInit's return and the
  RomSet byte window.

Hook-branch rel32 bytes are canonicalised to the hook name because they name the ASI's own body
addresses, which move between builds; every non-hook byte and every file offset is raw. These
files are evidence only and are not compiled by the normal build (they would replace the native
suite).
