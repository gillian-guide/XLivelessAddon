# Architecture

## Why modules

The add-on is organised as C++23 module interface units (`source/*.ixx`) with one plain header
(`source/common.hxx`), following GTAIV.EFLC.FusionFix. Each `.ixx` starts with a `module;`
global fragment that includes `common.hxx`, then `export module xla.<feature>;` and imports
`xla.common` (plus whatever else it needs). Only `dllmain.cpp` and `ini_file.cpp` are plain
translation units.

Two constraints shaped the split:

* mINI (inside IniReader) uses `std::istream` internals that MSVC does not serialise reliably
  from module purview, so the INI parser is wrapped by `ini_file.cpp`, a plain TU, and exposed to
  modules through `ini::File`.
* MSVC only accepts `__declspec(naked)` on a non-member function, and every module-scope function
  counts as a member in module purview, so the ROM `ret 8` hook body is assembled into an
  executable page as eleven opcode bytes (`rom::RomSetStub`) instead of an `__asm` function.

## Modules

| Module | Responsibility |
| --- | --- |
| `xla.common` | `Image` (base/size view with `contains`), `PatchError`/`PatchOutcome`, the logger, module paths, `MakeImageWritable` (unprotects `.text`/`.rdata`). |
| `xla.build` | The recovered build-classification table and `Detect` (bounds-checked read). |
| `xla.config` | `Options`, the embedded default INI, `Load` (own INI → legacy `ZolikaPatch.ini` → defaults), the FusionFix gates. |
| `xla.patch` | `Site`, `Find` (first Hooking.Patterns match), and the store helpers (`Write`, `Nop`, `Ret`, `Jump`, `Call`). Every helper logs applied/missing. |
| `xla.skip_launcher` | The recovered main/DFA/ROM tables, the collectors, the CreateFile slot capture, and the ABI-exact hook bodies. |
| `xla.dfa` | The legacy DFA file-API hooks, installed when `SkipLauncher=0` (and not on EFLC 1.1.0.0/1.1.1.0, as in the original). |
| `xla.rom_window` | The legacy WM_ROM message window and the SendMessage bypass, installed when `SkipLauncher=0`. |
| `xla.savegames` | The save-path replacement and the CRC32 bypass. |
| `xla.registry` | The ADVAPI32 IAT replacement that removes the Rockstar Games registry dependency. |
| `xla.userdata` | `LocalSettingsPath`: redirects the shell user-data folders to `<game>\saves`. |
| `xla.windowed` | Borderless IAT hooks, focus-loss input suppression and the legacy DefWindowProc shims. |
| `xla.patches` | The recovered signature table: GFWL/RGSC gating, file-integrity checks, DLC activation, intro/menu skips, VRAM fix. |
| `xla.addon` | The init pipeline (probe, config, image, build, installers, final log). |

`dllmain.cpp` imports `xla.addon` and calls `xla::Run(module)` on `DLL_PROCESS_ATTACH`.

## Init order

The order is the original add-on's; it matters, because later patches assume earlier ones ran:

1. `DllMain` → `xla::Run`.
2. Probe signature `B0 04 B2 18 B1 20`; if missing, retry on a worker thread (bounded, logged).
3. `config::Load` + FusionFix gates + `LogConfiguration`.
4. `MakeImageWritable`; on failure log and install nothing (the original terminated the process).
5. `build::Detect`; unknown → install nothing.
6. `userdata::InstallLocalSettingsPath` (if enabled).
7. `savegames::Install`.
8. `skip_launcher::ApplySkipLauncher` (DFA + ROM stages) when `SkipLauncher=1`.
9. `windowed::InstallBorderlessHooks` / `InstallFocusLossInput` (if enabled).
10. `patches::InstallCore` (the recovered table).
11. Legacy launcher: `dfa::Install` + `rom_window::Install` when `SkipLauncher=0`.
12. `patches::InstallWebConnectChecks`, `InstallIntro`, `InstallMenu`,
    `InstallDoNotPauseOnMinimize`, `windowed::InstallDefWindowProcShims`,
    `registry::Install`, `patches::InstallVramFix` in that order, each gated.

Every installer refuses to run on an unknown build and every store is preceded by a bounds check
on the game image; a site outside the image is an error, never a blind write.

## Hook bodies and ABIs

The bodies the installers jump to are ABI-exact, because the game calls them through a patched
`E8`/`E9` with its own stack and register contract:

* `rom::CreateFileBody` is `__cdecl` with the seven `CreateFileA` arguments: the trampoline is a
  plain `ret`, so a `__stdcall` body would corrupt the stack. It forwards through the IAT slot
  captured from the DFA stage, so a detour another ASI installed there still runs.
* `rom::CloseHandleGuardedBody` wraps `CloseHandle` in SEH and returns `-1` on a fault like the
  original (`or eax,-1` at `0x100047ec`).
* `rom::RomSetBody` (`0x10004610`) is `mov ecx,[esi+1c]; mov [esi+20],ecx; mov al,1; ret 8`;
  the object arrives in `ESI` and the site pushed two arguments the callee must pop. It is
  assembled at install time (see above).
* `patches::SkipIntroBody` is a naked body reached by a 6-byte jump before the load-screen site:
  `imul ecx,ecx,400`, `cmp edx,8000`, then `edx = 300` below that, then a jump through
  `g_skipIntroResume` (the instruction after the jump). The resume is a `jmp`, never a `call`.
* `patches::SkipMenuBody` preserves the original's one-shot `SHIFT` check and forwards to the
  original function.

## Recovered data

The signature strings, offsets, stored bytes and stage ordering come from the ZolikaPatch /
XLivelessAddon binaries and were not rewritten. Two checks keep that honest during refactors:

* a signature-parity script compares the old monolithic `dllmain.cpp` scans with the new modules
  (all 66 scans present, same order, plus the moved launcher/windowed ones);
* the SkipLauncher tables in `skip_launcher.ixx` compare structurally identical to the pre-split
  `skip_launcher.cpp` (entry rows, write rows, collectors, DFA/ROM installs, collected targets).

The unit tests additionally assert the table shape (25 entries, the 447-byte fill, the jump
target) and exercise the installers against synthetic images, including the out-of-bounds path.

## Fail-safes vs the original

This module follows OpenPreCEPatch's policy rather than the reconstruction's 1:1 rule: an
unwritable image, an unknown build or a missing signature is a logged skip, never a fault. On a
healthy supported image the write set is unchanged. `CHANGELOG.md` lists every guard that was
added or fixed.
