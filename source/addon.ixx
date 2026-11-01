// SPDX-License-Identifier: GPL-3.0-or-later
//
// xla.addon — the init pipeline. The first pass runs synchronously at
// DLL_PROCESS_ATTACH; when the probe is absent it retries the whole pipeline once
// on a worker thread (StepProbe -> DelayedInit). The steps register themselves in
// one constexpr table with a phase (probe, config, install, post); the runner
// executes the phases in order and, inside a phase, the rows in table order. That
// filtered sequence is the original add-on's order, pinned by the 25-name test;
// there is no dependency graph. Every optional installer is INI-gated; the core
// patch list and the savegame CRC32 bypass are unconditional, as in the original.
// An unsupported or non-writable image installs nothing and says why.

module;

#include "common.hxx"

export module xla.addon;

import xla.build;
import xla.common;
import xla.config;
import xla.dfa;
import xla.patches;
import xla.registry;
import xla.rom_window;
import xla.savegames;
import xla.skip_launcher;
import xla.userdata;
import xla.windowed;

export namespace xla
{
    // Entry point called from DllMain. Returns the process exit code the original
    // init used (0 = installed or waiting, 1 = gave up).
    int Run(HMODULE module);

    // The effective step order the runner executes, phase by phase. The native
    // test pins this exact 25-name sequence.
    std::span<const std::string_view> StepOrder() noexcept;
} // namespace xla

namespace xla
{
    namespace
    {
        // The probe signature the original waits for: it proves the executable is
        // the one the add-on knows before any pattern is trusted.
        constexpr std::string_view kProbeSignature = "B0 04 B2 18 B1 20";
        constexpr int kProbeSpinLimit = 10000;
        constexpr DWORD kProbeSleepMs = 1;

        std::atomic<bool> g_delayed{false};

        // Everything a step reads or publishes. Steps are plain functions; the
        // registration table is the only thing that decides the sequence.
        struct RunState
        {
            std::filesystem::path directory;
            config::LoadResult loaded;
            bool fusionFix{};
            Image image;
            build::Id build{build::Id::unknown};
            // Tri-state install results: -1 = option off, 0 = pattern missing, 1 =
            // installed (the original's log legend).
            int borderless{-1};
            int focusLoss{-1};
            int exitCode{0};
        };

        enum class Outcome : std::uint8_t
        {
            next,
            stop,
        };

        bool ProbePresent()
        {
            return !hook::pattern{kProbeSignature}.empty();
        }

        Image CurrentImage()
        {
            auto* base = reinterpret_cast<std::uint8_t*>(::GetModuleHandleW(nullptr));
            if (base == nullptr)
            {
                return {};
            }

            const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            {
                return {};
            }

            const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE)
            {
                return {};
            }

            return {reinterpret_cast<std::byte*>(base), nt->OptionalHeader.SizeOfImage};
        }

        DWORD WINAPI DelayedInit(LPVOID)
        {
            return static_cast<DWORD>(Run(nullptr));
        }

        void LogConfiguration(const config::LoadResult& loaded, bool fusionFix)
        {
            const config::Options& options = loaded.options;
            log::Info("ini={} legacy={} fusionfix={}", loaded.iniPath.string(),
                      loaded.legacyPath.string(), fusionFix ? 1 : 0);
            log::Info("options: launcher={} intro={} menu={} dontPause={} borderless={} vram={} "
                      "webConnect={} registry={} localSettings={} customSave=\"{}\"",
                      options.skipLauncher, options.skipIntro, options.skipMenu,
                      options.doNotPauseOnMinimize, options.borderlessWindowed,
                      options.vramFix, options.skipWebConnect,
                      options.removeRegistryPathDependency, options.localSettingsPath,
                      options.customSavePath);
        }

        // ---- the steps (registered in kSteps below, in this order) -------------

        Outcome StepBanner(RunState&)
        {
            log::Banner();
            return Outcome::next;
        }

        Outcome StepConsole(RunState&)
        {
            if (::GetConsoleWindow() != nullptr)
            {
                ::FreeConsole();
            }
            return Outcome::next;
        }

        Outcome StepProbe(RunState& state)
        {
            // The game executable is checked for the probe before anything is trusted.
            if (!ProbePresent())
            {
                if (!g_delayed.exchange(true))
                {
                    log::Write("init: probe missing; retrying on a worker thread");
                    const HANDLE thread =
                        ::CreateThread(nullptr, 0, &DelayedInit, nullptr, 0, nullptr);
                    if (thread != nullptr)
                    {
                        ::CloseHandle(thread);
                    }
                    state.exitCode = 0;
                    return Outcome::stop;
                }

                // Wait for the probe instead of spinning a core forever. Supported
                // builds hit it on the first iterations; an unsupported build gets a
                // log line and an orderly return.
                int spins = 0;
                while (!ProbePresent())
                {
                    if (++spins > kProbeSpinLimit)
                    {
                        log::Write("init: probe never appeared; aborting");
                        state.exitCode = 1;
                        return Outcome::stop;
                    }
                    ::Sleep(kProbeSleepMs);
                }
            }
            return Outcome::next;
        }

        Outcome StepPaths(RunState& state)
        {
            state.directory = paths::ModuleDirectory();
            return Outcome::next;
        }

        Outcome StepConfig(RunState& state)
        {
            state.loaded = config::Load(state.directory);
            return Outcome::next;
        }

        Outcome StepFusionFix(RunState& state)
        {
            state.fusionFix = config::FusionFixPresent(state.directory);
            if (state.fusionFix)
            {
                for (const config::FusionFixGate& gate :
                     config::ApplyFusionFixGates(state.loaded.options))
                {
                    log::Info("fusionfix: gating {} (FusionFix {})", gate.option,
                              gate.fusionFixModule);
                }
            }
            return Outcome::next;
        }

        Outcome StepReportConfig(RunState& state)
        {
            LogConfiguration(state.loaded, state.fusionFix);
            return Outcome::next;
        }

        Outcome StepImage(RunState& state)
        {
            state.image = CurrentImage();
            if (state.image.empty())
            {
                log::Write("init: game image unavailable; no patches applied");
                state.exitCode = 0;
                return Outcome::stop;
            }
            return Outcome::next;
        }

        Outcome StepWritable(RunState& state)
        {
            if (!MakeImageWritable(state.image))
            {
                log::Write("init: image is not writable; no patches applied");
                state.exitCode = 0;
                return Outcome::stop;
            }
            return Outcome::next;
        }

        Outcome StepBuild(RunState& state)
        {
            const std::optional<build::Id> detected = build::Detect(state.image);
            if (!detected)
            {
                // Say what was read: "unsupported" alone cannot distinguish a new
                // build from an image that is not the game at all.
                const std::optional<std::uint32_t> signature = build::ReadSignature(state.image);
                if (signature)
                {
                    log::Info("init: unsupported build; classification dword {:#x} at RVA "
                              "{:#x}; no patches applied",
                              *signature, build::kSignatureOffset);
                }
                else
                {
                    log::Write("init: image is too small for the classification dword; no "
                               "patches applied");
                }
                state.exitCode = 0;
                return Outcome::stop;
            }
            state.build = *detected;
            log::Info("build={}", build::Label(state.build));
            return Outcome::next;
        }

        Outcome StepLocalSettings(RunState& state)
        {
            // LocalSettingsPath owns the shell user-data folders; install it before
            // the game can query them.
            if (state.loaded.options.localSettingsPath)
            {
                userdata::InstallLocalSettingsPath(state.image);
            }
            return Outcome::next;
        }

        Outcome StepSavegames(RunState& state)
        {
            savegames::Install(state.image, state.loaded.options.customSavePath);
            return Outcome::next;
        }

        Outcome StepSkipLauncher(RunState& state)
        {
            if (state.loaded.options.skipLauncher)
            {
                const auto applied =
                    ApplySkipLauncher(state.image.bytes(), &ResolveSkipHook, nullptr,
                                      kShippedStages);
                if (applied)
                {
                    const SkipLauncherReport& report = *applied;
                    // entries/missing/writes/jump are main-table counters; the
                    // shipping path never runs that stage, so label it rather than
                    // letting a healthy log read as "nothing found".
                    log::Info("skipLauncher: stages=dfa|rom main=not-applied entries={} "
                              "missing={} writes={} jump={} dfa={}/{} "
                              "rom={}/{} collected={} createFileSlot={:08X}",
                              report.entriesFound, report.entriesMissing, report.writes,
                              report.jumpInstalled, report.dfaInstalls, report.dfaMissing,
                              report.romInstalls, report.romMissing, report.collectedInstalls,
                              report.createFileSlot);
                }
                else
                {
                    log::Info("skipLauncher: failed with code {} ({})",
                              static_cast<int>(applied.error().code), applied.error().detail);
                }
            }
            return Outcome::next;
        }

        Outcome StepBorderless(RunState& state)
        {
            if (state.loaded.options.borderlessWindowed)
            {
                state.borderless = windowed::InstallBorderlessHooks(state.image) ? 1 : 0;
            }
            return Outcome::next;
        }

        Outcome StepFocusLoss(RunState& state)
        {
            if (state.loaded.options.doNotPauseOnMinimize)
            {
                state.focusLoss = windowed::InstallFocusLossInput(state.image) ? 1 : 0;
            }
            log::Info("window: borderless={} focusLoss={}", state.borderless, state.focusLoss);
            return Outcome::next;
        }

        Outcome StepCorePatches(RunState& state)
        {
            patches::InstallCore(state.image, state.build);
            // The settings redirect is INI-gated inside the installer (empty = off,
            // which is also the FusionFix-gated state).
            patches::InstallCustomSettingsPath(state.image,
                                               state.loaded.options.customSettingsPath);
            return Outcome::next;
        }

        Outcome StepLauncherStage(RunState& state)
        {
            // The launcher helpers only run when the recovered stage is disabled;
            // the original skipped the DFA hooks on EFLC 1.1.0.0/1.1.1.0: DFA there
            // faulted with an unhandled exception at 0x00426440 (0xC0000005), so the
            // crash evidence is the reason for the build test, not a preference.
            if (!state.loaded.options.skipLauncher)
            {
                if (!build::Is(state.build, {build::Id::v1100, build::Id::v1110}))
                {
                    dfa::Install(state.image);
                }
                rom_window::Install(state.image);
            }
            return Outcome::next;
        }

        Outcome StepWebConnect(RunState& state)
        {
            if (state.loaded.options.skipWebConnect)
            {
                patches::InstallWebConnectChecks(state.image);
            }
            return Outcome::next;
        }

        Outcome StepIntro(RunState& state)
        {
            if (state.loaded.options.skipIntro)
            {
                patches::InstallIntro(state.image);
            }
            return Outcome::next;
        }

        Outcome StepMenu(RunState& state)
        {
            if (state.loaded.options.skipMenu)
            {
                patches::InstallMenu(state.image);
            }
            return Outcome::next;
        }

        Outcome StepDoNotPause(RunState& state)
        {
            if (state.loaded.options.doNotPauseOnMinimize)
            {
                patches::InstallDoNotPauseOnMinimize(state.image);
            }
            return Outcome::next;
        }

        Outcome StepDefWindowShims(RunState& state)
        {
            if (state.loaded.options.borderlessWindowed)
            {
                windowed::InstallDefWindowProcShims(state.image);
            }
            return Outcome::next;
        }

        Outcome StepRegistry(RunState& state)
        {
            if (state.loaded.options.removeRegistryPathDependency)
            {
                registry::Install(state.image);
            }
            return Outcome::next;
        }

        Outcome StepVram(RunState& state)
        {
            if (state.loaded.options.vramFix)
            {
                patches::InstallVramFix(state.image);
            }
            return Outcome::next;
        }

        Outcome StepComplete(RunState&)
        {
            log::Write("init complete");
            return Outcome::next;
        }

        // The init phases, in the order the runner executes them. A step
        // registers itself with its phase; there is no dependency graph and no
        // sort.
        enum class Phase : std::uint8_t
        {
            probe,   // prove the executable and set up logging before any read
            config,  // paths, INI, FusionFix gates, image and build detection
            install, // the installers, in the recovered order
            post,    // the final log line
        };

        constexpr Phase kPhases[] = {Phase::probe, Phase::config, Phase::install, Phase::post};

        // Every step registers here: phase, name (the golden's key) and callback.
        // The runner walks the phases in kPhases order and, inside a phase, the
        // rows in table order; that filtered sequence is the effective order,
        // pinned by the 25-name golden test. Only the publish-before-install
        // contracts need an edge, and they are commented at their rows.
        struct Step
        {
            Phase phase;
            std::string_view name;
            Outcome (*run)(RunState&);
        };

        constexpr Step kSteps[] = {
            // probe: nothing reads the image before the probe has seen it.
            {Phase::probe, "banner", StepBanner},
            {Phase::probe, "console", StepConsole},
            {Phase::probe, "probe", StepProbe},

            // config: everything the installers need to decide what to do.
            {Phase::config, "paths", StepPaths},
            {Phase::config, "config", StepConfig},
            {Phase::config, "fusionfix", StepFusionFix},
            {Phase::config, "report-config", StepReportConfig},
            {Phase::config, "image", StepImage},
            {Phase::config, "writable", StepWritable},
            {Phase::config, "build", StepBuild},

            // install: the installers, in the recovered order.
            {Phase::install, "local-settings", StepLocalSettings},
            {Phase::install, "savegames", StepSavegames},
            // The CreateFile slot is captured and published inside
            // ApplySkipLauncher's DFA stage, before its hook jumps are written;
            // that publish-before-install edge is internal to the pass.
            {Phase::install, "skip-launcher", StepSkipLauncher},
            {Phase::install, "borderless-hooks", StepBorderless},
            {Phase::install, "focus-loss", StepFocusLoss},
            {Phase::install, "core-patches", StepCorePatches},
            // SkipLauncher=0 only: xla.dfa + xla.rom_window, the XLivelessAddon
            // copies. skip_launcher.ixx's header lists how its own (ZolikaPatch)
            // copies differ and why they are not merged.
            {Phase::install, "launcher-stage", StepLauncherStage},
            {Phase::install, "web-connect", StepWebConnect},
            // InstallIntro publishes g_skipIntroResume before its MakeJMP; publish
            // after the jump and the body resumes into itself.
            {Phase::install, "intro", StepIntro},
            // InstallMenu captures the original E8 target (MakeCALL returns it)
            // as the resume, in the same call that overwrites the site.
            {Phase::install, "menu", StepMenu},
            {Phase::install, "do-not-pause", StepDoNotPause},
            {Phase::install, "defwindow-shims", StepDefWindowShims},
            {Phase::install, "registry", StepRegistry},
            {Phase::install, "vram", StepVram},

            // post: the run is over, say so.
            {Phase::post, "complete", StepComplete},
        };

        // The effective order: each phase's rows in table order. The test pins the
        // 25 names; a row whose phase is missing from kPhases leaves an empty
        // slot, which fails the static_assert below.
        [[nodiscard]] constexpr std::array<std::string_view, std::size(kSteps)> BuildStepOrder()
        {
            std::array<std::string_view, std::size(kSteps)> order{};
            std::size_t at = 0;
            for (const Phase phase : kPhases)
            {
                for (const Step& step : kSteps)
                {
                    if (step.phase == phase)
                    {
                        order[at++] = step.name;
                    }
                }
            }
            return order;
        }

        inline constexpr auto kStepOrder = BuildStepOrder();

        [[nodiscard]] constexpr bool StepOrderComplete() noexcept
        {
            for (const std::string_view name : kStepOrder)
            {
                if (name.empty())
                {
                    return false;
                }
            }
            return true;
        }
        static_assert(StepOrderComplete());
    } // namespace

    std::span<const std::string_view> StepOrder() noexcept
    {
        return kStepOrder;
    }

    int Run(HMODULE module)
    {
        // The pipeline resolves the executable itself (GetModuleHandleW(nullptr) in
        // CurrentImage); DllMain's handle is kept as the entry-point contract.
        (void)module;

        RunState state;
        for (const Phase phase : kPhases)
        {
            for (const Step& step : kSteps)
            {
                if (step.phase != phase)
                {
                    continue;
                }
                if (step.run(state) == Outcome::stop)
                {
                    return state.exitCode;
                }
            }
        }
        return state.exitCode;
    }
} // namespace xla
