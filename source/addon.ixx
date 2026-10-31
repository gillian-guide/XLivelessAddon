// SPDX-License-Identifier: GPL-3.0-or-later
//
// xla.addon — the init pipeline. Runs once at DLL_PROCESS_ATTACH, in the
// original add-on's order: probe, configuration, image/build detection, then the
// installers. The order is not hand-written here: `xla.order` declares the steps,
// their phases and their named dependencies, sorts them deterministically, and
// this module executes the result. Every installer is INI-gated; an unsupported
// or non-writable image installs nothing and says why.

module;

#include "common.hxx"

export module xla.addon;

import xla.build;
import xla.common;
import xla.config;
import xla.dfa;
import xla.order;
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

        // Everything a step reads or publishes. Steps are plain functions so the
        // plan's order is the only thing that decides the sequence.
        struct RunState
        {
            std::filesystem::path directory;
            config::LoadResult loaded;
            bool fusionFix{};
            Image image;
            build::Id build{build::Id::unknown};
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

        // ---- the steps (declared in xla.order's Pipeline(), same order) --------

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
            if (!state.loaded.options.customSettingsPath.empty())
            {
                log::Write("settings: CustomSettingsPath is not hooked in this build; use "
                           "LocalSettingsPath or FusionFix userdata.ixx");
            }
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
                log::Write("init: unsupported build; no patches applied");
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
                                      SkipLauncherStage::dfa | SkipLauncherStage::rom);
                if (applied)
                {
                    const SkipLauncherReport& report = *applied;
                    log::Info("skipLauncher: entries={} missing={} writes={} jump={} dfa={}/{} "
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
            return Outcome::next;
        }

        Outcome StepLauncherStage(RunState& state)
        {
            // The launcher helpers only run when the recovered stage is disabled;
            // the original skipped the DFA hooks on EFLC 1.1.0.0/1.1.1.0.
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

        using StepFn = Outcome (*)(RunState&);

        struct StepEntry
        {
            std::string_view name; // must match xla.order::Pipeline() at the same index
            StepFn run;
        };

        // One entry per xla.order::Pipeline() node, in declaration order.
        constexpr StepEntry kSteps[] = {
            {"banner", StepBanner},
            {"console", StepConsole},
            {"probe", StepProbe},
            {"paths", StepPaths},
            {"config", StepConfig},
            {"fusionfix", StepFusionFix},
            {"report-config", StepReportConfig},
            {"image", StepImage},
            {"writable", StepWritable},
            {"build", StepBuild},
            {"local-settings", StepLocalSettings},
            {"savegames", StepSavegames},
            {"skip-launcher", StepSkipLauncher},
            {"borderless-hooks", StepBorderless},
            {"focus-loss", StepFocusLoss},
            {"core-patches", StepCorePatches},
            {"launcher-stage", StepLauncherStage},
            {"web-connect", StepWebConnect},
            {"intro", StepIntro},
            {"menu", StepMenu},
            {"do-not-pause", StepDoNotPause},
            {"defwindow-shims", StepDefWindowShims},
            {"registry", StepRegistry},
            {"vram", StepVram},
            {"complete", StepComplete},
        };

        // The names are the link between the schedule and the functions: a node
        // inserted, removed or renamed without the matching step is a compile
        // error, not a silently different install order.
        [[nodiscard]] constexpr bool StepTableMatchesPipeline() noexcept
        {
            const std::span<const order::Node> pipeline = order::Pipeline();
            if (std::size(kSteps) != pipeline.size())
            {
                return false;
            }
            for (std::size_t index = 0; index < pipeline.size(); ++index)
            {
                if (kSteps[index].name != pipeline[index].name)
                {
                    return false;
                }
            }
            return true;
        }
        static_assert(StepTableMatchesPipeline());

        [[nodiscard]] std::size_t IndexOf(std::span<const order::Node> pipeline,
                                          std::string_view name) noexcept
        {
            for (std::size_t index = 0; index < pipeline.size(); ++index)
            {
                if (pipeline[index].name == name)
                {
                    return index;
                }
            }
            return pipeline.size();
        }
    } // namespace

    int Run(HMODULE module)
    {
        (void)module;

        const std::span<const order::Node> pipeline = order::Pipeline();
        const order::Plan plan = order::Build(pipeline);
        if (!plan.valid)
        {
            for (const std::string& diagnostic : plan.diagnostics)
            {
                log::Info("{}", diagnostic);
            }
            log::Write("init: order invalid; no patches applied");
            return 1;
        }

        RunState state;
        std::vector<bool> executed(pipeline.size(), false);
        for (const std::size_t index : plan.order)
        {
            // `prerequisites` is also enforced by the sorter (a missing target makes the
            // plan invalid); the executor additionally refuses to run a step whose
            // hard prerequisite has not executed, so a future conditional step
            // cannot silently depend on one that was skipped.
            for (const std::string_view required : pipeline[index].prerequisites)
            {
                const std::size_t requiredIndex = IndexOf(pipeline, required);
                if (requiredIndex == pipeline.size() || !executed[requiredIndex])
                {
                    log::Info("init: order prerequisite '{}' for '{}' did not run", required,
                              pipeline[index].name);
                    return 1;
                }
            }

            const Outcome outcome = kSteps[index].run(state);
            executed[index] = true;
            if (outcome == Outcome::stop)
            {
                break;
            }
        }
        return state.exitCode;
    }
} // namespace xla
