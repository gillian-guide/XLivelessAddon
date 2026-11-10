// SPDX-License-Identifier: GPL-3.0-or-later
//
// xla.startup - the startup driver: one synchronous pass in DllMain, in the
// FusionFix tier shape. Ported from the pipeline in
// openprecepatch/xlivelessaddon/source/addon.ixx.
//
// `Game` is filled once, every feature subscribes one handler to `onInitEvent`,
// and the driver runs the tier. There is no install tier separate from init: the
// install handlers follow the context handlers in subscription order and check
// `Game::Stopped()` themselves, exactly like the old addon's two event tiers did
// after the pipeline was flattened. The first pass runs synchronously at
// DLL_PROCESS_ATTACH; the probe step schedules its one retry on a worker thread
// when the executable's signature has not appeared yet.

module;

#include <common.hxx>

export module startup;

import common;
import patch;
import build;
import config;
import warnings;
import probe;
import savegames;
import registry;
import userdata;
import settings_path;
import skip_launcher;
import dfa;
import rom_window;
import windowed;

export namespace xla::startup
{
    // Entry point called from DllMain. Returns the process exit code the original
    // init used (0 = installed or waiting, 1 = gave up).
    int Run(HMODULE module);

    // Called from DLL_PROCESS_DETACH: runs the shutdown tier and closes the log.
    void Shutdown();

    // The registration order the native test pins. This is the subscription order
    // inside the single onInit tier; the event remains the only runner.
    std::span<const std::string_view> Order() noexcept;
} // namespace xla::startup

namespace xla::startup
{
    namespace
    {
        std::atomic<bool> g_registered{false};
        std::vector<std::string_view> g_order;
        bool g_bannerWritten = false;
        bool g_loaderReported = false;
        config::LoadResult g_loaded;

        void Record(std::string_view name)
        {
            g_order.push_back(name);
        }

        void Banner()
        {
            if (g_bannerWritten)
            {
                return;
            }
            g_bannerWritten = true;

            SYSTEMTIME now{};
            ::GetLocalTime(&now);
            Log::Print("{} {} ({}) {:04}-{:02}-{:02} {:02}:{:02}:{:02}", kProductName,
                       kVersion, kGitSha.empty() ? "no-sha" : kGitSha, now.wYear, now.wMonth,
                       now.wDay, now.wHour, now.wMinute, now.wSecond);
        }

        void ReportConfiguration(const config::LoadResult& loaded, bool fusionFix)
        {
            const Game& game = Game::Get();
            Log::Print("ini={} legacy={} fusionfix={}", loaded.iniPath.string(),
                       loaded.legacyPath.string(), fusionFix ? 1 : 0);
            Log::Print("options: launcher={} localSettings={} customSave=\"{}\" "
                       "customSettings=\"{}\" borderless={} dontPause={}",
                       game.Option("SkipLauncher"), game.Option("LocalSettingsPath"),
                       game.OptionString("CustomSavePath"),
                       game.OptionString("CustomSettingsPath"),
                       game.Option("BorderlessWindowed"), game.Option("DoNotPauseOnMinimize"));
        }

        void InstallSkipLauncher(const Image& image)
        {
            const auto applied = skip_launcher::ApplySkipLauncher(
                image, &skip_launcher::ResolveSkipHook, nullptr,
                skip_launcher::kShippedStages);
            if (!applied)
            {
                Log::Print("skipLauncher: failed with code {} ({})",
                           static_cast<int>(applied.error().code), applied.error().detail);
                return;
            }

            const auto& report = *applied;
            Log::Print("skipLauncher: stages={} dfa={}/{} rom={}/{} collected={} "
                       "createFileSlot={:08X}",
                       skip_launcher::DescribeStages(skip_launcher::kShippedStages),
                       report.dfaInstalls, report.dfaMissing, report.romInstalls,
                       report.romMissing, report.collectedInstalls, report.createFileSlot);
        }

        void RegisterAll()
        {
            if (g_registered.exchange(true))
            {
                return;
            }

            Record("Banner");
            FusionFix::onInitEvent() += []
            {
                Banner();
            };

            Record("Console");
            FusionFix::onInitEvent() += []
            {
                if (::GetConsoleWindow() != nullptr)
                {
                    ::FreeConsole();
                }
            };

            Record("SingleInstance");
            FusionFix::onInitEvent() += []
            {
                static const bool claimed = warnings::ClaimSingleInstance();
                if (claimed)
                {
                    return;
                }

                Game& game = Game::Get();
                Log::Line("init: another copy of XLivelessAddon already initialized in this "
                          "process");
                warnings::ShowAsync(warnings::LoadedTwiceDialog(), std::optional<UINT>{1u});
                game.RequestStop(1);
            };

            Record("Loader");
            FusionFix::onInitEvent() += []
            {
                if (Game::Get().Stopped())
                {
                    return;
                }
                if (g_loaderReported)
                {
                    return;
                }
                g_loaderReported = true;

                const warnings::LoaderInfo info = warnings::QueryLoader();
                if (info.detected)
                {
                    Log::Print("loader: {} {}", info.name,
                               info.version.empty() ? "(version unknown)" : info.version);
                }
                else
                {
                    Log::Line("loader: no Ultimate ASI Loader found in this process");
                }

                const bool modern =
                    info.detected &&
                    (!info.versionKnown ||
                     warnings::LoaderVersionAccepted(info.versionMs, info.versionLs));
                if (!modern)
                {
                    warnings::ShowAsync(warnings::OldLoaderDialog(info), std::nullopt);
                }
            };

            Record("Probe");
            probe::Register([] { return Run(nullptr); });

            Record("Paths");
            FusionFix::onInitEvent() += []
            {
                if (Game::Get().Stopped())
                {
                    return;
                }
                const Game& game = Game::Get();
                Log::Print("paths: module={} game={}", game.ModuleDirectory().string(),
                           game.ExecutableDirectory().string());
            };

            Record("Config");
            FusionFix::onInitEvent() += []
            {
                Game& game = Game::Get();
                if (game.Stopped())
                {
                    return;
                }
                g_loaded = config::Load(game.ModuleDirectory(), game.ExecutableDirectory());
                config::Publish(g_loaded);
            };

            Record("FusionFix");
            FusionFix::onInitEvent() += []
            {
                Game& game = Game::Get();
                if (game.Stopped())
                {
                    return;
                }

                if (!config::FusionFixPresent(game.ModuleDirectory()))
                {
                    return;
                }

                const std::vector<config::FusionFixGate> gated =
                    config::ApplyFusionFixGates(g_loaded.options);
                config::Publish(g_loaded);
                for (const config::FusionFixGate& gate : gated)
                {
                    Log::Print("fusionfix: gating {} (FusionFix {})", gate.option,
                               gate.fusionFixModule);
                }
                warnings::PublishFusionFixNotice(game.ModuleDirectory(), gated);
            };

            Record("ReportConfiguration");
            FusionFix::onInitEvent() += []
            {
                if (Game::Get().Stopped())
                {
                    return;
                }
                ReportConfiguration(g_loaded,
                                    config::FusionFixPresent(Game::Get().ModuleDirectory()));
            };

            Record("Image");
            FusionFix::onInitEvent() += []
            {
                Game& game = Game::Get();
                if (game.Stopped())
                {
                    return;
                }
                if (game.View().empty())
                {
                    Log::Line("init: game image unavailable; no patches applied");
                    game.RequestStop(0);
                }
            };

            Record("Writable");
            FusionFix::onInitEvent() += []
            {
                Game& game = Game::Get();
                if (game.Stopped())
                {
                    return;
                }
                if (!patch::MakeImageWritable(game.View()))
                {
                    Log::Line("init: image is not writable; no patches applied");
                    game.RequestStop(0);
                }
            };

            Record("Build");
            FusionFix::onInitEvent() += []
            {
                Game& game = Game::Get();
                if (game.Stopped())
                {
                    return;
                }

                const std::optional<GameBuild> detected = build::Detect(game.View());
                if (!detected)
                {
                    const std::optional<std::uint32_t> signature =
                        build::ReadSignature(game.View());
                    if (signature)
                    {
                        Log::Print("init: unsupported build; classification dword {:#x} at RVA "
                                   "{:#x}; no patches applied",
                                   *signature, build::kSignatureOffset);
                        warnings::ShowAsync(warnings::UnsupportedGameVersionDialog(),
                                            std::optional<UINT>{1u});
                        game.RequestStop(1);
                    }
                    else
                    {
                        Log::Line("init: image is too small for the classification dword; no "
                                  "patches applied");
                        game.RequestStop(0);
                    }
                    return;
                }

                game.SetBuild(*detected);
                Log::Print("build={}", BuildLabel(game.Build()));
            };

            // ---- install handlers (same tier, after the context) --------------

            Record("LocalSettings");
            FusionFix::onInitEvent() += []
            {
                const Game& game = Game::Get();
                if (game.Stopped())
                {
                    return;
                }
                if (!game.Option("LocalSettingsPath"))
                {
                    Log::Trace("userdata: option off");
                    return;
                }
                userdata::InstallLocalSettingsPath(game.View());
            };

            Record("Savegames");
            FusionFix::onInitEvent() += []
            {
                const Game& game = Game::Get();
                if (game.Stopped())
                {
                    return;
                }
                // The savegame path reconstruction and the CRC32 bypass are the
                // original's unconditional core install (the old addon's AGENTS
                // says so explicitly). CustomSavePath selects the folder and is
                // never FusionFix-gated; an empty value keeps the game default.
                savegames::Install(game.View(), game.OptionString("CustomSavePath"));
            };

            Record("SkipLauncher");
            FusionFix::onInitEvent() += []
            {
                const Game& game = Game::Get();
                if (game.Stopped())
                {
                    return;
                }
                if (!game.Option("SkipLauncher"))
                {
                    Log::Trace("skipLauncher: option off");
                    return;
                }
                InstallSkipLauncher(game.View());
            };

            Record("BorderlessWindow");
            FusionFix::onInitEvent() += []
            {
                const Game& game = Game::Get();
                if (game.Stopped())
                {
                    return;
                }
                if (!game.Option("BorderlessWindowed"))
                {
                    return;
                }
                const bool installed = windowed::InstallBorderlessHooks(game.View());
                Log::Print("window: borderless={}", installed ? "installed" : "missing");
            };

            Record("FocusLoss");
            FusionFix::onInitEvent() += []
            {
                const Game& game = Game::Get();
                if (game.Stopped())
                {
                    return;
                }
                if (!game.Option("DoNotPauseOnMinimize"))
                {
                    return;
                }
                const bool installed = windowed::InstallFocusLossInput(game.View());
                Log::Print("window: focusLoss={}", installed ? "installed" : "missing");
            };

            Record("CustomSettingsPath");
            FusionFix::onInitEvent() += []
            {
                const Game& game = Game::Get();
                if (game.Stopped())
                {
                    return;
                }
                settings_path::InstallCustomSettingsPath(
                    game.View(), game.OptionString("CustomSettingsPath"));
            };

            Record("LauncherStage");
            FusionFix::onInitEvent() += []
            {
                const Game& game = Game::Get();
                if (game.Stopped())
                {
                    return;
                }
                if (game.Option("SkipLauncher"))
                {
                    return;
                }

                // The original skipped the DFA hooks on EFLC 1.1.0.0/1.1.1.0:
                // DFA there faulted with an unhandled exception at 0x00426440
                // (0xC0000005), so the crash evidence is the reason for the build
                // test, not a preference.
                if (!IsBuild(game.Build(), {GameBuild::v1100, GameBuild::v1110}))
                {
                    dfa::Install(game.View());
                }
                rom_window::Install(game.View());
            };

            Record("DoNotPauseOnMinimize");
            FusionFix::onInitEvent() += []
            {
                const Game& game = Game::Get();
                if (game.Stopped())
                {
                    return;
                }
                if (!game.Option("DoNotPauseOnMinimize"))
                {
                    return;
                }
                windowed::InstallDoNotPauseOnMinimize(game.View());
            };

            Record("DefWindowProcShims");
            FusionFix::onInitEvent() += []
            {
                const Game& game = Game::Get();
                if (game.Stopped())
                {
                    return;
                }
                if (!game.Option("BorderlessWindowed"))
                {
                    return;
                }
                windowed::InstallDefWindowProcShims(game.View());
            };

            Record("Registry");
            FusionFix::onInitEvent() += []
            {
                const Game& game = Game::Get();
                if (game.Stopped())
                {
                    return;
                }
                if (!game.Option("RemoveRegistryPathDependency"))
                {
                    Log::Trace("registry: option off");
                    return;
                }
                registry::Install(game.View());
            };

            Record("Complete");
            FusionFix::onInitEvent() += []
            {
                if (Game::Get().Stopped())
                {
                    return;
                }
                Log::Line("init complete");
            };
        }
    } // namespace

    int Run(HMODULE module)
    {
        Game& game = Game::Get();
        game.Initialise(module);

        // A retry pass is a fresh pass: the previous one only stopped to hand the
        // probe wait to this thread, and the single-instance/loader answers are
        // static, so resetting the pass state is safe.
        game.ResetPass();

        if (!Log::IsOpen() && !game.LogPath().empty())
        {
            Log::Open(game.LogPath());
        }

        RegisterAll();
        FusionFix::onInitEvent().executeAll();

        if (game.Stopped())
        {
            // Release the worker the probe step may have started, but only now:
            // this pass is done reading and writing the pass state. A retry pass
            // that itself stops sets `retryGo` before `Run` returns, which the
            // worker has already consumed, so this is a harmless store.
            probe::ReleaseRetry();
        }

        return game.ExitCode();
    }

    void Shutdown()
    {
        FusionFix::onShutdownEvent().executeAll();
        Log::Close();
    }

    std::span<const std::string_view> Order() noexcept
    {
        // Registering is the only way to observe the subscription order; the test
        // calls this accessor without executing the tier.
        RegisterAll();
        return g_order;
    }
} // namespace xla::startup
