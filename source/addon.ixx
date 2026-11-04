// SPDX-License-Identifier: GPL-3.0-or-later
//
// xla.addon — the init pipeline in FusionFix's shape.
//
// `Game` is the process-wide state (directories, loaded INI, image, build and the
// install results); `Run(HMODULE)` initializes it once and executes the three
// Event<> tiers. Each step is a feature class whose constructor subscribes one
// handler; the file-scope instances below are the registration. There is no step
// table and no dependency graph: the effective order is the tier order plus the
// static-init subscription order inside a tier, and `StartupOrder()` exposes that
// sequence so the native test can pin it. The publish-before-install contracts are
// called out at the classes that own them.
//
// The first pass runs synchronously at DLL_PROCESS_ATTACH; when the probe is
// absent, the probe step schedules one retry on a worker thread instead of
// blocking attach. Every optional installer is INI-gated while the core patch list
// and the savegame CRC32 bypass stay unconditional; an unsupported or non-writable
// image installs nothing and says why.

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
import xla.warnings;
import xla.windowed;

export namespace xla
{
    // What an optional install step did, in the original's three states (its log
    // legend was -1/0/1; the names are used here).
    enum class InstallState : std::int8_t
    {
        off,       // the INI option is off
        missing,   // the option is on but the pattern/import was not found
        installed, // the hooks are in place
    };

    [[nodiscard]] constexpr std::string_view InstallStateName(InstallState state) noexcept
    {
        switch (state)
        {
        case InstallState::off:
            return "off";
        case InstallState::missing:
            return "missing";
        case InstallState::installed:
            return "installed";
        }
        return "?";
    }

    // The process exit code the original init used: 0 = installed or waiting,
    // 1 = gave up (the probe never appeared). DllMain ignores it; the retry
    // worker returns it.
    enum class ExitCode : int
    {
        ok = 0,
        gaveUp = 1,
    };

    // The process-wide install context. Run initializes it once; every handler
    // reads it, so a step publishes into Game and the next step reads it without a
    // parameter list or a dependency edge.
    class Game
    {
    public:
        static Game& Get() noexcept
        {
            static Game game;
            return game;
        }

        // Resolves the module/game directories and the image, and publishes the
        // image to the shared scan helper. Only the first call does work: the
        // probe retry re-enters Run and must not reset what the first pass wrote.
        static void Initialize(HMODULE module) noexcept;

        HMODULE module{};

        // The ASI's own folder (INI, log, notice) and the game folder
        // (game-relative option values). They differ when the ASI is installed in
        // plugins\.
        std::filesystem::path moduleDirectory;
        std::filesystem::path gameDirectory;
        config::LoadResult loaded;
        bool fusionFix{};
        Image image;
        build::Id build{build::Id::unknown};
        InstallState borderless{InstallState::off};
        InstallState focusLoss{InstallState::off};
        ExitCode exitCode{ExitCode::ok};

        // A step asked the current pass to stop (single instance, missing image,
        // unwritable image, unsupported build). Run checks it between tiers and
        // the few init handlers that follow a stopping one check it themselves.
        bool stop{};

        // Probe state: the bootstrap signature is checked by the probe step, and
        // that step owns the one allowed retry worker. `retryGo` releases the
        // worker only after the pass that started it has returned, so the two
        // passes never share mutable pass state.
        bool probePresent{};
        std::atomic<bool> retryStarted{false};
        std::atomic<bool> retryGo{false};
        bool initialized{};
    };

    // The feature registrations in execution order: the init tier, the install
    // tier and the post tier, each in static-init subscription order. The native
    // test pins this sequence.
    std::span<const std::string_view> StartupOrder() noexcept;

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

        Image CurrentImage()
        {
            auto* base = ::GetModuleHandleW(nullptr);
            const IMAGE_NT_HEADERS* nt = NtHeaders(base);
            if (nt == nullptr)
            {
                return {};
            }
            return {reinterpret_cast<std::byte*>(base), nt->OptionalHeader.SizeOfImage};
        }

        bool ProbePresent()
        {
            // The probe runs on every spin of the retry, so it uses the scan
            // helper directly: a miss is the normal state here and must not write
            // 10,000 log lines.
            return !make_game_pattern(kProbeSignature).empty();
        }

        DWORD WINAPI DelayedInit(LPVOID)
        {
            Game& game = Game::Get();
            // The first pass is still unwinding after scheduling this worker; wait
            // for it to stop touching the pass state before starting the retry.
            while (!game.retryGo.load(std::memory_order_acquire))
            {
                ::Sleep(kProbeSleepMs);
            }
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

        // The tier a registration belongs to. The order of the enumerators is the
        // execution order; StartupOrder() groups by it.
        enum class Tier : std::uint8_t
        {
            init,
            install,
            post,
        };

        struct Registration
        {
            Tier tier;
            std::string_view name;
        };

        // FusionFix's Event carries no names: it only knows the std::function it
        // runs. A class records its own name next to its subscription so the test
        // can pin the sequence the static-init order produces. This is a record of
        // what was subscribed, not a dispatch table - the event remains the only
        // runner.
        std::vector<Registration>& Registrations()
        {
            static std::vector<Registration> registrations;
            return registrations;
        }

        void Record(Tier tier, std::string_view name)
        {
            Registrations().push_back({tier, name});
        }

        std::vector<std::string_view> BuildStartupOrder()
        {
            std::vector<std::string_view> order;
            order.reserve(Registrations().size());
            for (const Tier tier : {Tier::init, Tier::install, Tier::post})
            {
                for (const Registration& registration : Registrations())
                {
                    if (registration.tier == tier)
                    {
                        order.push_back(registration.name);
                    }
                }
            }
            return order;
        }

        // ---- the init tier ----------------------------------------------------

        // The first three steps are unconditional startup, before anything reads
        // the image. A failure here stops the pass.
        class Banner
        {
        public:
            Banner()
            {
                Record(Tier::init, "Banner");
                InitEvent() += [] { log::Banner(); };
            }
        } banner;

        class Console
        {
        public:
            Console()
            {
                Record(Tier::init, "Console");
                InitEvent() += []
                {
                    if (::GetConsoleWindow() != nullptr)
                    {
                        ::FreeConsole();
                    }
                };
            }
        } console;

        class SingleInstance
        {
        public:
            SingleInstance()
            {
                Record(Tier::init, "SingleInstance");
                InitEvent() += []
                {
                    // DllMain and the probe retry can each run the pipeline; the
                    // marker is per process, so it is claimed once and the answer
                    // remembered.
                    static const bool claimed = warnings::ClaimSingleInstance();
                    if (claimed)
                    {
                        return;
                    }

                    Game& game = Game::Get();
                    log::Write("init: another copy of XLivelessAddon already initialized in "
                               "this process");
                    warnings::ShowAsync(warnings::LoadedTwiceDialog(), std::optional<UINT>{1u});
                    game.exitCode = ExitCode::gaveUp;
                    game.stop = true;
                };
            }
        } singleInstance;

        // The loader notice and the probe check must not run after a stopping
        // step; these two are the only init handlers that follow one.
        class Loader
        {
        public:
            Loader()
            {
                Record(Tier::init, "Loader");
                InitEvent() += []
                {
                    if (Game::Get().stop)
                    {
                        return;
                    }

                    // Runs once even when the probe retry starts the pipeline
                    // again.
                    static const bool reported = [] {
                        const warnings::LoaderInfo info = warnings::QueryLoader();
                        if (info.detected)
                        {
                            log::Info("loader: {} {}", info.name,
                                      info.version.empty() ? "(version unknown)" : info.version);
                        }
                        else
                        {
                            log::Write("loader: no Ultimate ASI Loader found in this process");
                        }

                        const bool modern =
                            info.detected &&
                            (!info.versionKnown ||
                             warnings::LoaderVersionAccepted(info.versionMs, info.versionLs));
                        if (!modern)
                        {
                            warnings::ShowAsync(warnings::OldLoaderDialog(info),
                                                std::nullopt);
                        }
                        return true;
                    }();
                    (void)reported;
                };
            }
        } loader;

        class Probe
        {
        public:
            Probe()
            {
                Record(Tier::init, "Probe");
                InitEvent() += []
                {
                    Game& game = Game::Get();
                    if (game.stop)
                    {
                        return;
                    }

                    // The game executable is checked for the probe before
                    // anything is trusted.
                    if (ProbePresent())
                    {
                        game.probePresent = true;
                        return;
                    }

                    if (!game.retryStarted.exchange(true))
                    {
                        log::Write("init: probe missing; retrying on a worker thread");
                        const HANDLE thread =
                            ::CreateThread(nullptr, 0, &DelayedInit, nullptr, 0, nullptr);
                        if (thread != nullptr)
                        {
                            ::CloseHandle(thread);
                        }
                        game.exitCode = ExitCode::ok;
                        game.stop = true;
                        return;
                    }

                    // Wait for the probe instead of spinning a core forever.
                    // Supported builds hit it on the first iterations; an
                    // unsupported build gets a log line and an orderly return.
                    int spins = 0;
                    while (!ProbePresent())
                    {
                        if (++spins > kProbeSpinLimit)
                        {
                            log::Write("init: probe never appeared; aborting");
                            game.exitCode = ExitCode::gaveUp;
                            game.stop = true;
                            return;
                        }
                        ::Sleep(kProbeSleepMs);
                    }
                    game.probePresent = true;
                };
            }
        } probe;

        // ---- the config tier --------------------------------------------------

        class Paths
        {
        public:
            Paths()
            {
                Record(Tier::init, "Paths");
                InitEvent() += []
                {
                    if (Game::Get().stop)
                    {
                        return;
                    }
                    const Game& game = Game::Get();
                    log::Info("paths: module={} game={}", game.moduleDirectory.string(),
                              game.gameDirectory.string());
                };
            }
        } paths;

        class Config
        {
        public:
            Config()
            {
                Record(Tier::init, "Config");
                InitEvent() += []
                {
                    Game& game = Game::Get();
                    if (game.stop)
                    {
                        return;
                    }
                    // The add-on's own INI is read next to the ASI; the legacy
                    // ZolikaPatch.ini is found in the ASI folder or a loader
                    // folder.
                    game.loaded = config::Load(game.moduleDirectory, game.gameDirectory);
                };
            }
        } configStep;

        class FusionFix
        {
        public:
            FusionFix()
            {
                Record(Tier::init, "FusionFix");
                InitEvent() += []
                {
                    Game& game = Game::Get();
                    if (game.stop)
                    {
                        return;
                    }
                    game.fusionFix = config::FusionFixPresent(game.moduleDirectory);
                    if (!game.fusionFix)
                    {
                        return;
                    }

                    const std::vector<config::FusionFixGate> gated =
                        config::ApplyFusionFixGates(game.loaded.options);
                    for (const config::FusionFixGate& gate : gated)
                    {
                        log::Info("fusionfix: gating {} (FusionFix {})", gate.option,
                                  gate.fusionFixModule);
                    }
                    // The notice belongs next to the ASI, like the INI and the log.
                    warnings::PublishFusionFixNotice(game.moduleDirectory, gated);
                };
            }
        } fusionFix;

        class ReportConfiguration
        {
        public:
            ReportConfiguration()
            {
                Record(Tier::init, "ReportConfiguration");
                InitEvent() += []
                {
                    const Game& game = Game::Get();
                    if (game.stop)
                    {
                        return;
                    }
                    LogConfiguration(game.loaded, game.fusionFix);
                };
            }
        } reportConfiguration;

        class Image
        {
        public:
            Image()
            {
                Record(Tier::init, "Image");
                InitEvent() += []
                {
                    Game& game = Game::Get();
                    if (game.stop)
                    {
                        return;
                    }
                    game.image = CurrentImage();
                    scan::SetImage(game.image);
                    if (game.image.empty())
                    {
                        log::Write("init: game image unavailable; no patches applied");
                        game.exitCode = ExitCode::ok;
                        game.stop = true;
                    }
                };
            }
        } imageStep;

        // The two handlers after the image step must not run when it stopped.
        class Writable
        {
        public:
            Writable()
            {
                Record(Tier::init, "Writable");
                InitEvent() += []
                {
                    Game& game = Game::Get();
                    if (game.stop)
                    {
                        return;
                    }
                    if (!MakeImageWritable(game.image))
                    {
                        log::Write("init: image is not writable; no patches applied");
                        game.exitCode = ExitCode::ok;
                        game.stop = true;
                    }
                };
            }
        } writable;

        class Build
        {
        public:
            Build()
            {
                Record(Tier::init, "Build");
                InitEvent() += []
                {
                    Game& game = Game::Get();
                    if (game.stop)
                    {
                        return;
                    }

                    const std::optional<build::Id> detected = build::Detect(game.image);
                    if (!detected)
                    {
                        // Say what was read: "unsupported" alone cannot
                        // distinguish a new build from an image that is not the
                        // game at all.
                        const std::optional<std::uint32_t> signature =
                            build::ReadSignature(game.image);
                        if (signature)
                        {
                            log::Info("init: unsupported build; classification dword {:#x} at "
                                      "RVA {:#x}; no patches applied",
                                      *signature, build::kSignatureOffset);
                            // The add-on has no patch rows for this build: tell
                            // the user and exit rather than leaving a silently
                            // unpatched game behind.
                            warnings::ShowAsync(warnings::UnsupportedGameVersionDialog(),
                                                std::optional<UINT>{1u});
                            game.exitCode = ExitCode::gaveUp;
                        }
                        else
                        {
                            log::Write("init: image is too small for the classification dword; "
                                       "no patches applied");
                        }
                        game.stop = true;
                        return;
                    }
                    game.build = *detected;
                    log::Info("build={}", build::Label(game.build));
                };
            }
        } buildStep;

        // ---- the install tier -------------------------------------------------

        class LocalSettings
        {
        public:
            LocalSettings()
            {
                Record(Tier::install, "LocalSettings");
                InstallEvent() += []
                {
                    const Game& game = Game::Get();
                    // LocalSettingsPath owns the shell user-data folders; install
                    // it before the game can query them.
                    if (game.loaded.options.localSettingsPath)
                    {
                        userdata::InstallLocalSettingsPath(game.image);
                    }
                };
            }
        } localSettings;

        class Savegames
        {
        public:
            Savegames()
            {
                Record(Tier::install, "Savegames");
                InstallEvent() += []
                {
                    const Game& game = Game::Get();
                    savegames::Install(game.image, game.loaded.options.customSavePath);
                };
            }
        } savegames;

        // The CreateFile slot is captured and published inside
        // ApplySkipLauncher's DFA stage, before its hook jumps are written; that
        // publish-before-install edge is internal to the pass.
        class SkipLauncher
        {
        public:
            SkipLauncher()
            {
                Record(Tier::install, "SkipLauncher");
                InstallEvent() += []
                {
                    const Game& game = Game::Get();
                    if (!game.loaded.options.skipLauncher)
                    {
                        return;
                    }

                    constexpr SkipLauncherStage kStages = kShippedStages;
                    const auto applied = ApplySkipLauncher(game.image.bytes(),
                                                           &ResolveSkipHook, nullptr, kStages);
                    if (applied)
                    {
                        const SkipLauncherReport& report = *applied;
                        log::Info("skipLauncher: stages={} dfa={}/{} rom={}/{} collected={} "
                                  "createFileSlot={:08X}",
                                  DescribeStages(kStages), report.dfaInstalls,
                                  report.dfaMissing, report.romInstalls, report.romMissing,
                                  report.collectedInstalls, report.createFileSlot);
                        // The main-table counters only mean something when `main`
                        // ran; print them then, and say "not applied" otherwise so
                        // a healthy log cannot be read as "nothing found".
                        if (HasStage(kStages, SkipLauncherStage::main))
                        {
                            log::Info("skipLauncher: main entries={}/{} writes={} jump={}",
                                      report.entriesFound,
                                      report.entriesFound + report.entriesMissing,
                                      report.writes, report.jumpInstalled);
                        }
                        else
                        {
                            log::Write("skipLauncher: main=not-applied (the recovered main "
                                       "table is not in the shipping stage set)");
                        }
                    }
                    else
                    {
                        log::Info("skipLauncher: failed with code {} ({})",
                                  static_cast<int>(applied.error().code),
                                  applied.error().detail);
                    }
                };
            }
        } skipLauncher;

        class BorderlessWindow
        {
        public:
            BorderlessWindow()
            {
                Record(Tier::install, "BorderlessWindow");
                InstallEvent() += []
                {
                    Game& game = Game::Get();
                    if (game.loaded.options.borderlessWindowed)
                    {
                        game.borderless = windowed::InstallBorderlessHooks(game.image)
                                              ? InstallState::installed
                                              : InstallState::missing;
                    }
                };
            }
        } borderlessWindow;

        class FocusLoss
        {
        public:
            FocusLoss()
            {
                Record(Tier::install, "FocusLoss");
                InstallEvent() += []
                {
                    Game& game = Game::Get();
                    if (game.loaded.options.doNotPauseOnMinimize)
                    {
                        game.focusLoss = windowed::InstallFocusLossInput(game.image)
                                             ? InstallState::installed
                                             : InstallState::missing;
                    }
                    log::Info("window: borderless={} focusLoss={}",
                              InstallStateName(game.borderless),
                              InstallStateName(game.focusLoss));
                };
            }
        } focusLoss;

        class CorePatches
        {
        public:
            CorePatches()
            {
                Record(Tier::install, "CorePatches");
                InstallEvent() += []
                {
                    const Game& game = Game::Get();
                    patches::InstallCore(game.image, game.build);
                    // The settings redirect is INI-gated inside the installer
                    // (empty = off, which is also the FusionFix-gated state).
                    patches::InstallCustomSettingsPath(
                        game.image, game.loaded.options.customSettingsPath);
                };
            }
        } corePatches;

        class LauncherStage
        {
        public:
            LauncherStage()
            {
                Record(Tier::install, "LauncherStage");
                InstallEvent() += []
                {
                    const Game& game = Game::Get();
                    // The launcher helpers only run when the recovered stage is
                    // disabled; the original skipped the DFA hooks on EFLC
                    // 1.1.0.0/1.1.1.0: DFA there faulted with an unhandled
                    // exception at 0x00426440 (0xC0000005), so the crash evidence
                    // is the reason for the build test, not a preference.
                    if (!game.loaded.options.skipLauncher)
                    {
                        if (!build::Is(game.build, {build::Id::v1100, build::Id::v1110}))
                        {
                            dfa::Install(game.image);
                        }
                        rom_window::Install(game.image);
                    }
                };
            }
        } launcherStage;

        class WebConnect
        {
        public:
            WebConnect()
            {
                Record(Tier::install, "WebConnect");
                InstallEvent() += []
                {
                    const Game& game = Game::Get();
                    if (game.loaded.options.skipWebConnect)
                    {
                        patches::InstallWebConnectChecks(game.image);
                    }
                };
            }
        } webConnect;

        class SkipIntro
        {
        public:
            SkipIntro()
            {
                Record(Tier::install, "SkipIntro");
                InstallEvent() += []
                {
                    const Game& game = Game::Get();
                    if (game.loaded.options.skipIntro)
                    {
                        // InstallIntro publishes g_skipIntroResume before its
                        // MakeJMP; publish after the jump and the body resumes into
                        // itself.
                        patches::InstallIntro(game.image);
                    }
                };
            }
        } skipIntro;

        class SkipMenu
        {
        public:
            SkipMenu()
            {
                Record(Tier::install, "SkipMenu");
                InstallEvent() += []
                {
                    const Game& game = Game::Get();
                    if (game.loaded.options.skipMenu)
                    {
                        // InstallMenu captures the original E8 target (MakeCALL
                        // returns it) as the resume, in the same call that
                        // overwrites the site.
                        patches::InstallMenu(game.image);
                    }
                };
            }
        } skipMenu;

        class DoNotPauseOnMinimize
        {
        public:
            DoNotPauseOnMinimize()
            {
                Record(Tier::install, "DoNotPauseOnMinimize");
                InstallEvent() += []
                {
                    const Game& game = Game::Get();
                    if (game.loaded.options.doNotPauseOnMinimize)
                    {
                        patches::InstallDoNotPauseOnMinimize(game.image);
                    }
                };
            }
        } doNotPauseOnMinimize;

        class DefWindowProcShims
        {
        public:
            DefWindowProcShims()
            {
                Record(Tier::install, "DefWindowProcShims");
                InstallEvent() += []
                {
                    const Game& game = Game::Get();
                    if (game.loaded.options.borderlessWindowed)
                    {
                        windowed::InstallDefWindowProcShims(game.image);
                    }
                };
            }
        } defWindowProcShims;

        class Registry
        {
        public:
            Registry()
            {
                Record(Tier::install, "Registry");
                InstallEvent() += []
                {
                    const Game& game = Game::Get();
                    if (game.loaded.options.removeRegistryPathDependency)
                    {
                        registry::Install(game.image);
                    }
                };
            }
        } registryStep;

        class VramFix
        {
        public:
            VramFix()
            {
                Record(Tier::install, "VramFix");
                InstallEvent() += []
                {
                    const Game& game = Game::Get();
                    if (game.loaded.options.vramFix)
                    {
                        patches::InstallVramFix(game.image);
                    }
                };
            }
        } vramFix;

        // ---- the post tier ----------------------------------------------------

        class Complete
        {
        public:
            Complete()
            {
                Record(Tier::post, "Complete");
                PostEvent() += [] { log::Write("init complete"); };
            }
        } complete;
    } // namespace

    void Game::Initialize(HMODULE module) noexcept
    {
        Game& game = Get();
        if (game.initialized)
        {
            return;
        }

        game.module = module;
        std::error_code error;
        game.moduleDirectory = paths::ModuleDirectory(error);
        if (error)
        {
            game.moduleDirectory.clear();
        }
        game.gameDirectory = paths::GameDirectory();
        game.image = CurrentImage();
        scan::SetImage(game.image);
        game.initialized = true;
    }

    std::span<const std::string_view> StartupOrder() noexcept
    {
        static const std::vector<std::string_view> order = BuildStartupOrder();
        return order;
    }

    int Run(HMODULE module)
    {
        Game& game = Game::Get();
        Game::Initialize(module);

        // A retry pass is a fresh pass: the previous one only stopped to hand the
        // probe wait to this thread, and the single-instance/loader answers are
        // static, so resetting the pass state is safe.
        game.stop = false;
        game.exitCode = ExitCode::ok;

        InitEvent().executeAll();
        if (game.stop)
        {
            // Release the worker the probe step may have started, but only now:
            // this pass is done reading and writing the pass state.
            if (!game.probePresent && game.retryStarted.load(std::memory_order_relaxed))
            {
                game.retryGo.store(true, std::memory_order_release);
            }
            return static_cast<int>(game.exitCode);
        }

        InstallEvent().executeAll();
        if (game.stop)
        {
            return static_cast<int>(game.exitCode);
        }

        PostEvent().executeAll();
        return static_cast<int>(game.exitCode);
    }
} // namespace xla
