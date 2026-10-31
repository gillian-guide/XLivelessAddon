// SPDX-License-Identifier: GPL-3.0-or-later
//
// xla.addon — the init pipeline. Runs once at DLL_PROCESS_ATTACH, in the
// original add-on's order: probe, configuration, image/build detection, then the
// installers. Every installer is INI-gated; an unsupported or non-writable image
// installs nothing and says why.

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
    } // namespace

    int Run(HMODULE module)
    {
        (void)module;
        log::Banner();

        if (::GetConsoleWindow() != nullptr)
        {
            ::FreeConsole();
        }

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
                return 0;
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
                    return 1;
                }
                ::Sleep(kProbeSleepMs);
            }
        }

        const std::filesystem::path directory = paths::ModuleDirectory();
        config::LoadResult loaded = config::Load(directory);
        config::Options& options = loaded.options;

        const bool fusionFix = config::FusionFixPresent(directory);
        if (fusionFix)
        {
            for (const config::FusionFixGate& gate : config::ApplyFusionFixGates(options))
            {
                log::Info("fusionfix: gating {} (FusionFix {})", gate.option,
                          gate.fusionFixModule);
            }
        }

        LogConfiguration(loaded, fusionFix);
        if (!options.customSettingsPath.empty())
        {
            log::Write("settings: CustomSettingsPath is not hooked in this build; use "
                       "LocalSettingsPath or FusionFix userdata.ixx");
        }

        const Image image = CurrentImage();
        if (image.empty())
        {
            log::Write("init: game image unavailable; no patches applied");
            return 0;
        }

        if (!MakeImageWritable(image))
        {
            log::Write("init: image is not writable; no patches applied");
            return 0;
        }

        const std::optional<build::Id> detected = build::Detect(image);
        if (!detected)
        {
            log::Write("init: unsupported build; no patches applied");
            return 0;
        }
        const build::Id build = *detected;
        log::Info("build={}", build::Label(build));

        // LocalSettingsPath owns the shell user-data folders; install it before the
        // game can query them.
        if (options.localSettingsPath)
        {
            userdata::InstallLocalSettingsPath(image);
        }

        savegames::Install(image, options.customSavePath);

        if (options.skipLauncher)
        {
            const auto applied = ApplySkipLauncher(image.bytes(), &ResolveSkipHook, nullptr,
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

        int borderless = -1;
        int focusLoss = -1;
        if (options.borderlessWindowed)
        {
            borderless = windowed::InstallBorderlessHooks(image) ? 1 : 0;
        }
        if (options.doNotPauseOnMinimize)
        {
            focusLoss = windowed::InstallFocusLossInput(image) ? 1 : 0;
        }
        log::Info("window: borderless={} focusLoss={}", borderless, focusLoss);

        patches::InstallCore(image, build);

        // The launcher helpers only run when the recovered stage is disabled; the
        // original skipped the DFA hooks on EFLC 1.1.0.0/1.1.1.0.
        if (!options.skipLauncher)
        {
            if (!build::Is(build, {build::Id::v1100, build::Id::v1110}))
            {
                dfa::Install(image);
            }
            rom_window::Install(image);
        }

        if (options.skipWebConnect)
        {
            patches::InstallWebConnectChecks(image);
        }
        if (options.skipIntro)
        {
            patches::InstallIntro(image);
        }
        if (options.skipMenu)
        {
            patches::InstallMenu(image);
        }
        if (options.doNotPauseOnMinimize)
        {
            patches::InstallDoNotPauseOnMinimize(image);
        }
        if (options.borderlessWindowed)
        {
            windowed::InstallDefWindowProcShims(image);
        }
        if (options.removeRegistryPathDependency)
        {
            registry::Install(image);
        }
        if (options.vramFix)
        {
            patches::InstallVramFix(image);
        }

        log::Write("init complete");
        return 0;
    }
} // namespace xla
