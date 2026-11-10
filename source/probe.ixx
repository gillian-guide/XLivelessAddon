// SPDX-License-Identifier: GPL-3.0-or-later
//
// xla.probe - the game-executable probe and its one allowed retry.
//
// Ported from the probe step of openprecepatch/xlivelessaddon/source/addon.ixx.
//
// The original add-on waited for a machine-code signature in the executable
// before trusting any pattern. The first pass is synchronous in DllMain; when the
// probe is absent (the DRM has not rewritten the image yet on some builds), one
// worker re-runs the whole pass instead of blocking attach. The worker waits for
// the current pass to return before it touches the pass state, so the two passes
// never share it.

module;

#include <common.hxx>

export module probe;

import common;
import patch;

export namespace xla::probe
{
    // The probe signature the original waits for: it proves the executable is the
    // one the add-on knows before any pattern is trusted.
    inline constexpr std::string_view kProbeSignature = "B0 04 B2 18 B1 20";
    inline constexpr int kSpinLimit = 10000;
    inline constexpr DWORD kSleepMs = 1;

    [[nodiscard]] bool ProbePresent();

    // Subscribes the probe step. `rerun` is the startup driver's pass entry point;
    // the retry thread must not import startup (that would be a module cycle).
    void Register(std::function<int()> rerun);

    // Releases a retry worker after the pass that started it has returned. Called
    // by the driver at the point the pass is finished reading the pass state.
    void ReleaseRetry() noexcept;
} // namespace xla::probe

namespace xla::probe
{
    namespace
    {
        std::atomic<bool> g_retryStarted{false};
        std::atomic<bool> g_retryGo{false};
        std::function<int()> g_rerun;

        DWORD WINAPI DelayedInit(LPVOID) noexcept
        {
            while (!g_retryGo.load(std::memory_order_acquire))
            {
                ::Sleep(kSleepMs);
            }
            return g_rerun ? static_cast<DWORD>(g_rerun()) : 0;
        }
    } // namespace

    bool ProbePresent()
    {
        // A miss is the normal state here and must not write 10,000 log lines, so
        // the scan helper is used directly rather than the logged Find.
        return !patch::find_pattern(kProbeSignature).empty();
    }

    void Register(std::function<int()> rerun)
    {
        g_rerun = std::move(rerun);

        FusionFix::onInitEvent() += []
        {
            Game& game = Game::Get();
            if (game.Stopped())
            {
                return;
            }

            if (ProbePresent())
            {
                Log::Trace("probe: signature present");
                return;
            }

            if (!g_retryStarted.exchange(true))
            {
                Log::Line("init: probe missing; retrying on a worker thread");
                const HANDLE thread =
                    ::CreateThread(nullptr, 0, &DelayedInit, nullptr, 0, nullptr);
                if (thread != nullptr)
                {
                    ::CloseHandle(thread);
                }
                game.RequestStop(0);
                return;
            }

            // Wait for the probe instead of spinning a core forever. Supported
            // builds hit it on the first iterations; an unsupported build gets a
            // log line and an orderly return.
            int spins = 0;
            while (!ProbePresent())
            {
                if (++spins > kSpinLimit)
                {
                    Log::Line("init: probe never appeared; aborting");
                    game.RequestStop(1);
                    return;
                }
                ::Sleep(kSleepMs);
            }
            Log::Trace("probe: signature appeared after {} spin(s)", spins);
        };
    }

    void ReleaseRetry() noexcept
    {
        g_retryGo.store(true, std::memory_order_release);
    }
} // namespace xla::probe
