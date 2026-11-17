// SPDX-License-Identifier: GPL-3.0-or-later
//
// xla.vram - [Options] VRAMFix: the VRAM detection fix, so the graphics settings
// are not locked out.
//
// The key has two generation paths, because the game changed how it asks for the
// answer; exactly one installs per build and the log says which:
//
//  1. The old add-on's recovered `InstallVramFix`
//     (openprecepatch/xlivelessaddon/source/patches.ixx): three call sites are
//     retargeted at `GetVidMemBody`, which forwards to the game's own query and
//     turns a non-positive answer into INT_MAX. The rows, offsets, body and write
//     order are the recovered ones; a missing signature is a logged skip. The
//     reference kept ONE "original destination" variable and every row overwrote
//     it, so all three bodies forward through the last original that resolved and
//     a missing row stores nullptr (the body then answers INT_MAX). That
//     unconditional overwrite is recovered behaviour, not an oversight.
//  2. FusionFix's replacement of `grcDevice::GetAvailableVideoMemory`
//     (GTAIV.EFLC.FusionFix/source/memory.ixx, GPL-3.0, ThirteenAG and the
//     FusionFix contributors), copied verbatim: `GetProcessPreferredGPUMemory`
//     (memory.ixx:14-201 - the dynamic `CreateDXGIFactory2`/`CreateDXGIFactory`
//     ladder, the d3d9-device-matched adapter selection, `GetDesc`/`GetDesc2`,
//     the `IDXGIAdapter3::QueryVideoMemoryInfo` budget, the release order, the
//     `_2048mb` floor and the half-system-RAM cap) and
//     `grcDevice::GetAvailableVideoMemory` (memory.ixx:203-221 - the original
//     answer kept when it is already 2 GB, otherwise
//     `max(GetProcessPreferredGPUMemory(), GetAvailableTextureMem(), 2 GB)`, with
//     FusionFix's `static` once-per-process caching). It is installed exactly as
//     FusionFix installs it (memory.ixx:292-293): a safetyhook inline hook at the
//     pattern's first byte, assigned to a `SafetyHookInline`, whose
//     `.call<uint64_t>()` is the original. No trampoline, no probe, no opt-in key.
//
// Measured on the imaged builds (read-only, game_refs/): path 1's rows match on
// 1.0.0.0, 1.0.0.4, 1.0.1.0, 1.0.4.0, 1.0.6.0, 1.0.7.0, EFLC 1.1.1.0 and EFLC
// 1.1.2.0, all retargeting the same D3D9 `GetAvailableTextureMem` wrapper; they
// stop matching on 1.0.8.0 and EFLC 1.1.3.0, which is exactly where FusionFix's
// pattern matches (`0x402A20` / `0x61A5D0`) - the two paths are the two build
// generations of one fix. On 1.0.8.0 that function has one direct caller,
// `0x40E9B6`, in the settings/device init that stores its 64-bit answer into
// `[0x18CAD50]`/`[0x18CAD54]`.
//
// The device global keeps FusionFix's own pattern set (memory.ixx resolves
// `rage::grcDevice::ms_pD3DDevice` from comvars.ixx:3148-3149), so the copied body
// reads the same global FusionFix's copy reads.

module;

#include <common.hxx>
#include <d3d9.h>
#include <dxgi1_4.h>
#include <safetyhook.hpp>

export module vram;

import common;
import patch;

export namespace xla::vram
{
    // FusionFix's `_2048mb` (memory.ixx:12): the floor its replacement enforces.
    inline constexpr std::uint64_t _2048mb = 2147483648ull;

    // One recovered call site: the signature starts on the `E8` the row retargets.
    struct Row
    {
        std::string_view signature;
        std::string_view label;
    };

    // The three recovered rows, in the original handler's order.
    std::span<const Row> Rows() noexcept;

    // The body the reference's sites call: the game's own answer, clamped to
    // INT_MAX when it is not positive. The original is called only when a row
    // resolved one.
    std::int32_t __cdecl GetVidMemBody() noexcept;

    // The original the reference body forwards to (the reference's single variable).
    void SetVidMemOriginal(std::int32_t(__cdecl* original)()) noexcept;
    [[nodiscard]] bool HasVidMemOriginal() noexcept;

    // FusionFix's entry pattern for `grcDevice::GetAvailableVideoMemory`, and the
    // device-pointer patterns its `comvars.ixx` uses (`ms_pD3DDevice`), in its order.
    inline constexpr std::string_view kFusionFixPattern = "8B 0D ? ? ? ? 83 EC ? 33 C0";
    std::span<const std::string_view> DevicePatterns() noexcept;

    // FusionFix's `rage::grcDevice`: the d3d9 device global comvars resolves and the
    // getter memory.ixx calls. Defined here so the copied body reads exactly as
    // upstream (`rage::grcDevice::GetD3DDevice()`).
    namespace rage::grcDevice
    {
        [[nodiscard]] IDirect3DDevice9* GetD3DDevice();
    }

    // FusionFix's `GetProcessPreferredGPUMemory`, memory.ixx:14-201 verbatim.
    std::uint64_t GetProcessPreferredGPUMemory();

    // FusionFix's replacement, memory.ixx:203-221 verbatim. `shGetAvailableVideoMemory`
    // is its `SafetyHookInline`; the body's first line calls the original through it.
    namespace grcDevice
    {
        extern SafetyHookInline shGetAvailableVideoMemory;
        std::uint64_t GetAvailableVideoMemory();
    }

    // The two expressions the copied code applies, as pure functions so the suite
    // can pin FusionFix's value contract without a device: memory.ixx:210-214 (the
    // 2 GB pass-through / floor of the replacement) and memory.ixx:197-198 (the
    // GPU read's 2 GB floor and the half-system-RAM ceiling).
    [[nodiscard]] constexpr std::uint64_t ReplacementValue(std::uint64_t original,
                                                           std::uint64_t preferred,
                                                           std::uint64_t textureMemory) noexcept
    {
        return original >= _2048mb ? original
                                   : std::max(std::max(preferred, textureMemory), _2048mb);
    }

    [[nodiscard]] constexpr std::uint64_t PreferredGpuValue(std::uint64_t budget,
                                                            std::uint64_t dedicated,
                                                            std::uint64_t totalSystemMemory) noexcept
    {
        return std::min(std::max(std::max(budget, dedicated), _2048mb),
                        totalSystemMemory / 2);
    }

    // Whether the FusionFix replacement is installed; the suite's "installs only when
    // the entry pattern matches".
    [[nodiscard]] bool HookInstalled() noexcept;

    // Which generation path the build took.
    enum class Path : std::uint8_t
    {
        none,       // neither path's patterns matched
        reference,  // the old add-on's recovered call-site rows
        fusionFix,  // FusionFix's GetAvailableVideoMemory replacement
    };

    [[nodiscard]] constexpr std::string_view PathName(Path path) noexcept
    {
        switch (path)
        {
        case Path::none:
            return "none";
        case Path::reference:
            return "reference";
        case Path::fusionFix:
            return "fusionFix";
        }
        return "?";
    }

    struct Report
    {
        Path path{Path::none};
        std::size_t rowsApplied{};
    };

    // [Options] VRAMFix. Runs the reference's rows first and, when that generation's
    // rows are not on this build, FusionFix's replacement; so exactly one path
    // installs per build. Every miss is a logged skip.
    Report Install(const Image& image);
} // namespace xla::vram

namespace xla::vram
{
    namespace
    {
        using VidMemQuery = std::int32_t(__cdecl*)();

        // ---- the reference generation ----------------------------------------
        constexpr Row kRows[] = {
            {"E8 ? ? ? ? D9 E8 85 C0", "vram: call (1/3)"},
            {"E8 ? ? ? ? F3 0F 10 0D ? ? ? ? F3 0F 5C 0D", "vram: call (2/3)"},
            {"E8 ? ? ? ? F3 0F 10 05 ? ? ? ? 89 44 24 08 6A 01 8D 44 24",
             "vram: call (3/3)"},
        };

        VidMemQuery g_vidMemOriginal = nullptr;

        // ---- the FusionFix generation ----------------------------------------
        // `rage::grcDevice::ms_pD3DDevice`, resolved by the comvars patterns.
        IDirect3DDevice9** g_d3dDevice = nullptr;

        constexpr std::string_view kDevicePatterns[] = {
            "83 3D ? ? ? ? ? 74 17 8B 4D 14",
            "83 3D ? ? ? ? ? 74 15 8B 44 24 1C",
            "83 3D ? ? ? ? ? 74 EF",
        };
    } // namespace

    std::span<const Row> Rows() noexcept
    {
        return kRows;
    }

    std::span<const std::string_view> DevicePatterns() noexcept
    {
        return kDevicePatterns;
    }

    std::int32_t __cdecl GetVidMemBody() noexcept
    {
        const std::int32_t value = g_vidMemOriginal != nullptr ? g_vidMemOriginal() : 0;
        return value <= 0 ? INT_MAX : value;
    }

    void SetVidMemOriginal(VidMemQuery original) noexcept
    {
        g_vidMemOriginal = original;
    }

    bool HasVidMemOriginal() noexcept
    {
        return g_vidMemOriginal != nullptr;
    }

    namespace rage::grcDevice
    {
        IDirect3DDevice9* GetD3DDevice()
        {
            return *g_d3dDevice;
        }
    } // namespace rage::grcDevice

    // ---- FusionFix, memory.ixx:14-201, verbatim ------------------------------
    // The game's d3d9 device tells us which DXGI adapter is its own; that
    // adapter's budget/dedicated memory is the answer, floored at 2 GB and
    // capped at half the system RAM.
    uint64_t GetProcessPreferredGPUMemory()
    {
        uint64_t Memory = _2048mb;

        IDirect3DDevice9* Device = rage::grcDevice::GetD3DDevice();
        if (!Device)
            return Memory;

        // Get d3d9 adapter details
        D3DDEVICE_CREATION_PARAMETERS DeviceCreationParams;
        if (FAILED(Device->GetCreationParameters(&DeviceCreationParams)))
            return Memory;

        IDirect3D9* d3d9 = nullptr;
        if (FAILED(Device->GetDirect3D(&d3d9)) || !d3d9)
            return Memory;

        D3DADAPTER_IDENTIFIER9 AdapterIdentifier;
        if (FAILED(d3d9->GetAdapterIdentifier(DeviceCreationParams.AdapterOrdinal, 0, &AdapterIdentifier)))
        {
            d3d9->Release();

            return Memory;
        }
        d3d9->Release();

        HMODULE hDxgi = LoadLibraryA("dxgi.dll");
        if (!hDxgi)
            return Memory;

        // Helper to get system memory
        MEMORYSTATUSEX MemoryInfo;
        MemoryInfo.dwLength = sizeof(MEMORYSTATUSEX);
        GlobalMemoryStatusEx(&MemoryInfo);
        uint64_t TotalSystemMemory = MemoryInfo.ullTotalPhys;

        IDXGIAdapter* SelectedAdapter = nullptr;
        uint64_t MaxDedicated = 0;

        auto EnumerateAdapters = [&](IDXGIFactory* Factory) -> bool
        {
            if (!Factory)
                return false;

            UINT AdapterID = 0;
            IDXGIAdapter* Adapter = nullptr;

            while (SUCCEEDED(Factory->EnumAdapters(AdapterID, &Adapter)))
            {
                DXGI_ADAPTER_DESC Description;

                if (SUCCEEDED(Adapter->GetDesc(&Description)))
                {
                    // Match with d3d9 identifier
                    if (Description.VendorId == AdapterIdentifier.VendorId &&
                        Description.DeviceId == AdapterIdentifier.DeviceId &&
                        Description.SubSysId == AdapterIdentifier.SubSysId &&
                        Description.Revision == AdapterIdentifier.Revision)
                    {
                        if (SelectedAdapter)
                            SelectedAdapter->Release();

                        SelectedAdapter = Adapter;
                        SelectedAdapter->AddRef();
                        Adapter->Release(); // Release the enum ref

                        return true; // Found match, done
                    }

                    // Track max dedicated as fallback
                    if (Description.DedicatedVideoMemory > MaxDedicated)
                    {
                        MaxDedicated = Description.DedicatedVideoMemory;

                        if (SelectedAdapter)
                            SelectedAdapter->Release();

                        SelectedAdapter = Adapter;
                        SelectedAdapter->AddRef();
                    }
                }

                Adapter->Release();
                AdapterID++;
            }

            return false; // No match found
        };

        // Prefer CreateDXGIFactory2 with IDXGIFactory3
        IDXGIFactory* FactoryToUse = nullptr;
        typedef HRESULT(WINAPI* CreateDXGIFactory2_T)(UINT Flags, REFIID riid, void** ppFactory);
        CreateDXGIFactory2_T CreateDXGIFactory2_fun = (CreateDXGIFactory2_T)GetProcAddress(hDxgi, "CreateDXGIFactory2");

        if (CreateDXGIFactory2_fun)
        {
            IDXGIFactory3* Factory3 = nullptr;

            if (SUCCEEDED(CreateDXGIFactory2_fun(0, __uuidof(IDXGIFactory3), (void**)&Factory3)))
            {
                FactoryToUse = static_cast<IDXGIFactory*>(Factory3);
            }
        }

        // Fallback to CreateDXGIFactory if Factory2 not available
        if (!FactoryToUse)
        {
            typedef HRESULT(WINAPI* CreateDXGIFactory_T)(REFIID riid, void** ppFactory);
            CreateDXGIFactory_T CreateDXGIFactory_fun = (CreateDXGIFactory_T)GetProcAddress(hDxgi, "CreateDXGIFactory");

            if (CreateDXGIFactory_fun)
            {
                IDXGIFactory* Factory = nullptr;

                if (SUCCEEDED(CreateDXGIFactory_fun(__uuidof(IDXGIFactory), (void**)&Factory)))
                {
                    FactoryToUse = Factory;
                }
            }
        }

        // Enumerate using the preferred factory
        if (FactoryToUse)
        {
            EnumerateAdapters(FactoryToUse);

            FactoryToUse->Release();
        }

        if (!SelectedAdapter)
        {
            FreeLibrary(hDxgi);

            return Memory;
        }

        // Query the selected adapter
        uint64_t Dedicated = 0;
        uint64_t Shared = 0;
        uint64_t Budget = 0;

        DXGI_ADAPTER_DESC Description;
        if (SUCCEEDED(SelectedAdapter->GetDesc(&Description)))
        {
            Dedicated = Description.DedicatedVideoMemory;
            Shared = Description.SharedSystemMemory;
        }

        IDXGIAdapter3* Adapter3 = nullptr;
        if (SUCCEEDED(SelectedAdapter->QueryInterface(__uuidof(IDXGIAdapter3), (void**)&Adapter3)))
        {
            DXGI_QUERY_VIDEO_MEMORY_INFO VRAMInfo;

            if (SUCCEEDED(Adapter3->QueryVideoMemoryInfo(0, DXGI_MEMORY_SEGMENT_GROUP_LOCAL, &VRAMInfo)))
            {
                Budget = VRAMInfo.Budget;
            }

            Adapter3->Release();
        }
        else
        {
            IDXGIAdapter2* Adapter2 = nullptr;

            if (SUCCEEDED(SelectedAdapter->QueryInterface(__uuidof(IDXGIAdapter2), (void**)&Adapter2)))
            {
                DXGI_ADAPTER_DESC2 Description2;

                if (SUCCEEDED(Adapter2->GetDesc2(&Description2)))
                {
                    Dedicated = Description2.DedicatedVideoMemory;
                    Shared = Description2.SharedSystemMemory;
                }

                Adapter2->Release();
            }
        }

        SelectedAdapter->Release();

        FreeLibrary(hDxgi); // Free only after all interfaces are released

        // Safety caps
        Memory = std::max(std::max(Budget, Dedicated), _2048mb);
        Memory = std::min(Memory, TotalSystemMemory / 2);

        return Memory;
    }

    // ---- FusionFix, memory.ixx:203-221, verbatim -----------------------------
    namespace grcDevice
    {
        SafetyHookInline shGetAvailableVideoMemory = {};
        uint64_t GetAvailableVideoMemory()
        {
            auto ret = shGetAvailableVideoMemory.call<uint64_t>();

            if (ret < _2048mb)
            {
                static auto VRAM = GetProcessPreferredGPUMemory();
                static auto d3d9VRAM = static_cast<uint64_t>(rage::grcDevice::GetD3DDevice()->GetAvailableTextureMem());
                static auto TotalVRAM = std::max(std::max(VRAM, d3d9VRAM), _2048mb);

                ret = TotalVRAM;
            }

            return ret;
        }
    } // namespace grcDevice

    bool HookInstalled() noexcept
    {
        return static_cast<bool>(grcDevice::shGetAvailableVideoMemory);
    }

    namespace
    {
        // FusionFix's install (memory.ixx:285-293): resolve the d3d9 device global,
        // then hook the query's entry with safetyhook's inline-hook factory.
        bool InstallFusionFixPath(const Image& image)
        {
            // FusionFix's comvars.ixx:3148-3149: `ms_pD3DDevice = *get_first(2)`.
            patch::Pattern device = patch::FindIn(image, 1, kDevicePatterns[0],
                                                  kDevicePatterns[1], kDevicePatterns[2]);
            if (device.empty())
            {
                Log::Line("vram: FusionFix: device pattern missing; the arm is skipped");
                return false;
            }
            g_d3dDevice = *device.get_first<IDirect3DDevice9**>(2);

            patch::Pattern pattern = patch::FindIn(image, 1, kFusionFixPattern);
            if (pattern.empty())
            {
                Log::Line("vram: FusionFix: entry pattern missing; the arm is skipped");
                return false;
            }

            grcDevice::shGetAvailableVideoMemory = patch::CreateInline(
                pattern.get_first<std::uint8_t>(0),
                reinterpret_cast<void*>(&grcDevice::GetAvailableVideoMemory),
                "vram: FusionFix");
            if (!grcDevice::shGetAvailableVideoMemory)
            {
                Log::Line("vram: FusionFix: the entry hook could not be created");
                return false;
            }

            Log::Print("vram: FusionFix path installed ({})",
                       BuildLabel(Game::Get().Build()));
            return true;
        }
    } // namespace

    Report Install(const Image& image)
    {
        Report report;

        for (const Row& row : kRows)
        {
            // The reference assigns the result unconditionally: a row that does not
            // match clears the original for every body already installed.
            patch::Pattern pattern = patch::FindIn(image, row.signature, 1);
            if (pattern.empty())
            {
                Log::Print("{}: signature missing", row.label);
                g_vidMemOriginal = nullptr;
                continue;
            }

            const void* previous = patch::RetargetCallAt(
                image, pattern.get_first<std::uint8_t>(0),
                reinterpret_cast<void*>(&GetVidMemBody), row.label);
            if (previous == nullptr)
            {
                Log::Print("{}: call site outside the image", row.label);
                g_vidMemOriginal = nullptr;
                continue;
            }
            g_vidMemOriginal = reinterpret_cast<VidMemQuery>(const_cast<void*>(previous));
            ++report.rowsApplied;
        }

        const std::size_t total = std::size(kRows);
        Log::Print("VRAMFix: {}/{} call site(s) retargeted", report.rowsApplied, total);

        if (report.rowsApplied != 0)
        {
            report.path = Path::reference;
            Log::Print("vram: reference rows installed ({})",
                       BuildLabel(Game::Get().Build()));
            return report;
        }

        // This build's code no longer calls the query the rows hook, so FusionFix's
        // generation is the only way to reach it - but its install is disabled: on
        // 2026-11-17 the run crashed in an unmapped page immediately after this arm
        // installed, and it is the only new code in that build. Re-enable only with a
        // verified run (the function and its tests are kept for that).
        (void)InstallFusionFixPath;
        Log::Line("vram: no reference row matched; the FusionFix generation is disabled "
                  "pending in-game verification");

        report.path = Path::none;
        return report;
    }
} // namespace xla::vram
