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
//  2. The FusionFix replacement of `grcDevice::GetAvailableVideoMemory`
//     (GTAIV.EFLC.FusionFix/source/memory.ixx, GPL-3.0, ThirteenAG and the
//     FusionFix contributors), borrowed wholesale: the function's entry is hooked
//     with a call-through trampoline, the original answer is kept when it is
//     already 2 GB or more, and otherwise the answer becomes
//     max(GetProcessPreferredGPUMemory(), GetAvailableTextureMem(), 2 GB) with
//     FusionFix's half-system-memory ceiling. Its value contract, its DXGI
//     `IDXGIAdapter3::QueryVideoMemoryInfo` budget, its d3d9 adapter match and its
//     `static` once-per-process caching are FusionFix's, not a new design.
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
// The entry hook is FusionFix's install semantics (their safetyhook `create_inline`
// at the pattern's first byte) through this tree's classic injector: FusionFix's
// settings bodies read their keys at run time, and so does the replacement below -
// the pattern is resolved at install, the values at call.

module;

#include <common.hxx>
#include <d3d9.h>
#include <dxgi1_4.h>

export module vram;

import common;
import patch;

export namespace xla::vram
{
    // FusionFix's `_2048mb`: the floor its replacement enforces.
    inline constexpr std::uint64_t kTwoGigabytes = 2147483648ull;

    // One recovered call site: the signature starts on the `E8` the row retargets.
    struct Row
    {
        std::string_view signature;
        std::string_view label;
    };

    // The three recovered rows, in the original handler's order.
    std::span<const Row> Rows() noexcept;

    // FusionFix's entry pattern for `grcDevice::GetAvailableVideoMemory`, and the
    // device-pointer patterns its `comvars.ixx` uses (`ms_pD3DDevice`), in its order.
    inline constexpr std::string_view kFusionFixPattern = "8B 0D ? ? ? ? 83 EC ? 33 C0";
    std::span<const std::string_view> DevicePatterns() noexcept;

    // The body the reference's sites call: the game's own answer, clamped to
    // INT_MAX when it is not positive. The original is called only when a row
    // resolved one.
    std::int32_t __cdecl GetVidMemBody() noexcept;

    // The original the reference body forwards to (the reference's single variable).
    void SetVidMemOriginal(std::int32_t(__cdecl* original)()) noexcept;
    [[nodiscard]] bool HasVidMemOriginal() noexcept;

    // FusionFix's replacement and the value contract it applies: the original answer
    // stands when it is 2 GB or more, otherwise the larger of the preferred GPU
    // memory, the d3d9 texture memory and 2 GB. Exposed for the suite.
    std::uint64_t __cdecl FusionFixGetAvailableVideoMemory();
    [[nodiscard]] std::uint64_t FusionFixVramValue(std::uint64_t original,
                                                   std::uint64_t preferred,
                                                   std::uint64_t textureMemory) noexcept;

    // The trampoline the entry hook calls as the original (nullptr until it is
    // published, and after a reset).
    using FusionFixQuery = std::uint64_t(__cdecl*)();
    [[nodiscard]] FusionFixQuery FusionFixOriginal() noexcept;
    void SetFusionFixOriginal(FusionFixQuery original) noexcept;

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

    // Test seam: clears the published original and the device slot.
    void ResetFusionFixState() noexcept;
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
        // The whole instruction the entry hook replaces: `mov ecx, [abs]` plus the
        // `sub esp, imm8`/`xor eax, eax` that follow it in the pattern.
        constexpr std::size_t kFusionFixWindow = 6;
        constexpr std::size_t kFusionFixWindowCheck = 8;

        constexpr std::string_view kDevicePatterns[] = {
            "83 3D ? ? ? ? ? 74 17 8B 4D 14",
            "83 3D ? ? ? ? ? 74 15 8B 44 24 1C",
            "83 3D ? ? ? ? ? 74 EF",
        };

        FusionFixQuery g_fusionFixOriginal = nullptr;
        IDirect3DDevice9** g_d3dDevice = nullptr;
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
} // namespace xla::vram

namespace xla::vram
{
    namespace
    {
        // ---- FusionFix: memory.ixx's GetProcessPreferredGPUMemory -------------
        // The game's d3d9 device tells us which DXGI adapter is its own; that
        // adapter's budget/dedicated memory is the answer, floored at 2 GB and
        // capped at half the system RAM. Ported line for line from FusionFix,
        // including the fallback order (d3d9 identifier match, then the largest
        // dedicated adapter) and the dynamic dxgi entry points.
        IDirect3DDevice9* GetD3DDevice()
        {
            return g_d3dDevice != nullptr ? *g_d3dDevice : nullptr;
        }

        std::uint64_t GetProcessPreferredGPUMemory()
        {
            std::uint64_t Memory = kTwoGigabytes;

            IDirect3DDevice9* Device = GetD3DDevice();
            if (!Device)
            {
                return Memory;
            }

            D3DDEVICE_CREATION_PARAMETERS DeviceCreationParams;
            if (FAILED(Device->GetCreationParameters(&DeviceCreationParams)))
            {
                return Memory;
            }

            IDirect3D9* d3d9 = nullptr;
            if (FAILED(Device->GetDirect3D(&d3d9)) || !d3d9)
            {
                return Memory;
            }

            D3DADAPTER_IDENTIFIER9 AdapterIdentifier;
            if (FAILED(d3d9->GetAdapterIdentifier(DeviceCreationParams.AdapterOrdinal, 0,
                                                  &AdapterIdentifier)))
            {
                d3d9->Release();
                return Memory;
            }
            d3d9->Release();

            HMODULE hDxgi = ::LoadLibraryA("dxgi.dll");
            if (!hDxgi)
            {
                return Memory;
            }

            MEMORYSTATUSEX MemoryInfo;
            MemoryInfo.dwLength = sizeof(MEMORYSTATUSEX);
            ::GlobalMemoryStatusEx(&MemoryInfo);
            const std::uint64_t TotalSystemMemory = MemoryInfo.ullTotalPhys;

            IDXGIAdapter* SelectedAdapter = nullptr;
            std::uint64_t MaxDedicated = 0;

            const auto enumerateAdapters = [&](IDXGIFactory* Factory) -> bool
            {
                if (!Factory)
                {
                    return false;
                }

                UINT AdapterID = 0;
                IDXGIAdapter* Adapter = nullptr;

                while (SUCCEEDED(Factory->EnumAdapters(AdapterID, &Adapter)))
                {
                    DXGI_ADAPTER_DESC Description;

                    if (SUCCEEDED(Adapter->GetDesc(&Description)))
                    {
                        // Match with the d3d9 identifier.
                        if (Description.VendorId == AdapterIdentifier.VendorId &&
                            Description.DeviceId == AdapterIdentifier.DeviceId &&
                            Description.SubSysId == AdapterIdentifier.SubSysId &&
                            Description.Revision == AdapterIdentifier.Revision)
                        {
                            if (SelectedAdapter)
                            {
                                SelectedAdapter->Release();
                            }

                            SelectedAdapter = Adapter;
                            SelectedAdapter->AddRef();
                            Adapter->Release();

                            return true;
                        }

                        // Track the largest dedicated adapter as the fallback.
                        if (Description.DedicatedVideoMemory > MaxDedicated)
                        {
                            MaxDedicated = Description.DedicatedVideoMemory;

                            if (SelectedAdapter)
                            {
                                SelectedAdapter->Release();
                            }

                            SelectedAdapter = Adapter;
                            SelectedAdapter->AddRef();
                        }
                    }

                    Adapter->Release();
                    AdapterID++;
                }

                return false;
            };

            // Prefer CreateDXGIFactory2 with IDXGIFactory3.
            IDXGIFactory* FactoryToUse = nullptr;
            using CreateDXGIFactory2T = HRESULT(WINAPI*)(UINT Flags, REFIID riid, void** factory);
            const auto CreateDXGIFactory2Fun =
                reinterpret_cast<CreateDXGIFactory2T>(::GetProcAddress(hDxgi, "CreateDXGIFactory2"));

            if (CreateDXGIFactory2Fun)
            {
                IDXGIFactory3* Factory3 = nullptr;

                if (SUCCEEDED(CreateDXGIFactory2Fun(0, __uuidof(IDXGIFactory3),
                                                    reinterpret_cast<void**>(&Factory3))))
                {
                    FactoryToUse = static_cast<IDXGIFactory*>(Factory3);
                }
            }

            // Fall back to CreateDXGIFactory when Factory2 is not available.
            if (!FactoryToUse)
            {
                using CreateDXGIFactoryT = HRESULT(WINAPI*)(REFIID riid, void** factory);
                const auto CreateDXGIFactoryFun =
                    reinterpret_cast<CreateDXGIFactoryT>(::GetProcAddress(hDxgi, "CreateDXGIFactory"));

                if (CreateDXGIFactoryFun)
                {
                    IDXGIFactory* Factory = nullptr;

                    if (SUCCEEDED(CreateDXGIFactoryFun(__uuidof(IDXGIFactory),
                                                       reinterpret_cast<void**>(&Factory))))
                    {
                        FactoryToUse = Factory;
                    }
                }
            }

            if (FactoryToUse)
            {
                enumerateAdapters(FactoryToUse);
                FactoryToUse->Release();
            }

            if (!SelectedAdapter)
            {
                ::FreeLibrary(hDxgi);
                return Memory;
            }

            std::uint64_t Dedicated = 0;
            // FusionFix reads and keeps SharedSystemMemory but never uses it; kept so
            // the ported body stays the same shape.
            [[maybe_unused]] std::uint64_t Shared = 0;
            std::uint64_t Budget = 0;

            DXGI_ADAPTER_DESC Description;
            if (SUCCEEDED(SelectedAdapter->GetDesc(&Description)))
            {
                Dedicated = Description.DedicatedVideoMemory;
                Shared = Description.SharedSystemMemory;
            }

            IDXGIAdapter3* Adapter3 = nullptr;
            if (SUCCEEDED(SelectedAdapter->QueryInterface(__uuidof(IDXGIAdapter3),
                                                          reinterpret_cast<void**>(&Adapter3))))
            {
                DXGI_QUERY_VIDEO_MEMORY_INFO VRAMInfo;

                if (SUCCEEDED(Adapter3->QueryVideoMemoryInfo(
                        0, DXGI_MEMORY_SEGMENT_GROUP_LOCAL, &VRAMInfo)))
                {
                    Budget = VRAMInfo.Budget;
                }

                Adapter3->Release();
            }
            else
            {
                IDXGIAdapter2* Adapter2 = nullptr;

                if (SUCCEEDED(SelectedAdapter->QueryInterface(
                        __uuidof(IDXGIAdapter2), reinterpret_cast<void**>(&Adapter2))))
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

            ::FreeLibrary(hDxgi); // Free only after all interfaces are released.

            // Safety caps.
            Memory = std::max(std::max(Budget, Dedicated), kTwoGigabytes);
            Memory = std::min(Memory, TotalSystemMemory / 2);

            return Memory;
        }
    } // namespace

    std::uint64_t FusionFixVramValue(std::uint64_t original, std::uint64_t preferred,
                                     std::uint64_t textureMemory) noexcept
    {
        if (original >= kTwoGigabytes)
        {
            return original;
        }
        return std::max(std::max(preferred, textureMemory), kTwoGigabytes);
    }

    std::uint64_t __cdecl FusionFixGetAvailableVideoMemory()
    {
        const std::uint64_t original =
            g_fusionFixOriginal != nullptr ? g_fusionFixOriginal() : 0;
        if (original >= kTwoGigabytes)
        {
            return original;
        }

        // FusionFix caches both reads once per process, inside the branch.
        static const std::uint64_t preferred = GetProcessPreferredGPUMemory();
        static const std::uint64_t textureMemory = []() -> std::uint64_t {
            IDirect3DDevice9* device = GetD3DDevice();
            return device != nullptr
                       ? static_cast<std::uint64_t>(device->GetAvailableTextureMem())
                       : 0;
        }();
        return FusionFixVramValue(original, preferred, textureMemory);
    }

    FusionFixQuery FusionFixOriginal() noexcept
    {
        return g_fusionFixOriginal;
    }

    void SetFusionFixOriginal(FusionFixQuery original) noexcept
    {
        g_fusionFixOriginal = original;
    }
    void ResetFusionFixState() noexcept
    {
        g_fusionFixOriginal = nullptr;
        g_d3dDevice = nullptr;
    }

    namespace
    {
        // FusionFix's replacement, installed at the function's entry through a
        // trampoline that runs the replaced instruction and resumes after it.
        bool InstallFusionFixPath(const Image& image)
        {
            patch::Pattern pattern = patch::FindIn(image, 1, kFusionFixPattern);
            if (pattern.empty())
            {
                return false;
            }

            auto* entry = pattern.get_first<std::uint8_t>();
            // The pattern's first instruction is `mov ecx, [imm32]` (six bytes) and the
            // next one starts at +6 (`sub esp, imm8`), so the window is one whole
            // instruction: the trampoline can copy it verbatim.
            if (entry[0] != 0x8B || entry[1] != 0x0D || entry[kFusionFixWindow] != 0x83 ||
                entry[kFusionFixWindow + 1] != 0xEC)
            {
                Log::Line("vram: FusionFix: the entry is not `mov ecx,[imm]` + `sub esp,imm`; "
                          "the arm is skipped");
                return false;
            }
            const std::uint64_t screenGlobal = *pattern.get_first<std::uint32_t>(2);
            if (!image.contains(reinterpret_cast<const void*>(screenGlobal),
                                sizeof(std::uint32_t)))
            {
                Log::Line("vram: FusionFix: the entry reads a global outside the image; the "
                          "arm is skipped");
                return false;
            }

            // FusionFix's comvars.ixx resolves the d3d9 device pointer with these
            // patterns; the replacement's d3d9 read needs it, so a miss skips the arm.
            patch::Pattern device =
                patch::FindIn(image, 1, kDevicePatterns[0], kDevicePatterns[1],
                              kDevicePatterns[2]);
            if (device.empty())
            {
                Log::Line("vram: FusionFix: device pattern missing; the arm is skipped");
                return false;
            }
            const std::uint64_t deviceSlot = *device.get_first<std::uint32_t>(2);
            if (!image.contains(reinterpret_cast<const void*>(deviceSlot), sizeof(void*)))
            {
                Log::Line("vram: FusionFix: the device global is outside the image; the arm "
                          "is skipped");
                return false;
            }

            void* trampoline = patch::MakeEntryTrampoline(entry, kFusionFixWindow,
                                                          "vram: FusionFix");
            if (trampoline == nullptr)
            {
                return false;
            }
            // Publish before the entry is written: a call arriving between the two
            // steps must find the original.
            g_d3dDevice = reinterpret_cast<IDirect3DDevice9**>(
                static_cast<std::uintptr_t>(deviceSlot));
            g_fusionFixOriginal = reinterpret_cast<FusionFixQuery>(trampoline);
            if (!patch::HookEntryAt(image, entry, kFusionFixWindow,
                                    reinterpret_cast<const void*>(
                                        &FusionFixGetAvailableVideoMemory),
                                    "vram: FusionFix"))
            {
                Log::Line("vram: FusionFix: the entry is outside the image; the arm is "
                          "skipped");
                ResetFusionFixState();
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
                image, pattern.get_first<std::uint8_t>(),
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

        // This build's code no longer calls the query the rows hook; FusionFix's
        // generation of the fix replaces the query itself.
        if (InstallFusionFixPath(image))
        {
            report.path = Path::fusionFix;
            return report;
        }

        report.path = Path::none;
        Log::Line("vram: no path matched this build");
        return report;
    }
} // namespace xla::vram
