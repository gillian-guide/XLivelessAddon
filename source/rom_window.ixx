// SPDX-License-Identifier: GPL-3.0-or-later
//
// xla.rom_window — the legacy WM_ROM message window (installed when
// SkipLauncher=0), descended from XLivelessAddon.
//
// The game sends WM_ROM to a window it creates once; the add-on answers it with
// the original's action table (copy table / add / set). The SendMessage call that
// deadlocks the audio thread is redirected to an empty stub.

module;

#include "common.hxx"

export module xla.rom_window;

import xla.common;

export namespace xla::rom_window
{
    inline constexpr UINT kMessage = 43858; // WM_ROM

    // The table action 18 copies into the game (xmmword_10104050..0x10104080).
    inline constexpr std::array<std::uint32_t, 16> kActionTable{
        8, 11, 241, 1, 240, 2, 7, 12, 3, 243, 9, 6, 10, 5, 4, 242,
    };

    // Message payload: [4] action, [5] and [6] its operands.
    struct Payload
    {
        char reserved[16];
        int action;
        char* setAddress;
        char* copyAddress;
    };

    inline constexpr int kActionCopyTable = 18;
    inline constexpr int kActionAdd = 51;
    inline constexpr int kActionSet = 100;

    // Creates the service window the game pushes messages to.
    HWND CreateServiceWindow();

    // Passed to the game's SendMessage call site: does nothing (the original's
    // stub, which stopped the audio-update deadlock).
    void __stdcall SendMessageStub(int, int, int, int);

    // Installs both sites. Signatures absent on this build are logged and skipped.
    void Install(const Image& image);
} // namespace xla::rom_window

namespace xla::rom_window
{
    namespace
    {
        LRESULT WINAPI WindowProc(HWND /*window*/, UINT message, WPARAM /*wparam*/, LPARAM lparam)
        {
            if (message != kMessage)
            {
                return 1;
            }

            auto* payload = reinterpret_cast<Payload*>(lparam);
            switch (payload->action)
            {
            case kActionSet:
                *reinterpret_cast<std::uint32_t*>(payload->setAddress) = 1;
                return 0;
            case kActionCopyTable:
                std::memcpy(payload->copyAddress, kActionTable.data(), sizeof(kActionTable));
                return 0;
            case kActionAdd:
                return static_cast<LRESULT>(reinterpret_cast<std::uintptr_t>(payload->setAddress) +
                                            reinterpret_cast<std::uintptr_t>(payload->copyAddress));
            default:
                return 0;
            }
        }

        HWND CreateRomWindow()
        {
            WNDCLASSEXW wc{};
            wc.cbSize = sizeof(wc);
            wc.style = 3;
            wc.lpfnWndProc = &WindowProc;
            wc.lpszClassName = L"banana";
            wc.hInstance = ::GetModuleHandleW(nullptr);
            wc.hbrBackground = reinterpret_cast<HBRUSH>(static_cast<std::uintptr_t>(5));
            wc.hCursor = ::LoadCursorW(nullptr, MAKEINTRESOURCEW(0x7F00));

            ::RegisterClassExW(&wc);

            return ::CreateWindowExW(0, L"banana", L"", 0xCC00000, 0, 0, 0, 0, nullptr, nullptr,
                                     ::GetModuleHandleW(nullptr), nullptr);
        }
    } // namespace

    HWND CreateServiceWindow()
    {
        return CreateRomWindow();
    }

    void __stdcall SendMessageStub(int, int, int, int)
    {
    }

    void Install(const Image& image)
    {
        // The game's two globals (window handle, message id) are reached through the
        // operands of `mov eax, [g1]` / `mov ecx, [g2]`; write them only when they
        // point inside the image.
        hook::pattern pattern{"A1 ? ? ? ? 8B 0D ? ? ? ? 68 ? ? ? ? 53 50 51 FF 15"};
        if (!pattern.empty())
        {
            auto* match = pattern.get(0).get<std::uint8_t>();
            const auto messageSlot =
                *reinterpret_cast<const std::uint32_t*>(match + 1);
            const auto windowSlot = *reinterpret_cast<const std::uint32_t*>(match + 7);
            if (image.contains(reinterpret_cast<const void*>(
                                   static_cast<std::uintptr_t>(messageSlot)),
                               4) &&
                image.contains(reinterpret_cast<const void*>(
                                   static_cast<std::uintptr_t>(windowSlot)),
                               4))
            {
                injector::WriteMemory<std::uint32_t>(
                    static_cast<std::uintptr_t>(messageSlot), kMessage, true);
                injector::WriteMemory<std::uint32_t>(
                    static_cast<std::uintptr_t>(windowSlot),
                    static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(
                        rom_window::CreateServiceWindow())),
                    true);
                log::Info("rom: window {:08X}, message id {}", windowSlot, kMessage);
            }
            else
            {
                log::Write("rom: message/window globals outside the image; skipped");
            }
        }
        else
        {
            log::Write("rom: window pattern missing");
        }

        // The SendMessage call freezes the audio update thread; replace it with the
        // stub (6-byte slot: 5-byte call + one nop).
        hook::pattern send{"FF 15 ? ? ? ? E8 ? ? ? ? E8 ? ? ? ? E8 ? ? ? ? E8 ? ? ? ? B9 ? ? ? ? "
                           "E8 ? ? ? ? B9 ? ? ? ? E8 ? ? ? ? 83 7C 24"};
        if (!send.empty())
        {
            auto* site = send.get(0).get<void>();
            injector::MakeNOP(site, 6, true);
            injector::MakeCALL(site, reinterpret_cast<void*>(&SendMessageStub), true);
            log::Write("rom: SendMessage bypass installed");
        }
        else
        {
            log::Write("rom: SendMessage pattern missing");
        }
    }
} // namespace xla::rom_window
