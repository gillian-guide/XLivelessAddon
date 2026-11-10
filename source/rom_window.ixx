// SPDX-License-Identifier: GPL-3.0-or-later
//
// xla.rom_window - the legacy WM_ROM message window (installed when
// SkipLauncher=0), descended from XLivelessAddon.
//
// Ported from openprecepatch/xlivelessaddon/source/rom_window.ixx.
//
// The game sends WM_ROM to a window it creates once; the add-on answers it with
// the original's action table (copy table / add / set). The SendMessage call that
// deadlocks the audio thread is redirected to an empty stub.
//
// xla::skip_launcher has its own, independent WM_ROM service for ZolikaPatch's
// 0x100041A0..0x10004570 ("MessageWindow"/"MessageWindow2"). The message id
// (43858) and the 16-entry action table are duplicated on purpose; the two copies
// are not cross-checked, so a protocol change must be made in both.

module;

#include <common.hxx>

export module rom_window;

import common;
import patch;

export namespace xla::rom_window
{
    inline constexpr UINT kMessage = 43858; // WM_ROM

    // The table action 18 copies into the game (xmmword_10104050..0x10104080).
    inline constexpr std::array<std::uint32_t, 16> kActionTable{
        8, 11, 241, 1, 240, 2, 7, 12, 3, 243, 9, 6, 10, 5, 4, 242,
    };

    // Message payload, indexed as the original's 32-bit slots: slots 0..3 are
    // unused, slot 4 (offset 16) is the action, slots 5 and 6 (offsets 20/24) are
    // its operands. The layout is the protocol, so the offsets are compile-checked.
    struct Payload
    {
        std::array<char, 4 * sizeof(int)> reserved{};
        int action;
        char* setAddress;
        char* copyAddress;
    };
    static_assert(offsetof(Payload, action) == 16);
    static_assert(offsetof(Payload, setAddress) == 20);
    static_assert(offsetof(Payload, copyAddress) == 24);

    inline constexpr int kActionCopyTable = 18;
    inline constexpr int kActionAdd = 51;
    inline constexpr int kActionSet = 100;

    HWND CreateServiceWindow();

    // Passed to the game's SendMessage call site: does nothing (the original's
    // stub, which stopped the audio-update deadlock).
    void __stdcall SendMessageStub(int, int, int, int);

    void Install(const Image& image);
} // namespace xla::rom_window

namespace xla::rom_window
{
    namespace
    {
        LRESULT WINAPI WindowProc(HWND /*window*/, UINT message, WPARAM /*wparam*/,
                                  LPARAM lparam)
        {
            if (message != kMessage)
            {
                // The original answers 1 for a message it does not handle (the
                // skip_launcher copy of this protocol calls DefWindowProcA
                // instead; these are two independent services).
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
                return static_cast<LRESULT>(
                    reinterpret_cast<std::uintptr_t>(payload->setAddress) +
                    reinterpret_cast<std::uintptr_t>(payload->copyAddress));
            default:
                return 0;
            }
        }

        // The original add-on's window recipe, preserved value for value:
        // CS_VREDRAW|CS_HREDRAW, class "banana", and a background brush of the
        // COLOR_WINDOW system-colour index as-is (5, not the documented +1 form),
        // because that is what the original passed. The window is a hidden message
        // window (WS_DISABLED|WS_CLIPSIBLINGS|WS_CAPTION). The asserts below pin
        // the named constants back to the recovered literals (provenance, not
        // values).
        constexpr std::uintptr_t kRomBackgroundColor = COLOR_WINDOW;
        constexpr DWORD kRomWindowStyle = WS_DISABLED | WS_CLIPSIBLINGS | WS_CAPTION;
        // IDC_ARROW's numeric id (32512, i.e. 0x7F00); the header's macro is the
        // ANSI resource form and LoadCursorW wants the wide one.
        constexpr WORD kArrowCursorId = 32512;
        static_assert(kRomBackgroundColor == 5);       // recovered: COLOR_WINDOW index 5
        static_assert(kRomWindowStyle == 0x0CC00000); // recovered: disabled|clipsiblings|caption
        static_assert(kArrowCursorId == 0x7F00);      // recovered: IDC_ARROW id
    } // namespace

    HWND CreateServiceWindow()
    {
        WNDCLASSEXW wc{};
        wc.cbSize = sizeof(wc);
        wc.style = CS_VREDRAW | CS_HREDRAW;
        wc.lpfnWndProc = &WindowProc;
        wc.lpszClassName = L"banana";
        wc.hInstance = ::GetModuleHandleW(nullptr);
        wc.hbrBackground =
            reinterpret_cast<HBRUSH>(static_cast<std::uintptr_t>(kRomBackgroundColor));
        wc.hCursor = ::LoadCursorW(nullptr, MAKEINTRESOURCEW(kArrowCursorId));

        ::RegisterClassExW(&wc);

        return ::CreateWindowExW(0, L"banana", L"", kRomWindowStyle, 0, 0, 0, 0, nullptr,
                                 nullptr, ::GetModuleHandleW(nullptr), nullptr);
    }

    void __stdcall SendMessageStub(int, int, int, int)
    {
    }

    void Install(const Image& image)
    {
        // The game's two globals (window handle, message id) are reached through
        // the operands of `mov eax, [g1]` / `mov ecx, [g2]`; write them only when
        // they point inside the image.
        // A1 <rel32> at +0 and 8B 0D <rel32> at +5; the operands are at +1 and +7.
        constexpr std::ptrdiff_t kMessageOperandOffset = 1;
        constexpr std::ptrdiff_t kWindowOperandOffset = 7;
        patch::Pattern pattern =
            patch::FindIn(image, "A1 ? ? ? ? 8B 0D ? ? ? ? 68 ? ? ? ? 53 50 51 FF 15", 1);
        if (!pattern.empty())
        {
            auto* match = pattern.get_first<std::uint8_t>();
            const auto messageSlot =
                *reinterpret_cast<const std::uint32_t*>(match + kMessageOperandOffset);
            const auto windowSlot =
                *reinterpret_cast<const std::uint32_t*>(match + kWindowOperandOffset);
            if (image.contains(reinterpret_cast<const void*>(
                                   static_cast<std::uintptr_t>(messageSlot)),
                               4) &&
                image.contains(reinterpret_cast<const void*>(
                                   static_cast<std::uintptr_t>(windowSlot)),
                               4))
            {
                patch::Write(
                    patch::Site{reinterpret_cast<std::uint8_t*>(
                        static_cast<std::uintptr_t>(messageSlot))},
                    0, static_cast<std::uint32_t>(kMessage), "rom: message id");
                patch::Write(
                    patch::Site{reinterpret_cast<std::uint8_t*>(
                        static_cast<std::uintptr_t>(windowSlot))},
                    0,
                    static_cast<std::uint32_t>(
                        reinterpret_cast<std::uintptr_t>(CreateServiceWindow())),
                    "rom: window handle");
                Log::Print("rom: window slot {:08X}, message id {}", windowSlot, kMessage);
            }
            else
            {
                Log::Line("rom: message/window globals outside the image; skipped");
            }
        }
        else
        {
            Log::Line("rom: window pattern missing");
        }

        // The SendMessage call freezes the audio update thread; replace it with
        // the stub (6-byte slot: 5-byte call + one nop).
        patch::Pattern send = patch::FindIn(
            image,
            "FF 15 ? ? ? ? E8 ? ? ? ? E8 ? ? ? ? E8 ? ? ? ? E8 ? ? ? ? B9 ? ? ? ? E8 ? ? ? ? B9 "
            "? ? ? ? E8 ? ? ? ? 83 7C 24",
            1);
        if (!send.empty())
        {
            auto* site = send.get_first<std::uint8_t>();
            patch::Nop(patch::Site{site}, 0, 6, "rom: send message nop");
            patch::Call(patch::Site{site}, 0,
                        reinterpret_cast<void*>(&SendMessageStub), "rom: send message bypass");
            Log::Line("rom: SendMessage bypass installed");
        }
        else
        {
            Log::Line("rom: SendMessage pattern missing");
        }
    }
} // namespace xla::rom_window
