// SPDX-License-Identifier: GPL-3.0-or-later
//
// xla.windowed - borderless window, window centring, focus-loss input suppression
// and the legacy DefWindowProc shims.
//
// Ported from GTAIV.EFLC.FusionFix's windowed.ixx (GPL-3.0, ThirteenAG and
// contributors), via the old addon's xla.windowed. The original add-on stripped
// the window styles once from the DefWindowProc shims; this port keeps the style
// in sync when the window is created/resized, centres it on the monitor and
// suppresses game input while a borderless window is unfocused.
//
// DIVERGENCE FROM THE OLD ADDON: the windowed options are still gated off when
// FusionFix is present (FusionFix owns the same subsystem). Only the local-path
// options are ungated.

module;

#include <common.hxx>

export module windowed;

import common;
import patch;

export namespace xla::windowed
{
    // Installs the CreateWindowEx/MoveWindow/AdjustWindowRect/SetWindowPos/
    // SetWindowLongA/SetRect import hooks. Returns true when at least one import
    // slot was replaced.
    bool InstallBorderlessHooks(const Image& image) noexcept;

    // Hooks the game's per-frame input call and skips it while a borderless
    // window is unfocused.
    bool InstallFocusLossInput(const Image& image) noexcept;

    // The legacy DefWindowProc A/W shims (the original add-on's borderless patch).
    void InstallDefWindowProcShims(const Image& image);

    // DoNotPauseOnMinimize: stop the game pausing when the window loses focus
    // (the recovered `75 ?` branch NOP).
    void InstallDoNotPauseOnMinimize(const Image& image);
} // namespace xla::windowed

namespace xla::windowed
{
    namespace
    {
        using CreateWindowExAFn = HWND(WINAPI*)(DWORD, LPCSTR, LPCSTR, DWORD, int, int, int, int,
                                                HWND, HMENU, HINSTANCE, LPVOID);
        using CreateWindowExWFn = HWND(WINAPI*)(DWORD, LPCWSTR, LPCWSTR, DWORD, int, int, int,
                                                int, HWND, HMENU, HINSTANCE, LPVOID);
        using MoveWindowFn = BOOL(WINAPI*)(HWND, int, int, int, int, BOOL);
        using AdjustWindowRectFn = BOOL(WINAPI*)(LPRECT, DWORD, BOOL);
        using SetWindowPosFn = BOOL(WINAPI*)(HWND, HWND, int, int, int, int, UINT);
        using SetWindowLongAFn = LONG(WINAPI*)(HWND, int, LONG);
        using SetRectFn = BOOL(WINAPI*)(LPRECT, int, int, int, int);

        CreateWindowExAFn g_createA = nullptr;
        CreateWindowExWFn g_createW = nullptr;
        MoveWindowFn g_move = nullptr;
        AdjustWindowRectFn g_adjust = nullptr;
        SetWindowPosFn g_setPos = nullptr;
        SetWindowLongAFn g_setLong = nullptr;
        SetRectFn g_setRect = nullptr;

        HWND g_window = nullptr;
        RECT g_rect{};

        constexpr LONG kBorderlessMask =
            static_cast<LONG>(WS_CAPTION | WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX |
                              WS_SYSMENU);

        bool* g_windowed = nullptr;
        bool* g_focusLost = nullptr;
        bool* g_onTop = nullptr;
        void* g_inputOriginal = nullptr;

        bool g_borderlessInstalled = false;
        bool g_focusInstalled = false;

        void* User32Proc(const char* name) noexcept
        {
            const HMODULE user32 = ::GetModuleHandleA("user32.dll");
            return user32 != nullptr ? reinterpret_cast<void*>(::GetProcAddress(user32, name))
                                     : nullptr;
        }

        template <typename Function>
        void UseCaptured(void* captured, Function& target) noexcept
        {
            if (captured != nullptr)
            {
                target = reinterpret_cast<Function>(captured);
            }
        }

        BOOL WINAPI MoveWindowHook(HWND window, int x, int y, int width, int height,
                                   BOOL repaint) noexcept;

        void SwitchWindowStyle() noexcept
        {
            if (g_window == nullptr || g_setLong == nullptr)
            {
                return;
            }

            RECT rect = g_rect;
            const LONG style = ::GetWindowLongA(g_window, GWL_STYLE) & ~kBorderlessMask;
            if (g_adjust != nullptr)
            {
                g_adjust(&rect, static_cast<DWORD>(style), FALSE);
            }
            g_setLong(g_window, GWL_STYLE, style);
            MoveWindowHook(g_window, 0, 0, rect.right - rect.left, rect.bottom - rect.top, TRUE);
            ::ShowWindow(g_window, SW_SHOW);
        }

        // FusionFix's MoveWindow_Hook: centre on the nearest monitor and use the
        // captured SetRect rectangle when the requested size is larger than the
        // desktop. The float halves are FusionFix's own arithmetic (it truncates
        // the sum), so the one-pixel rounding matches upstream.
        BOOL WINAPI MoveWindowHook(HWND window, int x, int y, int width, int height,
                                   BOOL repaint) noexcept
        {
            RECT rect{x, y, width, height};
            const HMONITOR monitor = ::MonitorFromWindow(window, MONITOR_DEFAULTTONEAREST);
            MONITORINFO info{};
            info.cbSize = sizeof(info);
            if (::GetMonitorInfoA(monitor, &info))
            {
                const int desktopWidth = info.rcMonitor.right - info.rcMonitor.left;
                const int desktopHeight = info.rcMonitor.bottom - info.rcMonitor.top;
                if ((rect.right - rect.left) >= desktopWidth ||
                    (rect.bottom - rect.top) >= desktopHeight)
                {
                    rect = g_rect;
                }
                rect.left = info.rcMonitor.left +
                            static_cast<LONG>(static_cast<float>(desktopWidth) / 2.0f -
                                              static_cast<float>(rect.right) / 2.0f);
                rect.top = info.rcMonitor.top +
                           static_cast<LONG>(static_cast<float>(desktopHeight) / 2.0f -
                                             static_cast<float>(rect.bottom) / 2.0f);
                return g_move != nullptr
                           ? g_move(window, rect.left, rect.top, rect.right, rect.bottom, repaint)
                           : FALSE;
            }
            return g_move != nullptr ? g_move(window, x, y, width, height, repaint) : FALSE;
        }

        BOOL WINAPI AdjustWindowRectHook(LPRECT rect, DWORD style, BOOL menu) noexcept
        {
            style &= ~static_cast<DWORD>(kBorderlessMask);
            return g_adjust != nullptr ? g_adjust(rect, style, menu) : FALSE;
        }

        BOOL WINAPI SetWindowPosHook(HWND window, HWND insertAfter, int x, int y, int width,
                                     int height, UINT flags) noexcept
        {
            if (g_onTop != nullptr)
            {
                insertAfter = *g_onTop ? HWND_TOPMOST : HWND_NOTOPMOST;
            }
            if (g_setPos == nullptr)
            {
                return FALSE;
            }

            const BOOL result = g_setPos(window, insertAfter, x, y, width, height, flags);
            SwitchWindowStyle();
            return result;
        }

        LONG WINAPI SetWindowLongAHook(HWND window, int index, LONG value) noexcept
        {
            if (index == GWL_EXSTYLE && (g_onTop == nullptr || !*g_onTop))
            {
                value &= ~static_cast<LONG>(WS_EX_TOPMOST);
            }
            return g_setLong != nullptr ? g_setLong(window, index, value) : 0;
        }

        BOOL WINAPI SetRectHook(LPRECT rect, int left, int top, int right, int bottom) noexcept
        {
            g_rect = RECT{left, top, right, bottom};
            return g_setRect != nullptr ? g_setRect(rect, left, top, right, bottom) : FALSE;
        }

        template <typename CharT, typename CreateFn>
        HWND CreateWindowExHook(DWORD exStyle, const CharT* className, const CharT* windowName,
                                DWORD /*style*/, int x, int y, int width, int height,
                                HWND parent, HMENU menu, HINSTANCE instance, LPVOID param,
                                CreateFn& create) noexcept
        {
            HWND window = create != nullptr
                              ? create(exStyle, className, windowName, 0, x, y, width, height,
                                       parent, menu, instance, param)
                              : nullptr;
            if (window != nullptr)
            {
                g_window = window;
                SwitchWindowStyle();
            }
            return window;
        }

        HWND WINAPI CreateWindowExAHook(DWORD exStyle, LPCSTR className, LPCSTR windowName,
                                        DWORD style, int x, int y, int width, int height,
                                        HWND parent, HMENU menu, HINSTANCE instance,
                                        LPVOID param) noexcept
        {
            return CreateWindowExHook(exStyle, className, windowName, style, x, y, width, height,
                                      parent, menu, instance, param, g_createA);
        }

        HWND WINAPI CreateWindowExWHook(DWORD exStyle, LPCWSTR className, LPCWSTR windowName,
                                        DWORD style, int x, int y, int width, int height,
                                        HWND parent, HMENU menu, HINSTANCE instance,
                                        LPVOID param) noexcept
        {
            return CreateWindowExHook(exStyle, className, windowName, style, x, y, width, height,
                                      parent, menu, instance, param, g_createW);
        }

        constexpr std::ptrdiff_t kGlobalOperandOffset = 2;

        [[nodiscard]] bool* ResolveGlobalBool(const Image& image, std::string_view primary,
                                              std::string_view fallback = {}) noexcept
        {
            patch::Pattern pattern = patch::find_pattern(primary, fallback);
            if (pattern.empty())
            {
                return nullptr;
            }

            auto* slot = pattern.get_first<std::uint32_t>(kGlobalOperandOffset);
            if (!image.contains(slot, sizeof(std::uint32_t)))
            {
                return nullptr;
            }
            // The operand is a global only when it points into the image. A matched
            // site whose operand is a plain constant must not become a pointer: reading
            // the module start's DOS bytes as one crashed the input hook on focus loss.
            const auto resolved = static_cast<std::uintptr_t>(*slot);
            if (!image.contains(reinterpret_cast<const void*>(resolved), 1))
            {
                return nullptr;
            }
            return reinterpret_cast<bool*>(resolved);
        }

        LRESULT WINAPI DefWindowProcAProxy(HWND window, UINT message, WPARAM wparam,
                                           LPARAM lparam)
        {
            static bool once = false;
            if (!once)
            {
                ::SetWindowLongA(
                    window, GWL_STYLE,
                    ::GetWindowLongA(window, GWL_STYLE) &
                        ~static_cast<LONG>(WS_OVERLAPPEDWINDOW));
                once = true;
            }
            return ::DefWindowProcA(window, message, wparam, lparam);
        }

        LRESULT WINAPI DefWindowProcWProxy(HWND window, UINT message, WPARAM wparam,
                                           LPARAM lparam)
        {
            static bool once = false;
            if (!once)
            {
                ::SetWindowLongW(
                    window, GWL_STYLE,
                    ::GetWindowLongW(window, GWL_STYLE) &
                        ~static_cast<LONG>(WS_OVERLAPPEDWINDOW));
                once = true;
            }
            return ::DefWindowProcW(window, message, wparam, lparam);
        }
    } // namespace

    // ABI: __cdecl with one char argument, plain ret. It replaces the game's
    // per-frame input call, so the original call target is invoked with the same
    // argument when input is not suppressed.
    extern "C" void __cdecl FocusLossInput(char argument) noexcept
    {
        if (g_windowed != nullptr && g_focusLost != nullptr && *g_windowed && *g_focusLost)
        {
            return;
        }
        if (g_inputOriginal != nullptr)
        {
            reinterpret_cast<void(__cdecl*)(char)>(g_inputOriginal)(argument);
        }
    }

    bool InstallBorderlessHooks(const Image& image) noexcept
    {
        // A parity dump maps a private copy at an arbitrary address; hooks in its
        // own process are neither needed nor safe.
        if (::GetModuleHandleW(nullptr) != reinterpret_cast<HMODULE>(image.base))
        {
            return false;
        }
        if (g_borderlessInstalled)
        {
            return true;
        }

        const HMODULE module = ::GetModuleHandleW(nullptr);
        if (module == nullptr)
        {
            return false;
        }

        g_createA = reinterpret_cast<CreateWindowExAFn>(User32Proc("CreateWindowExA"));
        g_createW = reinterpret_cast<CreateWindowExWFn>(User32Proc("CreateWindowExW"));
        g_move = reinterpret_cast<MoveWindowFn>(User32Proc("MoveWindow"));
        g_adjust = reinterpret_cast<AdjustWindowRectFn>(User32Proc("AdjustWindowRect"));
        g_setPos = reinterpret_cast<SetWindowPosFn>(User32Proc("SetWindowPos"));
        g_setLong = reinterpret_cast<SetWindowLongAFn>(User32Proc("SetWindowLongA"));
        g_setRect = reinterpret_cast<SetRectFn>(User32Proc("SetRect"));

        const auto originals = patch::ReplaceImports(
            module, "USER32.DLL",
            {{"CreateWindowExA", reinterpret_cast<void*>(&CreateWindowExAHook)},
             {"CreateWindowExW", reinterpret_cast<void*>(&CreateWindowExWHook)},
             {"MoveWindow", reinterpret_cast<void*>(&MoveWindowHook)},
             {"AdjustWindowRect", reinterpret_cast<void*>(&AdjustWindowRectHook)},
             {"SetWindowPos", reinterpret_cast<void*>(&SetWindowPosHook)},
             {"SetWindowLongA", reinterpret_cast<void*>(&SetWindowLongAHook)},
             {"SetRect", reinterpret_cast<void*>(&SetRectHook)}});

        const auto captured = [&originals](std::string_view name) -> void*
        {
            const auto found = originals.find(std::string(name));
            return found == originals.end() ? nullptr : found->second;
        };

        UseCaptured(captured("CreateWindowExA"), g_createA);
        UseCaptured(captured("CreateWindowExW"), g_createW);
        UseCaptured(captured("MoveWindow"), g_move);
        UseCaptured(captured("AdjustWindowRect"), g_adjust);
        UseCaptured(captured("SetWindowPos"), g_setPos);
        UseCaptured(captured("SetWindowLongA"), g_setLong);
        UseCaptured(captured("SetRect"), g_setRect);

        if (originals.empty())
        {
            return false;
        }

        Log::Print("windowed: {} import hook(s) installed", originals.size());
        g_borderlessInstalled = true;
        return true;
    }

    bool InstallFocusLossInput(const Image& image) noexcept
    {
        if (::GetModuleHandleW(nullptr) != reinterpret_cast<HMODULE>(image.base))
        {
            return false;
        }
        if (g_focusInstalled)
        {
            return true;
        }

        g_windowed = ResolveGlobalBool(image, "80 3D ? ? ? ? ? 74 0E 68 ? ? ? ? 53",
                                       "80 3D ? ? ? ? ? 74 13 68");
        if (g_windowed == nullptr)
        {
            Log::Line("windowed: windowed global not found");
            return false;
        }
        g_focusLost = ResolveGlobalBool(image, "C6 05 ? ? ? ? ? 85 C0 74 02 FF D0 E8",
                                        "C6 05 ? ? ? ? ? 74 02 FF D0 C6 05");
        if (g_focusLost == nullptr)
        {
            Log::Line("windowed: focus-loss global not found");
            return false;
        }
        // Optional: without it the topmost style is simply not kept in sync.
        g_onTop = ResolveGlobalBool(image, "80 3D ? ? ? ? ? 74 07 BF");

        patch::Pattern pattern =
            patch::find_pattern("E8 ? ? ? ? A1 ? ? ? ? A3 ? ? ? ? A1 ? ? ? ? 83 C4 04",
                                "E8 ? ? ? ? 8B 0D ? ? ? ? 8B 15 ? ? ? ? 83 C4 04 83 3D");
        if (pattern.empty())
        {
            Log::Line("windowed: input call pattern not found");
            return false;
        }

        g_inputOriginal =
            patch::Call(patch::Site{pattern.get_first<std::uint8_t>()}, 0,
                        reinterpret_cast<void*>(&FocusLossInput), "windowed: focus-loss input");
        if (g_inputOriginal == nullptr)
        {
            return false;
        }

        Log::Print("windowed: focus-loss input hook installed");
        g_focusInstalled = true;
        return true;
    }

    void InstallDefWindowProcShims(const Image& image)
    {
        (void)image;

        // `FF 15 <rel32>` is a 6-byte import call; the original patches the first
        // two matches, the W shim then the A shim.
        constexpr std::size_t kImportCallLength = 6;
        constexpr std::size_t kShimCount = 2;

        patch::Pattern pattern =
            patch::find_pattern<2>("FF 15 ? ? ? ? 5F 5E 5D 5B 83 C4 10 C2 10 00");
        if (pattern.size() < kShimCount)
        {
            Log::Print("windowed: DefWindowProc patterns missing ({})", pattern.size());
            return;
        }

        patch::Nop(patch::Site{pattern.get<std::uint8_t>(0)}, 0, kImportCallLength,
                   "windowed: DefWindowProc W nop");
        patch::Call(patch::Site{pattern.get<std::uint8_t>(0)}, 0,
                    reinterpret_cast<void*>(&DefWindowProcWProxy), "windowed: DefWindowProc W");
        patch::Nop(patch::Site{pattern.get<std::uint8_t>(1)}, 0, kImportCallLength,
                   "windowed: DefWindowProc A nop");
        patch::Call(patch::Site{pattern.get<std::uint8_t>(1)}, 0,
                    reinterpret_cast<void*>(&DefWindowProcAProxy), "windowed: DefWindowProc A");
        Log::Line("windowed: DefWindowProc shims installed");
    }

    void InstallDoNotPauseOnMinimize(const Image& image)
    {
        (void)image;

        // NOP the `75 ?` branch; original site 0x402D5A.
        patch::NopFirst("75 ? 8B 0D ? ? ? ? 51 FF 15 ? ? ? ? 85 C0 75 ? 8B 15", 0, 2,
                        "input: do not pause on minimize");
    }
} // namespace xla::windowed
