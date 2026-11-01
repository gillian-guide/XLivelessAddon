// SPDX-License-Identifier: GPL-3.0-or-later
//
// xla.windowed — borderless window, window centring, focus-loss input suppression
// and the legacy DefWindowProc shims.
//
// Ported from GTAIV.EFLC.FusionFix's windowed.ixx (GPL-3.0, ThirteenAG and
// contributors) and XLivelessAddon. The original add-on stripped the window
// styles once from the DefWindowProc shims; this port keeps the style in sync
// when the window is created/resized, centres it on the monitor and suppresses
// game input while a borderless window is unfocused.

module;

#include "common.hxx"

export module xla.windowed;

import xla.common;

export namespace xla::windowed
{
    // Installs the CreateWindowEx/MoveWindow/AdjustWindowRect/SetWindowPos/
    // SetWindowLongA/SetRect import hooks. Returns true when at least one import
    // slot was replaced.
    bool InstallBorderlessHooks(const Image& image) noexcept;

    // Hooks the game's per-frame input call and skips it while a borderless
    // window is unfocused. Returns false when the pattern/globals are missing.
    bool InstallFocusLossInput(const Image& image) noexcept;

    // The legacy DefWindowProc A/W shims (the original add-on's borderless patch).
    // Runs in addition to InstallBorderlessHooks, exactly like the original.
    void InstallDefWindowProcShims(const Image& image);
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
        RECT g_clientRect{};
        bool g_clientValid = false;

        bool* g_windowed = nullptr;
        bool* g_focusLost = nullptr;
        bool* g_onTop = nullptr;
        void* g_inputOriginal = nullptr;

        bool g_borderlessInstalled = false;
        bool g_focusInstalled = false;

        bool EqualsIgnoreCase(const char* left, const char* right) noexcept
        {
            return left != nullptr && right != nullptr && _stricmp(left, right) == 0;
        }

        // Replaces the first matching USER32 import slot. The imported function
        // stays callable through `original`.
        // Deliberate near-copy of userdata::ReplaceShellImport and registry's inline
        // walker: this one trusts the PE headers (the other two bounds-check more),
        // and the OriginalFirstThunk == 0 fallback must be kept in sync by hand.
        bool ReplaceImport(HMODULE module, const char* function, void* replacement,
                           void** original) noexcept
        {
            if (module == nullptr || function == nullptr || replacement == nullptr)
            {
                return false;
            }

            const auto* base = reinterpret_cast<const std::uint8_t*>(module);
            const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            {
                return false;
            }

            const auto* nt =
                reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE)
            {
                return false;
            }

            const auto& directory =
                nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
            if (directory.VirtualAddress == 0)
            {
                return false;
            }

            auto* descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
                const_cast<std::uint8_t*>(base) + directory.VirtualAddress);
            for (; descriptor->Name != 0; ++descriptor)
            {
                const char* moduleName =
                    reinterpret_cast<const char*>(base + descriptor->Name);
                if (!EqualsIgnoreCase(moduleName, "USER32.dll") &&
                    !EqualsIgnoreCase(moduleName, "USER32"))
                {
                    continue;
                }

                auto* thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(
                    const_cast<std::uint8_t*>(base) + descriptor->OriginalFirstThunk);
                auto* slot = reinterpret_cast<IMAGE_THUNK_DATA*>(
                    const_cast<std::uint8_t*>(base) + descriptor->FirstThunk);
                if (descriptor->OriginalFirstThunk == 0)
                {
                    thunk = slot;
                }

                for (; thunk->u1.AddressOfData != 0; ++thunk, ++slot)
                {
                    if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal))
                    {
                        continue;
                    }

                    const auto* import = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(
                        base + thunk->u1.AddressOfData);
                    if (!EqualsIgnoreCase(reinterpret_cast<const char*>(import->Name),
                                          function))
                    {
                        continue;
                    }

                    DWORD previous = 0;
                    if (!::VirtualProtect(&slot->u1.Function, sizeof(void*), PAGE_READWRITE,
                                          &previous))
                    {
                        return false;
                    }
                    if (original != nullptr)
                    {
                        *original = reinterpret_cast<void*>(slot->u1.Function);
                    }
                    slot->u1.Function = reinterpret_cast<ULONG_PTR>(replacement);
                    ::VirtualProtect(&slot->u1.Function, sizeof(void*), previous, &previous);
                    return true;
                }
            }
            return false;
        }

        void* User32Proc(const char* name) noexcept
        {
            const HMODULE user32 = ::GetModuleHandleA("user32.dll");
            return user32 != nullptr
                       ? reinterpret_cast<void*>(::GetProcAddress(user32, name))
                       : nullptr;
        }

        // The captured IAT value is the function the loader (or another ASI) put
        // there; that is the one to forward to, not a second GetProcAddress.
        template <typename Function>
        void UseCaptured(void* captured, Function& target) noexcept
        {
            if (captured != nullptr)
            {
                target = reinterpret_cast<Function>(captured);
            }
        }

        // Centres on the nearest monitor. MoveWindowHook below has its own inline
        // copy of the same arithmetic (it also handles the oversized-client case);
        // keep the two in sync. Not merged because the hook has that extra branch.
        void CentreWindow(HWND window, int width, int height) noexcept
        {
            const HMONITOR monitor = ::MonitorFromWindow(window, MONITOR_DEFAULTTONEAREST);
            MONITORINFO info{};
            info.cbSize = sizeof(info);
            if (!::GetMonitorInfoA(monitor, &info))
            {
                return;
            }

            const int desktopWidth = info.rcMonitor.right - info.rcMonitor.left;
            const int desktopHeight = info.rcMonitor.bottom - info.rcMonitor.top;
            const int x = info.rcMonitor.left + (desktopWidth - width) / 2;
            const int y = info.rcMonitor.top + (desktopHeight - height) / 2;

            if (g_setPos != nullptr)
            {
                const HWND after =
                    (g_onTop != nullptr && *g_onTop) ? HWND_TOPMOST : HWND_NOTOPMOST;
                g_setPos(window, after, x, y, width, height, SWP_FRAMECHANGED | SWP_SHOWWINDOW);
            }
        }

        void SwitchWindowStyle() noexcept
        {
            if (g_window == nullptr || g_setLong == nullptr)
            {
                return;
            }

            const LONG style = ::GetWindowLongA(g_window, GWL_STYLE);
            const LONG borderless = style & ~static_cast<LONG>(WS_CAPTION | WS_THICKFRAME |
                                                               WS_MINIMIZEBOX | WS_MAXIMIZEBOX |
                                                               WS_SYSMENU);
            g_setLong(g_window, GWL_STYLE, borderless);

            RECT client = g_clientRect;
            if (!g_clientValid)
            {
                // No SetRect captured a client size: centre the window rect.
                client = RECT{0, 0, 0, 0};
                RECT current{};
                if (g_setPos != nullptr && ::GetWindowRect(g_window, &current))
                {
                    client = current;
                }
            }

            if (g_adjust != nullptr && g_clientValid)
            {
                g_adjust(&client, borderless, FALSE);
            }

            const int width = client.right - client.left;
            const int height = client.bottom - client.top;
            if (width > 0 && height > 0)
            {
                CentreWindow(g_window, width, height);
            }
        }

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
                if (g_clientValid && ((rect.right - rect.left) >= desktopWidth ||
                                      (rect.bottom - rect.top) >= desktopHeight))
                {
                    RECT client = g_clientRect;
                    if (g_adjust != nullptr)
                    {
                        g_adjust(&client, ::GetWindowLongA(window, GWL_STYLE), FALSE);
                    }
                    rect = client;
                }

                const int w = rect.right - rect.left;
                const int h = rect.bottom - rect.top;
                const int cx = info.rcMonitor.left + (desktopWidth - w) / 2;
                const int cy = info.rcMonitor.top + (desktopHeight - h) / 2;
                return g_move != nullptr ? g_move(window, cx, cy, w, h, repaint) : FALSE;
            }

            return g_move != nullptr ? g_move(window, x, y, width, height, repaint) : FALSE;
        }

        BOOL WINAPI AdjustWindowRectHook(LPRECT rect, DWORD style, BOOL menu) noexcept
        {
            style &= ~(WS_CAPTION | WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX |
                       WS_SYSMENU);
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
            g_clientRect = RECT{0, 0, right - left, bottom - top};
            g_clientValid = g_clientRect.right > 0 && g_clientRect.bottom > 0;
            return g_setRect != nullptr ? g_setRect(rect, left, top, right, bottom) : FALSE;
        }

        HWND WINAPI CreateWindowExAHook(DWORD exStyle, LPCSTR className, LPCSTR windowName,
                                        DWORD style, int x, int y, int width, int height,
                                        HWND parent, HMENU menu, HINSTANCE instance,
                                        LPVOID param) noexcept
        {
            g_clientRect = RECT{0, 0, width, height};
            g_clientValid = width > 0 && height > 0;
            HWND window = g_createA != nullptr
                              ? g_createA(exStyle, className, windowName, style, x, y, width,
                                          height, parent, menu, instance, param)
                              : nullptr;
            if (window != nullptr)
            {
                g_window = window;
                SwitchWindowStyle();
            }
            return window;
        }

        HWND WINAPI CreateWindowExWHook(DWORD exStyle, LPCWSTR className, LPCWSTR windowName,
                                        DWORD style, int x, int y, int width, int height,
                                        HWND parent, HMENU menu, HINSTANCE instance,
                                        LPVOID param) noexcept
        {
            g_clientRect = RECT{0, 0, width, height};
            g_clientValid = width > 0 && height > 0;
            HWND window = g_createW != nullptr
                              ? g_createW(exStyle, className, windowName, style, x, y, width,
                                          height, parent, menu, instance, param)
                              : nullptr;
            if (window != nullptr)
            {
                g_window = window;
                SwitchWindowStyle();
            }
            return window;
        }

        bool ResolveBool(const Image& image, const char* primary, const char* fallback,
                         bool** out) noexcept
        {
            hook::pattern pattern{primary};
            if (pattern.empty() && fallback != nullptr)
            {
                pattern = hook::pattern{fallback};
            }
            if (pattern.empty())
            {
                return false;
            }

            auto* slot = pattern.get(0).get<std::uint32_t>(2);
            if (!image.contains(slot, sizeof(void*)))
            {
                return false;
            }
            *out = reinterpret_cast<bool*>(static_cast<std::uintptr_t>(*slot));
            return *out != nullptr;
        }

        // The legacy DefWindowProc shims: strip the window styles once, then call
        // the real procedure.
        LRESULT WINAPI DefWindowProcAProxy(HWND window, UINT message, WPARAM wparam,
                                           LPARAM lparam)
        {
            static bool once = false;
            if (!once)
            {
                ::SetWindowLongA(window, GWL_STYLE,
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
                ::SetWindowLongW(window, GWL_STYLE,
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

        void* oldCreateA = nullptr;
        void* oldCreateW = nullptr;
        void* oldMove = nullptr;
        void* oldAdjust = nullptr;
        void* oldSetPos = nullptr;
        void* oldSetLong = nullptr;
        void* oldSetRect = nullptr;

        // Every ReplaceImport call has to run, so the results are combined with
        // `|`, not `||`: a missing import must not short-circuit the rest.
        const bool hookedCreate =
            ReplaceImport(module, "CreateWindowExA",
                          reinterpret_cast<void*>(&CreateWindowExAHook), &oldCreateA) |
            ReplaceImport(module, "CreateWindowExW",
                          reinterpret_cast<void*>(&CreateWindowExWHook), &oldCreateW);
        const bool hookedOthers =
            ReplaceImport(module, "MoveWindow", reinterpret_cast<void*>(&MoveWindowHook),
                          &oldMove) |
            ReplaceImport(module, "AdjustWindowRect",
                          reinterpret_cast<void*>(&AdjustWindowRectHook), &oldAdjust) |
            ReplaceImport(module, "SetWindowPos", reinterpret_cast<void*>(&SetWindowPosHook),
                          &oldSetPos) |
            ReplaceImport(module, "SetWindowLongA",
                          reinterpret_cast<void*>(&SetWindowLongAHook), &oldSetLong) |
            ReplaceImport(module, "SetRect", reinterpret_cast<void*>(&SetRectHook), &oldSetRect);

        UseCaptured(oldCreateA, g_createA);
        UseCaptured(oldCreateW, g_createW);
        UseCaptured(oldMove, g_move);
        UseCaptured(oldAdjust, g_adjust);
        UseCaptured(oldSetPos, g_setPos);
        UseCaptured(oldSetLong, g_setLong);
        UseCaptured(oldSetRect, g_setRect);

        if (!hookedCreate && !hookedOthers)
        {
            return false;
        }

        log::Info("windowed: import hooks installed");
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

        if (!ResolveBool(image, "80 3D ? ? ? ? ? 74 0E 68 ? ? ? ? 53",
                         "80 3D ? ? ? ? ? 74 13 68", &g_windowed))
        {
            log::Write("windowed: windowed global not found");
            return false;
        }
        if (!ResolveBool(image, "C6 05 ? ? ? ? ? 85 C0 74 02 FF D0 E8", nullptr,
                         &g_focusLost))
        {
            log::Write("windowed: focus-loss global not found");
            return false;
        }
        ResolveBool(image, "80 3D ? ? ? ? ? 74 07 BF", nullptr, &g_onTop);
        // g_onTop is optional: without it the topmost style is simply not kept in
        // sync (CentreWindow/SetWindowPosHook check it for null).

        hook::pattern pattern{"E8 ? ? ? ? A1 ? ? ? ? A3 ? ? ? ? A1 ? ? ? ? 83 C4 04"};
        if (pattern.empty())
        {
            pattern = hook::pattern{"E8 ? ? ? ? 8B 0D ? ? ? ? 8B 15 ? ? ? ? 83 C4 04 83 3D"};
        }
        if (pattern.empty())
        {
            log::Write("windowed: input call pattern not found");
            return false;
        }

        g_inputOriginal =
            injector::MakeCALL(injector::raw_ptr(pattern.get(0).get<void>()),
                               injector::raw_ptr(reinterpret_cast<void*>(&FocusLossInput)), true)
                .get<void*>();
        if (g_inputOriginal == nullptr)
        {
            return false;
        }

        log::Info("windowed: focus-loss input hook installed");
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

        hook::pattern pattern{"FF 15 ? ? ? ? 5F 5E 5D 5B 83 C4 10 C2 10 00"};
        if (pattern.size() < kShimCount)
        {
            log::Info("windowed: DefWindowProc patterns missing ({})", pattern.size());
            return;
        }

        injector::MakeNOP(injector::raw_ptr(pattern.get(0).get<void>()), kImportCallLength, true);
        injector::MakeCALL(injector::raw_ptr(pattern.get(0).get<void>()),
                           injector::raw_ptr(reinterpret_cast<void*>(&DefWindowProcWProxy)), true);
        injector::MakeNOP(injector::raw_ptr(pattern.get(1).get<void>()), kImportCallLength, true);
        injector::MakeCALL(injector::raw_ptr(pattern.get(1).get<void>()),
                           injector::raw_ptr(reinterpret_cast<void*>(&DefWindowProcAProxy)), true);
        log::Write("windowed: DefWindowProc shims installed");
    }
} // namespace xla::windowed
