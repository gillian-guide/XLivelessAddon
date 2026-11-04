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
        // FusionFix's windowed.ixx keeps the last SetRect rectangle here and
        // centres the window through MoveWindow (not SetWindowPos with
        // SWP_FRAMECHANGED|SWP_SHOWWINDOW), which is the part this companion
        // previously did differently.
        RECT g_rect{};

        // The bordered-window style bits the borderless mode removes. Keeping
        // the mask in one place lets SwitchWindowStyle and AdjustWindowRectHook
        // agree on the borderless style.
        constexpr LONG kBorderlessMask =
            static_cast<LONG>(WS_CAPTION | WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX |
                              WS_SYSMENU);

        bool* g_windowed = nullptr;
        bool* g_focusLost = nullptr;
        bool* g_onTop = nullptr;
        void* g_inputOriginal = nullptr;

        bool g_borderlessInstalled = false;
        bool g_focusInstalled = false;

        // Replaces the first matching USER32 import slot and returns the value it
        // held (the function the game keeps calling), or nullopt when there is no
        // such slot. The value can itself be null, so the optional, not the pointer,
        // says whether the slot was replaced. The walk is FusionFix's IATHook; the
        // map lookup is what distinguishes "not present" from "present and null".
        [[nodiscard]] std::optional<void*> ReplaceImport(HMODULE module, const char* function,
                                                         void* replacement) noexcept
        {
            if (module == nullptr || function == nullptr || replacement == nullptr ||
                NtHeaders(module) == nullptr)
            {
                return std::nullopt;
            }

            auto originals = IATHook::Replace(
                module, "USER32.dll",
                std::pair<const char*, void*>{function, replacement});
            const auto found = originals.find(function);
            if (found == originals.end())
            {
                return std::nullopt;
            }
            return found->second.get();
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

        // Port of FusionFix's SwitchWindowStyle: strip the bordered style,
        // AdjustWindowRect the captured rect, SetWindowLong, MoveWindow and
        // ShowWindow. No SWP_FRAMECHANGED/SWP_SHOWWINDOW re-centre loop.
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
                g_adjust(&rect, style, FALSE);
            }
            g_setLong(g_window, GWL_STYLE, style);
            MoveWindowHook(g_window, 0, 0, rect.right - rect.left, rect.bottom - rect.top, TRUE);
            ::ShowWindow(g_window, SW_SHOW);
        }

        // Port of FusionFix's MoveWindow_Hook: centre on the nearest monitor and
        // use the captured SetRect rectangle when the requested size is larger
        // than the desktop. The float halves are FusionFix's own arithmetic (it
        // truncates the sum), so the one-pixel rounding matches upstream.
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

        // The A and W CreateWindowEx hooks differ only in the captured import they
        // forward to, so one body serves both; the wrappers below keep the exact
        // Win32 signatures the import table expects. The requested style is ignored
        // on purpose: FusionFix creates the game window with style 0 and lets
        // SwitchWindowStyle apply the borderless style, so it never flashes a
        // bordered window first.
        template <typename CharT, typename CreateFn>
        HWND CreateWindowExHook(DWORD exStyle, const CharT* className, const CharT* windowName,
                                DWORD /*style*/, int x, int y, int width, int height, HWND parent,
                                HMENU menu, HINSTANCE instance, LPVOID param,
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

        // The operand of `cmp byte [imm32], imm8` / `mov byte [imm32], imm8` is the
        // 4-byte global the row refers to.
        constexpr std::ptrdiff_t kGlobalOperandOffset = 2;

        // Resolves the bool global one of those windows refers to. `fallback` is the
        // older variant of the signature (empty = none). Returns nullptr when neither
        // matches or the operand points outside the image.
        [[nodiscard]] bool* ResolveGlobalBool(const Image& image, std::string_view primary,
                                              std::string_view fallback = {}) noexcept
        {
            hook::pattern pattern = find_pattern(primary, fallback);
            if (pattern.empty())
            {
                return nullptr;
            }

            auto* slot = pattern.get(0).get<std::uint32_t>(kGlobalOperandOffset);
            if (!image.contains(slot, sizeof(std::uint32_t)))
            {
                return nullptr;
            }
            return reinterpret_cast<bool*>(static_cast<std::uintptr_t>(*slot));
        }

        // The legacy DefWindowProc shims: strip the window styles once per proxy,
        // then call the real procedure. They are the A/W pair of one recovered
        // body: each keeps its own one-shot flag (the original had one per site, so
        // the first window each shim sees is the one that gets stripped) and its own
        // API family - that difference is the contract, not duplication.
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

        // Every import is attempted; a missing one must not stop the rest, so the
        // seven calls are named before they are combined.
        const auto createA = ReplaceImport(module, "CreateWindowExA",
                                           reinterpret_cast<void*>(&CreateWindowExAHook));
        const auto createW = ReplaceImport(module, "CreateWindowExW",
                                           reinterpret_cast<void*>(&CreateWindowExWHook));
        const auto move = ReplaceImport(module, "MoveWindow",
                                        reinterpret_cast<void*>(&MoveWindowHook));
        const auto adjust = ReplaceImport(module, "AdjustWindowRect",
                                          reinterpret_cast<void*>(&AdjustWindowRectHook));
        const auto setPos = ReplaceImport(module, "SetWindowPos",
                                          reinterpret_cast<void*>(&SetWindowPosHook));
        const auto setLong = ReplaceImport(module, "SetWindowLongA",
                                           reinterpret_cast<void*>(&SetWindowLongAHook));
        const auto setRect = ReplaceImport(module, "SetRect",
                                           reinterpret_cast<void*>(&SetRectHook));

        if (createA)
        {
            UseCaptured(*createA, g_createA);
        }
        if (createW)
        {
            UseCaptured(*createW, g_createW);
        }
        if (move)
        {
            UseCaptured(*move, g_move);
        }
        if (adjust)
        {
            UseCaptured(*adjust, g_adjust);
        }
        if (setPos)
        {
            UseCaptured(*setPos, g_setPos);
        }
        if (setLong)
        {
            UseCaptured(*setLong, g_setLong);
        }
        if (setRect)
        {
            UseCaptured(*setRect, g_setRect);
        }

        if (!createA && !createW && !move && !adjust && !setPos && !setLong && !setRect)
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

        g_windowed = ResolveGlobalBool(image, "80 3D ? ? ? ? ? 74 0E 68 ? ? ? ? 53",
                                       "80 3D ? ? ? ? ? 74 13 68");
        if (g_windowed == nullptr)
        {
            log::Write("windowed: windowed global not found");
            return false;
        }
        g_focusLost = ResolveGlobalBool(image, "C6 05 ? ? ? ? ? 85 C0 74 02 FF D0 E8");
        if (g_focusLost == nullptr)
        {
            log::Write("windowed: focus-loss global not found");
            return false;
        }
        // Optional: without it the topmost style is simply not kept in sync
        // (SetWindowPosHook and SetWindowLongAHook check g_onTop for null).
        g_onTop = ResolveGlobalBool(image, "80 3D ? ? ? ? ? 74 07 BF");

        hook::pattern pattern =
            find_pattern("E8 ? ? ? ? A1 ? ? ? ? A3 ? ? ? ? A1 ? ? ? ? 83 C4 04",
                         "E8 ? ? ? ? 8B 0D ? ? ? ? 8B 15 ? ? ? ? 83 C4 04 83 3D");
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

        hook::pattern pattern =
            find_pattern<2>("FF 15 ? ? ? ? 5F 5E 5D 5B 83 C4 10 C2 10 00");
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
