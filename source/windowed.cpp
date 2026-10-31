// SPDX-License-Identifier: GPL-3.0-or-later

#include "windowed.hxx"

#include <Hooking.Patterns.h>
#include <injector/injector.hpp>
#include <injector/calling.hpp>

#include <windows.h>

#include <cstring>

namespace opp
{
    namespace
    {
        hook::pattern Pattern(const GameImage& image, std::string_view signature)
        {
            const uintptr_t begin = reinterpret_cast<uintptr_t>(image.base);
            return hook::make_range_pattern(begin, begin + image.size, signature);
        }
    } // namespace
} // namespace opp

namespace opp

{

    namespace

    {

        using CreateWindowExAFn = HWND(WINAPI*)(DWORD, LPCSTR, LPCSTR, DWORD, int, int,

                                               int, int, HWND, HMENU, HINSTANCE, LPVOID);

        using CreateWindowExWFn = HWND(WINAPI*)(DWORD, LPCWSTR, LPCWSTR, DWORD, int, int,

                                               int, int, HWND, HMENU, HINSTANCE, LPVOID);

        using MoveWindowFn = BOOL(WINAPI*)(HWND, int, int, int, int, BOOL);

        using AdjustWindowRectFn = BOOL(WINAPI*)(LPRECT, DWORD, BOOL);

        using SetWindowPosFn = BOOL(WINAPI*)(HWND, HWND, int, int, int, int, UINT);

        using SetWindowLongAFn = LONG(WINAPI*)(HWND, int, LONG);

        using SetRectFn = BOOL(WINAPI*)(LPRECT, int, int, int, int);

        CreateWindowExAFn g_create_a = nullptr;

        CreateWindowExWFn g_create_w = nullptr;

        MoveWindowFn g_move = nullptr;

        AdjustWindowRectFn g_adjust = nullptr;

        SetWindowPosFn g_set_pos = nullptr;

        SetWindowLongAFn g_set_long = nullptr;

        SetRectFn g_set_rect = nullptr;

        HWND g_wnd = nullptr;

        RECT g_client_rect{};

        bool g_client_valid = false;

        bool* g_windowed = nullptr;

        bool* g_focus_lost = nullptr;

        bool* g_on_top = nullptr;

        void* g_input_orig = nullptr;

        bool g_borderless_installed = false;

        bool g_focus_installed = false;

        bool EqualsIgnoreCase(const char* left, const char* right) noexcept

        {

            return left != nullptr && right != nullptr && _stricmp(left, right) == 0;

        }

        // Replaces the first matching USER32 import slot. The imported function

        // stays callable through `original`.

        bool ReplaceImport(HMODULE module, const char* function, void* replacement,

                           void** original) noexcept

        {

            if (module == nullptr || function == nullptr || replacement == nullptr)

                return false;

            const auto* base = reinterpret_cast<const uint8_t*>(module);

            const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);

            if (dos->e_magic != IMAGE_DOS_SIGNATURE)

                return false;

            const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(

                base + dos->e_lfanew);

            if (nt->Signature != IMAGE_NT_SIGNATURE)

                return false;

            const auto& directory =

                nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

            if (directory.VirtualAddress == 0)

                return false;

            auto* descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(

                const_cast<uint8_t*>(base) + directory.VirtualAddress);

            for (; descriptor->Name != 0; ++descriptor)

            {

                const char* module_name = reinterpret_cast<const char*>(

                    base + descriptor->Name);

                if (!EqualsIgnoreCase(module_name, "USER32.dll") &&

                    !EqualsIgnoreCase(module_name, "USER32"))

                    continue;

                auto* thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(

                    const_cast<uint8_t*>(base) + descriptor->OriginalFirstThunk);

                auto* slot = reinterpret_cast<IMAGE_THUNK_DATA*>(

                    const_cast<uint8_t*>(base) + descriptor->FirstThunk);

                if (descriptor->OriginalFirstThunk == 0)

                {

                    thunk = slot;

                }

                for (; thunk->u1.AddressOfData != 0; ++thunk, ++slot)

                {

                    if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal))

                        continue;

                    const auto* import = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(

                        base + thunk->u1.AddressOfData);

                    if (!EqualsIgnoreCase(reinterpret_cast<const char*>(import->Name),

                                          function))

                        continue;

                    DWORD old_protect = 0;

                    if (!VirtualProtect(&slot->u1.Function, sizeof(void*),

                                        PAGE_READWRITE, &old_protect))

                        return false;

                    if (original != nullptr)

                        *original = reinterpret_cast<void*>(slot->u1.Function);

                    slot->u1.Function = reinterpret_cast<ULONG_PTR>(replacement);

                    VirtualProtect(&slot->u1.Function, sizeof(void*), old_protect,

                                   &old_protect);

                    return true;

                }

            }

            return false;

        }

        void* User32Proc(const char* name) noexcept

        {

            HMODULE user32 = GetModuleHandleA("user32.dll");

            return user32 != nullptr ? reinterpret_cast<void*>(GetProcAddress(user32, name))

                                     : nullptr;

        }

        void CentreWindow(HWND hwnd, int width, int height) noexcept

        {

            HMONITOR monitor = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);

            MONITORINFO info{};

            info.cbSize = sizeof(info);

            if (!GetMonitorInfoA(monitor, &info))

                return;

            const int desktop_width = info.rcMonitor.right - info.rcMonitor.left;

            const int desktop_height = info.rcMonitor.bottom - info.rcMonitor.top;

            const int x = info.rcMonitor.left + (desktop_width - width) / 2;

            const int y = info.rcMonitor.top + (desktop_height - height) / 2;

            if (g_set_pos != nullptr)

            {

                const HWND after = (g_on_top != nullptr && *g_on_top) ? HWND_TOPMOST

                                                                      : HWND_NOTOPMOST;

                g_set_pos(hwnd, after, x, y, width, height,

                          SWP_FRAMECHANGED | SWP_SHOWWINDOW);

            }

        }

        void SwitchWindowStyle() noexcept

        {

            if (g_wnd == nullptr || g_set_long == nullptr)

                return;

            const LONG style = GetWindowLongA(g_wnd, GWL_STYLE);

            const LONG borderless =

                style &

                ~static_cast<LONG>(WS_CAPTION | WS_THICKFRAME | WS_MINIMIZEBOX |

                                   WS_MAXIMIZEBOX | WS_SYSMENU);

            g_set_long(g_wnd, GWL_STYLE, borderless);

            RECT client = g_client_valid ? g_client_rect : RECT{0, 0, 0, 0};

            if (!g_client_valid)

            {

                RECT current{};

                if (g_set_pos != nullptr && GetWindowRect(g_wnd, &current))

                    client = current;

            }

            if (g_adjust != nullptr && g_client_valid)

                g_adjust(&client, borderless, FALSE);

            const int width = client.right - client.left;

            const int height = client.bottom - client.top;

            if (width > 0 && height > 0)

                CentreWindow(g_wnd, width, height);

        }

        BOOL WINAPI MoveWindowHook(HWND hwnd, int x, int y, int width, int height,

                                   BOOL repaint) noexcept

        {

            RECT rect{x, y, width, height};

            HMONITOR monitor = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);

            MONITORINFO info{};

            info.cbSize = sizeof(info);

            if (GetMonitorInfoA(monitor, &info))

            {

                const int desktop_width = info.rcMonitor.right - info.rcMonitor.left;

                const int desktop_height = info.rcMonitor.bottom - info.rcMonitor.top;

                if (g_client_valid &&

                    ((rect.right - rect.left) >= desktop_width ||

                     (rect.bottom - rect.top) >= desktop_height))

                {

                    RECT client = g_client_rect;

                    if (g_adjust != nullptr)

                        g_adjust(&client, GetWindowLongA(hwnd, GWL_STYLE), FALSE);

                    rect = client;

                }

                const int w = rect.right - rect.left;

                const int h = rect.bottom - rect.top;

                const int cx = info.rcMonitor.left + (desktop_width - w) / 2;

                const int cy = info.rcMonitor.top + (desktop_height - h) / 2;

                return g_move != nullptr ? g_move(hwnd, cx, cy, w, h, repaint)

                                         : FALSE;

            }

            return g_move != nullptr ? g_move(hwnd, x, y, width, height, repaint)

                                     : FALSE;

        }

        BOOL WINAPI AdjustWindowRectHook(LPRECT rect, DWORD style, BOOL menu) noexcept

        {

            style &= ~(WS_CAPTION | WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX |

                       WS_SYSMENU);

            return g_adjust != nullptr ? g_adjust(rect, style, menu) : FALSE;

        }

        BOOL WINAPI SetWindowPosHook(HWND hwnd, HWND insert_after, int x, int y,

                                     int width, int height, UINT flags) noexcept

        {

            if (g_on_top != nullptr)

                insert_after = *g_on_top ? HWND_TOPMOST : HWND_NOTOPMOST;

            if (g_set_pos == nullptr)

                return FALSE;

            const BOOL result =

                g_set_pos(hwnd, insert_after, x, y, width, height, flags);

            SwitchWindowStyle();

            return result;

        }

        LONG WINAPI SetWindowLongAHook(HWND hwnd, int index, LONG value) noexcept

        {

            if (index == GWL_EXSTYLE && (g_on_top == nullptr || !*g_on_top))

                value &= ~static_cast<LONG>(WS_EX_TOPMOST);

            return g_set_long != nullptr ? g_set_long(hwnd, index, value) : 0;

        }

        BOOL WINAPI SetRectHook(LPRECT rect, int left, int top, int right,

                                int bottom) noexcept

        {

            g_client_rect = RECT{0, 0, right - left, bottom - top};

            g_client_valid = g_client_rect.right > 0 && g_client_rect.bottom > 0;

            return g_set_rect != nullptr

                       ? g_set_rect(rect, left, top, right, bottom)

                       : FALSE;

        }

        HWND WINAPI CreateWindowExAHook(DWORD ex_style, LPCSTR class_name,

                                        LPCSTR window_name, DWORD style, int x, int y,

                                        int width, int height, HWND parent, HMENU menu,

                                        HINSTANCE instance, LPVOID param) noexcept

        {

            g_client_rect = RECT{0, 0, width, height};

            g_client_valid = width > 0 && height > 0;

            HWND hwnd = g_create_a != nullptr

                            ? g_create_a(ex_style, class_name, window_name, style, x, y,

                                         width, height, parent, menu, instance, param)

                            : nullptr;

            if (hwnd != nullptr)

            {

                g_wnd = hwnd;

                SwitchWindowStyle();

            }

            return hwnd;

        }

        HWND WINAPI CreateWindowExWHook(DWORD ex_style, LPCWSTR class_name,

                                        LPCWSTR window_name, DWORD style, int x, int y,

                                        int width, int height, HWND parent, HMENU menu,

                                        HINSTANCE instance, LPVOID param) noexcept

        {

            g_client_rect = RECT{0, 0, width, height};

            g_client_valid = width > 0 && height > 0;

            HWND hwnd = g_create_w != nullptr

                            ? g_create_w(ex_style, class_name, window_name, style, x, y,

                                         width, height, parent, menu, instance, param)

                            : nullptr;

            if (hwnd != nullptr)

            {

                g_wnd = hwnd;

                SwitchWindowStyle();

            }

            return hwnd;

        }

        bool ResolveBool(const GameImage& image, const char* primary,

                         const char* fallback, bool** out) noexcept

        {

            auto pattern = Pattern(image, primary);

            if (pattern.size() == 0 && fallback != nullptr)

                pattern = Pattern(image, fallback);

            if (pattern.size() == 0)

                return false;

            *out = reinterpret_cast<bool*>(static_cast<uintptr_t>(

                *pattern.get(0).get<uint32_t>(2)));

            return *out != nullptr;

        }

    } // namespace

    extern "C" void __cdecl FocusLossInput(char arg) noexcept

    {

        if (g_windowed != nullptr && g_focus_lost != nullptr && *g_windowed &&

            *g_focus_lost)

            return;

        if (g_input_orig != nullptr)

            reinterpret_cast<void(__cdecl*)(char)>(g_input_orig)(arg);

    }

    bool InstallBorderlessHooks(GameImage image) noexcept

    {

        // The parity dump maps a private copy at an arbitrary address; hooks in

        // its own process are neither needed nor safe.

        if (GetModuleHandleW(nullptr) != reinterpret_cast<HMODULE>(image.base))

            return false;

        if (g_borderless_installed)

            return true;

        HMODULE module = GetModuleHandleW(nullptr);

        if (module == nullptr)

            return false;

        g_create_a = reinterpret_cast<CreateWindowExAFn>(

            User32Proc("CreateWindowExA"));

        g_create_w = reinterpret_cast<CreateWindowExWFn>(

            User32Proc("CreateWindowExW"));

        g_move = reinterpret_cast<MoveWindowFn>(User32Proc("MoveWindow"));

        g_adjust = reinterpret_cast<AdjustWindowRectFn>(

            User32Proc("AdjustWindowRect"));

        g_set_pos = reinterpret_cast<SetWindowPosFn>(User32Proc("SetWindowPos"));

        g_set_long = reinterpret_cast<SetWindowLongAFn>(

            User32Proc("SetWindowLongA"));

        g_set_rect = reinterpret_cast<SetRectFn>(User32Proc("SetRect"));

        void* old_create_a = nullptr;

        void* old_create_w = nullptr;

        void* old_move = nullptr;

        void* old_adjust = nullptr;

        void* old_set_pos = nullptr;

        void* old_set_long = nullptr;

        void* old_set_rect = nullptr;

        const bool hooked_create =

            ReplaceImport(module, "CreateWindowExA",

                          reinterpret_cast<void*>(&CreateWindowExAHook),

                          &old_create_a) |

            ReplaceImport(module, "CreateWindowExW",

                          reinterpret_cast<void*>(&CreateWindowExWHook),

                          &old_create_w);

        const bool hooked_others =

            ReplaceImport(module, "MoveWindow",

                          reinterpret_cast<void*>(&MoveWindowHook), &old_move) |

            ReplaceImport(module, "AdjustWindowRect",

                          reinterpret_cast<void*>(&AdjustWindowRectHook),

                          &old_adjust) |

            ReplaceImport(module, "SetWindowPos",

                          reinterpret_cast<void*>(&SetWindowPosHook), &old_set_pos) |

            ReplaceImport(module, "SetWindowLongA",

                          reinterpret_cast<void*>(&SetWindowLongAHook), &old_set_long) |

            ReplaceImport(module, "SetRect", reinterpret_cast<void*>(&SetRectHook),

                          &old_set_rect);

        if (old_create_a != nullptr) g_create_a = reinterpret_cast<CreateWindowExAFn>(old_create_a);

        if (old_create_w != nullptr) g_create_w = reinterpret_cast<CreateWindowExWFn>(old_create_w);

        if (old_move != nullptr) g_move = reinterpret_cast<MoveWindowFn>(old_move);

        if (old_adjust != nullptr) g_adjust = reinterpret_cast<AdjustWindowRectFn>(old_adjust);

        if (old_set_pos != nullptr) g_set_pos = reinterpret_cast<SetWindowPosFn>(old_set_pos);

        if (old_set_long != nullptr) g_set_long = reinterpret_cast<SetWindowLongAFn>(old_set_long);

        if (old_set_rect != nullptr) g_set_rect = reinterpret_cast<SetRectFn>(old_set_rect);

        if (!hooked_create && !hooked_others)

            return false;

        g_borderless_installed = true;

        return true;

    }

    bool InstallFocusLossInputHook(GameImage image) noexcept

    {

        if (GetModuleHandleW(nullptr) != reinterpret_cast<HMODULE>(image.base))

            return false;

        if (g_focus_installed)

            return true;

        if (!ResolveBool(image, "80 3D ? ? ? ? ? 74 0E 68 ? ? ? ? 53",

                         "80 3D ? ? ? ? ? 74 13 68", &g_windowed))

            return false;

        if (!ResolveBool(image, "C6 05 ? ? ? ? ? 85 C0 74 02 FF D0 E8", nullptr,

                         &g_focus_lost))

            return false;

        ResolveBool(image, "80 3D ? ? ? ? ? 74 07 BF", nullptr, &g_on_top);

        auto pattern = Pattern(image,

                               "E8 ? ? ? ? A1 ? ? ? ? A3 ? ? ? ? A1 ? ? ? ? 83 C4 04");

        if (pattern.size() == 0)

            pattern = Pattern(image,

                              "E8 ? ? ? ? 8B 0D ? ? ? ? 8B 15 ? ? ? ? 83 C4 04 83 3D");

        if (pattern.size() == 0)

            return false;

        auto* site = pattern.get(0).get<uint8_t>();

        const auto previous =

            injector::MakeCALL(site, reinterpret_cast<void*>(&FocusLossInput), true);

        g_input_orig = previous.get<void*>();

        if (g_input_orig == nullptr)

            return false;

        g_focus_installed = true;

        return true;

    }

} // namespace opp

