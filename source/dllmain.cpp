#include <windows.h>
#include <Shlobj.h>
#include <stdint.h>
#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <string>
#include <string_view>
#include <IniReader.h>
#include <injector/injector.hpp>
#include <injector/calling.hpp>
#include <injector/hooking.hpp>
#include <injector/utility.hpp>
#include <Hooking.Patterns.h>
#include "skip_launcher.h"
#include "windowed.hxx"

bool bDelay;
char* pszPath;
std::string szCustomSavePath;
std::string szCustomSettingsPath;

#define WM_ROM (43858)

static void XLog(const char* format, ...);

static uint32_t g_skip_intro_resume = 0;
__declspec(naked) static void SkipIntroBody()
{
    __asm {
        imul ecx, ecx, 0x190
        cmp edx, 0x1f40
        jge  skip_intro_ok
        mov  edx, 0x12c
    skip_intro_ok:
        jmp dword ptr [g_skip_intro_resume]
    }
}

const static uint8_t staticData[] = { 0x08, 0x00, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 0xF1,
                                      0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xF0, 0x00,
                                      0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00,
                                      0x00, 0x0C, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
                                      0xF3, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x06,
                                      0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x05, 0x00,
                                      0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xF2, 0x00, 0x00,
                                      0x00
                                    };

struct dataStruct
{
    char a[16];
    int action;
    char* act100Addr;
    char* act18Addr;
};

// change savefile path to "%USERPROFILE%\Documents\Rockstar Games\GTA IV\savegames\"
void getSavefilePath(int __unused, char * pBuffer, char * pszSaveName)
{
    // The game hands us a 256-byte buffer. Build the path with snprintf so an
    // over-long custom path or save name is truncated instead of writing past
    // the buffer (the original addon copied without a bound).
    constexpr size_t kCapacity = 256;
    char path[kCapacity] = {};

    if (szCustomSavePath.empty())
        std::snprintf(path, sizeof(path), "%s%s", pszPath ? pszPath : "", "savegames");
    else
        std::snprintf(path, sizeof(path), "%s", szCustomSavePath.c_str());

    if (std::strlen(path) == kCapacity - 1)
        XLog("savefile path truncated to %s", path);

    // check path and create directory if necessary
    DWORD attrs = GetFileAttributes(path);
    if (attrs == INVALID_FILE_ATTRIBUTES)
        CreateDirectory(path, NULL);
    else if (!(attrs & FILE_ATTRIBUTE_DIRECTORY))
    {
        std::snprintf(pBuffer, kCapacity, "%s", pszSaveName ? pszSaveName : "");
        return;
    }

    if (pszSaveName)
    {
        const size_t used = std::strlen(path);
        std::snprintf(path + used, sizeof(path) - used, "\\%s", pszSaveName);
    }

    std::memcpy(pBuffer, path, sizeof(path));
}

HANDLE CreateFileHook(_In_ LPCSTR lpFileName, _In_ DWORD dwDesiredAccess, _In_ DWORD dwShareMode, _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes, _In_ DWORD dwCreationDisposition, _In_ DWORD dwFlagsAndAttributes, _In_opt_ HANDLE hTemplateFile)
{
    return CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

BOOL CloseHandleHook(_In_ HANDLE hObject)
{
    __try
    {
        return CloseHandle(hObject);
    }
    __except (EXCEPTION_CONTINUE_EXECUTION)
    {}

    return TRUE;
}

BOOL GetFileSizeExHook(HANDLE hFile, PLARGE_INTEGER lpFileSize)
{
    return GetFileSizeEx(hFile, lpFileSize);
}

BOOL ReadFileHook(HANDLE hFile, LPVOID pBuffer, DWORD nNumberOfBytesRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped)
{
    return ReadFile(hFile, pBuffer, nNumberOfBytesRead, lpNumberOfBytesRead, lpOverlapped);
}

DWORD SetFilePointerHook(HANDLE hFile, LONG dtm, PLONG dtmHigh, DWORD mm)
{
    return SetFilePointer(hFile, dtm, dtmHigh, mm);
}

static LRESULT WINAPI WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    if (uMsg == WM_ROM)
    {
        dataStruct* str = (dataStruct*)lParam;

        switch (str->action)
        {
        case 100:
            *(DWORD*)(str->act100Addr) = 1;
            break;
        case 18:
            memcpy(str->act18Addr, staticData, sizeof(staticData));
            break;
        case 51:
            return (LRESULT)(str->act100Addr + (DWORD)str->act18Addr);
        }

        return 0;
    }

    return 1;
}

static HWND CreateROMWindow()
{
    WNDCLASSEXW wc;
    memset(&wc, 0, sizeof(wc));
    wc.cbSize = sizeof(wc);

    wc.style = 3;
    wc.lpfnWndProc = WndProc;
    wc.lpszClassName = L"banana";
    wc.hInstance = GetModuleHandle(NULL);
    wc.hbrBackground = (HBRUSH)5;
    wc.hCursor = LoadCursor(0, MAKEINTRESOURCE(0x7F00));

    RegisterClassExW(&wc);

    HWND hWnd = CreateWindowExW(0, L"banana", L"", 0xCC00000, 0, 0, 0, 0, 0, 0, GetModuleHandle(NULL), 0);

    return hWnd;
}

void __stdcall SendMessageFakie(int, int, int, int)
{

}

int __cdecl dfaInit(int, int, int)
{
    return 1;
}

injector::hook_back<void(__cdecl*)(int)> hbsub_7870A0;
void __cdecl sub_7870A0(int a1)
{
    static bool bOnce = false;
    if (!bOnce)
    {
        if (a1 == 0)
        {
            bool bNoLoad = (GetAsyncKeyState(VK_SHIFT) & 0xF000) != 0;
            if (!bNoLoad)
                a1 = 6;

            bOnce = true;
        }
    }
    return hbsub_7870A0.fun(a1);
}

injector::hook_back<int32_t(*)()> hbGetVidMem;
int32_t GetVidMem()
{
    auto v = hbGetVidMem.fun();
    return v <= 0 ? INT_MAX : v;
}

LRESULT WINAPI DefWindowProcAProxy(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
    static bool bOnce = false;
    if (!bOnce)
    {
        SetWindowLong(hWnd, GWL_STYLE, GetWindowLong(hWnd, GWL_STYLE) & ~WS_OVERLAPPEDWINDOW);
        bOnce = true;
    }

    return DefWindowProcA(hWnd, Msg, wParam, lParam);
}

LRESULT WINAPI DefWindowProcWProxy(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
    static bool bOnce = false;
    if (!bOnce)
    {
        SetWindowLong(hWnd, GWL_STYLE, GetWindowLong(hWnd, GWL_STYLE) & ~WS_OVERLAPPEDWINDOW);
        bOnce = true;
    }

    return DefWindowProcW(hWnd, Msg, wParam, lParam);
}

HKEY Key;
std::string SubKey;
LSTATUS WINAPI CustomRegOpenKeyA(HKEY hKey, LPCSTR lpSubKey, PHKEY phkResult)
{
    if (strstr(lpSubKey, "Rockstar Games") != NULL)
    {
        Key = hKey;
        SubKey = lpSubKey;
        *phkResult = NULL;
        return ERROR_SUCCESS;
    }
    else
        return ::RegOpenKeyA(hKey, lpSubKey, phkResult);
}

LSTATUS WINAPI CustomRegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult)
{
    if (strstr(lpSubKey, "Rockstar Games") != NULL)
    {
        Key = hKey;
        SubKey = lpSubKey;
        *phkResult = NULL;
        return ERROR_SUCCESS;
    }
    else
        return ::RegOpenKeyExA(hKey, lpSubKey, ulOptions, samDesired, phkResult);
}

LSTATUS WINAPI CustomRegQueryValueExA(HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
{
    if (hKey == NULL)
    {
        if (strstr(lpValueName, "InstallFolder") != NULL)
        {
            char path[MAX_PATH];
            GetModuleFileName(GetModuleHandle(NULL), path, MAX_PATH);
            auto ptr = strrchr(path, '\\');
            *(ptr + 1) = '\0';
            auto szPath = std::string_view(path);

            if (lpData != NULL)
            {
                std::string_view str((char*)lpData, *lpcbData);
                *lpcbData = static_cast<DWORD>(std::min<size_t>(szPath.length(), str.length()));
                szPath.copy((char*)str.data(), *lpcbData, 0);
                lpData[*lpcbData] = '\0';
            }
            else
            {
                *lpcbData = szPath.length();
            }
        }
        else
        {
            ::RegOpenKeyExA(Key, SubKey.c_str(), 0, KEY_READ, &hKey);
            return ::RegQueryValueExA(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
        }
        return ERROR_SUCCESS;
    }
    else
        return ::RegQueryValueExA(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
}

static const char kDefaultIni[] =
    "; XLivelessAddon\n"
    "\n"
    "[Options]\n"
    "; custom savegames folder; leave empty to use the game default (FusionFix userdata.ixx owns this when present)\n"
    "CustomSavePath=\n"
    "; custom settings folder; leave empty to use the game default (FusionFix userdata.ixx owns this when present)\n"
    "CustomSettingsPath=\n"
    "; skip the launcher/DRM checks (recovered DFA and ROM stages)\n"
    "SkipLauncher=1\n"
    "; remove the Rockstar Games registry path dependency\n"
    "RemoveRegistryPathDependency=1\n"
    "; skip the GFWL web-connect and health checks\n"
    "SkipWebConnect=1\n"
    "; shorten the intro screens to 300 ms (FusionFix skipintro.ixx owns this when present)\n"
    "SkipIntro=1\n"
    "; skip the main menu (hold SHIFT on startup to reach it) (FusionFix skipintro.ixx owns this when present)\n"
    "SkipMenu=0\n"
    "; keep rendering while the borderless window is unfocused (FusionFix windowed.ixx owns this when present)\n"
    "DoNotPauseOnMinimize=1\n"
    "; borderless window (FusionFix windowed.ixx owns this when present)\n"
    "BorderlessWindowed=1\n"
    "; fix the VRAM detection so the settings are not locked out (FusionFix memory.ixx owns this when present)\n"
    "VRAMFix=1\n"
    "; move savegames and settings to a saves folder inside the game folder (FusionFix userdata.ixx owns this when present)\n"
    "LocalSettingsPath=0\n"
;

static void XLog(const char* format, ...)
{
    char path[MAX_PATH] = {};
    GetModuleFileNameA(GetModuleHandle(NULL), path, MAX_PATH);
    char* slash = strrchr(path, '\\');
    if (slash != nullptr)
        *(slash + 1) = '\0';
    strcat_s(path, "XLivelessAddon.log");
    std::FILE* file = std::fopen(path, "a");
    if (file == nullptr)
        return;
    va_list args;
    va_start(args, format);
    std::vfprintf(file, format, args);
    va_end(args);
    std::fputc('\n', file);
    std::fclose(file);
}

static std::string ModuleDirectory()
{
    char path[MAX_PATH] = {};
    GetModuleFileNameA(GetModuleHandle(NULL), path, MAX_PATH);
    char* slash = strrchr(path, '\\');
    if (slash != nullptr)
        *(slash + 1) = '\0';
    return path;
}

static std::string EnsureIni()
{
    const std::string directory = ModuleDirectory();
    const std::string ini = directory + "XLivelessAddon.ini";
    if (GetFileAttributesA(ini.c_str()) == INVALID_FILE_ATTRIBUTES)
    {
        std::ofstream out(ini, std::ios::binary | std::ios::trunc);
        if (out)
            out.write(kDefaultIni, sizeof(kDefaultIni) - 1);
    }
    return ini;
}

static bool IniHas(CIniReader& ini, const char* section, const char* key,
                   std::string& value)
{
    static constexpr const char* kMissing = "\x01xla-missing";
    value = ini.ReadString(section, key, kMissing);
    return value != kMissing;
}

// The 2019 addon only read its own [MAIN]. Accept an old ZolikaPatch.ini too:
// own INI wins, then the flat legacy [Options], then the grouped legacy sections.
static std::string ReadOption(CIniReader& own, CIniReader* legacy, const char* key,
                              const char* defaultValue)
{
    static constexpr const char* kSections[] = {
        "MAIN", "Options", "COMPATIBILITY", "INPUT", "LOADING", "XLIVELESS",
        "STABILITY", "FIXES", "PERFORMANCE", "GRAPHICS", "VEHICLES", "MULTIPLAYER",
        "EPISODIC", "MISC", "INTERFACE",
    };
    std::string value;
    for (const char* section : kSections)
    {
        if (IniHas(own, section, key, value))
            return value;
    }
    if (legacy != nullptr)
    {
        for (const char* section : kSections)
        {
            if (IniHas(*legacy, section, key, value))
                return value;
        }
    }
    return defaultValue;
}

static bool FusionFixPresent()
{
    const std::string directory = ModuleDirectory();
    WIN32_FIND_DATAA data{};
    const std::string pattern = directory + "*FusionFix*.asi";
    HANDLE find = FindFirstFileA(pattern.c_str(), &data);
    if (find == INVALID_HANDLE_VALUE)
        return false;
    FindClose(find);
    return true;
}

// ---------------------------------------------------------------------------
// LocalSettingsPath, implemented the FusionFix way (userdata.ixx): redirect the
// shell user-data folders (CSIDL_APPDATA/PERSONAL/...) to <game>\saves instead
// of rewriting the game's path buffers. One hook covers saves and settings.
// ---------------------------------------------------------------------------

static std::string g_localProfilePath;
static std::wstring g_localProfilePathW;

using ShGetFolderPathAFn = HRESULT(WINAPI*)(HWND, int, HANDLE, DWORD, LPSTR);
using ShGetFolderPathWFn = HRESULT(WINAPI*)(HWND, int, HANDLE, DWORD, LPWSTR);
static ShGetFolderPathAFn g_shellFolderA = nullptr;
static ShGetFolderPathWFn g_shellFolderW = nullptr;

static bool RedirectUserFolder(int csidl) noexcept
{
    switch (csidl)
    {
    case CSIDL_APPDATA:
    case CSIDL_COMMON_APPDATA:
    case CSIDL_COMMON_DOCUMENTS:
    case CSIDL_LOCAL_APPDATA:
    case CSIDL_PERSONAL:
        return true;
    default:
        return false;
    }
}

HRESULT WINAPI ShellFolderPathA(HWND hwnd, int csidl, HANDLE token, DWORD flags, LPSTR path)
{
    if (RedirectUserFolder(csidl))
    {
        if (path == nullptr) return E_INVALIDARG;
        return strncpy_s(path, MAX_PATH, g_localProfilePath.c_str(), _TRUNCATE) == 0
                   ? S_OK
                   : E_FAIL;
    }
    return g_shellFolderA ? g_shellFolderA(hwnd, csidl, token, flags, path) : E_FAIL;
}

HRESULT WINAPI ShellFolderPathW(HWND hwnd, int csidl, HANDLE token, DWORD flags, LPWSTR path)
{
    if (RedirectUserFolder(csidl))
    {
        if (path == nullptr) return E_INVALIDARG;
        return wcsncpy_s(path, MAX_PATH, g_localProfilePathW.c_str(), _TRUNCATE) == 0
                   ? S_OK
                   : E_FAIL;
    }
    return g_shellFolderW ? g_shellFolderW(hwnd, csidl, token, flags, path) : E_FAIL;
}

// Replaces one shell32 IAT slot in the game module and hands back the original.
static bool ReplaceShellImport(const char* function, void* replacement, void** original)
{
    HMODULE module = GetModuleHandleA(nullptr);
    if (module == nullptr || function == nullptr || replacement == nullptr) return false;
    auto* base = reinterpret_cast<uint8_t*>(module);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    const auto& directory =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (directory.VirtualAddress == 0) return false;

    auto* descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
        base + directory.VirtualAddress);
    for (; descriptor->Name != 0; ++descriptor)
    {
        const char* dll = reinterpret_cast<const char*>(base + descriptor->Name);
        if (_stricmp(dll, "SHELL32.DLL") != 0) continue;
        auto* thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(
            base + (descriptor->OriginalFirstThunk ? descriptor->OriginalFirstThunk
                                                   : descriptor->FirstThunk));
        auto* iat = reinterpret_cast<IMAGE_THUNK_DATA*>(base + descriptor->FirstThunk);
        for (; thunk->u1.AddressOfData != 0; ++thunk, ++iat)
        {
            if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal)) continue;
            const auto* import = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(
                base + thunk->u1.AddressOfData);
            if (std::strcmp(reinterpret_cast<const char*>(import->Name), function) != 0)
                continue;

            DWORD oldProtect = 0;
            if (!VirtualProtect(&iat->u1.Function, sizeof(void*), PAGE_READWRITE, &oldProtect))
                return false;
            *original = reinterpret_cast<void*>(iat->u1.Function);
            iat->u1.Function = reinterpret_cast<ULONG_PTR>(replacement);
            DWORD ignored = 0;
            VirtualProtect(&iat->u1.Function, sizeof(void*), oldProtect, &ignored);
            return true;
        }
    }
    return false;
}

static void InstallLocalSettingsPath()
{
    std::filesystem::path directory =
        std::filesystem::path(ModuleDirectory()) / "saves";
    std::error_code error;
    std::filesystem::create_directories(directory, error);
    if (!std::filesystem::exists(directory))
    {
        XLog("localSettings: cannot create %s", directory.string().c_str());
        return;
    }

    g_localProfilePath = directory.string();
    g_localProfilePathW = directory.wstring();

    const bool ansi = ReplaceShellImport("SHGetFolderPathA", reinterpret_cast<void*>(&ShellFolderPathA),
                                         reinterpret_cast<void**>(&g_shellFolderA));
    const bool wide = ReplaceShellImport("SHGetFolderPathW", reinterpret_cast<void*>(&ShellFolderPathW),
                                         reinterpret_cast<void**>(&g_shellFolderW));
    XLog("localSettings: profile=%s (A=%d W=%d)", g_localProfilePath.c_str(), ansi ? 1 : 0,
         wide ? 1 : 0);
}

DWORD WINAPI Init(LPVOID)
{
    if(GetConsoleWindow())
        FreeConsole();

    auto pattern = hook::pattern("B0 04 B2 18 B1 20");
    if (!(pattern.size() > 0) && !bDelay)
    {
        bDelay = true;
        CreateThread(0, 0, (LPTHREAD_START_ROUTINE)&Init, NULL, 0, NULL);
        return 0;
    }

    if (bDelay)
    {
        // Wait for the probe instead of spinning a core forever. Supported
        // builds hit it on the first iterations; an unsupported build gets a
        // log line and an orderly return instead of a hung worker.
        int spins = 0;
        while (!(pattern.size() > 0))
        {
            if (++spins > 10000)
            {
                XLog("init: probe pattern never appeared; aborting");
                return 1;
            }
            Sleep(1);
            pattern = hook::pattern("B0 04 B2 18 B1 20");
        }
    }

    const std::string iniPath = EnsureIni();
    CIniReader iniReader(iniPath.c_str());
    const std::string legacyPath = ModuleDirectory() + "ZolikaPatch.ini";
    CIniReader legacyReader(legacyPath.c_str());
    CIniReader* legacy =
        GetFileAttributesA(legacyPath.c_str()) != INVALID_FILE_ATTRIBUTES
            ? &legacyReader
            : nullptr;
    const auto option = [&](const char* key, const char* defaultValue) {
        return ReadOption(iniReader, legacy, key, defaultValue);
    };
    const auto flag = [&](const char* key, const char* defaultValue) {
        return atoi(option(key, defaultValue).c_str()) != 0;
    };

    szCustomSavePath = option("CustomSavePath", "");
    szCustomSettingsPath = option("CustomSettingsPath", "");
    bool bRemoveRegistryPathDependency = flag("RemoveRegistryPathDependency", "1");
    bool bSkipWebConnect = flag("SkipWebConnect", "0");
    bool bSkipIntro = flag("SkipIntro", "0");
    bool bSkipMenu = flag("SkipMenu", "0");
    bool bDoNotPauseOnMinimize = flag("DoNotPauseOnMinimize", "0");
    bool bBorderlessWindowed = flag("BorderlessWindowed", "0");
    bool bVRAMFix = flag("VRAMFix", "1");
    bool bSkipLauncher = flag("SkipLauncher", "1");
    bool bLocalSettingsPath = flag("LocalSettingsPath", "0");

    // Never stack on FusionFix. Each overlapping fork feature is gated by the
    // FusionFix module that owns the same subsystem; the log names every gate so
    // a live run shows why an option did nothing.
    if (FusionFixPresent())
    {
        struct ForkGate
        {
            const char* option;
            bool* enabled;
            const char* fusionFixModule;
        };
        ForkGate gates[] = {
            {"SkipIntro", &bSkipIntro, "skipintro.ixx"},
            {"SkipMenu", &bSkipMenu, "skipintro.ixx"},
            {"BorderlessWindowed", &bBorderlessWindowed, "windowed.ixx"},
            {"DoNotPauseOnMinimize", &bDoNotPauseOnMinimize, "windowed.ixx"},
            {"VRAMFix", &bVRAMFix, "memory.ixx"},
            {"LocalSettingsPath", &bLocalSettingsPath, "userdata.ixx"},
        };
        for (const ForkGate& gate : gates)
        {
            if (!*gate.enabled)
                continue;
            *gate.enabled = false;
            XLog("fusionfix: gating %s (FusionFix %s)", gate.option, gate.fusionFixModule);
        }

        // The custom path hooks overlap FusionFix's CustomUserProfilePath
        // redirect even when the key is set to a value.
        if (!szCustomSavePath.empty())
        {
            XLog("fusionfix: gating CustomSavePath (FusionFix userdata.ixx)");
            szCustomSavePath.clear();
        }
        if (!szCustomSettingsPath.empty())
        {
            XLog("fusionfix: gating CustomSettingsPath (FusionFix userdata.ixx)");
            szCustomSettingsPath.clear();
        }
    }
    XLog("ini=%s legacy=%s skipLauncher=%d skipIntro=%d skipMenu=%d dontPause=%d borderless=%d vram=%d skipWeb=%d registry=%d fusionfix=%d", iniPath.c_str(), legacyPath.c_str(), bSkipLauncher, bSkipIntro, bSkipMenu, bDoNotPauseOnMinimize, bBorderlessWindowed, bVRAMFix, bSkipWebConnect, bRemoveRegistryPathDependency, FusionFixPresent());

    // The fork has no write-set dump, so the log records which optional installs
    // actually applied: -1 = option off, 0 = pattern missing, 1 = installed.
    int borderlessInstalled = -1;
    int focusInstalled = -1;
    bool skipIntroSite = false;
    bool skipMenuSite = false;
    int vramHooks = 0;
    size_t registryPatches = 0;
    bool legacyRom = false;

    // Unprotect image - make .text and .rdata section writeable
    // get load address of the exe
    DWORD dwLoadOffset = (DWORD)GetModuleHandle(NULL);
    BYTE * pImageBase = reinterpret_cast<BYTE *>(dwLoadOffset);
    PIMAGE_DOS_HEADER   pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER> (dwLoadOffset);
    PIMAGE_NT_HEADERS   pNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS> (pImageBase + pDosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeader);

    for (int iSection = 0; iSection < pNtHeader->FileHeader.NumberOfSections; ++iSection, ++pSection)
    {
        char * pszSectionName = reinterpret_cast<char *>(pSection->Name);
        if (!strcmp(pszSectionName, ".text") || !strcmp(pszSectionName, ".rdata"))
        {
            DWORD dwPhysSize = (pSection->Misc.VirtualSize + 4095) & ~4095;
            DWORD   oldProtect;
            DWORD   newProtect = (pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE) ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;
            if (!VirtualProtect(reinterpret_cast <VOID *>(dwLoadOffset + pSection->VirtualAddress), dwPhysSize, newProtect, &oldProtect))
            {
                ExitProcess(0);
            }
        }
    }

    //static bool isEFLC = false;
    //pattern = hook::pattern("68 ? ? ? ? E8 ? ? ? ? 8B F0 83 C4 ? 85 F6 0F 84 ? ? ? ? 6A 04");
    //if (pattern.size() > 0)
    //{
    //    if (strstr(*(char**)pattern.get(0).get<char*>(1), "EFLC") != NULL)
    //    {
    //        isEFLC = true;
    //    }
    //}

    auto gv = [&dwLoadOffset]() -> uint32_t
    {
        DWORD signature = *(DWORD*)(0x608C34 + dwLoadOffset - 0x400000);
        if (signature == 0xC25DE58B)
            return 1000;
        else if (signature == 0x831F7518)
            return 1010;
        else if (signature == 0xC483FFE4)
            return 1020;
        else if (signature == 0x280F0000)
            return 1030;
        else if (signature == 0x110FF300)
            return 1040;
        else if (signature == 0xF3385058)
            return 1050;
        else if (signature == 0x00A42494)
            return 1060;
        else if (signature == 0x1006E857)
            return 1070;
        else if (signature == 0x404B100F)
            return 1080;
        else if (signature == 0x5C0FF301)
            return 1100;
        else if (signature == 0x0F14247C)
            return 1110;
        else if (signature == 0x0D5C0FF3)
            return 1120;
        else if (signature == 0x04C1F600)
            return 1130;
        else
            return UINT_MAX;
    };

    auto game_version = gv();
    XLog("build=%u%s", game_version, game_version == UINT_MAX ? " (unknown)" : "");
    if (game_version == UINT_MAX)
    {
        // Same policy as the main module: an unrecognised build gets no
        // installs. The legacy code below used to dereference the first match
        // of assumptions that only hold on the supported builds.
        XLog("unsupported build; no patches applied");
        return 0;
    }
    auto gv_not = [&game_version](std::initializer_list<uint32_t> v) -> bool
    {
        if (std::find(std::begin(v), std::end(v), game_version) != std::end(v))
            return false;

        return true;
    };

    // LocalSettingsPath owns the shell user-data folders; install it before the
    // game can query them.
    if (bLocalSettingsPath)
        InstallLocalSettingsPath();

    // savegames [v1000 - v1008]
    {
        pattern = hook::pattern("8A 10 83 C0 01 84 D2 75 F7 56 57 BF ? ? ? ? 2B C1 8B F1 83 C7 FF 8A 4F 01 83 C7 01");
        if (pattern.count(3).size() > 0)
        {
            auto range_end = (uintptr_t)pattern.get(2).get<uintptr_t>(0);
            auto tmp = hook::pattern(range_end - 0x80, range_end, "8A 88 ? ? ? ? 88 88 ? ? ? ? 83 C0 01");
            if (tmp.size() > 0)
                pszPath = *tmp.get(0).get<char*>(2);
            else
                XLog("savegames: path pattern not found; using the game default");

            pattern = hook::pattern("75 ? 83 C1 01 83 C0 01 83 F9 04");
            if (pattern.size() > 0)
                injector::MakeNOP(pattern.get(0).get<uintptr_t>(0), 2, true); // NOP - save file CRC32 check

            pattern = hook::pattern("55 8B EC 83 E4 F8 83 EC 4C 56");
            if (pattern.size() > 0)
                injector::MakeJMP(pattern.get(0).get<uintptr_t>(0), getSavefilePath, true); // replace getSavefilePath
        }
    }

    //settings [v1001-v1008]
    // Custom settings path needs a register-contract inline hook; the original
    // implementation used injector::MakeInline, which pulls in safetyhook and a
    // C++23 runtime. Keep custom save path working and leave settings path on the
    // game default until the hooked body is ported.
    if (!szCustomSettingsPath.empty())
    {
        // TODO: port the SettingsPath inline hook without safetyhook.
    }

    if (bSkipLauncher)
    {
        SkipLauncherReport report;
        const GameImage image{pImageBase,
                              pNtHeader->OptionalHeader.SizeOfImage};
        // The recovered "main" table is the ZolikaPatch handler's extra pass;
        // the XLivelessAddon path only ever ran the DFA and ROM stages. Applying
        // the main table after the addon already hooked the launcher is what
        // broke the GFWL session.
        const PatchResult launcher =
            ApplySkipLauncher(image, &ResolveSkipHook, nullptr, report,
                              SkipLauncherStage::dfa | SkipLauncherStage::rom);
        // ApplySkipLauncher publishes the captured CreateFile IAT slot itself
        // (before the hook can run), so only the diagnostics are left here.
        XLog("skipLauncher status=%d entries=%zu missing=%zu writes=%zu jump=%d dfa=%zu/%zu rom=%zu/%zu collected=%zu createFileSlot=%08X (%s)",
             static_cast<int>(launcher.code), report.entriesFound, report.entriesMissing,
             report.writes, report.jumpInstalled ? 1 : 0, report.dfaInstalls,
             report.dfaMissing, report.romInstalls, report.romMissing,
             report.collectedInstalls, report.createFileSlot,
             report.createFileSlot != 0 ? "forwarding" : "direct");
    }

    {
        const GameImage image{pImageBase, pNtHeader->OptionalHeader.SizeOfImage};
        if (bBorderlessWindowed)
            borderlessInstalled = InstallBorderlessHooks(image) ? 1 : 0;
        if (bDoNotPauseOnMinimize)
            focusInstalled = InstallFocusLossInputHook(image) ? 1 : 0;
        XLog("window: borderless=%d focusLoss=%d", borderlessInstalled, focusInstalled);
    }

    // process patches
    uintptr_t* jmp_efc = nullptr;
    pattern = hook::pattern("68 ? ? ? ? 89 35 ? ? ? ? E8 ? ? ? ? 83 C4 04 84 C0 0F 84");
    if (pattern.size() > 0)
        jmp_efc = pattern.get(0).get<uintptr_t>(0);

    // disable sleep [v1002 - v1008]
    pattern = hook::pattern("68 88 13 00 00 FF 15");
    if (pattern.size() > 0)
        injector::WriteMemory(pattern.get(0).get<uintptr_t>(1), 1, true);

    // RETN - enable debugger in error menu (don't load WER.dll) [v1000 - v1008]
    pattern = hook::pattern("81 EC ? ? ? ? A1 ? ? ? ? 33 C4 89 84 24 ? ? 00 00 53 56 8B 35 ? ? ? ? 68");
    if (pattern.size() > 0)
        injector::WriteMemory<uint8_t>(pattern.get(0).get<uintptr_t>(0), 0xC3, true);

    // RETN 8 - certificates check [v1002 - v1008]
    pattern = hook::pattern("81 EC ? ? ? ? A1 ? ? ? ? 33 C4 89 84 24 ? ? ? ? 53 8B 9C 24 ? ? ? ? 55 8B AC ? ? ? ? ? 8B 45 00");
    if (pattern.size() > 0)
        injector::MakeRET(pattern.get(0).get<uintptr_t>(0), 8, true);

    // RETN - skip files.txt hash check [v1002 - v1005]
    pattern = hook::pattern("81 EC ? ? ? ? A1 ? ? ? ? 33 C4 89 84 24 ? ? ? ? 83 3D ? ? ? ? ? 56 57 0F 85 ? ? ? ? 83 3D");
    if (pattern.size() > 0)
        injector::MakeRET(pattern.get(0).get<uintptr_t>(0), 0, true);

    // RETN - skip files.txt hash check [v1000 - v1001]
    pattern = hook::pattern("81 EC ? ? ? ? A1 ? ? ? ? 33 C4 89 84 24 ? ? ? ? 83 3D ? ? ? ? ? 0F 85 ? ? ? ? 83 3D");
    if (pattern.size() > 0)
        injector::MakeRET(pattern.get(0).get<uintptr_t>(0), 0, true);

    // RETN - skip files.txt hash check [v1000 - v1001]
    pattern = hook::pattern("81 EC ? ? ? ? A1 ? ? ? ? 33 C4 89 84 24 ? ? ? ? 56 68 ? ? ? ? 68 ? ? ? ? 68");
    if (pattern.size() > 0)
        injector::MakeRET(pattern.get(0).get<uintptr_t>(0), 0, true);

    // JMP [v1002 - v1004]
    pattern = hook::pattern("3B 56 20 74 19");
    if (pattern.size() > 0)
    {
        injector::WriteMemory<uint8_t>(pattern.get(0).get<uintptr_t>(3), 0xE9, true);
        injector::WriteMemory<uint32_t>(pattern.get(0).get<uintptr_t>(4), 0x16, true);
    }

    // NOP - another files.txt hash check [v1000 - v1001]
    pattern = hook::pattern("74 F7 8B CE");
    if (pattern.size() > 0)
        injector::MakeNOP(pattern.get(0).get<uintptr_t>(0), 2, true);

    // RETN - remove connect to the RGSC [v1000 - v1001]
    pattern = hook::pattern("83 EC 68 A1 ? ? ? ? 33 C4 89 44 24 60 53 56 57 8B F1 68 ? ? ? ? 8D 44 24 2C 8D 4C 24 3C 68");
    if (pattern.size() > 0)
        injector::MakeRET(pattern.get(0).get<uintptr_t>(0), 0, true);

    // RETN 4 - remove connect to the RGSC [v1002 - v1005]
    pattern = hook::pattern("83 EC 64 A1 ? ? ? ? 33 C4 89 44 24 60 8B 44 24 68 53 56 8B F1 8B 08 3B 4E 0C 57 0F 85");
    if (pattern.size() > 0)
        injector::MakeRET(pattern.get(0).get<uintptr_t>(0), 4, true);

    // data integrity checks VDS102 [v1002 - v1004]
    pattern = hook::pattern("C7 06 ? ? ? ? 74 19");
    if (pattern.size() > 0)
        injector::WriteMemory<uint8_t>(pattern.get(0).get<uintptr_t>(6), 0xEB, true); //jmp

    // data integrity checks VDS102 [v1005 - v1008]
    pattern = hook::pattern("83 C4 ? 3B 46 20");
    if (pattern.size() > 0)
        injector::WriteMemory<uint8_t>(pattern.get(0).get<uintptr_t>(12), 0xEB, true); //jmp

    // data integrity checks VDS100 [v1006 - v1008]
    pattern = hook::pattern("75 28 6A 00 6A 00 68 ? ? ? ? E8 ? ? ? ? 83 C4 0C");
    if (pattern.size() > 0)
        injector::WriteMemory<uint8_t>(pattern.get(0).get<uintptr_t>(0), 0xEB, true); //jmp

    // NOP - RGSC initialization check [v1000 - v1001]
    pattern = hook::pattern("74 EC 38 5E 06 74 E7 68");
    if (pattern.size() > 0)
    {
        injector::MakeNOP(pattern.get(0).get<uintptr_t>(0), 2, true);
        injector::MakeNOP(pattern.get(0).get<uintptr_t>(5), 2, true);
    }

    // NOP - RGSC initialization check [v1002 - v1004]
    pattern = hook::pattern("74 C4 8B 07 3B 46 18 75 BD 68");
    if (pattern.size() > 0)
        injector::MakeNOP(pattern.get(0).get<uintptr_t>(0), 2, true);

    // NOP - last RGSC init check [v1002 - v1004]
    pattern = hook::pattern("3B 56 18 0F 85");
    if (pattern.size() > 0)
        injector::MakeNOP(pattern.get(0).get<uintptr_t>(3), 6, true);

    // NOP - last RGSC init check [v1005]
    pattern = hook::pattern("3B 4E 18 0F 85");
    if (pattern.size() > 0)
        injector::MakeNOP(pattern.get(0).get<uintptr_t>(3), 6, true);

    // NOP - last RGSC init check [v1006 - v1008]
    pattern = hook::pattern("0F 85 ? ? ? ? 8B 8C 24 ? ? ? ? 5F 5E 5B 33 CC C6");
    if (pattern.size() > 0)
        injector::MakeNOP(pattern.get(0).get<uintptr_t>(0), 6, true);

    // RGSC initialization check [v1002 - v1004]
    pattern = hook::pattern("3B 46 18 75 BD");
    if (pattern.size() > 0)
    {
        injector::WriteMemory<uint16_t>(pattern.get(0).get<uintptr_t>(3), 0xC033, true); //XOR eax, eax
        injector::WriteMemory<uint16_t>(pattern.get(0).get<uintptr_t>(10), 0xA390, true); //NOP; MOV [], eax
    }

    // EFC20 [v1003 - v1004]
    pattern = hook::pattern("57 51 C7 44 24 ? ? ? ? ? C7 44 24 ? ? ? ? ? C7 44 24");
    if (pattern.size() > 0)
        injector::MakeNOP(pattern.get(0).get<uintptr_t>(1), 0x1BF, true);

    // fix messed sequences
    {
        pattern = hook::pattern("A1 ? ? ? ? 85 C0 8B 0D ? ? ? ? 75");
        if (pattern.size() > 0)
        {
            injector::WriteMemory(pattern.get(0).get<uintptr_t>(0), 0x90C301B0, true); // 0xBAC160  mov al, 1; retn
            injector::WriteMemory(pattern.get(1).get<uintptr_t>(0), 0x90C301B0, true); // 0xBAC190  mov al, 1; retn
        }

        pattern = hook::pattern("33 C0 83 3D ? ? ? ? 01 0F 94 C0 C3");
        if (pattern.size() > 0)
        {
            injector::WriteMemory(pattern.get(pattern.size() - 2).get<uintptr_t>(0), 0x90C301B0, true); // 0xBAC180  mov al, 1; retn
            injector::WriteMemory(pattern.get(pattern.size() - 1).get<uintptr_t>(0), 0x90C301B0, true); // 0xBAC1C0  mov al, 1; retn
        }
    }

    // skip RGSC connect and EFC checks [v1005 - v1008]
    pattern = hook::pattern("8B 56 1C 3B 56 20 ? ? 6A 00 6A 00");
    if (pattern.size() > 0 && jmp_efc != nullptr)
    {
        injector::WriteMemory<uint16_t>(pattern.get(0).get<uintptr_t>(0), 0xC033, true); // xor eax, eax - address of the RGSC object
        injector::MakeJMP(pattern.get(0).get<uintptr_t>(2), jmp_efc, true);
    }

    // NOP; MOV [g_rgsc], eax [v1000 - v1008]
    pattern = hook::pattern("89 35 ? ? ? ? E8 ? ? ? ? 83 C4 04 84 C0");
    if (pattern.size() > 0)
    {
        if (gv_not({ 1000, 1010 }))
            injector::WriteMemory<uint16_t>(pattern.get(0).get<uintptr_t>(0), 0xA390, true);
        else
            injector::WriteMemory<uint8_t>(pattern.get(0).get<uintptr_t>(1), 0x1D, true);
    }

    //skip missing tests [v1005]
    {
        pattern = hook::pattern("8B 50 2C 3B 50 30");
        if (pattern.size() > 0)
        {
            injector::WriteMemory<uint16_t>(pattern.get(0).get<uintptr_t>(0), 0xC033, true);
            injector::MakeNOP(pattern.get(0).get<uintptr_t>(2), 4, true);
        }

        pattern = hook::pattern("8B 48 2C 83 EC 78");
        if (pattern.size() > 0)
        {
            injector::MakeNOP(pattern.get(0).get<uintptr_t>(0), 3, true);
            injector::MakeNOP(pattern.get(0).get<uintptr_t>(6), 11, true);

        }

        pattern = hook::pattern("8B 48 2C 83 EC 74");
        if (pattern.size() > 0)
        {
            injector::MakeNOP(pattern.get(0).get<uintptr_t>(0), 3, true);
            injector::MakeNOP(pattern.get(0).get<uintptr_t>(6), 11, true);

        }

        pattern = hook::pattern("8B 48 2C 3B 48 30 74 03");
        if (pattern.size() > 0)
            injector::MakeNOP(pattern.get(0).get<uintptr_t>(0), 11, true);

        pattern = hook::pattern("8B 48 2C 3B 48 30 53");
        if (pattern.size() > 0)
            injector::MakeNOP(pattern.get(0).get<uintptr_t>(0), 32, true);

        pattern = hook::pattern("8B 48 2C 3B 48 30 74 11");
        if (pattern.size() > 0)
            injector::MakeNOP(pattern.get(0).get<uintptr_t>(0), 25, true);

        pattern = hook::pattern("8B 48 2C 3B 48 30 75 DC 8D 54 24 18");
        if (pattern.size() > 0)
            injector::MakeNOP(pattern.get(0).get<uintptr_t>(0), 8, true);

        pattern = hook::pattern("8B 48 2C 3B 48 30 75 DC 8D 54 24 1C");
        if (pattern.size() > 0)
            injector::MakeNOP(pattern.get(0).get<uintptr_t>(0), 8, true);

        pattern = hook::pattern("8B 0D ? ? ? ? 8B 51 2C");
        if (pattern.size() > 0)
            injector::MakeNOP(pattern.get(0).get<uintptr_t>(0), 14, true);
    }

    //skip missing tests [v1003 - v1005]
    pattern = hook::pattern("51 53 55 56 57 8B 3D ? ? ? ? 8B 47 2C");
    if (pattern.size() > 0)
        injector::MakeRET(pattern.get(0).get<uintptr_t>(0), 0, true);

    //skip missing tests [v1005 - v1008]
    pattern = hook::pattern("3B C7 0F 85 ? ? ? ? 85 C0");
    if (pattern.size() > 0)
        injector::MakeNOP(pattern.get(0).get<uintptr_t>(0), 16, true);

    //skip missing tests [v1005 - v1008]
    pattern = hook::pattern("0F 85 ? ? ? ? 85 C0 0F 84 ? ? ? ? E8 ? ? ? ? 85 D2");
    if (pattern.size() > 0)
        injector::MakeNOP(pattern.get(0).get<uintptr_t>(0), 14, true);

    // skip missing tests [v1006 - v1007]
    pattern = hook::pattern("83 EC 24 A1 ? ? ? ? 8B 48 14 53 55 56 57");
    if (pattern.size() > 0)
        injector::WriteMemory(pattern.get(0).get<uintptr_t>(0), 0x90C3C033, true);

    // skip missing tests [v1006 - v1007]
    pattern = hook::pattern("83 EC 08 8B 0D ? ? ? ? 8B 51 14 8D 04 24 50 6A 00 52");
    if (pattern.size() > 0)
        injector::WriteMemory(pattern.get(0).get<uintptr_t>(0), 0x90C3C033, true);

    /*
    //is this needed? I'm not sure
    //patchEflc1();
    memset((BYTE*)(0x49412C + dwLoadOffset), 0x90, 24);
    // >> TEST
    *(DWORD*)(0x474FD0 + dwLoadOffset) = 0x90C3C033;    // xor eax, eax; retn
    *(BYTE*)(0x7CAD20 + dwLoadOffset) = 0xC3;

    //patchEflc2();
    memset((BYTE*)(0x493D4C + dwLoadOffset), 0x90, 24);
    */

    // DLC
    // token activation [v1006 - v1007]
    pattern = hook::pattern("8B 54 24 04 52 A3");
    if (pattern.size() > 0)
        injector::WriteMemory<uint16_t>(pattern.get(0).get<uintptr_t>(0), 0xC9EB, true);

    // token activation [v1006 - v1007]
    pattern = hook::pattern("83 F8 01 75 30 A3");
    if (pattern.size() > 0)
    {
        injector::WriteMemory<uint8_t>(pattern.get(0).get<uintptr_t>(0), 0xB8, true);
        injector::WriteMemory(pattern.get(0).get<uintptr_t>(1), 1, true);
    }

    // skip first-time play ask [v1006 - v1008]
    pattern = hook::pattern("C7 05 ? ? ? ? 03 00 00 00 33 C0 5E 59 C3 C7");
    if (pattern.size() > 0)
        injector::WriteMemory<uint16_t>(pattern.get(0).get<uintptr_t>(0), 0x0DEB, true);

    // DFA (EFLC 1100/1110: Unhandled exception at 0x00426440 in EFLC.exe: 0xC0000005: Access violation reading location 0x00000014.)
    if (!bSkipLauncher && gv_not({ 1100, 1110 }))
    {
        //[v1006 - v1008]
        pattern = hook::pattern("E8 ? ? ? ? 83 C4 0C 83 F8 01 74 11 6A 00 6A 00");
        if (pattern.size() > 0)
            injector::MakeCALL(pattern.get_first(0), dfaInit, true);

        //[v1005 - v1008]
        pattern = hook::pattern("55 8B EC 6A 00 E8");
        if (pattern.size() > 0)
            injector::MakeJMP(pattern.get(0).get<uintptr_t>(0), CreateFileHook, true);

        //[v1005 - v1008]
        pattern = hook::pattern("6A 00 E8 ? ? ? ? 83 F8 01 59 75 17 FF 15 ? ? ? ? 50 B9 ? ? ? ? E8 ? ? ? ? 8B 40 08 FF 60 0C 33 C0 C3");
        if (pattern.size() > 0)
            injector::MakeJMP(pattern.get(0).get<uintptr_t>(0), CloseHandleHook, true);

        //[v1005 - v1008]
        pattern = hook::pattern("6A 00 E8 ? ? ? ? 83 F8 01 59 75 17 FF 15 ? ? ? ? 50 B9 ? ? ? ? E8 ? ? ? ? 8B 40 08 FF 60 ? 83 C8 FF C3");
        if (pattern.size() > 0)
            injector::MakeJMP(pattern.get(0).get<uintptr_t>(0), SetFilePointerHook, true);

        //[v1005 - v1008]
        pattern = hook::pattern("56 8B 74 24 0C 8D 46 04 50 FF 74 24 0C E8 ? ? ? ? 59 59 33 C9 83 F8 FF 0F 95 C1 89 06 5E 8B C1 C3");
        if (pattern.size() > 0)
            injector::MakeJMP(pattern.get(0).get<uintptr_t>(0), GetFileSizeExHook, true);

        //[v1005 - v1008]
        pattern = hook::pattern("55 8B EC 51 51 53 56 8B C5");
        if (pattern.size() > 0)
            injector::MakeJMP(pattern.get(0).get<uintptr_t>(0), ReadFileHook, true);

        //[v1006 - v1008]
        pattern = hook::pattern("A1 ? ? ? ? B9 A7 FA DC 5C F7 E1 8B 0D ? ? ? ? 33 F6");
        if (pattern.size() >= 2)
        {
            auto first = hook::pattern("80 BC 24 ? ? ? ? ? 6A 00");
            auto second = hook::pattern("6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 57");
            if (first.size() > 0 && second.size() > 0)
            {
                injector::MakeJMP(pattern.get(0).get<uintptr_t>(0), first.get(0).get<uintptr_t>(0), true);
                injector::MakeJMP(pattern.get(1).get<uintptr_t>(0), second.get(0).get<uintptr_t>(0), true);
            }
            else
            {
                XLog("DFA: secondary jump targets missing (first=%zu second=%zu)",
                     first.size(), second.size());
            }
        }
    }

    // windows message id [v1000 - v1008]
    // The recovered ROM stage above owns the service when SkipLauncher=1; only
    // the legacy path installs the old window/service in that case.
    if (!bSkipLauncher)
    {
        legacyRom = true;
        pattern = hook::pattern("A1 ? ? ? ? 8B 0D ? ? ? ? 68 ? ? ? ? 53 50 51 FF 15");
        if (pattern.size() > 0)
        {
            injector::WriteMemory(*pattern.get_first<uint32_t>(1), WM_ROM, true);
            injector::WriteMemory(*pattern.get_first<uint32_t>(7), CreateROMWindow(), true); // window handle
        }
        else
        {
            legacyRom = false;
            XLog("legacy ROM window pattern missing");
        }

        // SendMessage call to this window that ends up freezing the audio update thread and resulting in a deadlock [v1000 - v1008]
        pattern = hook::pattern("FF 15 ? ? ? ? E8 ? ? ? ? E8 ? ? ? ? E8 ? ? ? ? E8 ? ? ? ? B9 ? ? ? ? E8 ? ? ? ? B9 ? ? ? ? E8 ? ? ? ? 83 7C 24");
        if (pattern.size() > 0)
        {
            injector::MakeNOP(pattern.get_first(0), 6, true);
            injector::MakeCALL(pattern.get_first(0), SendMessageFakie, true);
        }
        else
        {
            XLog("legacy ROM SendMessage pattern missing");
        }
    }

    if (bSkipWebConnect)
    {
        // [v1000 - v1001]
        pattern = hook::pattern("FF 15 ? ? ? ? 85 C0 75 18");
        if (pattern.size() > 0)
            injector::MakeNOP(pattern.get(0).get<uintptr_t>(8), 2, true); //InternetGetConnectedState

        // [v1002 - v1005]
        pattern = hook::pattern("FF 15 ? ? ? ? 85 C0 75 04 32");
        if (pattern.size() > 0)
            injector::MakeNOP(pattern.get(0).get<uintptr_t>(8), 2, true); //InternetGetConnectedState

        // [v1006 - v1008]
        pattern = hook::pattern("FF 15 ? ? ? ? 85 C0 75 07 A0");
        if (pattern.size() > 0)
            injector::MakeNOP(pattern.get(0).get<uintptr_t>(8), 2, true); //InternetGetConnectedState

        // [v1003 - v1008]
        pattern = hook::pattern("81 EC ? ? ? ? A1 ? ? ? ? 33 C4 89 84 24 ? ? ? ? 53 ? 6A 3C 33 DB 8D 44 24 ? 53 50 E8"); // health check
        if (pattern.size() > 0)
            injector::WriteMemory<uint8_t>(pattern.get(0).get<uintptr_t>(0), 0xC3, true);
    }

    if (bSkipIntro)
    {
        //if (isEFLC)
        //{
        //    pattern = hook::pattern("74 ? 80 3D ? ? ? ? 00 74 ? E8 ? ? ? ? 0F");
        //    injector::WriteMemory<uint8_t>(pattern.get(0).get<uintptr_t>(0), 0xEB, true);
        //}
        //else
        {
            // [v1000 - v1008]
            // IV hangs with the jump-to-menu variant; shorten the load screens
            // instead. Same instruction contract as the original inline hook:
            // ecx *= 400, edx is zeroed below 8000, then resume at the match.
            pattern = hook::pattern("89 91 ? ? ? ? 8D 44 24 ? 68 ? ? ? ? 50");
            if (pattern.size() > 0)
            {
                skipIntroSite = true;
                g_skip_intro_resume = (uint32_t)pattern.get_first(0);
                injector::MakeJMP(pattern.get_first(-6), SkipIntroBody, true);
            }
        }
    }

    if (bSkipMenu)
    {
        pattern = hook::pattern("83 F8 03 75 ? A1 ? ? ? ? 80 88 ? ? ? ? ? 84 DB 74 0A 6A 00 E8 ? ? ? ? 83 C4 04 5F 5E");
        if (pattern.size() > 0)
        {
            // [v1002 - v1008]
            skipMenuSite = true;
            hbsub_7870A0.fun = injector::MakeCALL(pattern.get_first(23), sub_7870A0).get();
        }
        else
        {
            // [v1000]
            pattern = hook::pattern("6A 00 E8 ? ? ? ? 83 C4 04 8B 8C 24 ? ? ? ? 5F 5E 5D 5B 33 CC E8 ? ? ? ? 81 C4 ? ? ? ? C3");
            if (pattern.size() > 0)
            {
                skipMenuSite = true;
                hbsub_7870A0.fun = injector::MakeCALL(pattern.get(0).get<uintptr_t>(2), sub_7870A0).get();
            }
            else
            {
                // [v1001]
                pattern = hook::pattern("6A 00 E8 ? ? ? ? 83 C4 04 8B 8C 24 ? ? ? ? 5F 5E 5B 33 CC E8 ? ? ? ? 8B E5 5D C3");
                if (pattern.size() > 0)
                {
                    skipMenuSite = true;
                    hbsub_7870A0.fun = injector::MakeCALL(pattern.get(0).get<uintptr_t>(2), sub_7870A0).get();
                }
            }
        }
    }

    if (bDoNotPauseOnMinimize)
    {
        // [v1002 - v1008]
        pattern = hook::pattern("75 ? 8B 0D ? ? ? ? 51 FF 15 ? ? ? ? 85 C0 75 ? 8B 15"); //0x402D5A
        if (pattern.size() > 0)
            injector::MakeNOP(pattern.get(0).get<uintptr_t>(0), 2, true);
    }

    if (bBorderlessWindowed)
    {
        // [v1000 - v1008]
        pattern = hook::pattern("FF 15 ? ? ? ? 5F 5E 5D 5B 83 C4 10 C2 10 00");
        if (pattern.size() >= 2)
        {
            injector::MakeNOP(pattern.get(0).get<void>(0), 6, true);
            injector::MakeCALL(pattern.get(0).get<void>(0), DefWindowProcWProxy, true);
            injector::MakeNOP(pattern.get(1).get<void>(0), 6, true);
            injector::MakeCALL(pattern.get(1).get<void>(0), DefWindowProcAProxy, true);
        }
        else
        {
            XLog("borderless: DefWindowProc patterns missing (%zu)", pattern.size());
        }
    }

    if (bRemoveRegistryPathDependency)
    {
        IMAGE_IMPORT_DESCRIPTOR* pImports = (IMAGE_IMPORT_DESCRIPTOR*)(dwLoadOffset + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        const size_t importBytes = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
        size_t nNumImports = importBytes / sizeof(IMAGE_IMPORT_DESCRIPTOR);
        if (nNumImports > 0)
            --nNumImports;  // the last descriptor is the null terminator

        auto pRegOpenKeyA = (size_t)GetProcAddress(GetModuleHandle(TEXT("ADVAPI32.DLL")), "RegOpenKeyA");
        auto pRegQueryValueExA = (size_t)GetProcAddress(GetModuleHandle(TEXT("ADVAPI32.DLL")), "RegQueryValueExA");
        auto pRegOpenKeyExA = (size_t)GetProcAddress(GetModuleHandle(TEXT("ADVAPI32.DLL")), "RegOpenKeyExA");

        static auto getSection = [](const PIMAGE_NT_HEADERS nt_headers, unsigned section) -> PIMAGE_SECTION_HEADER
        {
            return reinterpret_cast<PIMAGE_SECTION_HEADER>(
                (UCHAR*)nt_headers->OptionalHeader.DataDirectory +
                nt_headers->OptionalHeader.NumberOfRvaAndSizes * sizeof(IMAGE_DATA_DIRECTORY) +
                section * sizeof(IMAGE_SECTION_HEADER));
        };

        static auto getSectionEnd = [](IMAGE_NT_HEADERS* ntHeader, size_t inst) -> auto
        {
            auto sec = getSection(ntHeader, ntHeader->FileHeader.NumberOfSections - 1);
            auto secSize = max(sec->SizeOfRawData, sec->Misc.VirtualSize);
            auto end = inst + max(sec->PointerToRawData, sec->VirtualAddress) + secSize;
            return end;
        };

        auto PatchIAT = [&](size_t start, size_t end, size_t exe_end)
        {
            for (size_t i = 0; i < nNumImports; i++)
            {
                if (dwLoadOffset + (pImports + i)->FirstThunk > start && !(end && dwLoadOffset + (pImports + i)->FirstThunk > end))
                    end = dwLoadOffset + (pImports + i)->FirstThunk;
            }

            if (!end) { end = start + 0x100; }
            if (end > exe_end)
            {
                start = dwLoadOffset;
                end = exe_end;
            }

            for (auto i = start; i < end; i += sizeof(size_t))
            {
                DWORD dwProtect[2];
                VirtualProtect((size_t*)i, sizeof(size_t), PAGE_EXECUTE_READWRITE, &dwProtect[0]);

                auto ptr = *(size_t*)i;
                if (!ptr)
                    continue;

                if (ptr == pRegOpenKeyA)
                {
                    *(size_t*)i = (size_t)CustomRegOpenKeyA;
                    ++registryPatches;
                }
                else if (ptr == pRegQueryValueExA)
                {
                    *(size_t*)i = (size_t)CustomRegQueryValueExA;
                    ++registryPatches;
                }
                else if (ptr == pRegOpenKeyExA)
                {
                    *(size_t*)i = (size_t)CustomRegOpenKeyExA;
                    ++registryPatches;
                }

                VirtualProtect((size_t*)i, sizeof(size_t), dwProtect[0], &dwProtect[1]);
            }
        };

        auto end = getSectionEnd(pNtHeader, dwLoadOffset);

        for (size_t i = 0; i < nNumImports; i++)
        {
            if ((size_t)(dwLoadOffset + (pImports + i)->Name) < end)
            {
                if (!_stricmp((const char*)(dwLoadOffset + (pImports + i)->Name), "ADVAPI32.DLL"))
                {
                    PatchIAT(dwLoadOffset + (pImports + i)->FirstThunk, 0, end);
                    break;
                }
            }
        }
    }

    if (bVRAMFix)
    {
        // workaround for vram detection, so settings won't be locked out [v1000 - v1007]
        pattern = hook::pattern("E8 ? ? ? ? D9 E8 85 C0");
        if (pattern.size() > 0)
        {
            hbGetVidMem.fun = injector::MakeCALL(pattern.get_first(0), GetVidMem).get();
            ++vramHooks;
        }

        pattern = hook::pattern("E8 ? ? ? ? F3 0F 10 0D ? ? ? ? F3 0F 5C 0D");
        if (pattern.size() > 0)
        {
            hbGetVidMem.fun = injector::MakeCALL(pattern.get_first(0), GetVidMem).get();
            ++vramHooks;
        }

        pattern = hook::pattern("E8 ? ? ? ? F3 0F 10 05 ? ? ? ? 89 44 24 08 6A 01 8D 44 24");
        if (pattern.size() > 0)
        {
            hbGetVidMem.fun = injector::MakeCALL(pattern.get_first(0), GetVidMem).get();
            ++vramHooks;
        }
    }

    XLog("init complete: skipIntroSite=%d skipMenuSite=%d vramHooks=%d registryIAT=%zu legacyRom=%d (skipLauncher=%d)",
         skipIntroSite ? 1 : 0, skipMenuSite ? 1 : 0, vramHooks, registryPatches,
         legacyRom ? 1 : 0, bSkipLauncher ? 1 : 0);
    return 0;
}


BOOL APIENTRY DllMain(HMODULE /*hModule*/, DWORD reason, LPVOID /*lpReserved*/)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        Init(NULL);
    }
    return TRUE;
}
