// SPDX-License-Identifier: GPL-3.0-or-later
//
// xla.warnings - the add-on's startup warnings: the ASI loader probe, the
// single-instance guard and the FusionFix compatibility notice.
//
// The game executable carries no common-controls dependency, so comctl32 v6 (and
// with it TaskDialogIndirect) is only mapped while this add-on's own activation
// context is active. The manifest is embedded as RT_MANIFEST #1 by
// res/warnings.rc, and CreateActCtx/ActivateActCtx below use it.
//
// Every dialog is posted to a worker thread: this add-on initializes from
// DllMain, where loading a DLL (which TaskDialogIndirect does for comctl32) is
// not allowed. A worker blocks on the loader lock and shows the dialog once the
// entry point has returned.

module;

#include "common.hxx"

export module xla.warnings;

import xla.common;
import xla.config;

export namespace xla::warnings
{
    struct Button
    {
        std::wstring text;
        // Empty: the button closes the dialog. Otherwise the target is opened with
        // ShellExecute (an https URL or a file such as the FusionFix notice).
        std::wstring link;
    };

    struct Dialog
    {
        std::wstring title;
        std::wstring header;   // the bold main instruction
        std::wstring content;
        std::wstring footer;
        bool error{};          // error icon instead of the information icon
        std::vector<Button> buttons;
    };

    // Shows `dialog` on a worker thread and, when `exitCode` is set, terminates
    // the process with it after the dialog has been closed.
    void ShowAsync(Dialog dialog, std::optional<UINT> exitCode) noexcept;

    // ---------------------------------------------------------------------
    // ASI loader probe. "Modern" is Ultimate ASI Loader >= 6.9.0: that release
    // added the IsUltimateASILoader export (2023-10-24, first tag v6.9.0) and the
    // extended version resource, and it is the marker FusionFix's own
    // compatibility check trusts. Any other loader (or an older one) cannot be
    // identified, so it is reported as old.
    // ---------------------------------------------------------------------
    constexpr uint32_t kMinimumAsiLoaderVersionMs = 0x00060009; // 6.9.0
    constexpr uint32_t kMinimumAsiLoaderVersionLs = 0;
    constexpr const char* kAsiLoaderMarker = "IsUltimateASILoader";

    struct LoaderInfo
    {
        bool detected{};
        bool versionKnown{};
        uint32_t versionMs{};
        uint32_t versionLs{};
        std::string name;
        std::string version;
    };

    bool LoaderVersionAccepted(uint32_t versionMs, uint32_t versionLs) noexcept;
    LoaderInfo QueryLoader() noexcept;

    // Claims this process's single-instance marker. False when another copy of
    // this ASI already initialized here (a renamed duplicate, or two ASI loaders
    // each loading their own copy).
    bool ClaimSingleInstance() noexcept;

    // Rewrites XLivelessAddon.fusionfix-notice.txt with the current gated options
    // and returns its path; empty when nothing was gated or it cannot be written.
    std::filesystem::path WriteFusionFixNotice(const std::filesystem::path& directory,
                                               const std::vector<config::FusionFixGate>& gated);

    // WriteFusionFixNotice, plus the notice dialog while the file did not exist
    // yet. Returns true when the dialog was posted.
    bool PublishFusionFixNotice(const std::filesystem::path& directory,
                                const std::vector<config::FusionFixGate>& gated);

    // The warning texts, built here so every call site shows the same wording.
    Dialog OldLoaderDialog(const LoaderInfo& loader);
    Dialog UnsupportedGameVersionDialog();
    Dialog LoadedTwiceDialog();
    Dialog FusionFixNoticeDialog(const std::wstring& noticeName,
                                 const std::wstring& noticePath,
                                 const std::vector<std::wstring>& gatedLines);
} // namespace xla::warnings

namespace xla::warnings
{
    namespace
    {
        constexpr int kButtonBase = 1000;
        constexpr const wchar_t* kUltimateAsiLoaderDownload =
            L"https://github.com/ThirteenAG/Ultimate-ASI-Loader/releases/latest";

        using TaskDialogIndirectFn = HRESULT(WINAPI*)(const TASKDIALOGCONFIG*, int*, int*, BOOL*);

        std::wstring Widen(const std::string_view text)
        {
            return std::wstring(text.begin(), text.end());
        }

        std::string Narrow(const std::wstring& text)
        {
            std::string out;
            out.reserve(text.size());
            for (const wchar_t c : text)
            {
                out.push_back(c < 0x80 ? static_cast<char>(c) : '?');
            }
            return out;
        }

        // The module this code lives in (the ASI, not the game).
        HMODULE SelfModule() noexcept
        {
            HMODULE self = nullptr;
            if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                    reinterpret_cast<LPCWSTR>(&SelfModule), &self))
            {
                return nullptr;
            }
            return self;
        }

        // Activates the add-on manifest for the calling thread. Scoped: the
        // context only has to be live while the dialog is created.
        class Activation final
        {
        public:
            Activation() noexcept
            {
                const HMODULE self = SelfModule();
                if (self == nullptr)
                {
                    return;
                }

                ACTCTXW context{};
                context.cbSize = sizeof context;
                context.dwFlags = ACTCTX_FLAG_RESOURCE_NAME_VALID | ACTCTX_FLAG_HMODULE_VALID;
                context.lpResourceName = MAKEINTRESOURCEW(1);
                context.hModule = self;
                handle_ = CreateActCtxW(&context);
                if (handle_ == INVALID_HANDLE_VALUE)
                {
                    return;
                }
                active_ = ActivateActCtx(handle_, &cookie_) != FALSE;
            }

            ~Activation()
            {
                if (active_)
                {
                    DeactivateActCtx(0, cookie_);
                }
                if (handle_ != INVALID_HANDLE_VALUE)
                {
                    ReleaseActCtx(handle_);
                }
            }

            Activation(const Activation&) = delete;
            Activation& operator=(const Activation&) = delete;

            [[nodiscard]] bool ok() const noexcept
            {
                return active_;
            }

        private:
            HANDLE handle_{INVALID_HANDLE_VALUE};
            ULONG_PTR cookie_{};
            bool active_{};
        };

        void OpenLink(const std::wstring& link) noexcept
        {
            if (link.empty())
            {
                return;
            }
            ShellExecuteW(nullptr, L"open", link.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
        }

        HRESULT CALLBACK DialogCallback(HWND window, UINT notification, WPARAM /*wparam*/,
                                        LPARAM lparam, LONG_PTR /*data*/) noexcept
        {
            if (notification == TDN_HYPERLINK_CLICKED)
            {
                ShellExecuteW(window, L"open", reinterpret_cast<LPCWSTR>(lparam), nullptr,
                              nullptr, SW_SHOWNORMAL);
            }
            return S_OK;
        }

        // The modern presentation. False when comctl32 v6 could not be activated
        // or the task dialog could not be created; the caller then falls back.
        bool ShowTaskDialog(const Dialog& dialog) noexcept
        {
            Activation activation;
            if (!activation.ok())
            {
                return false;
            }

            const HMODULE comctl = LoadLibraryW(L"comctl32.dll");
            if (comctl == nullptr)
            {
                return false;
            }
            const auto taskDialog = reinterpret_cast<TaskDialogIndirectFn>(
                GetProcAddress(comctl, "TaskDialogIndirect"));
            if (taskDialog == nullptr)
            {
                return false;
            }

            std::vector<TASKDIALOG_BUTTON> buttons;
            buttons.reserve(dialog.buttons.size());
            for (size_t i = 0; i < dialog.buttons.size(); ++i)
            {
                buttons.push_back(
                    {kButtonBase + static_cast<int>(i), dialog.buttons[i].text.c_str()});
            }

            TASKDIALOGCONFIG config{};
            config.cbSize = sizeof config;
            config.dwFlags = TDF_ENABLE_HYPERLINKS | TDF_SIZE_TO_CONTENT |
                             TDF_ALLOW_DIALOG_CANCELLATION;
            if (buttons.size() > 1)
            {
                config.dwFlags |= TDF_USE_COMMAND_LINKS;
            }
            config.pszWindowTitle = dialog.title.c_str();
            config.pszMainIcon = dialog.error ? reinterpret_cast<PCWSTR>(TD_ERROR_ICON)
                                              : reinterpret_cast<PCWSTR>(TD_INFORMATION_ICON);
            config.pszMainInstruction = dialog.header.c_str();
            config.pszContent = dialog.content.c_str();
            config.pszFooter = dialog.footer.empty() ? nullptr : dialog.footer.c_str();
            config.pButtons = buttons.data();
            config.cButtons = static_cast<UINT>(buttons.size());
            config.pfCallback = &DialogCallback;

            int clicked = 0;
            if (FAILED(taskDialog(&config, &clicked, nullptr, nullptr)))
            {
                return false;
            }

            const int index = clicked - kButtonBase;
            if (index >= 0 && static_cast<size_t>(index) < dialog.buttons.size())
            {
                OpenLink(dialog.buttons[index].link);
            }
            return true;
        }

        // The last resort: a message box maps nothing comctl32.
        void ShowMessageBox(const Dialog& dialog) noexcept
        {
            std::wstring text = dialog.content;
            if (!dialog.footer.empty())
            {
                text += L"\n\n";
                text += dialog.footer;
            }
            for (const Button& button : dialog.buttons)
            {
                if (button.link.empty())
                {
                    continue;
                }
                text += L"\n\n";
                text += button.text;
                text += L": ";
                text += button.link;
            }

            MessageBoxW(nullptr, text.c_str(), dialog.header.c_str(),
                        MB_OK | (dialog.error ? MB_ICONERROR : MB_ICONINFORMATION));
        }

        void ShowNow(const Dialog& dialog) noexcept
        {
            if (ShowTaskDialog(dialog))
            {
                return;
            }
            log::Write("warnings: task dialog unavailable; using a message box");
            ShowMessageBox(dialog);
        }

        struct Request
        {
            Dialog dialog;
            std::optional<UINT> exitCode;
        };

        DWORD WINAPI WarningThread(LPVOID parameter) noexcept
        {
            std::unique_ptr<Request> request(static_cast<Request*>(parameter));
            ShowNow(request->dialog);
            if (request->exitCode)
            {
                TerminateProcess(GetCurrentProcess(), *request->exitCode);
            }
            return 0;
        }

        bool HasAsiLoaderMarker(HMODULE module) noexcept
        {
            return module != nullptr && GetProcAddress(module, kAsiLoaderMarker) != nullptr;
        }

        HMODULE CurrentModule() noexcept
        {
            HMODULE self = nullptr;
            if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                    reinterpret_cast<LPCWSTR>(&CurrentModule), &self))
            {
                return nullptr;
            }
            return self;
        }

        // The loader that called us, when it is still on the stack (UAL calls
        // InitializeASI from its own frames, and LoadLibrary keeps the caller's
        // frames above DllMain).
        HMODULE LoaderOnStack(HMODULE self) noexcept
        {
            void* frames[64]{};
            const USHORT count = CaptureStackBackTrace(1, 64, frames, nullptr);
            for (USHORT i = 0; i < count; ++i)
            {
                HMODULE module = nullptr;
                if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                       reinterpret_cast<LPCWSTR>(frames[i]), &module) &&
                    module != self && HasAsiLoaderMarker(module))
                {
                    return module;
                }
            }
            return nullptr;
        }

        // Fallback for an entry point that no loader frame is visible from.
        HMODULE AnyAsiLoaderModule(HMODULE self) noexcept
        {
            HMODULE modules[512]{};
            DWORD needed = 0;
            if (!EnumProcessModules(GetCurrentProcess(), modules, sizeof modules, &needed))
            {
                return nullptr;
            }
            const DWORD count = needed / sizeof(HMODULE);
            for (DWORD i = 0; i < count && i < _countof(modules); ++i)
            {
                if (modules[i] != self && HasAsiLoaderMarker(modules[i]))
                {
                    return modules[i];
                }
            }
            return nullptr;
        }

        std::string ModuleBaseName(HMODULE module) noexcept
        {
            wchar_t path[MAX_PATH]{};
            if (GetModuleFileNameW(module, path, MAX_PATH) == 0)
            {
                return {};
            }
            const wchar_t* base = path;
            for (const wchar_t* p = path; *p != L'\0'; ++p)
            {
                if (*p == L'\\' || *p == L'/')
                {
                    base = p + 1;
                }
            }
            std::string out;
            for (const wchar_t* p = base; *p != L'\0'; ++p)
            {
                out.push_back(*p < 0x80 ? static_cast<char>(*p) : '?');
            }
            return out;
        }

        std::string ModuleVersionText(HMODULE module, uint32_t& versionMs,
                                      uint32_t& versionLs) noexcept
        {
            versionMs = 0;
            versionLs = 0;

            wchar_t path[MAX_PATH]{};
            if (GetModuleFileNameW(module, path, MAX_PATH) == 0)
            {
                return {};
            }

            DWORD ignored = 0;
            const DWORD size = GetFileVersionInfoSizeW(path, &ignored);
            if (size == 0)
            {
                return {};
            }
            std::vector<uint8_t> data(size);
            if (!GetFileVersionInfoW(path, ignored, size, data.data()))
            {
                return {};
            }

            VS_FIXEDFILEINFO* info = nullptr;
            UINT length = 0;
            if (!VerQueryValueW(data.data(), L"\\", reinterpret_cast<void**>(&info), &length) ||
                info == nullptr)
            {
                return {};
            }

            versionMs = info->dwFileVersionMS;
            versionLs = info->dwFileVersionLS;
            char text[40]{};
            std::snprintf(text, sizeof text, "%u.%u.%u.%u", HIWORD(versionMs),
                          LOWORD(versionMs), HIWORD(versionLs), LOWORD(versionLs));
            return text;
        }

        constexpr wchar_t kNoticeName[] = L"XLivelessAddon.fusionfix-notice.txt";
        constexpr wchar_t kIniName[] = L"XLivelessAddon.ini";
    } // namespace

    void ShowAsync(Dialog dialog, std::optional<UINT> exitCode) noexcept
    {
        auto* request = new (std::nothrow) Request{std::move(dialog), exitCode};
        if (request == nullptr)
        {
            if (exitCode)
            {
                TerminateProcess(GetCurrentProcess(), *exitCode);
            }
            return;
        }

        const HANDLE thread = CreateThread(nullptr, 0, &WarningThread, request, 0, nullptr);
        if (thread == nullptr)
        {
            // Creating a thread can only fail when resources are exhausted; a
            // message box is safe from this thread, comctl32 is not.
            ShowMessageBox(request->dialog);
            if (exitCode)
            {
                TerminateProcess(GetCurrentProcess(), *exitCode);
            }
            delete request;
            return;
        }
        CloseHandle(thread);
    }

    bool LoaderVersionAccepted(uint32_t versionMs, uint32_t versionLs) noexcept
    {
        return versionMs > kMinimumAsiLoaderVersionMs ||
               (versionMs == kMinimumAsiLoaderVersionMs &&
                versionLs >= kMinimumAsiLoaderVersionLs);
    }

    LoaderInfo QueryLoader() noexcept
    {
        LoaderInfo info;
        const HMODULE self = CurrentModule();

        HMODULE loader = LoaderOnStack(self);
        if (loader == nullptr)
        {
            loader = AnyAsiLoaderModule(self);
        }
        if (loader == nullptr)
        {
            return info;
        }

        info.detected = true;
        info.name = ModuleBaseName(loader);
        info.version = ModuleVersionText(loader, info.versionMs, info.versionLs);
        info.versionKnown = info.versionMs != 0 || info.versionLs != 0;
        return info;
    }

    bool ClaimSingleInstance() noexcept
    {
        wchar_t mutexName[128]{};
        std::swprintf(mutexName, _countof(mutexName), L"Local\\XLivelessAddon-%lu",
                      GetCurrentProcessId());

        const HANDLE mutex = CreateMutexW(nullptr, FALSE, mutexName);
        if (mutex == nullptr)
        {
            return true; // the marker cannot be created; never block the game on it
        }
        if (GetLastError() == ERROR_ALREADY_EXISTS)
        {
            CloseHandle(mutex);
            return false;
        }
        // Intentionally never closed: the object must live for the whole process.
        return true;
    }

    std::filesystem::path WriteFusionFixNotice(const std::filesystem::path& directory,
                                               const std::vector<config::FusionFixGate>& gated)
    {
        if (gated.empty())
        {
            return {};
        }

        std::vector<std::wstring> lines;
        lines.reserve(gated.size());
        for (const config::FusionFixGate& gate : gated)
        {
            lines.push_back(Widen(gate.option) + L" - FusionFix " +
                            Widen(gate.fusionFixModule));
        }

        const std::filesystem::path notice = directory / kNoticeName;
        std::ofstream file(notice, std::ios::binary | std::ios::trunc);
        if (!file)
        {
            return {};
        }

        file << "XLivelessAddon: FusionFix compatibility notice\r\n"
                "FusionFix is installed next to the game executable. These "
                "XLivelessAddon.ini options are enabled but were switched off because "
                "FusionFix owns the same feature:\r\n\r\n";
        for (const std::wstring& line : lines)
        {
            file << "  " << Narrow(line) << "\r\n";
        }
        file << "\r\nThis file is rewritten on every launch. Delete it to show the "
                "notice dialog again.\r\n";
        return file.good() ? notice : std::filesystem::path{};
    }

    bool PublishFusionFixNotice(const std::filesystem::path& directory,
                                const std::vector<config::FusionFixGate>& gated)
    {
        if (gated.empty())
        {
            return false;
        }

        const std::filesystem::path noticePath = directory / kNoticeName;
        const bool existed = std::filesystem::exists(noticePath);

        const std::filesystem::path written = WriteFusionFixNotice(directory, gated);
        if (written.empty())
        {
            log::Info("compat: cannot write {}", noticePath.string());
        }

        if (existed)
        {
            return false;
        }

        std::vector<std::wstring> lines;
        lines.reserve(gated.size());
        for (const config::FusionFixGate& gate : gated)
        {
            lines.push_back(Widen(gate.option) + L" - FusionFix " +
                            Widen(gate.fusionFixModule));
        }
        ShowAsync(FusionFixNoticeDialog(kNoticeName, noticePath.wstring(), lines),
                  std::nullopt);
        return true;
    }

    Dialog OldLoaderDialog(const LoaderInfo& loader)
    {
        Dialog dialog;
        dialog.title = L"XLivelessAddon";
        dialog.header = L"Old ASI Loader detected!";
        dialog.content =
            L"It's recommended to use latest Ultimate ASI Loader as either dinput8.dll or "
            L"xlive.dll.";
        if (loader.name.empty())
        {
            dialog.footer = L"No Ultimate ASI Loader was found in this process.";
        }
        else if (loader.versionKnown)
        {
            dialog.footer = L"Detected " + Widen(loader.name) + L" " + Widen(loader.version) +
                            L"; this add-on expects Ultimate ASI Loader 6.9.0 or newer.";
        }
        else
        {
            dialog.footer = L"Detected " + Widen(loader.name) +
                            L"; this add-on expects Ultimate ASI Loader 6.9.0 or newer.";
        }
        dialog.buttons = {{L"Download Ultimate ASI Loader", kUltimateAsiLoaderDownload},
                          {L"Continue", L""}};
        return dialog;
    }

    Dialog UnsupportedGameVersionDialog()
    {
        Dialog dialog;
        dialog.title = L"XLivelessAddon";
        dialog.header = L"Unsupported game version.";
        dialog.content =
            L"Downgrade the game to use this mod, although note that if you don't have any "
            L"other reasons to downgrade, you're likely using this mod by accident, in which "
            L"case simply remove this mod. The game will now exit";
        dialog.error = true;
        dialog.buttons = {{L"Close the program", L""}};
        return dialog;
    }

    Dialog LoadedTwiceDialog()
    {
        Dialog dialog;
        dialog.title = L"XLivelessAddon";
        dialog.header = L"XLivelessAddon was loaded twice!";
        dialog.content =
            L"Make sure that you don't have multiple ASI loaders installed! The game will now "
            L"exit.";
        dialog.error = true;
        dialog.buttons = {{L"Close the program", L""}};
        return dialog;
    }

    Dialog FusionFixNoticeDialog(const std::wstring& noticeName,
                                 const std::wstring& noticePath,
                                 const std::vector<std::wstring>& gatedLines)
    {
        Dialog dialog;
        dialog.title = L"XLivelessAddon";
        dialog.header = L"FusionFix is installed.";
        dialog.content = std::wstring(L"These ") + kIniName +
                         L" options are enabled but were switched off because FusionFix owns "
                         L"the same feature:\n\n";
        for (const std::wstring& line : gatedLines)
        {
            dialog.content += L"  ";
            dialog.content += line;
            dialog.content += L"\n";
        }
        dialog.content += L"\nThe full list is written to ";
        dialog.content += noticeName;
        dialog.content += L".";
        dialog.footer = L"This notice is shown once. Delete " + noticeName +
                        L" to show it again.";
        dialog.buttons = {{L"Open the notice", noticePath}, {L"Continue", L""}};
        return dialog;
    }
} // namespace xla::warnings
