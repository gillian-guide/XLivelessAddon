// SPDX-License-Identifier: GPL-3.0-or-later
//
// Loads the built ASI as an image. DllMain is deliberately not executed: in this
// test process the executable is not a supported game build, so startup would
// show the unsupported-version dialog and terminate the process by design. The
// test proves the artifact is a loadable PE image with the expected identity and
// version resource; the native suite exercises the module code directly.

#include <Windows.h>
#include <winver.h>
#include <cstdio>
#include <filesystem>
#include <string>
#include <string_view>

namespace
{
    int failures = 0;
    int checks = 0;

    void Check(bool condition, std::string_view what, std::string_view detail = {})
    {
        ++checks;
        if (condition)
        {
            std::printf("PASS %.*s\n", static_cast<int>(what.size()), what.data());
            return;
        }
        ++failures;
        std::printf("FAIL %.*s", static_cast<int>(what.size()), what.data());
        if (!detail.empty())
        {
            std::printf(" (%s)", std::string(detail).c_str());
        }
        std::printf("\n");
    }

    bool QueryString(HMODULE module, const wchar_t* name, std::wstring& value)
    {
        HRSRC resource =
            FindResourceW(module, MAKEINTRESOURCEW(VS_VERSION_INFO), MAKEINTRESOURCEW(16));
        if (resource == nullptr)
        {
            return false;
        }
        HGLOBAL loaded = LoadResource(module, resource);
        if (loaded == nullptr)
        {
            return false;
        }
        void* data = LockResource(loaded);
        if (data == nullptr)
        {
            return false;
        }

        wchar_t subBlock[64]{};
        std::swprintf(subBlock, 64, L"\\StringFileInfo\\040904b0\\%s", name);
        void* text = nullptr;
        UINT length = 0;
        if (!VerQueryValueW(data, subBlock, &text, &length) || text == nullptr)
        {
            return false;
        }
        // VerQueryValueW reports the string length in characters for a StringFileInfo
        // value (the terminating NUL included).
        value.assign(static_cast<const wchar_t*>(text), length);
        if (!value.empty() && value.back() == L'\0')
        {
            value.pop_back();
        }
        return true;
    }
}

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        std::printf("usage: xla_asi_load <artifact.asi>\n");
        return 2;
    }

    const std::filesystem::path path(argv[1]);
    Check(std::filesystem::exists(path), "asi: the artifact exists", path.string());

    // Map the image as a data/image resource: the file is loaded and its
    // resources are readable, but DllMain is not called and imports are not
    // resolved.
    HMODULE module = LoadLibraryExW(path.c_str(), nullptr,
                                   LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
    Check(module != nullptr, "asi: the image loads without running DllMain");
    if (module == nullptr)
    {
        std::printf("%d check(s), %d failure(s)\n", checks, failures);
        return 1;
    }

    // A data-file handle does not answer GetModuleFileNameW; the artifact's name
    // is the caller's argument and the PE's OriginalFilename is checked below.
    std::wstring description;
    Check(QueryString(module, L"FileDescription", description),
          "asi: the version resource has a FileDescription");
    Check(description == L"XLivelessAddon for GTA IV / EFLC",
          "asi: the FileDescription names the add-on");

    std::wstring originalName;
    Check(QueryString(module, L"OriginalFilename", originalName),
          "asi: the version resource has an OriginalFilename");
    Check(originalName == L"XLivelessAddon.asi",
          "asi: the OriginalFilename matches the artifact");

    FreeLibrary(module);

    std::printf("%d check(s), %d failure(s)\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
