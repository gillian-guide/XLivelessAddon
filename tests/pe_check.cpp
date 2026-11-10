// SPDX-License-Identifier: GPL-3.0-or-later
//
// PE header checks on the built ASI: 32-bit PE32, image base 0x10000000,
// windowed subsystem, the imports the feature code needs, and a static CRT.

#include <Windows.h>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>

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

    const IMAGE_SECTION_HEADER* SectionFor(const IMAGE_NT_HEADERS32* nt, DWORD rva)
    {
        const auto* section = IMAGE_FIRST_SECTION(nt);
        for (WORD index = 0; index < nt->FileHeader.NumberOfSections; ++index, ++section)
        {
            const DWORD start = section->VirtualAddress;
            const DWORD span =
                section->Misc.VirtualSize != 0 ? section->Misc.VirtualSize : section->SizeOfRawData;
            if (rva >= start && rva - start < span)
            {
                return section;
            }
        }
        return nullptr;
    }

    bool ReadAt(const std::vector<uint8_t>& file, const IMAGE_NT_HEADERS32* nt, DWORD rva,
                void* out, size_t size)
    {
        const auto* section = SectionFor(nt, rva);
        if (section == nullptr)
        {
            return false;
        }
        const DWORD offset = rva - section->VirtualAddress + section->PointerToRawData;
        if (static_cast<size_t>(offset) + size > file.size())
        {
            return false;
        }
        std::memcpy(out, file.data() + offset, size);
        return true;
    }

    std::string ReadName(const std::vector<uint8_t>& file, const IMAGE_NT_HEADERS32* nt, DWORD rva)
    {
        std::string name;
        for (size_t index = 0; index < 256; ++index)
        {
            char character{};
            if (!ReadAt(file, nt, rva + static_cast<DWORD>(index), &character, sizeof(character)))
            {
                break;
            }
            if (character == '\0')
            {
                return name;
            }
            name.push_back(character);
        }
        return {};
    }

    void CheckImports(const std::vector<uint8_t>& file, const IMAGE_NT_HEADERS32* nt)
    {
        const auto& directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (directory.VirtualAddress == 0)
        {
            Check(false, "imports: the image has an import table");
            return;
        }

        bool foundCrt = false;
        std::string crt;
        std::string libraries;
        size_t count = 0;
        for (size_t index = 0;; ++index)
        {
            IMAGE_IMPORT_DESCRIPTOR descriptor{};
            if (!ReadAt(file, nt,
                        directory.VirtualAddress + static_cast<DWORD>(index * sizeof(descriptor)),
                        &descriptor, sizeof(descriptor)))
            {
                break;
            }
            if (descriptor.Name == 0)
            {
                break;
            }

            ++count;
            const auto name = ReadName(file, nt, descriptor.Name);
            libraries += name;
            libraries += ' ';
            for (const auto& pattern : {"msvcp", "msvcr", "vcruntime", "ucrtbase", "api-ms-win-crt"})
            {
                if (_strnicmp(name.c_str(), pattern, std::strlen(pattern)) == 0)
                {
                    foundCrt = true;
                    crt = name;
                }
            }
        }

        Check(count > 0, "imports: the import table has at least one library", libraries);
        Check(!foundCrt, "imports: no CRT redistributable DLL (static runtime)", crt);
        Check(libraries.find("USER32") != std::string::npos,
              "imports: USER32 is imported (windowed hooks and dialogs)", libraries);
        Check(libraries.find("SHELL32") != std::string::npos,
              "imports: SHELL32 is imported (LocalSettingsPath)", libraries);
        Check(libraries.find("ADVAPI32") != std::string::npos,
              "imports: ADVAPI32 is imported (registry path)", libraries);
        // The loader probe's EnumProcessModules is resolved to the K32 alias in
        // kernel32 by the MSVC headers, so PSAPI itself is not always an import.
        Check(libraries.find("VERSION") != std::string::npos,
              "imports: VERSION is imported (loader/executable version)", libraries);
    }
}

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        std::printf("usage: xla_pe_check <artifact.asi>\n");
        return 2;
    }

    std::ifstream stream(argv[1], std::ios::binary);
    if (!stream)
    {
        std::printf("FAIL pe: the artifact could not be read (%s)\n", argv[1]);
        return 1;
    }

    std::vector<uint8_t> file((std::istreambuf_iterator<char>(stream)),
                              std::istreambuf_iterator<char>());
    Check(file.size() > sizeof(IMAGE_DOS_HEADER), "pe: the artifact has a DOS header");
    if (file.size() <= sizeof(IMAGE_DOS_HEADER))
    {
        return 1;
    }

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(file.data());
    Check(dos->e_magic == IMAGE_DOS_SIGNATURE, "pe: the DOS signature is MZ");
    const auto ntOffset = static_cast<size_t>(dos->e_lfanew);
    if (ntOffset + sizeof(IMAGE_NT_HEADERS32) > file.size())
    {
        Check(false, "pe: the NT headers fit in the file");
        return 1;
    }

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(file.data() + ntOffset);
    Check(nt->Signature == IMAGE_NT_SIGNATURE, "pe: the NT signature is PE");
    Check(nt->FileHeader.Machine == IMAGE_FILE_MACHINE_I386, "pe: the machine is i386 (Win32)");
    Check(nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC,
          "pe: the optional header is PE32");
    Check((nt->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0, "pe: the artifact is a DLL");
    Check(nt->OptionalHeader.ImageBase == 0x10000000, "pe: the image base is 0x10000000",
          std::to_string(nt->OptionalHeader.ImageBase));
    Check(nt->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI,
          "pe: the subsystem is windowed", std::to_string(nt->OptionalHeader.Subsystem));

    CheckImports(file, nt);

    std::printf("%d check(s), %d failure(s)\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
