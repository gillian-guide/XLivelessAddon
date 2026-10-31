// SPDX-License-Identifier: GPL-3.0-or-later
//
// Tiny read-only INI wrapper over ThirteenAG/IniReader (and its mINI backend).
//
// The wrapper exists so the INI parser is instantiated in a plain translation unit:
// mINI's stream code is fragile inside module purview, and every module only needs
// "give me this key or nothing". The pimpl keeps mINI out of public declarations.

#pragma once

#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace xla::ini
{
    class File
    {
    public:
        // Opens `path`, normalising an LF-only file to CRLF first (mINI splits on
        // CRLF on Windows). Returns nothing when the file cannot be read.
        static std::optional<File> Open(const std::filesystem::path& path);

        File(File&&) noexcept;
        File& operator=(File&&) noexcept;
        ~File();

        File(const File&) = delete;
        File& operator=(const File&) = delete;

        // The value of `key` in `section`, or nothing when the key is absent.
        [[nodiscard]] std::optional<std::string> Read(std::string_view section,
                                                      std::string_view key) const;

        [[nodiscard]] const std::filesystem::path& Path() const noexcept
        {
            return m_path;
        }

    private:
        explicit File(std::filesystem::path path);

        struct Impl;

        std::filesystem::path m_path;
        std::unique_ptr<Impl> m_impl;
    };
} // namespace xla::ini
