// SPDX-License-Identifier: GPL-3.0-or-later

#include "ini_file.hxx"

#include "common.hxx"

#include <IniReader.h>

import xla.common;

namespace xla::ini
{
    struct File::Impl
    {
        explicit Impl(const std::filesystem::path& path) : reader(path) {}

        CIniReader reader;
    };

    namespace
    {
        // mINI splits on '\n', so a bare-LF file parses correctly already. The
        // CRLF rewrite is inherited from the original loader (editor and
        // round-trip compatibility) and is value-preserving; it is *not* needed
        // for parsing. It rewrites the user's file once, and that is the whole
        // behaviour change if it is ever removed.
        void NormalizeLineEndings(const std::filesystem::path& path)
        {
            std::ifstream in{path, std::ios::binary};
            if (!in)
            {
                return;
            }
            const std::string text{std::istreambuf_iterator<char>{in},
                                   std::istreambuf_iterator<char>{}};

            bool hasBareLf = false;
            for (std::size_t i = 0; i < text.size(); ++i)
            {
                if (text[i] == '\n' && (i == 0 || text[i - 1] != '\r'))
                {
                    hasBareLf = true;
                    break;
                }
            }
            if (!hasBareLf)
            {
                return;
            }

            std::string normalized;
            normalized.reserve(text.size() + 16);
            for (std::size_t i = 0; i < text.size(); ++i)
            {
                if (text[i] == '\n' && (i == 0 || text[i - 1] != '\r'))
                {
                    normalized += "\r\n";
                }
                else
                {
                    normalized += text[i];
                }
            }

            std::ofstream out{path, std::ios::binary | std::ios::trunc};
            if (!out)
            {
                return;
            }
            out.write(normalized.data(), static_cast<std::streamsize>(normalized.size()));
            log::Info("config: normalized {} to CRLF (inherited editor/round-trip norm; "
                      "mINI already splits on LF)",
                      path.string());
        }

    } // namespace

    File::File(std::filesystem::path path) : m_path(std::move(path)) {}

    File::~File() = default;
    File::File(File&&) noexcept = default;
    File& File::operator=(File&&) noexcept = default;

    std::optional<File> File::Open(const std::filesystem::path& path)
    {
        std::error_code error;
        if (!std::filesystem::exists(path, error) || error)
        {
            return std::nullopt;
        }

        NormalizeLineEndings(path);

        std::optional<File> file;
        file.emplace(File{path});
        file->m_impl = std::make_unique<Impl>(path);
        return file;
    }

    std::optional<std::string> File::Read(std::string_view section, std::string_view key) const
    {
        if (!m_impl)
        {
            return std::nullopt;
        }

        static constexpr std::string_view kMissing = "\x01xla-missing";
        std::string value = m_impl->reader.ReadString(section, key, kMissing);
        if (value == kMissing)
        {
            return std::nullopt;
        }
        return value;
    }
} // namespace xla::ini
