// SPDX-License-Identifier: GPL-3.0-or-later

#include "common.hxx"
#include "ini_file.h"

#include <IniReader.h>

namespace xla::ini
{
    namespace
    {
        // A value no INI line can contain; CIniReader cannot otherwise tell an
        // absent key from one whose value equals the caller's default.
        constexpr std::string_view kMissing = "\x01xla-ini-missing";
    }

    struct Reader::Impl
    {
        explicit Impl(const std::filesystem::path& path) : reader(path) {}
        CIniReader reader;
    };

    Reader::Reader(const std::filesystem::path& path) : m_impl(std::make_unique<Impl>(path)) {}

    Reader::~Reader() = default;
    Reader::Reader(Reader&&) noexcept = default;
    Reader& Reader::operator=(Reader&&) noexcept = default;

    std::optional<std::string> Reader::Read(std::string_view section,
                                            std::string_view key) const
    {
        std::string value = m_impl->reader.ReadString(section, key, kMissing);
        if (value == kMissing)
            return std::nullopt;
        return value;
    }
} // namespace xla::ini
