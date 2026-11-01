// SPDX-License-Identifier: GPL-3.0-or-later
//
// The vendored IniReader is header-only and all-inline upstream; mINI crashed
// when that inline code was instantiated in module purview, so this plain
// translation unit owns the reader and the module only sees these declarations.
//
// Adjusts to the vendored API; it does not patch it.

#pragma once

#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace xla::ini
{
    class Reader
    {
    public:
        explicit Reader(const std::filesystem::path& path);
        ~Reader();

        Reader(Reader&&) noexcept;
        Reader& operator=(Reader&&) noexcept;
        Reader(const Reader&) = delete;
        Reader& operator=(const Reader&) = delete;

        [[nodiscard]] std::optional<std::string> Read(std::string_view section,
                                                      std::string_view key) const;

    private:
        struct Impl;
        std::unique_ptr<Impl> m_impl;
    };
} // namespace xla::ini
