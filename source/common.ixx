// SPDX-License-Identifier: GPL-3.0-or-later
//
// xla.common — the pieces every other module shares: the view of the loaded
// game image, the error type used by the installers, the logger, module paths
// and the single place that makes the game image writable.
//
// The layout (common.hxx + one .ixx per feature, definitions inside the module
// interface) follows GTAIV.EFLC.FusionFix.

module;

#include "common.hxx"

export module xla.common;

export namespace xla
{
    // A writable view of the game module: `base` is the load address and `size`
    // is OptionalHeader.SizeOfImage, so `contains()` is the one bounds check used
    // by every write.
    struct Image
    {
        std::byte* base{};
        std::size_t size{};

        [[nodiscard]] constexpr bool empty() const noexcept
        {
            return base == nullptr || size == 0;
        }

        [[nodiscard]] constexpr std::span<std::byte> bytes() const noexcept
        {
            return {base, size};
        }

        [[nodiscard]] bool contains(const void* site, std::size_t length) const noexcept
        {
            const auto begin = reinterpret_cast<std::uintptr_t>(base);
            const auto address = reinterpret_cast<std::uintptr_t>(site);
            if (begin == 0 || address < begin)
            {
                return false;
            }
            const auto offset = address - begin;
            return length <= size && offset <= size - length;
        }
    };

    enum class PatchErrorCode : std::uint8_t
    {
        invalid_input,
        out_of_bounds,
        not_writable,
        unsupported_build,
    };

    struct PatchError
    {
        PatchErrorCode code{PatchErrorCode::invalid_input};
        std::string_view detail{};
    };

    // Installers return void on success and a PatchError otherwise.
    using PatchOutcome = std::expected<void, PatchError>;

    namespace paths
    {
        // Same, but reports why it failed instead of returning an empty path.
        inline std::filesystem::path ModuleDirectory(std::error_code& error) noexcept
        {
            std::array<wchar_t, 32768> buffer{};
            const DWORD length =
                ::GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
            if (length == 0 || length >= buffer.size())
            {
                error = std::error_code(static_cast<int>(::GetLastError()),
                                        std::system_category());
                return {};
            }
            error.clear();
            return std::filesystem::path(std::wstring_view(buffer.data(), length)).parent_path();
        }

        // The directory of the process executable (the game folder).
        inline std::filesystem::path ModuleDirectory() noexcept
        {
            std::error_code error;
            return ModuleDirectory(error);
        }
    } // namespace paths

    namespace log
    {
        namespace detail
        {
            inline std::mutex g_mutex;
            inline std::filesystem::path g_path;
            inline bool g_banner_written = false;

            inline const std::filesystem::path& ResolvePath()
            {
                if (g_path.empty())
                {
                    std::error_code error;
                    auto directory = paths::ModuleDirectory(error);
                    g_path = error ? std::filesystem::path(L"XLivelessAddon.log")
                                   : directory / L"XLivelessAddon.log";
                }
                return g_path;
            }
        } // namespace detail

        // Overrides the destination. The default is "<module directory>\\XLivelessAddon.log".
        inline void SetPath(std::filesystem::path path)
        {
            std::scoped_lock lock{detail::g_mutex};
            detail::g_path = std::move(path);
        }

        // The destination in use; the default is resolved on first use.
        inline const std::filesystem::path& Path()
        {
            std::scoped_lock lock{detail::g_mutex};
            return detail::ResolvePath();
        }

        // Appends one line; the trailing newline is added. Never throws.
        inline void Write(std::string_view line) noexcept
        {
            std::scoped_lock lock{detail::g_mutex};
            try
            {
                std::FILE* file = nullptr;
                if (::_wfopen_s(&file, detail::ResolvePath().c_str(), L"ab") != 0 ||
                    file == nullptr)
                {
                    return;
                }
                std::fwrite(line.data(), 1, line.size(), file);
                std::fputc('\n', file);
                std::fclose(file);
            }
            catch (...)
            {
                // Logging never takes the game down.
            }
        }

        // Formats and writes one line.
        template <typename... Args>
        void Info(std::format_string<Args...> format, Args&&... args)
        {
            Write(std::format(format, std::forward<Args>(args)...));
        }

        // Writes the version/build banner once per process.
        inline void Banner() noexcept
        {
            {
                std::scoped_lock lock{detail::g_mutex};
                if (detail::g_banner_written)
                {
                    return;
                }
                detail::g_banner_written = true;
            }

            SYSTEMTIME now{};
            ::GetLocalTime(&now);
            Info("{} {} ({}) {}", kProductName, kVersion,
                 kGitSha.empty() ? "no-sha" : kGitSha,
                 std::format("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", now.wYear, now.wMonth,
                             now.wDay, now.wHour, now.wMinute, now.wSecond));
        }
    } // namespace log

    // Makes .text and .rdata writable so the patch helpers can store into them.
    // Returns false (and logs) instead of terminating the game when the image is
    // not the one this build expects.
    inline bool MakeImageWritable(const Image& image) noexcept
    {
        if (image.empty())
        {
            return false;
        }

        auto* base = reinterpret_cast<std::uint8_t*>(image.base);
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        {
            log::Write("image: bad DOS signature; no patches applied");
            return false;
        }

        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE)
        {
            log::Write("image: bad NT signature; no patches applied");
            return false;
        }

        auto* section = IMAGE_FIRST_SECTION(nt);
        for (WORD index = 0; index < nt->FileHeader.NumberOfSections; ++index, ++section)
        {
            const auto* name = reinterpret_cast<const char*>(section->Name);
            const bool is_text = std::strncmp(name, ".text", IMAGE_SIZEOF_SHORT_NAME) == 0;
            const bool is_rdata = std::strncmp(name, ".rdata", IMAGE_SIZEOF_SHORT_NAME) == 0;
            if (!is_text && !is_rdata)
            {
                continue;
            }

            const DWORD physical_size = (section->Misc.VirtualSize + 0xFFFu) & ~0xFFFu;
            const DWORD protection = (section->Characteristics & IMAGE_SCN_MEM_EXECUTE)
                                         ? PAGE_EXECUTE_READWRITE
                                         : PAGE_READWRITE;
            DWORD previous = 0;
            if (!::VirtualProtect(image.base + section->VirtualAddress, physical_size, protection,
                                  &previous))
            {
                log::Info("image: cannot unprotect {} ({:#x}); no patches applied", name,
                          ::GetLastError());
                return false;
            }
        }

        return true;
    }
} // namespace xla
