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

    // The x86 opcodes the recovered tables store. Naming them keeps a byte in a
    // table read as an instruction instead of a number (research 07's taxonomy).
    // Each value is the instruction's first byte; ModRM values are named next to
    // the opcode they belong to.
    enum class Opcode : std::uint8_t
    {
        kNop = 0x90,         // nop
        kRet = 0xC3,         // ret
        kRetImm16 = 0xC2,    // ret imm16
        kCallRel32 = 0xE8,   // call rel32
        kJmpRel32 = 0xE9,    // jmp rel32
        kJmpRel8 = 0xEB,     // jmp rel8
        kMovAlImm8 = 0xB0,   // mov al, imm8
        kMovMoffsEax = 0xA3, // mov moffs32, eax
        kMovEaxImm32 = 0xB8, // mov eax, imm32
        kMovR32Rm32 = 0x8B,  // mov r32, r/m32
        kMovRm32R32 = 0x89,  // mov r/m32, r32
        kXorEaxEax = 0x33,   // first byte of `xor eax,eax`
        kModRmEaxEax = 0xC0, // its ModRM
    };

    [[nodiscard]] constexpr std::uint8_t Byte(Opcode opcode) noexcept
    {
        return static_cast<std::uint8_t>(opcode);
    }

    // `EB <rel8>` as one little-endian word (the recovered rows store rel8 pairs
    // this way; naming the displacement makes the packed value readable).
    [[nodiscard]] constexpr std::uint16_t JmpShort(std::int8_t displacement) noexcept
    {
        return static_cast<std::uint16_t>(Byte(Opcode::kJmpRel8) |
                                          (static_cast<std::uint16_t>(
                                               static_cast<std::uint8_t>(displacement))
                                           << 8));
    }

    // The little-endian dword of a four-byte instruction window, derived from the
    // byte catalogue instead of re-spelling the number.
    [[nodiscard]] constexpr std::uint32_t Dword(std::span<const std::uint8_t, 4> bytes) noexcept
    {
        return static_cast<std::uint32_t>(bytes[0]) |
               (static_cast<std::uint32_t>(bytes[1]) << 8) |
               (static_cast<std::uint32_t>(bytes[2]) << 16) |
               (static_cast<std::uint32_t>(bytes[3]) << 24);
    }

    // The little-endian word of a two-byte instruction window.
    [[nodiscard]] constexpr std::uint16_t Word(std::span<const std::uint8_t, 2> bytes) noexcept
    {
        return static_cast<std::uint16_t>(static_cast<std::uint16_t>(bytes[0]) |
                                          (static_cast<std::uint16_t>(bytes[1]) << 8));
    }

    // Recovered instruction windows shared by the patch tables. Each is the exact
    // byte sequence the original writes; the names say what it executes.
    namespace ops
    {
        inline constexpr std::uint8_t kJmpRel8[]{Byte(Opcode::kJmpRel8)};
        inline constexpr std::uint8_t kJmpRel32[]{Byte(Opcode::kJmpRel32)};
        inline constexpr std::uint8_t kRet[]{Byte(Opcode::kRet)};
        inline constexpr std::uint8_t kXorEaxEax[]{Byte(Opcode::kXorEaxEax),
                                                   Byte(Opcode::kModRmEaxEax)};
        inline constexpr std::uint8_t kNopMovMoffsEax[]{Byte(Opcode::kNop),
                                                        Byte(Opcode::kMovMoffsEax)};
        inline constexpr std::uint8_t kNop2[]{Byte(Opcode::kNop), Byte(Opcode::kNop)};
        inline constexpr std::uint8_t kNop3[]{Byte(Opcode::kNop), Byte(Opcode::kNop),
                                              Byte(Opcode::kNop)};
        inline constexpr std::uint8_t kNop4[]{Byte(Opcode::kNop), Byte(Opcode::kNop),
                                              Byte(Opcode::kNop), Byte(Opcode::kNop)};
        inline constexpr std::uint8_t kNop6[]{Byte(Opcode::kNop), Byte(Opcode::kNop),
                                              Byte(Opcode::kNop), Byte(Opcode::kNop),
                                              Byte(Opcode::kNop), Byte(Opcode::kNop)};
        inline constexpr std::uint8_t kNop8[]{Byte(Opcode::kNop), Byte(Opcode::kNop),
                                              Byte(Opcode::kNop), Byte(Opcode::kNop),
                                              Byte(Opcode::kNop), Byte(Opcode::kNop),
                                              Byte(Opcode::kNop), Byte(Opcode::kNop)};
        inline constexpr std::uint8_t kNop11[]{
            Byte(Opcode::kNop), Byte(Opcode::kNop), Byte(Opcode::kNop), Byte(Opcode::kNop),
            Byte(Opcode::kNop), Byte(Opcode::kNop), Byte(Opcode::kNop), Byte(Opcode::kNop),
            Byte(Opcode::kNop), Byte(Opcode::kNop), Byte(Opcode::kNop)};
        inline constexpr std::uint8_t kNop14[]{
            Byte(Opcode::kNop), Byte(Opcode::kNop), Byte(Opcode::kNop), Byte(Opcode::kNop),
            Byte(Opcode::kNop), Byte(Opcode::kNop), Byte(Opcode::kNop), Byte(Opcode::kNop),
            Byte(Opcode::kNop), Byte(Opcode::kNop), Byte(Opcode::kNop), Byte(Opcode::kNop),
            Byte(Opcode::kNop), Byte(Opcode::kNop)};
        inline constexpr std::uint8_t kXorEaxRetNop[]{Byte(Opcode::kXorEaxEax),
                                                      Byte(Opcode::kModRmEaxEax),
                                                      Byte(Opcode::kRet), Byte(Opcode::kNop)};
        inline constexpr std::uint8_t kMovAl1RetNop[]{
            Byte(Opcode::kMovAlImm8), 0x01, // mov al, 1 (imm8)
            Byte(Opcode::kRet), Byte(Opcode::kNop)};
        inline constexpr std::uint8_t kRet8[]{
            Byte(Opcode::kRetImm16), 0x08, 0x00}; // ret 8 (imm16, little-endian)
    } // namespace ops

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
        // PE sections are page-aligned; round VirtualSize up to the section
        // alignment before VirtualProtect. 0x1000 is the PE32 section alignment
        // the game image uses; the mask is derived from it.
        constexpr DWORD kSectionAlignment = 0x1000; // 4 KiB
        constexpr DWORD kSectionAlignmentMask = kSectionAlignment - 1;
        static_assert(kSectionAlignmentMask == 0xFFF); // derived: 0x1000 - 1
        static_assert((kSectionAlignment & kSectionAlignmentMask) == 0);

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

            const DWORD physical_size = (section->Misc.VirtualSize + kSectionAlignmentMask) &
                                        ~kSectionAlignmentMask;
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
