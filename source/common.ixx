// SPDX-License-Identifier: GPL-3.0-or-later
//
// xla.common — the pieces every other module shares: the view of the loaded
// game image, the error type used by the installers, the logger, module paths
// and the helper that makes the game's .text/.rdata writable. Installers that
// patch their own IAT slots protect those slots themselves, so this is not the
// only writability path.
//
// The layout (common.hxx + one .ixx per feature, definitions inside the module
// interface) follows GTAIV.EFLC.FusionFix.

module;

#include "common.hxx"

export module xla.common;

export namespace xla
{
    // A writable view of the game module: `base` is the load address and `size`
    // is OptionalHeader.SizeOfImage. `contains()` is the bounds check for the
    // installers that take an `Image` (savegames, rom_window, the IAT walkers).
    // `xla.patch`'s helpers take no image and trust the signature match, and
    // `xla.skip_launcher` wraps a caller-owned span with a private `InBounds`
    // (the same arithmetic, for passes that do not own an Image).
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

    // The PE headers of a mapped module. Every installer walks the import table of
    // the same image, so the two signature checks live here once; a caller that
    // wants to say which one failed uses the two pieces directly. No bounds check:
    // the load address is either the module the loader mapped or a caller's copy of
    // the same file, exactly as the original's helpers assumed.
    [[nodiscard]] inline const IMAGE_DOS_HEADER* DosHeader(const void* module) noexcept
    {
        const auto* dos = static_cast<const IMAGE_DOS_HEADER*>(module);
        return dos != nullptr && dos->e_magic == IMAGE_DOS_SIGNATURE ? dos : nullptr;
    }

    [[nodiscard]] inline const IMAGE_NT_HEADERS* NtHeaders(const void* module) noexcept
    {
        const IMAGE_DOS_HEADER* dos = DosHeader(module);
        if (dos == nullptr)
        {
            return nullptr;
        }
        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
            static_cast<const std::uint8_t*>(module) + dos->e_lfanew);
        return nt->Signature == IMAGE_NT_SIGNATURE ? nt : nullptr;
    }

    // FusionFix's Event, verbatim: a mutex-guarded std::function handler list. A
    // subscription returns the token that removes it; executeAll runs a snapshot
    // in subscription order, executeAllAsync runs each handler on its own thread.
    // The startup tiers below are Event<> because their handlers read the Game.
    template <typename... Args>
    class Event : public std::function<void(Args...)>
    {
    public:
        using std::function<void(Args...)>::function;

    private:
        struct Handler
        {
            std::function<void(Args...)> callback;
            std::atomic<bool> active{true};

            explicit Handler(std::function<void(Args...)>&& fn) : callback(std::move(fn)) {}
        };

        mutable std::mutex handlersMutex;
        std::list<std::shared_ptr<Handler>> handlers;

        auto snapshot() const
        {
            std::lock_guard lock(handlersMutex);
            return std::vector<std::shared_ptr<Handler>>(handlers.begin(), handlers.end());
        }

    public:
        auto operator+=(std::function<void(Args...)>&& callback) -> std::function<void()>
        {
            auto handler = std::make_shared<Handler>(std::move(callback));
            {
                std::lock_guard lock(handlersMutex);
                handlers.push_back(handler);
            }
            return [this, handler]()
            {
                std::lock_guard lock(handlersMutex);
                handler->active = false;
                handlers.remove(handler);
            };
        }

        void executeAll(Args... args) const
        {
            for (const auto& handler : snapshot())
            {
                if (handler->active)
                {
                    handler->callback(args...);
                }
            }
        }

        std::vector<std::future<void>> executeAllAsync(Args... args) const
        {
            std::vector<std::future<void>> futures;
            for (const auto& handler : snapshot())
            {
                futures.emplace_back(std::async(
                    std::launch::async,
                    [handler, values = std::tuple<Args...>(args...)]() mutable
                    {
                        if (handler->active)
                        {
                            std::apply(handler->callback, values);
                        }
                    }));
            }
            return futures;
        }
    };

    // The startup tiers, run in this order by xla::Run. The init tier detects the
    // executable and publishes everything the installers read; the install tier
    // keeps the original handler order; the post tier closes the log.
    Event<>& InitEvent() noexcept;
    Event<>& InstallEvent() noexcept;
    Event<>& PostEvent() noexcept;

    enum class PatchErrorCode : std::uint8_t
    {
        invalid_input,
        out_of_bounds,
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
        namespace detail
        {
            // Windows' documented maximum path length (including the terminator).
            inline constexpr std::size_t kMaxModulePathChars = 32768;

            // The directory of `module`; nullptr means the process's main
            // executable (the game folder), never the working directory.
            inline std::filesystem::path DirectoryOfModule(HMODULE module,
                                                           std::error_code& error) noexcept
            {
                std::array<wchar_t, kMaxModulePathChars> buffer{};
                const DWORD length = ::GetModuleFileNameW(
                    module, buffer.data(), static_cast<DWORD>(buffer.size()));
                if (length == 0)
                {
                    error = std::error_code(static_cast<int>(::GetLastError()),
                                            std::system_category());
                    return {};
                }
                if (length >= buffer.size())
                {
                    // The path did not fit: say so instead of returning a
                    // silently truncated directory.
                    error = std::error_code(ERROR_INSUFFICIENT_BUFFER,
                                            std::system_category());
                    return {};
                }
                error.clear();
                return std::filesystem::path(std::wstring_view(buffer.data(), length))
                    .parent_path();
            }

            // Any address in this ASI; GetModuleHandleExW resolves it to the
            // module handle even when the file was renamed.
            inline void ModuleAnchor() noexcept {}

            inline HMODULE ThisModule() noexcept
            {
                HMODULE module = nullptr;
                ::GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                         GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                     reinterpret_cast<LPCWSTR>(&ModuleAnchor), &module);
                return module;
            }
        } // namespace detail

        // The directory containing this ASI. The INI, log and FusionFix notice
        // live here, whatever folder the ASI was installed in.
        inline std::filesystem::path ModuleDirectory(std::error_code& error) noexcept
        {
            return detail::DirectoryOfModule(detail::ThisModule(), error);
        }

        // The same path, ignoring the failure reason; empty when it fails.
        inline std::filesystem::path ModuleDirectory() noexcept
        {
            std::error_code error;
            return ModuleDirectory(error);
        }

        // The game folder (the directory of the process executable). Options
        // documented as relative to the game folder (saves/settings paths) use
        // this, so a plugins\ install still writes into the game tree.
        inline std::filesystem::path GameDirectory(std::error_code& error) noexcept
        {
            return detail::DirectoryOfModule(nullptr, error);
        }

        inline std::filesystem::path GameDirectory() noexcept
        {
            std::error_code error;
            return GameDirectory(error);
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

        // Appends one line; the trailing newline is added. Binary append keeps the
        // LF endings the log has always had (text mode would double them on
        // Windows), and the stream's destructor flushes inside the try. Never
        // throws: a log failure must never take the game down.
        inline void Write(std::string_view line) noexcept
        {
            std::scoped_lock lock{detail::g_mutex};
            try
            {
                std::ofstream file{detail::ResolvePath(), std::ios::binary | std::ios::app};
                if (!file)
                {
                    return;
                }
                file.write(line.data(), static_cast<std::streamsize>(line.size()));
                file.put('\n');
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

    // The image the shared scan helper reads. xla::Game publishes the running
    // game image once in Run; the native tests publish their own buffer. It is a
    // single value, not a second image registry: the Game owns the image and this
    // is only how the scan helper in this module can see it.
    namespace scan
    {
        namespace detail
        {
            inline Image g_image{};
        } // namespace detail

        inline void SetImage(Image image) noexcept
        {
            detail::g_image = image;
        }

        [[nodiscard]] inline Image GetImage() noexcept
        {
            return detail::g_image;
        }
    } // namespace scan

    // The range Hooking.Patterns' own module pattern scans: module base up to the
    // end of the last executable section. A buffer that is not a readable PE32
    // image keeps the whole-image range, so the tests can scan synthetic data.
    [[nodiscard]] inline Image ExecutableView(Image image) noexcept
    {
        const Image whole = image;
        if (image.base == nullptr || image.size < sizeof(IMAGE_DOS_HEADER))
        {
            return whole;
        }

        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image.base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0)
        {
            return whole;
        }

        const std::size_t ntOffset = static_cast<std::size_t>(dos->e_lfanew);
        if (ntOffset + sizeof(IMAGE_NT_HEADERS) > image.size)
        {
            return whole;
        }

        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(image.base + ntOffset);
        if (nt->Signature != IMAGE_NT_SIGNATURE ||
            nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        {
            return whole;
        }

        const std::size_t sectionTable = static_cast<std::size_t>(
            reinterpret_cast<std::uintptr_t>(IMAGE_FIRST_SECTION(nt)) -
            reinterpret_cast<std::uintptr_t>(image.base));
        const std::size_t sectionCount = nt->FileHeader.NumberOfSections;
        if (sectionCount == 0 || sectionTable < ntOffset ||
            sectionTable + sectionCount * sizeof(IMAGE_SECTION_HEADER) > image.size)
        {
            return whole;
        }

        const auto* sections =
            reinterpret_cast<const IMAGE_SECTION_HEADER*>(image.base + sectionTable);
        std::size_t end = 0;
        for (std::size_t index = 0; index < sectionCount; ++index)
        {
            const IMAGE_SECTION_HEADER& section = sections[index];
            // Hooking.Patterns' own range: the raw size when the section has one,
            // otherwise the virtual size, and the last executable section in
            // table order wins.
            const std::size_t sectionSize =
                section.SizeOfRawData != 0 ? section.SizeOfRawData : section.Misc.VirtualSize;
            if ((section.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0)
            {
                end = static_cast<std::size_t>(section.VirtualAddress) + sectionSize;
            }
        }

        // No executable section, or headers that leave the mapped image: keep the
        // whole-image behaviour instead of silently scanning less.
        if (end == 0 || end > image.size)
        {
            return whole;
        }
        return {image.base, end};
    }

    // One scan over the executable view of the published image. Hooking.Patterns
    // applies its own wildcard grammar; the literal is passed through unchanged.
    [[nodiscard]] inline hook::pattern make_game_pattern(std::string_view signature)
    {
        if (signature.empty())
        {
            return hook::pattern{};
        }
        const Image view = ExecutableView(scan::GetImage());
        if (view.empty())
        {
            return hook::pattern{};
        }
        const auto begin = reinterpret_cast<std::uintptr_t>(view.base);
        return hook::make_range_pattern(begin, begin + view.size, signature);
    }

    // The original's hook::pattern with FusionFix's build variants: each argument
    // is a signature for a different build and the first one that matches wins.
    // `count` is the number of matches the caller needs (0 scans every match).
    template <std::size_t count = 1, typename... Args>
    hook::pattern find_pattern(Args... args)
    {
        hook::pattern pattern;
        ((pattern = make_game_pattern(args),
          !pattern.count_hint(static_cast<std::uint32_t>(count)).empty()) ||
         ...);
        if (pattern.empty())
        {
            std::string_view first;
            ((first = std::string_view(args), true) || ...);
            log::Info("pattern missing: {}", first);
        }
        return pattern;
    }

    // FusionFix's byte helpers, verbatim where the types exist in this tree.
    inline std::string format(const char* fmt, ...)
    {
        va_list args;
        va_start(args, fmt);
        std::vector<char> v(1024);
        while (true)
        {
            va_list args2;
            va_copy(args2, args);
            int res = vsnprintf(v.data(), v.size(), fmt, args2);
            if ((res >= 0) && (res < static_cast<int>(v.size())))
            {
                va_end(args);
                va_end(args2);
                return std::string(v.data());
            }
            size_t size;
            if (res < 0)
            {
                size = v.size() * 2;
            }
            else
            {
                size = static_cast<size_t>(res) + 1;
            }
            v.clear();
            v.resize(size);
            va_end(args2);
        }
    }

    template <typename T>
    std::array<std::uint8_t, sizeof(T)> to_bytes(const T& object)
    {
        std::array<std::uint8_t, sizeof(T)> bytes;
        const std::uint8_t* begin = reinterpret_cast<const std::uint8_t*>(std::addressof(object));
        const std::uint8_t* end = begin + sizeof(T);
        std::copy(begin, end, std::begin(bytes));
        return bytes;
    }

    template <typename T>
    T& from_bytes(const std::array<std::uint8_t, sizeof(T)>& bytes, T& object)
    {
        static_assert(std::is_trivially_copyable<T>::value, "not a TriviallyCopyable type");
        std::uint8_t* beginObject = reinterpret_cast<std::uint8_t*>(std::addressof(object));
        std::copy(std::begin(bytes), std::end(bytes), beginObject);
        return object;
    }

    template <class T, class T1>
    T from_bytes(const T1& bytes)
    {
        static_assert(std::is_trivially_copyable<T>::value, "not a TriviallyCopyable type");
        T object;
        std::uint8_t* beginObject = reinterpret_cast<std::uint8_t*>(std::addressof(object));
        std::copy(std::begin(bytes), std::end(bytes) - (sizeof(T1) - sizeof(T)), beginObject);
        return object;
    }

    template <size_t n>
    std::string pattern_str(const std::array<std::uint8_t, n> bytes)
    {
        std::string result;
        for (size_t index = 0; index < n; index++)
        {
            result += format("%02X ", bytes[index]);
        }
        return result;
    }

    template <typename T>
    std::string pattern_str(T value)
    {
        return std::string(
            (std::is_same<T, char>::value ? format("%c ", value) : format("%02X ", value)));
    }

    template <typename T, typename... Rest>
    std::string pattern_str(T value, Rest... rest)
    {
        return std::string((std::is_same<T, char>::value ? format("%c ", value)
                                                         : format("%02X ", value)) +
                           pattern_str(rest...));
    }

    inline std::string pattern_str(std::string_view text)
    {
        std::stringstream stream;
        for (const auto& item : text)
        {
            stream << std::uppercase << std::hex << std::setw(2) << std::setfill('0')
                   << +std::uint8_t(item) << " ";
        }
        return stream.str();
    }

    // FusionFix's IAT replacement: walk the import descriptors of `target_module`
    // and replace every `dll_name!name` (or `name@ordinal`) slot in `inputs`.
    // The return value maps each input name to a future holding the value the slot
    // held before the replacement. A name that does not exist in that module has
    // no map entry, so "was it replaced" is the map lookup, not a null pointer.
    class IATHook
    {
    public:
        template <class... Ts>
        static auto Replace(HMODULE target_module, std::string_view dll_name, Ts&&... inputs)
        {
            std::map<std::string, std::future<void*>> originalPtrs;

            const DWORD_PTR instance = reinterpret_cast<DWORD_PTR>(target_module);
            if (instance == 0)
            {
                return originalPtrs;
            }
            const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(instance);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            {
                return originalPtrs;
            }
            const auto* ntHeader = reinterpret_cast<const IMAGE_NT_HEADERS*>(
                instance + dos->e_lfanew);
            if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
            {
                return originalPtrs;
            }

            const auto& importDirectory =
                ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
            if (importDirectory.VirtualAddress == 0)
            {
                return originalPtrs;
            }
            PIMAGE_IMPORT_DESCRIPTOR pImports = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
                instance + importDirectory.VirtualAddress);
            DWORD dwProtect[2];

            // Regular imports
            for (; pImports->Name != 0; pImports++)
            {
                if (_stricmp(reinterpret_cast<const char*>(instance + pImports->Name),
                             dll_name.data()) == 0)
                {
                    if (pImports->OriginalFirstThunk != 0)
                    {
                        const PIMAGE_THUNK_DATA pThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(
                            instance + pImports->OriginalFirstThunk);

                        for (ptrdiff_t j = 0; pThunk[j].u1.AddressOfData != 0; j++)
                        {
                            auto pAddress =
                                reinterpret_cast<void**>(instance + pImports->FirstThunk) + j;
                            if (!pAddress)
                            {
                                continue;
                            }
                            VirtualProtect(pAddress, sizeof(void*),
                                           PAGE_EXECUTE_READWRITE, &dwProtect[0]);
                            ([&]
                             {
                                 auto name = std::string_view(std::get<0>(inputs));
                                 auto num = std::string("-1");
                                 if (name.contains("@"))
                                 {
                                     num = name.substr(name.find_last_of("@") + 1);
                                     name = name.substr(0, name.find_last_of("@"));
                                 }

                                 if (pThunk[j].u1.Ordinal & IMAGE_ORDINAL_FLAG)
                                 {
                                     try
                                     {
                                         if (IMAGE_ORDINAL(pThunk[j].u1.Ordinal) ==
                                             static_cast<DWORD>(std::stoi(num.data())))
                                         {
                                             originalPtrs[std::get<0>(inputs)] =
                                                 std::async(std::launch::deferred,
                                                            [&]() -> void* {
                                                                return *pAddress;
                                                            });
                                             originalPtrs[std::get<0>(inputs)].wait();
                                             *pAddress = std::get<1>(inputs);
                                         }
                                     }
                                     catch (...)
                                     {
                                     }
                                 }
                                 else if ((*pAddress &&
                                           *pAddress ==
                                               (void*)GetProcAddress(
                                                   GetModuleHandleA(dll_name.data()),
                                                   name.data())) ||
                                          (strcmp(reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
                                                      instance + pThunk[j].u1.AddressOfData)
                                                      ->Name,
                                                  name.data()) == 0))
                                 {
                                     originalPtrs[std::get<0>(inputs)] =
                                         std::async(std::launch::deferred,
                                                    [&]() -> void* { return *pAddress; });
                                     originalPtrs[std::get<0>(inputs)].wait();
                                     *pAddress = std::get<1>(inputs);
                                 }
                             }(),
                             ...);
                            VirtualProtect(pAddress, sizeof(void*), dwProtect[0], &dwProtect[1]);
                        }
                    }
                    else
                    {
                        auto pFunctions =
                            reinterpret_cast<void**>(instance + pImports->FirstThunk);

                        for (ptrdiff_t j = 0; pFunctions[j] != nullptr; j++)
                        {
                            auto pAddress = &pFunctions[j];
                            VirtualProtect(pAddress, sizeof(void*),
                                           PAGE_EXECUTE_READWRITE, &dwProtect[0]);
                            ([&]
                             {
                                 if (*pAddress &&
                                     *pAddress == (void*)GetProcAddress(
                                                       GetModuleHandleA(dll_name.data()),
                                                       std::get<0>(inputs)))
                                 {
                                     originalPtrs[std::get<0>(inputs)] =
                                         std::async(std::launch::deferred,
                                                    [&]() -> void* { return *pAddress; });
                                     originalPtrs[std::get<0>(inputs)].wait();
                                     *pAddress = std::get<1>(inputs);
                                 }
                             }(),
                             ...);
                            VirtualProtect(pAddress, sizeof(void*), dwProtect[0], &dwProtect[1]);
                        }
                    }
                }
            }

            // Delay-loaded imports. The directory is absent on the game image; a
            // zero RVA must not be read as a descriptor at the module base.
            const auto& delayDirectory =
                ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
            if (delayDirectory.VirtualAddress != 0 && delayDirectory.Size != 0)
            {
                PIMAGE_DELAYLOAD_DESCRIPTOR pDelayImports =
                    reinterpret_cast<PIMAGE_DELAYLOAD_DESCRIPTOR>(instance +
                                                                  delayDirectory.VirtualAddress);
                for (; pDelayImports->DllNameRVA != 0; pDelayImports++)
                {
                    if (_stricmp(reinterpret_cast<const char*>(instance +
                                                               pDelayImports->DllNameRVA),
                                 dll_name.data()) == 0)
                    {
                        if (pDelayImports->ImportAddressTableRVA == 0)
                        {
                            continue;
                        }
                        PIMAGE_THUNK_DATA pThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(
                            instance + pDelayImports->ImportNameTableRVA);
                        PIMAGE_THUNK_DATA pAddressThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(
                            instance + pDelayImports->ImportAddressTableRVA);

                        for (; pThunk->u1.AddressOfData != 0; pThunk++, pAddressThunk++)
                        {
                            auto pAddress = reinterpret_cast<void**>(pAddressThunk);
                            VirtualProtect(pAddress, sizeof(void*),
                                           PAGE_EXECUTE_READWRITE, &dwProtect[0]);
                            ([&]
                             {
                                 auto name = std::string_view(std::get<0>(inputs));
                                 auto num = std::string("-1");
                                 if (name.contains("@"))
                                 {
                                     num = name.substr(name.find_last_of("@") + 1);
                                     name = name.substr(0, name.find_last_of("@"));
                                 }

                                 if (pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
                                 {
                                     try
                                     {
                                         if (IMAGE_ORDINAL(pThunk->u1.Ordinal) ==
                                             static_cast<DWORD>(std::stoi(num.data())))
                                         {
                                             originalPtrs[std::get<0>(inputs)] =
                                                 std::async(std::launch::deferred,
                                                            [&]() -> void* {
                                                                return *pAddress;
                                                            });
                                             originalPtrs[std::get<0>(inputs)].wait();
                                             *pAddress = std::get<1>(inputs);
                                         }
                                     }
                                     catch (...)
                                     {
                                     }
                                 }
                                 else if (strcmp(reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
                                                     instance + pThunk->u1.AddressOfData)
                                                     ->Name,
                                                 name.data()) == 0)
                                 {
                                     originalPtrs[std::get<0>(inputs)] =
                                         std::async(std::launch::deferred,
                                                    [&]() -> void* { return *pAddress; });
                                     originalPtrs[std::get<0>(inputs)].wait();
                                     *pAddress = std::get<1>(inputs);
                                 }
                             }(),
                             ...);
                            VirtualProtect(pAddress, sizeof(void*), dwProtect[0], &dwProtect[1]);
                        }
                    }
                }
            }

            return originalPtrs;
        }
    };

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

        if (DosHeader(image.base) == nullptr)
        {
            log::Write("image: bad DOS signature; no patches applied");
            return false;
        }

        const auto* nt = NtHeaders(image.base);
        if (nt == nullptr)
        {
            log::Write("image: bad NT signature; no patches applied");
            return false;
        }

        auto* section = IMAGE_FIRST_SECTION(nt);
        for (WORD index = 0; index < nt->FileHeader.NumberOfSections; ++index, ++section)
        {
            const auto* name = reinterpret_cast<const char*>(section->Name);
            // PE section names are 8 bytes and not necessarily NUL-terminated.
            std::size_t name_length = 0;
            while (name_length < IMAGE_SIZEOF_SHORT_NAME && name[name_length] != '\0')
            {
                ++name_length;
            }
            const std::string_view section_name{name, name_length};
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
                log::Info("image: cannot unprotect {} ({:#x}); no patches applied", section_name,
                          ::GetLastError());
                return false;
            }
        }

        return true;
    }

    // Function-local statics, as in FusionFix: the tier is constructed on first
    // use, and a feature's file-scope constructor is that first use.
    Event<>& InitEvent() noexcept
    {
        static Event<> event;
        return event;
    }

    Event<>& InstallEvent() noexcept
    {
        static Event<> event;
        return event;
    }

    Event<>& PostEvent() noexcept
    {
        static Event<> event;
        return event;
    }
} // namespace xla
