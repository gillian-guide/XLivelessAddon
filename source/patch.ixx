// SPDX-License-Identifier: GPL-3.0-or-later
//
// xla.patch - the one unit allowed to install. It owns signature scanning and
// every write primitive (injector stores and branches, the IAT replacement, the
// image unprotect). A feature module calls these helpers; it never names
// injector/safetyhook/VirtualProtect itself, which tools/check_no_installs.py
// enforces.
//
// Ported from openprecepatch/xlivelessaddon/source/patch.ixx; the IAT walker and
// the find_pattern shape follow GTAIV.EFLC.FusionFix's common.ixx/IATHook
// (GPL-3.0, ThirteenAG and contributors).
//
// The scanning idiom is FusionFix's: `find_pattern` tries build variants in order
// and the first one that matches wins, then `get_first<T>(offset)` recovers the
// operand/global the row names. A wildcard is one `?` per byte in this scanner
// (`??` is two wildcard bytes). The scanner caches hits per signature string for
// the life of the process, so one string cannot be scanned twice with different
// counts; a multi-hit row asks for its count up front.

module;

#include <common.hxx>
#include <injector/injector.hpp>
#include <Hooking.Patterns.h>

export module patch;

import common;

export namespace xla::patch
{
    // A scan result. `get_first` asserts a single match (the scanner's own
    // contract); a multi-hit row uses `get(index)` after checking `size()`.
    class Pattern
    {
    public:
        Pattern() = default;
        explicit Pattern(hook::pattern pattern) : m_pattern(std::move(pattern)) {}

        bool empty() const { return m_pattern.empty(); }
        size_t size() const { return m_pattern.size(); }

        template <typename T = void>
        T* get_first(std::ptrdiff_t offset = 0)
        {
            return m_pattern.get_first<T>(offset);
        }

        template <typename T = void>
        T* get(size_t index, std::ptrdiff_t offset = 0)
        {
            return m_pattern.get(index).get<T>(offset);
        }

        template <typename Predicate>
        void for_each(Predicate&& predicate)
        {
            m_pattern.for_each_result(std::forward<Predicate>(predicate));
        }

    private:
        mutable hook::pattern m_pattern;
    };

    // FusionFix's find_pattern: each argument is a signature for a different
    // build and the first one that matches wins. `count` is a scan hint, not a
    // minimum.
    template <std::size_t count = 1, typename... Args>
    Pattern find_pattern(Args... args)
    {
        hook::pattern pattern;
        // An empty variant is never scanned. Hooking.Patterns reads an empty signature
        // as a match at the module start, so a caller that omitted its fallback (the
        // string_view default is empty) would get the DOS header as its "hit".
        auto tryVariant = [&pattern](std::string_view signature) -> bool
        {
            if (signature.empty())
            {
                return false;
            }
            pattern = hook::pattern(signature);
            return !pattern.count_hint(static_cast<std::uint32_t>(count)).empty();
        };
        (tryVariant(args) || ...);
        return Pattern(std::move(pattern));
    }

    // The same scan over a caller-owned image (a parity/test buffer or the game
    // module's view). `count` is the number of hits wanted; 0 asks for all.
    inline Pattern FindIn(const Image& image, std::string_view signature,
                          std::size_t count = 1)
    {
        if (image.empty() || signature.empty())
        {
            return {};
        }
        const auto begin = reinterpret_cast<std::uintptr_t>(image.base);
        hook::pattern pattern =
            hook::make_range_pattern(begin, begin + image.size, signature);
        pattern.count_hint(static_cast<std::uint32_t>(count));
        return Pattern(std::move(pattern));
    }

    template <typename... Args>
    Pattern FindIn(const Image& image, std::size_t count, Args... variants)
    {
        Pattern pattern;
        ((pattern = FindIn(image, variants, count), !pattern.empty()) || ...);
        return pattern;
    }

    // The address of a matched site. Empty when the signature was not found.
    struct Site
    {
        std::uint8_t* address{};

        [[nodiscard]] explicit operator bool() const noexcept { return address != nullptr; }

        [[nodiscard]] std::uint8_t* at(std::ptrdiff_t offset) const noexcept
        {
            return address + offset;
        }
    };

    // The first match of `signature` in the live game image; logs a miss.
    inline Site Find(std::string_view signature, std::string_view label)
    {
        Pattern pattern = find_pattern(signature);
        if (pattern.empty())
        {
            Log::Print("{}: signature missing", label);
            return {};
        }
        return {pattern.get_first<std::uint8_t>()};
    }

    // Build variants, tried in order.
    template <typename... Args>
    Site FindVariants(std::string_view label, Args... signatures)
    {
        Pattern pattern = find_pattern<1>(signatures...);
        if (pattern.empty())
        {
            Log::Print("{}: signature missing (all variants)", label);
            return {};
        }
        return {pattern.get_first<std::uint8_t>()};
    }

    // A raw store. `Write` is the typed form used by the recovered rows; `WriteRaw`
    // stores a byte window whose length is the window's own size.
    template <typename T>
    bool Write(Site site, std::ptrdiff_t offset, T value, std::string_view label)
    {
        static_assert(std::is_integral_v<T>, "patch::Write only stores integers");
        if (!site)
        {
            return false;
        }
        auto* target = site.at(offset);
        injector::WriteMemory<T>(injector::raw_ptr(target), value, true);
        Log::Print("{}: wrote {:#x} at {:08X}", label,
                   static_cast<std::uint64_t>(value),
                   reinterpret_cast<std::uintptr_t>(target));
        return true;
    }

    inline bool WriteRaw(Site site, std::ptrdiff_t offset,
                         std::span<const std::uint8_t> bytes, std::string_view label)
    {
        if (!site || bytes.empty())
        {
            return false;
        }
        auto* target = site.at(offset);
        injector::WriteMemoryRaw(injector::raw_ptr(target),
                                 const_cast<std::uint8_t*>(bytes.data()), bytes.size(), true);
        Log::Print("{}: wrote {} byte(s) at {:08X}", label, bytes.size(),
                   reinterpret_cast<std::uintptr_t>(target));
        return true;
    }

    inline bool Nop(Site site, std::ptrdiff_t offset, std::size_t count,
                    std::string_view label)
    {
        if (!site)
        {
            return false;
        }
        auto* target = site.at(offset);
        injector::MakeNOP(injector::raw_ptr(target), count, true);
        Log::Print("{}: nop {} byte(s) at {:08X}", label, count,
                   reinterpret_cast<std::uintptr_t>(target));
        return true;
    }

    inline bool Fill(Site site, std::ptrdiff_t offset, std::uint8_t value, std::size_t count,
                     std::string_view label)
    {
        if (!site)
        {
            return false;
        }
        auto* target = site.at(offset);
        injector::MemoryFill(injector::raw_ptr(target), value, count, true);
        Log::Print("{}: fill {} byte(s) at {:08X}", label, count,
                   reinterpret_cast<std::uintptr_t>(target));
        return true;
    }

    // Writes `ret`/`ret N` at the instruction's exact width: one byte (C3) for
    // `ret`, three (C2 imm16) for `ret N`.
    //
    // The pinned classic injector's `MakeRET` writes `pop ? 0xC2 : 0xC3` through
    // a deduced `int`, i.e. four bytes for both forms; the maintained fork fixed
    // it, but this tree is pinned to the classic revision. The width is therefore
    // written here instead of calling the vendor helper, and the native suite
    // pins both widths plus the untouched byte after them.
    inline bool Ret(Site site, std::ptrdiff_t offset, std::size_t popBytes,
                    std::string_view label)
    {
        if (!site || popBytes > 0xFFFF)
        {
            return false;
        }
        auto* target = site.at(offset);
        std::array<std::uint8_t, 3> code{Byte(Opcode::kRet), 0, 0};
        std::size_t length = 1;
        if (popBytes != 0)
        {
            code[0] = Byte(Opcode::kRetImm16);
            code[1] = static_cast<std::uint8_t>(popBytes & 0xFF);
            code[2] = static_cast<std::uint8_t>((popBytes >> 8) & 0xFF);
            length = 3;
        }
        injector::WriteMemoryRaw(injector::raw_ptr(target), code.data(), length, true);
        Log::Print("{}: ret {} at {:08X}", label, popBytes,
                   reinterpret_cast<std::uintptr_t>(target));
        return true;
    }

    inline bool Jump(Site site, std::ptrdiff_t offset, const void* destination,
                     std::string_view label)
    {
        if (!site || destination == nullptr)
        {
            return false;
        }
        auto* target = site.at(offset);
        injector::MakeJMP(injector::raw_ptr(target),
                          injector::raw_ptr(const_cast<void*>(destination)), true);
        Log::Print("{}: jmp to {:08X} at {:08X}", label,
                   reinterpret_cast<std::uintptr_t>(destination),
                   reinterpret_cast<std::uintptr_t>(target));
        return true;
    }

    inline void* Call(Site site, std::ptrdiff_t offset, void* destination,
                      std::string_view label)
    {
        if (!site || destination == nullptr)
        {
            return nullptr;
        }
        auto* target = site.at(offset);
        void* previous =
            injector::MakeCALL(injector::raw_ptr(target), injector::raw_ptr(destination), true)
                .get<void*>();
        Log::Print("{}: call to {:08X} at {:08X} (was {:08X})", label,
                   reinterpret_cast<std::uintptr_t>(destination),
                   reinterpret_cast<std::uintptr_t>(target),
                   reinterpret_cast<std::uintptr_t>(previous));
        return previous;
    }

    // The same call writer without the offset argument: a feature that retargets a
    // site it has already resolved names the site directly. `E8` plus the rel32 are
    // written through the injected CALL, the same discipline as `Jump`/`Write`.
    inline void* Call(Site site, void* destination, std::string_view label)
    {
        return Call(site, 0, destination, label);
    }

    // The find-and-apply conveniences the recovered rows use: one line per row,
    // with the signature and the offset visible at the call site.
    inline bool WriteByte(std::string_view signature, std::ptrdiff_t offset,
                          std::uint8_t value, std::string_view label)
    {
        return Write(Find(signature, label), offset, value, label);
    }

    inline bool WriteWord(std::string_view signature, std::ptrdiff_t offset,
                          std::uint16_t value, std::string_view label)
    {
        return Write(Find(signature, label), offset, value, label);
    }

    inline bool WriteDword(std::string_view signature, std::ptrdiff_t offset,
                           std::uint32_t value, std::string_view label)
    {
        return Write(Find(signature, label), offset, value, label);
    }

    inline bool NopFirst(std::string_view signature, std::ptrdiff_t offset, std::size_t count,
                         std::string_view label)
    {
        return Nop(Find(signature, label), offset, count, label);
    }

    inline bool RetFirst(std::string_view signature, std::ptrdiff_t offset,
                         std::size_t popBytes, std::string_view label)
    {
        return Ret(Find(signature, label), offset, popBytes, label);
    }

    inline bool JumpFirst(std::string_view signature, std::ptrdiff_t offset,
                          const void* destination, std::string_view label)
    {
        return Jump(Find(signature, label), offset, destination, label);
    }

    inline void* CallFirst(std::string_view signature, std::ptrdiff_t offset, void* destination,
                           std::string_view label)
    {
        return Call(Find(signature, label), offset, destination, label);
    }

    // Stores into a caller-owned image (the SkipLauncher pass and the tests), with
    // the bounds check the pass needs. A store outside the image is a hard failure
    // in the pass, not a partial write.
    inline bool WriteRawAt(const Image& image, std::uint8_t* site,
                           std::span<const std::uint8_t> bytes, std::string_view label)
    {
        if (site == nullptr || bytes.empty() || !image.contains(site, bytes.size()))
        {
            return false;
        }
        injector::WriteMemoryRaw(injector::raw_ptr(site),
                                 const_cast<std::uint8_t*>(bytes.data()), bytes.size(), true);
        Log::Trace("{}: wrote {} byte(s) at {:08X}", label, bytes.size(),
                   reinterpret_cast<std::uintptr_t>(site));
        return true;
    }

    inline bool FillAt(const Image& image, std::uint8_t* site, std::uint8_t value,
                       std::size_t count, std::string_view label)
    {
        if (site == nullptr || !image.contains(site, count))
        {
            return false;
        }
        injector::MemoryFill(injector::raw_ptr(site), value, count, true);
        Log::Trace("{}: fill {} byte(s) at {:08X}", label, count,
                   reinterpret_cast<std::uintptr_t>(site));
        return true;
    }

    inline bool JumpAt(const Image& image, std::uint8_t* branch, std::uint8_t* target,
                       std::string_view label)
    {
        if (branch == nullptr || target == nullptr || !image.contains(branch, 5))
        {
            return false;
        }
        injector::MakeJMP(injector::raw_ptr(branch), injector::raw_ptr(target), true);
        Log::Trace("{}: jmp to {:08X} at {:08X}", label,
                   reinterpret_cast<std::uintptr_t>(target),
                   reinterpret_cast<std::uintptr_t>(branch));
        return true;
    }

    // Returns whether the call was written. Unlike the live-site `Call`, this does
    // not report the previous destination: a caller-owned image is not inspected
    // for one, and "the site was a call" is not part of this contract.
    inline bool CallAt(const Image& image, std::uint8_t* site, void* destination,
                       std::string_view label)
    {
        if (site == nullptr || destination == nullptr || !image.contains(site, 5))
        {
            return false;
        }
        injector::MakeCALL(injector::raw_ptr(site), injector::raw_ptr(destination), true);
        Log::Trace("{}: call to {:08X} at {:08X}", label,
                   reinterpret_cast<std::uintptr_t>(destination),
                   reinterpret_cast<std::uintptr_t>(site));
        return true;
    }

    // Retargets the `call rel32` at `site` and returns the destination it had
    // before (nullptr when the site is not writable). The previous destination is
    // read first: the caller publishes it as its body's resume, the same contract
    // as the live-site `Call` and as FusionFix's `injector::MakeCALL(..).get()`.
    inline void* RetargetCallAt(const Image& image, std::uint8_t* site, void* destination,
                                std::string_view label)
    {
        if (site == nullptr || destination == nullptr || !image.contains(site, 5))
        {
            return nullptr;
        }
        std::int32_t displacement = 0;
        std::memcpy(&displacement, site + 1, sizeof(displacement));
        auto* previous = reinterpret_cast<void*>(
            site + 5 + static_cast<std::ptrdiff_t>(displacement));
        injector::MakeCALL(injector::raw_ptr(site), injector::raw_ptr(destination), true);
        Log::Print("{}: call to {:08X} at {:08X} (was {:08X})", label,
                   reinterpret_cast<std::uintptr_t>(destination),
                   reinterpret_cast<std::uintptr_t>(site),
                   reinterpret_cast<std::uintptr_t>(previous));
        return previous;
    }

    // Replaces the whole `length`-byte instruction window at `site` with a jump to
    // `destination` (five bytes) and NOP-fills the rest, so the destination owns
    // the instructions the window held and continues at `site + length`. The pinned
    // injector's classic revision has no `MakeInline`/`reg_pack`, so a window hook
    // is this jump plus a body; FusionFix writes the same window through
    // `injector::MakeInline`.
    inline bool InlineJumpAt(const Image& image, std::uint8_t* site, std::size_t length,
                             const void* destination, std::string_view label)
    {
        if (site == nullptr || destination == nullptr || length < 5 ||
            !image.contains(site, length))
        {
            return false;
        }
        injector::MakeJMP(injector::raw_ptr(site),
                          injector::raw_ptr(const_cast<void*>(destination)), true);
        if (length > 5)
        {
            injector::MemoryFill(injector::raw_ptr(site + 5), 0x90, length - 5, true);
        }
        Log::Print("{}: window jmp to {:08X} at {:08X} ({} byte(s), resume {:08X})", label,
                   reinterpret_cast<std::uintptr_t>(destination),
                   reinterpret_cast<std::uintptr_t>(site), length,
                   reinterpret_cast<std::uintptr_t>(site + length));
        return true;
    }

    // Copies a caller-assembled body into fresh executable memory and flushes the
    // instruction cache. The bytes are the caller's data (a recovered stub or the
    // register contract a window hook has to reproduce); a failed allocation is a
    // logged skip, so the caller can leave the site alone.
    inline void* MakeStub(std::span<const std::uint8_t> code, std::string_view label)
    {
        if (code.empty())
        {
            return nullptr;
        }
        void* memory = ::VirtualAlloc(nullptr, code.size(), MEM_COMMIT | MEM_RESERVE,
                                      PAGE_EXECUTE_READWRITE);
        if (memory == nullptr)
        {
            Log::Print("{}: cannot allocate a {} byte stub", label, code.size());
            return nullptr;
        }
        std::memcpy(memory, code.data(), code.size());
        ::FlushInstructionCache(::GetCurrentProcess(), memory, code.size());
        Log::Print("{}: {} byte stub at {:08X}", label, code.size(),
                   reinterpret_cast<std::uintptr_t>(memory));
        return memory;
    }

    // A callable copy of the whole instruction in the `length` bytes at `entry`:
    // the window is copied into fresh executable memory, followed by
    // `jmp entry + length`, so a caller can call the copy and reach the rest of the
    // original function. This is the trampoline half of a call-through entry hook
    // (safetyhook builds the same thing for FusionFix's `create_inline`). The caller
    // owns the claim that the window is one instruction and publishes the returned
    // pointer BEFORE `HookEntryAt` writes the jump.
    inline void* MakeEntryTrampoline(const std::uint8_t* entry, std::size_t length,
                                     std::string_view label)
    {
        if (entry == nullptr || length < 5)
        {
            return nullptr;
        }
        const std::size_t size = length + 5;
        auto* memory = static_cast<std::uint8_t*>(
            ::VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        if (memory == nullptr)
        {
            Log::Print("{}: cannot allocate a {} byte trampoline", label, size);
            return nullptr;
        }
        std::memcpy(memory, entry, length);
        const auto resume = reinterpret_cast<std::uintptr_t>(entry) + length;
        const auto displacement = static_cast<std::int32_t>(
            resume - (reinterpret_cast<std::uintptr_t>(memory) + size));
        memory[length] = Byte(Opcode::kJmpRel32);
        std::memcpy(memory + length + 1, &displacement, sizeof(displacement));
        ::FlushInstructionCache(::GetCurrentProcess(), memory, size);
        Log::Print("{}: {} byte trampoline at {:08X} (resume {:08X})", label, size,
                   reinterpret_cast<std::uintptr_t>(memory), resume);
        return memory;
    }

    // The entry half of the same hook: the `length` bytes at `entry` become a jump to
    // `replacement`, with the rest of the window NOPed.
    inline bool HookEntryAt(const Image& image, std::uint8_t* entry, std::size_t length,
                            const void* replacement, std::string_view label)
    {
        if (entry == nullptr || replacement == nullptr || length < 5 ||
            !image.contains(entry, length))
        {
            return false;
        }
        injector::MakeJMP(injector::raw_ptr(entry),
                          injector::raw_ptr(const_cast<void*>(replacement)), true);
        if (length > 5)
        {
            injector::MemoryFill(injector::raw_ptr(entry + 5), 0x90, length - 5, true);
        }
        Log::Print("{}: entry hook to {:08X} at {:08X} ({} byte(s))", label,
                   reinterpret_cast<std::uintptr_t>(replacement),
                   reinterpret_cast<std::uintptr_t>(entry), length);
        return true;
    }

    // Replaces import slots in `module`'s import (and delay-import) tables. The
    // return value maps each input name to the target the slot held before the
    // replacement; a name with no map entry was not present, so "was it replaced"
    // is the lookup, not a null pointer.
    using ImportHooks = std::initializer_list<std::pair<std::string_view, void*>>;

    inline std::map<std::string, void*> ReplaceImports(HMODULE module, std::string_view library,
                                                       ImportHooks hooks)
    {
        std::map<std::string, void*> originals;
        const auto base = reinterpret_cast<uintptr_t>(module);
        if (base == 0)
        {
            return originals;
        }

        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        {
            return originals;
        }
        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE)
        {
            return originals;
        }

        const auto replaceSlot = [&](void** slot, std::string_view hookedName, void* replacement)
        {
            if (slot == nullptr || *slot == nullptr)
            {
                return;
            }
            DWORD previous = 0;
            if (!::VirtualProtect(slot, sizeof(void*), PAGE_READWRITE, &previous))
            {
                return;
            }
            originals.try_emplace(std::string(hookedName), *slot);
            *slot = replacement;
            ::VirtualProtect(slot, sizeof(void*), previous, &previous);
        };

        // A hook entry may name an ordinal as `Name@12`; the ordinal is matched
        // against the thunk's ordinal instead of the name.
        const auto splitHook = [](std::string_view hook, std::string_view& name,
                                  std::uint16_t& ordinal)
        {
            name = hook;
            ordinal = 0;
            if (const auto at = hook.find_last_of('@'); at != std::string_view::npos)
            {
                ordinal = static_cast<std::uint16_t>(
                    std::strtoul(std::string(hook.substr(at + 1)).c_str(), nullptr, 10));
                name = hook.substr(0, at);
            }
        };

        const auto tryReplace = [&](std::string_view importName, std::uint16_t importOrdinal,
                                    void** slot)
        {
            for (const auto& [hook, replacement] : hooks)
            {
                std::string_view name;
                std::uint16_t ordinal = 0;
                splitHook(hook, name, ordinal);
                const bool matches =
                    importOrdinal != 0 ? ordinal != 0 && importOrdinal == ordinal
                                       : iequals(importName, name);
                if (matches)
                {
                    replaceSlot(slot, hook, replacement);
                }
            }
        };

        const auto& directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (directory.VirtualAddress != 0)
        {
            for (auto* descriptor = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(
                     base + directory.VirtualAddress);
                 descriptor->Name != 0; ++descriptor)
            {
                if (!iequals(std::string_view(
                                 reinterpret_cast<const char*>(base + descriptor->Name)),
                             library))
                {
                    continue;
                }

                auto* slots = reinterpret_cast<void**>(base + descriptor->FirstThunk);
                const auto* thunks =
                    descriptor->OriginalFirstThunk != 0
                        ? reinterpret_cast<const IMAGE_THUNK_DATA*>(base +
                                                                     descriptor->OriginalFirstThunk)
                        : nullptr;

                if (thunks == nullptr)
                {
                    // No name table: the IAT holds resolved addresses. Match them
                    // against the loader's own answer for each hook, which is what
                    // the old addon's IATHook did for this case.
                    const HMODULE libraryModule =
                        ::GetModuleHandleA(std::string(library).c_str());
                    if (libraryModule != nullptr)
                    {
                        for (size_t index = 0; slots[index] != nullptr; ++index)
                        {
                            for (const auto& [hook, replacement] : hooks)
                            {
                                std::string_view name;
                                std::uint16_t ordinal = 0;
                                splitHook(hook, name, ordinal);
                                const auto address = ordinal != 0
                                                         ? ::GetProcAddress(
                                                               libraryModule,
                                                               MAKEINTRESOURCEA(ordinal))
                                                         : ::GetProcAddress(
                                                               libraryModule,
                                                               std::string(name).c_str());
                                if (address != nullptr && slots[index] == address)
                                {
                                    replaceSlot(&slots[index], hook, replacement);
                                }
                            }
                        }
                    }
                    continue;
                }

                for (size_t index = 0; slots[index] != nullptr; ++index)
                {
                    if (thunks[index].u1.AddressOfData == 0)
                    {
                        break;
                    }
                    if (IMAGE_SNAP_BY_ORDINAL(thunks[index].u1.Ordinal))
                    {
                        tryReplace({}, static_cast<std::uint16_t>(
                                            IMAGE_ORDINAL(thunks[index].u1.Ordinal)),
                                   &slots[index]);
                    }
                    else
                    {
                        const auto* import = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(
                            base + thunks[index].u1.AddressOfData);
                        tryReplace(import->Name, 0, &slots[index]);
                    }
                }
            }
        }

        // Delay-loaded imports. The directory is absent on the game image; a zero
        // RVA must not be read as a descriptor at the module base.
        const auto& delay =
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
        if (delay.VirtualAddress != 0 && delay.Size != 0)
        {
            struct DelayLoadDescriptor
            {
                DWORD Attributes;
                DWORD DllNameRVA;
                DWORD ModuleHandleRVA;
                DWORD ImportAddressTableRVA;
                DWORD ImportNameTableRVA;
                DWORD BoundImportAddressTableRVA;
                DWORD UnloadInformationTableRVA;
                DWORD TimeDateStamp;
            };
            static_assert(sizeof(DelayLoadDescriptor) == 32, "invalid delay descriptor");

            for (auto* descriptor =
                     reinterpret_cast<const DelayLoadDescriptor*>(base + delay.VirtualAddress);
                 descriptor->DllNameRVA != 0; ++descriptor)
            {
                if (descriptor->DllNameRVA == 0 || descriptor->ImportNameTableRVA == 0 ||
                    descriptor->ImportAddressTableRVA == 0 ||
                    !iequals(std::string_view(
                                 reinterpret_cast<const char*>(base + descriptor->DllNameRVA)),
                             library))
                {
                    continue;
                }

                auto* slots = reinterpret_cast<void**>(base +
                                                       descriptor->ImportAddressTableRVA);
                const auto* thunks = reinterpret_cast<const IMAGE_THUNK_DATA*>(
                    base + descriptor->ImportNameTableRVA);
                for (size_t index = 0; slots[index] != nullptr; ++index)
                {
                    if (thunks[index].u1.AddressOfData == 0)
                    {
                        break;
                    }
                    if (IMAGE_SNAP_BY_ORDINAL(thunks[index].u1.Ordinal))
                    {
                        tryReplace({}, static_cast<std::uint16_t>(
                                            IMAGE_ORDINAL(thunks[index].u1.Ordinal)),
                                   &slots[index]);
                    }
                    else
                    {
                        const auto* import = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(
                            base + thunks[index].u1.AddressOfData);
                        tryReplace(import->Name, 0, &slots[index]);
                    }
                }
            }
        }

        return originals;
    }

    // Makes .text and .rdata writable so the recovered stores can land. Returns
    // false (and logs) instead of terminating the game when the image is not the
    // one this build expects.
    inline bool MakeImageWritable(const Image& image)
    {
        constexpr DWORD kSectionAlignment = 0x1000;
        constexpr DWORD kSectionAlignmentMask = kSectionAlignment - 1;

        if (image.empty() || image.size < sizeof(IMAGE_DOS_HEADER))
        {
            return false;
        }

        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image.base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        {
            Log::Line("image: bad DOS signature; no patches applied");
            return false;
        }
        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
            image.base + dos->e_lfanew);
        if (!image.contains(nt, sizeof(IMAGE_NT_HEADERS)))
        {
            Log::Line("image: NT headers outside the image; no patches applied");
            return false;
        }
        if (nt->Signature != IMAGE_NT_SIGNATURE)
        {
            Log::Line("image: bad NT signature; no patches applied");
            return false;
        }

        auto* section = IMAGE_FIRST_SECTION(nt);
        for (WORD index = 0; index < nt->FileHeader.NumberOfSections; ++index, ++section)
        {
            const auto* name = reinterpret_cast<const char*>(section->Name);
            std::size_t nameLength = 0;
            while (nameLength < IMAGE_SIZEOF_SHORT_NAME && name[nameLength] != '\0')
            {
                ++nameLength;
            }
            const std::string_view sectionName{name, nameLength};
            const bool isText = std::strncmp(name, ".text", IMAGE_SIZEOF_SHORT_NAME) == 0;
            const bool isRdata = std::strncmp(name, ".rdata", IMAGE_SIZEOF_SHORT_NAME) == 0;
            if (!isText && !isRdata)
            {
                continue;
            }

            const DWORD physicalSize =
                (section->Misc.VirtualSize + kSectionAlignmentMask) & ~kSectionAlignmentMask;
            const DWORD protection = (section->Characteristics & IMAGE_SCN_MEM_EXECUTE)
                                         ? PAGE_EXECUTE_READWRITE
                                         : PAGE_READWRITE;
            DWORD previous = 0;
            if (!::VirtualProtect(image.base + section->VirtualAddress, physicalSize, protection,
                                  &previous))
            {
                Log::Print("image: cannot unprotect {} ({:#x}); no patches applied",
                           sectionName, ::GetLastError());
                return false;
            }
        }
        return true;
    }
} // namespace xla::patch
