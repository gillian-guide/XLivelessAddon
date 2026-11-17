// SPDX-License-Identifier: GPL-3.0-or-later
//
// xla.patch - the one unit allowed to install. It owns signature scanning and
// every write primitive (injector stores and branches, the safetyhook inline
// hooks, the IAT replacement, the image unprotect). A feature module calls these
// helpers; it never names injector/safetyhook/VirtualProtect itself, which
// tools/check_no_installs.py enforces.
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
#include <injector/assembly.hpp>
#include <injector/utility.hpp>
#include <safetyhook.hpp>
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
    // before (nullptr when the site is not a writable call). The previous
    // destination is injector::MakeCALL's own return value, i.e. FusionFix's
    // `injector::MakeCALL(at, body).get<T>()` idiom; the bounds check is this
    // tree's caller-owned-image contract.
    inline void* RetargetCallAt(const Image& image, std::uint8_t* site, void* destination,
                                std::string_view label)
    {
        if (site == nullptr || destination == nullptr || !image.contains(site, 5))
        {
            return nullptr;
        }
        void* previous =
            injector::MakeCALL(injector::raw_ptr(site), injector::raw_ptr(destination), true)
                .get<void*>();
        Log::Print("{}: call to {:08X} at {:08X} (was {:08X})", label,
                   reinterpret_cast<std::uintptr_t>(destination),
                   reinterpret_cast<std::uintptr_t>(site),
                   reinterpret_cast<std::uintptr_t>(previous));
        return previous;
    }

    // FusionFix's `injector::reg_pack`: the register file an inline functor gets.
    // A feature module names this alias instead of the injector type, so the
    // no-installs guard still holds.
    using Registers = injector::reg_pack;

    // FusionFix's `injector::MakeInline<Functor>(at, end)`: the window [at, end) is
    // NOPed and `at` becomes a call into a stub that saves the register file, runs
    // `Functor(registers)`, restores it and returns to `end`. The functor therefore
    // reproduces the instructions the window held. A thin forwarder, so the
    // install itself stays in this unit.
    template <typename Functor>
    bool InlineHook(const Image& image, std::uint8_t* at, std::size_t length,
                    std::string_view label)
    {
        if (at == nullptr || length == 0 || !image.contains(at, length))
        {
            return false;
        }
        injector::MakeInline<Functor>(injector::raw_ptr(at),
                                      injector::raw_ptr(at + length));
        Log::Print("{}: inline hook at {:08X} ({} byte(s), resume {:08X})", label,
                   reinterpret_cast<std::uintptr_t>(at), length,
                   reinterpret_cast<std::uintptr_t>(at + length));
        return true;
    }

    // FusionFix's `safetyhook::create_inline(at, replacement)`: an entry hook with a
    // callable trampoline. The feature keeps the returned SafetyHookInline and calls
    // the original through `.call<...>()`, which is FusionFix's own idiom; the hook
    // is created here because this unit is the only installer.
    inline SafetyHookInline CreateInline(std::uint8_t* at, void* replacement,
                                         std::string_view label)
    {
        if (at == nullptr || replacement == nullptr)
        {
            return {};
        }
        SafetyHookInline hook =
            safetyhook::create_inline(reinterpret_cast<void*>(at), replacement);
        if (!hook)
        {
            Log::Print("{}: inline hook at {:08X} failed", label,
                       reinterpret_cast<std::uintptr_t>(at));
            return {};
        }
        Log::Print("{}: inline hook at {:08X} -> {:08X}", label,
                   reinterpret_cast<std::uintptr_t>(at),
                   reinterpret_cast<std::uintptr_t>(replacement));
        return hook;
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
            // The injector owns the unprotect, exactly like its own writes.
            originals.try_emplace(std::string(hookedName), *slot);
            injector::WriteMemory<void*>(injector::raw_ptr(slot), replacement, true);
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

} // namespace xla::patch
