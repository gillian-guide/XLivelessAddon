// SPDX-License-Identifier: GPL-3.0-or-later
//
// xla.patch — the primitive patch helpers every installer uses.
//
// Hooking.Patterns finds the site, injector performs the store. Each helper
// logs whether the signature was found and what was written, which is what makes
// a user's log say exactly which patches applied on their build.
//
// These helpers deliberately take no `Image`: they scan the live game module and
// trust the match. Bounds-checked passes do their own check: `savegames` and
// `rom_window` use `Image::contains`; `skip_launcher` wraps a caller-owned span
// and keeps a private `InBounds` with the same arithmetic. Installers that take a
// `const Image&` but discard it keep the parameter for that install-time
// contract; it is not a gate.

module;

#include "common.hxx"

export module xla.patch;

import xla.common;

export namespace xla::patch
{
    // A matched patch site. Empty when the signature was not found.
    struct Site
    {
        void* address{};

        [[nodiscard]] explicit operator bool() const noexcept
        {
            return address != nullptr;
        }

        // The address a row writes: the match advanced by the row's named offset.
        // A negative offset reaches back into the enclosing function.
        [[nodiscard]] std::uint8_t* At(std::ptrdiff_t offset) const noexcept
        {
            return static_cast<std::uint8_t*>(address) + offset;
        }
    };

    // First match of `signature` in the game module; logs a miss.
    inline Site Find(std::string_view signature, std::string_view label)
    {
        hook::pattern pattern{signature};
        if (pattern.empty())
        {
            log::Info("{}: signature missing", label);
            return {};
        }
        return {pattern.get(0).get<void>()};
    }

    template <typename T>
    bool Write(Site site, std::ptrdiff_t offset, T value, std::string_view label)
    {
        static_assert(std::is_integral_v<T>, "patch::Write only stores integers");
        if (!site)
        {
            return false;
        }
        auto* target = site.At(offset);
        injector::WriteMemory<T>(injector::raw_ptr(target), value, true);
        log::Info("{}: wrote {:#x} at {:08X}", label, static_cast<std::uint64_t>(value),
                  reinterpret_cast<std::uintptr_t>(target));
        return true;
    }

    inline bool Nop(Site site, std::ptrdiff_t offset, std::size_t count, std::string_view label)
    {
        if (!site)
        {
            return false;
        }
        auto* target = site.At(offset);
        injector::MakeNOP(injector::raw_ptr(target), count, true);
        log::Info("{}: nop {} byte(s) at {:08X}", label, count,
                  reinterpret_cast<std::uintptr_t>(target));
        return true;
    }

    // Writes `ret`/`ret N`. The width is injector::MakeRET's contract: the pinned
    // injector revision stores one byte (C3) for `ret` and three (C2 imm16) for
    // `ret N`; the native test pins both and the byte after them.
    inline bool Ret(Site site, std::ptrdiff_t offset, std::size_t pop_bytes, std::string_view label)
    {
        if (!site)
        {
            return false;
        }
        auto* target = site.At(offset);
        injector::MakeRET(injector::raw_ptr(target), static_cast<std::uint16_t>(pop_bytes), true);
        log::Info("{}: ret {} at {:08X}", label, pop_bytes,
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
        auto* target = site.At(offset);
        injector::MakeJMP(injector::raw_ptr(target),
                          injector::raw_ptr(const_cast<void*>(destination)), true);
        log::Info("{}: jmp to {:08X} at {:08X}", label,
                  reinterpret_cast<std::uintptr_t>(destination),
                  reinterpret_cast<std::uintptr_t>(target));
        return true;
    }

    // Installs a call and returns the previous destination (nullptr on a miss).
    inline void* Call(Site site, std::ptrdiff_t offset, void* destination, std::string_view label)
    {
        if (!site || destination == nullptr)
        {
            return nullptr;
        }
        auto* target = site.At(offset);
        void* previous =
            injector::MakeCALL(injector::raw_ptr(target), injector::raw_ptr(destination), true)
                .get<void*>();
        log::Info("{}: call to {:08X} at {:08X} (was {:08X})", label,
                  reinterpret_cast<std::uintptr_t>(destination),
                  reinterpret_cast<std::uintptr_t>(target),
                  reinterpret_cast<std::uintptr_t>(previous));
        return previous;
    }

    // The find-and-apply conveniences the patch list uses. They keep the
    // signature strings and offsets visible at the call site, one line per patch.
    inline bool WriteByte(std::string_view signature, std::ptrdiff_t offset, std::uint8_t value,
                          std::string_view label)
    {
        return Write(Find(signature, label), offset, value, label);
    }

    inline bool WriteWord(std::string_view signature, std::ptrdiff_t offset, std::uint16_t value,
                          std::string_view label)
    {
        return Write(Find(signature, label), offset, value, label);
    }

    inline bool WriteDword(std::string_view signature, std::ptrdiff_t offset, std::uint32_t value,
                           std::string_view label)
    {
        return Write(Find(signature, label), offset, value, label);
    }

    inline bool NopFirst(std::string_view signature, std::ptrdiff_t offset, std::size_t count,
                         std::string_view label)
    {
        return Nop(Find(signature, label), offset, count, label);
    }

    inline bool RetFirst(std::string_view signature, std::ptrdiff_t offset, std::size_t pop_bytes,
                         std::string_view label)
    {
        return Ret(Find(signature, label), offset, pop_bytes, label);
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
} // namespace xla::patch
