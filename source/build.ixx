// SPDX-License-Identifier: GPL-3.0-or-later
//
// xla.build — recognise the executable this add-on was started in.
//
// The original add-on read one dword at 0x608C34 + base - 0x400000 and compared
// it against a table. The table is preserved byte-for-byte; the read is bounded
// so an unrelated executable logs "unknown" instead of faulting, and every
// installer refuses to run on an unknown build.

module;

#include "common.hxx"

export module xla.build;

import xla.common;

export namespace xla::build
{
    // The ids are the original add-on's compact ids (not the game's four-part
    // version): 1010/1020/1030/1050 are its own intermediate ids.
    enum class Id : std::uint32_t
    {
        unknown = 0,
        v1000 = 1000,
        v1010 = 1010,
        v1020 = 1020,
        v1030 = 1030,
        v1040 = 1040,
        v1050 = 1050,
        v1060 = 1060,
        v1070 = 1070,
        v1080 = 1080,
        v1100 = 1100,
        v1110 = 1110,
        v1120 = 1120,
        v1130 = 1130,
    };

    struct Signature
    {
        std::uint32_t value;
        Id id;
    };

    // opaque: the first four code bytes at kSignatureOffset; a fingerprint of
    // machine code, compared and never decoded.
    // provenance: the original add-on's classification switch (its `gv()` lambda),
    // reproduced byte-for-byte from dcc4f31 source/dllmain.cpp:677-708.
    // why: the bytes are another module's code and change per build, so no
    // expression can derive them; each row names the build it identifies.
    inline constexpr std::array<Signature, 13> kSignatures{{
        {0xC25DE58Bu, Id::v1000},  // 1.0.0.0
        {0x831F7518u, Id::v1010},  // 1.0.1.0
        {0xC483FFE4u, Id::v1020},  // 1.0.2.0
        {0x280F0000u, Id::v1030},  // 1.0.3.0
        {0x110FF300u, Id::v1040},  // 1.0.4.0
        {0xF3385058u, Id::v1050},  // 1.0.0.4
        {0x00A42494u, Id::v1060},  // 1.0.6.0
        {0x1006E857u, Id::v1070},  // 1.0.7.0
        {0x404B100Fu, Id::v1080},  // 1.0.8.0
        {0x5C0FF301u, Id::v1100},  // 1.1.0.0
        {0x0F14247Cu, Id::v1110},  // 1.1.1.0
        {0x0D5C0FF3u, Id::v1120},  // 1.1.2.0
        {0x04C1F600u, Id::v1130},  // 1.1.3.0
    }};

    // The game executable's PE ImageBase on every supported build (the recovered
    // mechanism reads through the load address, so the offset is base-relative).
    inline constexpr std::uintptr_t kGtaImageBase = 0x400000; // = 4 MiB, PE ImageBase
    static_assert(kGtaImageBase == (1u << 22));

    // The original's absolute VA of the classification dword: its `gv()` lambda
    // reads `0x608C34 + base - 0x400000`, so this is the recovered VA and the
    // next constant is the base-relative offset it turns into.
    inline constexpr std::uintptr_t kRecoveredSignatureVa = 0x608C34;

    // The image offset (RVA) the original read: recovered VA minus the image
    // base, 0x608C34 - 0x400000 = 0x208C34. `Detect` adds it to the mapped base.
    inline constexpr std::uintptr_t kSignatureOffset =
        kRecoveredSignatureVa - kGtaImageBase;
    static_assert(kSignatureOffset == 0x208C34); // derived: 0x608C34 - 0x400000

    // A duplicate fingerprint would make two ids indistinguishable; a compile-time
    // check is cheaper than noticing it in the field.
    [[nodiscard]] constexpr bool SignaturesAreUnique() noexcept
    {
        for (std::size_t i = 0; i < kSignatures.size(); ++i)
        {
            for (std::size_t j = i + 1; j < kSignatures.size(); ++j)
            {
                if (kSignatures[i].value == kSignatures[j].value)
                {
                    return false;
                }
            }
        }
        return true;
    }
    static_assert(SignaturesAreUnique());

    [[nodiscard]] inline constexpr std::optional<Id> FromSignature(
        std::uint32_t signature) noexcept
    {
        for (const auto& entry : kSignatures)
        {
            if (entry.value == signature)
            {
                return entry.id;
            }
        }
        return std::nullopt;
    }

    // Reads the classification dword out of an image. A view that does not even
    // cover the offset is simply an unknown build.
    [[nodiscard]] inline std::optional<Id> Detect(const Image& image) noexcept
    {
        if (!image.contains(reinterpret_cast<const void*>(
                                reinterpret_cast<std::uintptr_t>(image.base) + kSignatureOffset),
                            sizeof(std::uint32_t)))
        {
            return std::nullopt;
        }

        std::uint32_t signature = 0;
        std::memcpy(&signature,
                    reinterpret_cast<const void*>(reinterpret_cast<std::uintptr_t>(image.base) +
                                                  kSignatureOffset),
                    sizeof(signature));
        return FromSignature(signature);
    }

    [[nodiscard]] inline std::string Label(Id id) noexcept
    {
        return id == Id::unknown ? std::string{"unknown"}
                                 : std::to_string(static_cast<std::uint32_t>(id));
    }

    [[nodiscard]] inline constexpr bool Is(Id id, std::initializer_list<Id> set) noexcept
    {
        for (const Id candidate : set)
        {
            if (candidate == id)
            {
                return true;
            }
        }
        return false;
    }

    [[nodiscard]] inline constexpr bool IsEflc(Id id) noexcept
    {
        return Is(id, {Id::v1100, Id::v1110, Id::v1120, Id::v1130});
    }
} // namespace xla::build
