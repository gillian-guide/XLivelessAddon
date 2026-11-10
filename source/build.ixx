// SPDX-License-Identifier: GPL-3.0-or-later
//
// xla.build - recognise the executable the add-on was started in.
//
// The original add-on read one dword at 0x608C34 + base - 0x400000 and compared
// it against a table. The table is preserved byte-for-byte from
// openprecepatch/xlivelessaddon/source/build.ixx (itself recovered from the
// original's classification switch); the read is bounded so an unrelated
// executable logs "unknown" instead of faulting. Every installer refuses to run
// on an unknown build.

module;

#include <common.hxx>

export module build;

import common;

export namespace xla::build
{
    struct Signature
    {
        std::uint32_t value;
        GameBuild build;
    };

    // The first four code bytes at kSignatureOffset. These are instruction bytes,
    // not float bit patterns, even where one starts like a float (0x404B100F for
    // 1.0.8.0): nothing here is ever reinterpreted as a number.
    // provenance: the original add-on's classification switch (its `gv()` lambda),
    // reproduced byte-for-byte from the recovered table.
    inline constexpr std::array<Signature, 13> kSignatures{{
        {0xC25DE58Bu, GameBuild::v1000}, // 1.0.0.0
        {0x831F7518u, GameBuild::v1010}, // 1.0.1.0
        {0xC483FFE4u, GameBuild::v1020}, // 1.0.2.0
        {0x280F0000u, GameBuild::v1030}, // 1.0.3.0
        {0x110FF300u, GameBuild::v1040}, // 1.0.4.0
        {0xF3385058u, GameBuild::v1050}, // 1.0.0.4
        {0x00A42494u, GameBuild::v1060}, // 1.0.6.0
        {0x1006E857u, GameBuild::v1070}, // 1.0.7.0
        {0x404B100Fu, GameBuild::v1080}, // 1.0.8.0
        {0x5C0FF301u, GameBuild::v1100}, // 1.1.0.0
        {0x0F14247Cu, GameBuild::v1110}, // 1.1.1.0
        {0x0D5C0FF3u, GameBuild::v1120}, // 1.1.2.0
        {0x04C1F600u, GameBuild::v1130}, // 1.1.3.0
    }};

    // The game executable's PE ImageBase on every supported build (the recovered
    // mechanism reads through the load address, so the offset is base-relative).
    inline constexpr std::uintptr_t kGtaImageBase = 0x400000; // = 4 MiB, PE ImageBase

    // The original's absolute VA of the classification dword: its `gv()` lambda
    // reads `0x608C34 + base - 0x400000`, so this is the recovered VA and the
    // next constant is the base-relative offset it turns into.
    inline constexpr std::uintptr_t kRecoveredSignatureVa = 0x608C34;
    inline constexpr std::uintptr_t kSignatureOffset = kRecoveredSignatureVa - kGtaImageBase;
    static_assert(kSignatureOffset == 0x208C34); // derived: 0x608C34 - 0x400000

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

    [[nodiscard]] inline constexpr std::optional<GameBuild> FromSignature(
        std::uint32_t signature) noexcept
    {
        for (const Signature& entry : kSignatures)
        {
            if (entry.value == signature)
            {
                return entry.build;
            }
        }
        return std::nullopt;
    }

    // Reads the classification dword out of an image, or nullopt when the view
    // does not even cover the offset.
    [[nodiscard]] inline std::optional<std::uint32_t> ReadSignature(
        const Image& image) noexcept
    {
        const auto* site = reinterpret_cast<const void*>(
            reinterpret_cast<std::uintptr_t>(image.base) + kSignatureOffset);
        if (!image.contains(site, sizeof(std::uint32_t)))
        {
            return std::nullopt;
        }

        std::uint32_t signature = 0;
        std::memcpy(&signature, site, sizeof(signature));
        return signature;
    }

    [[nodiscard]] inline std::optional<GameBuild> Detect(const Image& image) noexcept
    {
        const std::optional<std::uint32_t> signature = ReadSignature(image);
        return signature ? FromSignature(*signature) : std::nullopt;
    }
} // namespace xla::build
