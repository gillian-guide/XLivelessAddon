#pragma once
// Minimal types shared with the recovered SkipLauncher tables. The fork is a
// standalone ASI, so it does not link OpenPreCEPatch's common/config modules.
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace opp
{
    enum class PatchResultCode
    {
        ok,
        out_of_bounds,
        invalid_input,
        io_error,
        parse_error,
        not_found,
        unsupported_platform,
        mismatch,
    };

    struct PatchResult final
    {
        PatchResultCode code{PatchResultCode::ok};
        std::string_view detail{};
        constexpr explicit operator bool() const noexcept { return code == PatchResultCode::ok; }
    };

    struct GameImage
    {
        uint8_t* base{};
        size_t size{};
    };
} // namespace opp

using namespace opp;
