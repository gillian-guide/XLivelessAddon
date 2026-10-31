// SPDX-License-Identifier: GPL-3.0-or-later
//
// xla.config — the add-on's INI: defaults, loading, the legacy ZolikaPatch.ini
// fallback and the FusionFix compatibility gates.
//
// Precedence is unchanged from the original add-on: `XLivelessAddon.ini` wins,
// then a flat/legacy `ZolikaPatch.ini`. The FusionFix gates disable any option
// whose subsystem FusionFix owns, so two modules never write the same code.
//
// The parser itself lives in ini_file.cpp (a plain translation unit): mINI's
// stream code is unreliable inside module purview, and a wrong key silently
// falling back to its default is the one failure this loader must not have.

module;

#include "common.hxx"
#include "ini_file.hxx"

export module xla.config;

import xla.common;

export namespace xla::config
{
    // One INI option set. Defaults are the original add-on's INI defaults, not the
    // shipped INI file: that file explicitly enables four non-default keys
    // (skipWebConnect, skipIntro, doNotPauseOnMinimize, borderlessWindowed).
    struct Options
    {
        std::string customSavePath;
        std::string customSettingsPath;
        bool skipLauncher{true};
        bool removeRegistryPathDependency{true};
        bool skipWebConnect{false};
        bool skipIntro{false};
        bool skipMenu{false};
        bool doNotPauseOnMinimize{false};
        bool borderlessWindowed{false};
        bool vramFix{true};
        bool localSettingsPath{false};
    };

    // An option that was switched off because FusionFix owns the subsystem.
    struct FusionFixGate
    {
        std::string_view option;
        std::string_view fusionFixModule;
    };

    struct LoadResult
    {
        Options options;
        std::filesystem::path iniPath;
        std::filesystem::path legacyPath;
        bool legacyPresent{};
        bool iniReadable{false};
    };

    // The sections searched, in order, in both INIs. `Options` is the modern
    // layout; the rest are the legacy ZolikaPatch groups.
    inline constexpr std::array<std::string_view, 15> kSections{{
        "MAIN",
        "Options",
        "COMPATIBILITY",
        "INPUT",
        "LOADING",
        "XLIVELESS",
        "STABILITY",
        "FIXES",
        "PERFORMANCE",
        "GRAPHICS",
        "VEHICLES",
        "MULTIPLAYER",
        "EPISODIC",
        "MISC",
        "INTERFACE",
    }};

    // The INI written when the file is missing; kept in sync with
    // data/XLivelessAddon.ini.
    inline constexpr std::string_view kDefaultIni =
        "; XLivelessAddon\n"
        "\n"
        "[Options]\n"
        "; custom savegames folder; leave empty to use the game default (FusionFix userdata.ixx owns this when present)\n"
        "CustomSavePath=\n"
        "; custom settings folder; PARSED AND LOGGED ONLY - the hook is not ported, so this "
        "value changes nothing (use LocalSettingsPath or FusionFix userdata.ixx)\n"
        "CustomSettingsPath=\n"
        "; skip the launcher/DRM checks (recovered DFA and ROM stages)\n"
        "SkipLauncher=1\n"
        "; remove the Rockstar Games registry path dependency\n"
        "RemoveRegistryPathDependency=1\n"
        "; skip the GFWL web-connect and health checks\n"
        "SkipWebConnect=1\n"
        "; shorten the intro screens to 300 ms (FusionFix skipintro.ixx owns this when present)\n"
        "SkipIntro=1\n"
        "; skip the main menu (hold SHIFT on startup to reach it) (FusionFix skipintro.ixx owns this when present)\n"
        "SkipMenu=0\n"
        "; keep rendering while the borderless window is unfocused (FusionFix windowed.ixx owns this when present)\n"
        "DoNotPauseOnMinimize=1\n"
        "; borderless window (FusionFix windowed.ixx owns this when present)\n"
        "BorderlessWindowed=1\n"
        "; fix the VRAM detection so the settings are not locked out (FusionFix memory.ixx owns this when present)\n"
        "VRAMFix=1\n"
        "; move savegames and settings to a saves folder inside the game folder (FusionFix userdata.ixx owns this when present)\n"
        "LocalSettingsPath=0\n";

    inline constexpr std::string_view DefaultIniText() noexcept
    {
        return kDefaultIni;
    }

    namespace detail
    {
        // `std::atoi`'s base-10 grammar without the library call: skip leading white
        // space, accept one optional sign, consume digits, stop at the first other
        // character. No digits (or an empty value) is 0, exactly like atoi. Never
        // throws, which is the point: a bad INI value must not escape DllMain.
        [[nodiscard]] constexpr long long ParseIntPrefix(std::string_view text) noexcept
        {
            std::size_t index = 0;
            while (index < text.size() &&
                   (text[index] == ' ' || text[index] == '\t' || text[index] == '\n' ||
                    text[index] == '\v' || text[index] == '\f' || text[index] == '\r'))
            {
                ++index;
            }

            bool negative = false;
            if (index < text.size() && (text[index] == '+' || text[index] == '-'))
            {
                negative = text[index] == '-';
                ++index;
            }

            long long value = 0;
            for (; index < text.size() && text[index] >= '0' && text[index] <= '9'; ++index)
            {
                const int digit = text[index] - '0';
                if (value > (LLONG_MAX - digit) / 10)
                {
                    value = LLONG_MAX;
                    continue;
                }
                value = value * 10 + digit;
            }
            return negative ? -value : value;
        }

        // The table that maps each INI key to the `Options` member it fills. The
        // member's initializer is the option's default, so a key that is absent from
        // both files keeps it and there is no second copy of the default to drift.
        struct BoolOption
        {
            std::string_view key;
            bool Options::* member;
        };

        struct StringOption
        {
            std::string_view key;
            std::string Options::* member;
        };

        inline constexpr std::array<BoolOption, 9> kBoolOptions{{
            {"SkipLauncher", &Options::skipLauncher},
            {"RemoveRegistryPathDependency", &Options::removeRegistryPathDependency},
            {"SkipWebConnect", &Options::skipWebConnect},
            {"SkipIntro", &Options::skipIntro},
            {"SkipMenu", &Options::skipMenu},
            {"DoNotPauseOnMinimize", &Options::doNotPauseOnMinimize},
            {"BorderlessWindowed", &Options::borderlessWindowed},
            {"VRAMFix", &Options::vramFix},
            {"LocalSettingsPath", &Options::localSettingsPath},
        }};

        inline constexpr std::array<StringOption, 2> kStringOptions{{
            {"CustomSavePath", &Options::customSavePath},
            {"CustomSettingsPath", &Options::customSettingsPath},
        }};

        // The first present value for `key`: the add-on's own INI, then the legacy
        // one, in `kSections` order (the list order is the precedence, not the file
        // order - the shipped flat ZolikaPatch.ini relies on it).
        inline std::optional<std::string> FindOption(const ini::File* own,
                                                    const ini::File* legacy,
                                                    std::string_view key)
        {
            if (own != nullptr)
            {
                for (const std::string_view section : kSections)
                {
                    if (auto value = own->Read(section, key))
                    {
                        return value;
                    }
                }
            }
            if (legacy != nullptr)
            {
                for (const std::string_view section : kSections)
                {
                    if (auto value = legacy->Read(section, key))
                    {
                        return value;
                    }
                }
            }
            return std::nullopt;
        }
    } // namespace detail

    // The add-on's flag rule, unchanged from the original's `atoi(value) != 0`: any
    // non-zero integer prefix enables the option, so "2" and "-1" enable and an empty
    // or non-numeric value disables (it does not fall back to the default).
    // Exported so the test suite can pin the grammar.
    [[nodiscard]] inline bool ParseFlag(std::string_view value) noexcept
    {
        return detail::ParseIntPrefix(value) != 0;
    }

    // Creates XLivelessAddon.ini in `directory` when it does not exist and
    // returns its path.
    inline std::filesystem::path EnsureIni(const std::filesystem::path& directory)
    {
        // CIniReader resolves a relative path against the ASI directory, so the
        // loader always works on absolute paths.
        std::error_code absoluteError;
        const std::filesystem::path base = std::filesystem::absolute(directory, absoluteError);
        const std::filesystem::path ini =
            (absoluteError ? directory : base) / "XLivelessAddon.ini";

        std::error_code error;
        if (std::filesystem::exists(ini, error) && !error)
        {
            return ini;
        }

        std::ofstream out{ini, std::ios::trunc};
        if (!out)
        {
            log::Info("config: cannot write {}; using defaults", ini.string());
            return ini;
        }

        out << kDefaultIni;
        if (!out)
        {
            log::Info("config: failed while writing {}; using defaults", ini.string());
        }
        return ini;
    }

    // Reads the options for `directory` (the game folder).
    inline LoadResult Load(const std::filesystem::path& directory)
    {
        std::error_code absoluteError;
        const std::filesystem::path base = std::filesystem::absolute(directory, absoluteError);
        const std::filesystem::path& resolved = absoluteError ? directory : base;

        LoadResult result;
        result.iniPath = EnsureIni(resolved);
        result.legacyPath = resolved / "ZolikaPatch.ini";

        std::error_code error;
        result.legacyPresent = std::filesystem::exists(result.legacyPath, error) && !error;

        std::optional<ini::File> own = ini::File::Open(result.iniPath);
        result.iniReadable = own.has_value();
        if (!result.iniReadable)
        {
            log::Info("config: cannot read {}; using defaults", result.iniPath.string());
        }

        std::optional<ini::File> legacy;
        if (result.legacyPresent)
        {
            legacy = ini::File::Open(result.legacyPath);
        }

        const ini::File* ownFile = own ? &*own : nullptr;
        const ini::File* legacyFile = legacy ? &*legacy : nullptr;

        // One pass over the key→member table. A key that neither file has keeps the
        // member's default; an empty or non-numeric flag value is false (the original
        // `atoi("") != 0` rule), not the default.
        Options& options = result.options;
        for (const detail::BoolOption& row : detail::kBoolOptions)
        {
            if (auto value = detail::FindOption(ownFile, legacyFile, row.key))
            {
                options.*(row.member) = ParseFlag(*value);
            }
        }
        for (const detail::StringOption& row : detail::kStringOptions)
        {
            if (auto value = detail::FindOption(ownFile, legacyFile, row.key))
            {
                options.*(row.member) = std::move(*value);
            }
        }
        return result;
    }

    // True when an *FusionFix*.asi sits next to the game executable.
    inline bool FusionFixPresent(const std::filesystem::path& directory) noexcept
    {
        WIN32_FIND_DATAA data{};
        const std::string pattern = (directory / "*FusionFix*.asi").string();
        const HANDLE find = ::FindFirstFileA(pattern.c_str(), &data);
        if (find == INVALID_HANDLE_VALUE)
        {
            return false;
        }
        ::FindClose(find);
        return true;
    }

    // Switches the FusionFix-owned options off and returns what was gated.
    inline std::vector<FusionFixGate> ApplyFusionFixGates(Options& options)
    {
        struct Gate
        {
            std::string_view option;
            bool Options::* value;
            std::string_view fusionFixModule;
        };

        constexpr std::array<Gate, 6> gates{{
            {"SkipIntro", &Options::skipIntro, "skipintro.ixx"},
            {"SkipMenu", &Options::skipMenu, "skipintro.ixx"},
            {"BorderlessWindowed", &Options::borderlessWindowed, "windowed.ixx"},
            {"DoNotPauseOnMinimize", &Options::doNotPauseOnMinimize, "windowed.ixx"},
            {"VRAMFix", &Options::vramFix, "memory.ixx"},
            {"LocalSettingsPath", &Options::localSettingsPath, "userdata.ixx"},
        }};

        std::vector<FusionFixGate> gated;
        for (const Gate& gate : gates)
        {
            bool& value = options.*(gate.value);
            if (!value)
            {
                continue;
            }
            value = false;
            gated.push_back({gate.option, gate.fusionFixModule});
        }

        // The custom path redirects overlap FusionFix's CustomUserProfilePath even
        // when the INI key holds a value.
        if (!options.customSavePath.empty())
        {
            options.customSavePath.clear();
            gated.push_back({"CustomSavePath", "userdata.ixx"});
        }
        if (!options.customSettingsPath.empty())
        {
            options.customSettingsPath.clear();
            gated.push_back({"CustomSettingsPath", "userdata.ixx"});
        }

        return gated;
    }
} // namespace xla::config
