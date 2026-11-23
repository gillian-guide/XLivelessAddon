// SPDX-License-Identifier: GPL-3.0-or-later
//
// xla.config - the add-on's INI: defaults, loading, the legacy ZolikaPatch.ini
// fallback and the FusionFix compatibility gates.
//
// Ported from openprecepatch/xlivelessaddon/source/config.ixx.
//
// Precedence is the original's: `XLivelessAddon.ini` wins, then a flat/legacy
// `ZolikaPatch.ini`. The parser is the vendored IniReader (ThirteenAG, MIT);
// upstream is all-inline and this project's module-probe build shows it compiles
// in module purview with MSVC 19.51, so no plain-TU boundary is needed.
//
// DIVERGENCE FROM THE OLD ADDON: the user-data redirect is never switched off
// because FusionFix is installed. The old addon gated LocalSettingsPath,
// CustomSavePath and CustomSettingsPath on a FusionFix check, which misbehaves
// with FusionFix on 1.0.8.0 (the two redirects fight over the same shell/import
// slots and the gate can clear a path the user configured for this add-on). Those
// three keys are gone; `[USERPROFILE] CustomUserProfilePath` is one redirect of the
// shell profile folders and works on this add-on's own detection. The frontend pair
// (SkipIntro/SkipMenu) and the windowed options are genuinely FusionFix's
// subsystems and stay gated.
//
// The recovered `[COMPATIBILITY]` set (NewFilesCompatibility, NewSavesCompatibility,
// GFWLProtectionDisabler, SteamAchievements) lives here too: OpenPreCEPatch's section
// moved to this companion, with its shipped defaults. The keys stay flat under
// `[Options]` like every other key of this INI; the section list still searches an old
// INI's own `[COMPATIBILITY]` section.

module;

#include <common.hxx>
#include <IniReader.h>

export module config;

import common;

export namespace xla::config
{
    // One INI option set. Every member's initializer is the original add-on's
    // distribution default, not the shipped INI: the shipped file explicitly
    // enables DoNotPauseOnMinimize and BorderlessWindowed. The four restored
    // frontend/GFWL/VRAM keys carry their shipped values here too, so an existing
    // INI written before they existed keeps the old add-on's shipped behaviour.
    struct Options
    {
        std::string customUserProfilePath;
        bool savegameFix{true};
        bool removeDataIntegrityChecks{true};
        bool skipTokenActivation{true};
        bool skipFirstTimePlayAsk{true};
        bool skipInternetConnectionCheck{true};
        bool skipHealthCheck{true};
        bool skipWebConnect{true};
        bool skipLauncher{true};
        bool legacyLauncher{true};
        bool launchWithPlayGTAIV{true};
        bool removeRegistryPathDependency{true};
        // The recovered [COMPATIBILITY] set (OpenPreCEPatch's section, shipped on).
        bool newFilesCompatibility{true};
        bool newSavesCompatibility{true};
        bool gfwlProtectionDisabler{true};
        bool steamAchievements{true};
        // The recovered ZolikaPatch fixes ported from the fork (shipped on).
        bool benchmarkFix{true};
        bool combinedRadioFreezeFix{true};
        bool loadDLCs{true};
        bool skipIntro{true};
        bool skipMenu{false};
        bool vramFix{true};
        bool doNotPauseOnMinimize{false};
        bool borderlessWindowed{false};
        bool startupWarnings{true};
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
    // layout; `USERPROFILE` is FusionFix's section for the profile redirect; the
    // rest are the legacy ZolikaPatch groups. The list order is the precedence, not
    // the file order: the shipped flat ZolikaPatch.ini relies on it.
    inline constexpr std::array<std::string_view, 16> kSections{{
        "MAIN",
        "Options",
        "USERPROFILE",
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
    // data/XLivelessAddon.ini by a test.
    inline constexpr std::string_view kDefaultIni =
        R"(; XLivelessAddon

[Options]
; the save-file CRC32 bypass
SavegameFix=1
; various GFWL things
RemoveDataIntegrityChecks=1
SkipTokenActivation=1
SkipFirstTimePlayAsk=1
SkipInternetConnectionCheck=1
SkipHealthCheck=1
; skip the GFWL web-connect and health checks
SkipWebConnect=1
; skip the launcher/DRM checks
SkipLauncher=1
; legacy skip launcher mode, only when SkipLauncher=0
LegacyLauncher=1
; rewrite the game's LaunchGTAIV.exe name slots to PlayGTAIV.exe while a live PlayGTAIV.exe is present, so a PlayGTAIV-launched game passes the DRM's launcher check;
LaunchWithPlayGTAIV=1
; remove the Rockstar Games registry path dependency
RemoveRegistryPathDependency=1
; allow script.img and radiohud from newer versions to work (script.img is 1060+ only)
NewFilesCompatibility=1
; allow newer savefiles to load properly without needing them to be downgraded first [1060-1080]
NewSavesCompatibility=1
; disable the GFWL xlive.dll protection check
GFWLProtectionDisabler=1
; mirror GFWL achievements to Steam
SteamAchievements=1
; fix the crash after the benchmark ends (every build except 1.0.8.0 and 1.1.3.0)
BenchmarkFix=1
; fix the freeze after Concrete Jungle with the 3 EFLC exclusive radio stations installed
CombinedRadioFreezeFix=1
; load TBoGT and TLAD from EFLC or CE folders, plus addon episodes named Episode3, Episode4,
; etc. (set their ids in setup2.xml to the episode id multiplied by 2) [1060,1070,1080]
LoadDLCs=1
; shorten the intro screens (the ones under 8000 ms; FusionFix owns this when present)
SkipIntro=1
; skip the main menu (hold SHIFT on startup to reach it) (FusionFix owns this when present)
SkipMenu=0
; fix the VRAM detection so the graphics settings are not locked out
VRAMFix=1
; keep rendering while the borderless window is unfocused
DoNotPauseOnMinimize=1
; borderless window
BorderlessWindowed=1
; non-fatal startup warnings (old ASI loader, FusionFix notice); fatal checks always run
StartupWarnings=1

[USERPROFILE]
; where the game keeps its user data: saves, settings, user music, videos and benchmarks.
; relative paths are relative to the game folder; leave empty to use the Windows profile
CustomUserProfilePath=./Savefiles
)";

    inline constexpr std::string_view DefaultIniText() noexcept
    {
        return kDefaultIni;
    }

    namespace detail
    {
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

        // One table, one default (the member initializer). A key absent from both
        // files keeps it, and Publish writes the same values into the Game context.
        inline constexpr std::array<BoolOption, 24> kBoolOptions{{
            {"SavegameFix", &Options::savegameFix},
            {"RemoveDataIntegrityChecks", &Options::removeDataIntegrityChecks},
            {"SkipTokenActivation", &Options::skipTokenActivation},
            {"SkipFirstTimePlayAsk", &Options::skipFirstTimePlayAsk},
            {"SkipInternetConnectionCheck", &Options::skipInternetConnectionCheck},
            {"SkipHealthCheck", &Options::skipHealthCheck},
            {"SkipWebConnect", &Options::skipWebConnect},
            {"SkipLauncher", &Options::skipLauncher},
            {"LegacyLauncher", &Options::legacyLauncher},
            {"LaunchWithPlayGTAIV", &Options::launchWithPlayGTAIV},
            {"RemoveRegistryPathDependency", &Options::removeRegistryPathDependency},
            {"NewFilesCompatibility", &Options::newFilesCompatibility},
            {"NewSavesCompatibility", &Options::newSavesCompatibility},
            {"GFWLProtectionDisabler", &Options::gfwlProtectionDisabler},
            {"SteamAchievements", &Options::steamAchievements},
            {"BenchmarkFix", &Options::benchmarkFix},
            {"CombinedRadioFreezeFix", &Options::combinedRadioFreezeFix},
            {"LoadDLCs", &Options::loadDLCs},
            {"SkipIntro", &Options::skipIntro},
            {"SkipMenu", &Options::skipMenu},
            {"VRAMFix", &Options::vramFix},
            {"DoNotPauseOnMinimize", &Options::doNotPauseOnMinimize},
            {"BorderlessWindowed", &Options::borderlessWindowed},
            {"StartupWarnings", &Options::startupWarnings},
        }};

        inline constexpr std::array<StringOption, 1> kStringOptions{{
            {"CustomUserProfilePath", &Options::customUserProfilePath},
        }};

        // The reader splits on '\n' already, so the CRLF rewrite is inherited
        // editor/round-trip compatibility (it rewrites the user's file once), not
        // a parse requirement. Only a bare LF becomes CRLF; every other byte
        // survives.
        inline void NormalizeLineEndings(const std::filesystem::path& path)
        {
            std::ifstream in{path, std::ios::binary};
            if (!in)
            {
                return;
            }
            in.seekg(0, std::ios::end);
            const std::streampos size = in.tellg();
            if (size <= 0)
            {
                return;
            }
            in.seekg(0, std::ios::beg);

            std::string text(static_cast<std::size_t>(size), '\0');
            in.read(text.data(), static_cast<std::streamsize>(text.size()));
            text.resize(static_cast<std::size_t>(in.gcount()));

            bool hasBareLf = false;
            std::string normalized;
            normalized.reserve(text.size() + 16);
            for (std::size_t i = 0; i < text.size(); ++i)
            {
                if (text[i] == '\n' && (i == 0 || text[i - 1] != '\r'))
                {
                    normalized += "\r\n";
                    hasBareLf = true;
                }
                else
                {
                    normalized += text[i];
                }
            }
            if (!hasBareLf)
            {
                return;
            }

            std::ofstream out{path, std::ios::binary | std::ios::trunc};
            if (!out)
            {
                return;
            }
            out.write(normalized.data(), static_cast<std::streamsize>(normalized.size()));
            Log::Print("config: normalized {} to CRLF (inherited editor/round-trip norm; "
                       "mINI already splits on LF)",
                       path.string());
        }

        // One INI file. CIniReader cannot distinguish an absent key from one whose
        // value equals the caller's default, so the sentinel is a value no line can
        // contain.
        class IniFile
        {
        public:
            static std::optional<IniFile> Open(const std::filesystem::path& path)
            {
                std::error_code error;
                if (!std::filesystem::exists(path, error) || error)
                {
                    return std::nullopt;
                }
                NormalizeLineEndings(path);
                return IniFile{path};
            }

            [[nodiscard]] std::optional<std::string> Read(std::string_view section,
                                                          std::string_view key)
            {
                constexpr std::string_view kMissing = "\x01xla-ini-missing";
                std::string value = m_reader.ReadString(section, key, kMissing);
                if (value == kMissing)
                {
                    return std::nullopt;
                }
                return value;
            }

        private:
            explicit IniFile(const std::filesystem::path& path) : m_reader(path) {}

            CIniReader m_reader;
        };

        // The first present value for `key`: the add-on's own INI, then the legacy
        // one, in kSections order.
        inline std::optional<std::string> FindOption(IniFile* own, IniFile* legacy,
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

    // The add-on's flag rule, unchanged from the original's `atoi(value) != 0`.
    [[nodiscard]] inline bool ParseFlag(std::string_view value) noexcept
    {
        return xla::ParseFlag(value);
    }

    // Creates XLivelessAddon.ini in `directory` when it does not exist and
    // returns its path.
    inline std::filesystem::path EnsureIni(const std::filesystem::path& directory)
    {
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
            Log::Print("config: cannot write {}; using defaults", ini.string());
            return ini;
        }

        out << kDefaultIni;
        if (!out)
        {
            Log::Print("config: failed while writing {}; using defaults", ini.string());
        }
        return ini;
    }

    // Finds the old ZolikaPatch.ini. It is read next to the ASI first, then in
    // the folders the ASI loader uses under the game folder (root, plugins,
    // scripts, update), because an old install may have left it in any of them.
    inline std::filesystem::path FindLegacyIni(
        const std::filesystem::path& moduleDirectory,
        const std::filesystem::path& gameDirectory)
    {
        std::error_code error;
        const auto exists = [&error](const std::filesystem::path& path)
        {
            error.clear();
            return std::filesystem::exists(path, error) && !error;
        };

        const std::filesystem::path own = moduleDirectory / "ZolikaPatch.ini";
        if (!moduleDirectory.empty() && exists(own))
        {
            return own;
        }

        if (!gameDirectory.empty())
        {
            constexpr const wchar_t* kLoaderFolders[] = {L"", L"plugins", L"scripts", L"update"};
            for (const wchar_t* folder : kLoaderFolders)
            {
                const std::filesystem::path candidate =
                    folder[0] == 0 ? gameDirectory / "ZolikaPatch.ini"
                                   : gameDirectory / folder / "ZolikaPatch.ini";
                if (candidate != own && exists(candidate))
                {
                    return candidate;
                }
            }
        }

        return own;
    }

    // Reads the options next to the ASI (`moduleDirectory`). The legacy
    // `ZolikaPatch.ini` may be next to it or in one of the loader folders.
    //
    // The body is out of line on purpose: CIniReader is all-inline, and MSVC
    // 19.51 crashes when that body is imported into another module interface
    // unit. The module's own interface only carries the declaration.
    LoadResult Load(const std::filesystem::path& moduleDirectory,
                    const std::filesystem::path& gameDirectory = {});

    // Writes the loaded values (including defaults) into the Game context. A
    // feature reads them through Game::Get().Option("Key"), so the INI's key
    // names are the only place the two sides have to agree.
    void Publish(const LoadResult& loaded);

    // True when FusionFix is loaded in the process, or its ASI sits next to this
    // one. Its folder does not matter: the loaded-module check covers any loader
    // folder.
    inline bool FusionFixPresent(const std::filesystem::path& moduleDirectory) noexcept
    {
        if (::GetModuleHandleW(L"GTAIV.EFLC.FusionFix.asi") != nullptr ||
            ::GetModuleHandleW(L"GTAIV.FusionFix.asi") != nullptr)
        {
            return true;
        }
        if (moduleDirectory.empty())
        {
            return false;
        }

        WIN32_FIND_DATAA data{};
        const std::string pattern = (moduleDirectory / "*FusionFix*.asi").string();
        const HANDLE find = ::FindFirstFileA(pattern.c_str(), &data);
        if (find == INVALID_HANDLE_VALUE)
        {
            return false;
        }
        ::FindClose(find);
        return true;
    }

    // Switches off the options whose subsystem FusionFix owns and returns what
    // was gated. The local-directory options are deliberately absent: they must
    // work on this add-on's own detection (see the file header). `VRAMFix` and
    // `SkipWebConnect` are absent too: this tree's VRAM fix is the recovered
    // call-site clamp (not FusionFix's `grcDevice::GetAvailableVideoMemory`
    // rewrite), and FusionFix has no GFWL, so neither overlaps.
    inline std::vector<FusionFixGate> ApplyFusionFixGates(Options& options)
    {
        struct Gate
        {
            std::string_view option;
            bool Options::* value;
            std::string_view fusionFixModule;
        };

        constexpr std::array<Gate, 4> gates{{
            {"SkipIntro", &Options::skipIntro, "skipintro.ixx"},
            {"SkipMenu", &Options::skipMenu, "skipintro.ixx"},
            {"BorderlessWindowed", &Options::borderlessWindowed, "windowed.ixx"},
            {"DoNotPauseOnMinimize", &Options::doNotPauseOnMinimize, "windowed.ixx"},
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
        return gated;
    }
} // namespace xla::config

namespace xla::config
{
    LoadResult Load(const std::filesystem::path& moduleDirectory,
                    const std::filesystem::path& gameDirectory)
    {
        std::error_code absoluteError;
        const std::filesystem::path base =
            std::filesystem::absolute(moduleDirectory, absoluteError);
        const std::filesystem::path& resolved = absoluteError ? moduleDirectory : base;

        LoadResult result;
        result.iniPath = EnsureIni(resolved);
        result.legacyPath = FindLegacyIni(resolved, gameDirectory);

        std::error_code error;
        result.legacyPresent = std::filesystem::exists(result.legacyPath, error) && !error;

        std::optional<detail::IniFile> own = detail::IniFile::Open(result.iniPath);
        result.iniReadable = own.has_value();
        if (!result.iniReadable)
        {
            Log::Print("config: cannot read {}; using defaults", result.iniPath.string());
        }

        std::optional<detail::IniFile> legacy;
        if (result.legacyPresent)
        {
            legacy = detail::IniFile::Open(result.legacyPath);
        }

        detail::IniFile* ownFile = own ? &*own : nullptr;
        detail::IniFile* legacyFile = legacy ? &*legacy : nullptr;

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

    void Publish(const LoadResult& loaded)
    {
        Game& game = Game::Get();
        for (const detail::BoolOption& row : detail::kBoolOptions)
        {
            game.SetOption(std::string(row.key),
                           loaded.options.*(row.member) ? std::string{"1"} : std::string{"0"});
        }
        for (const detail::StringOption& row : detail::kStringOptions)
        {
            game.SetOption(std::string(row.key), loaded.options.*(row.member));
        }
    }
} // namespace xla::config
