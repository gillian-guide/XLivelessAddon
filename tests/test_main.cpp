// SPDX-License-Identifier: GPL-3.0-or-later
//
// Native tests for the XLivelessAddon successor. No game files are needed: the
// INI loader is driven against temporary directories, the build table against a
// synthetic image, and the recovered SkipLauncher tables against a scratch image
// with the real signatures written into it.

#include "common.hxx"

import xla.addon;
import xla.build;
import xla.common;
import xla.config;
import xla.patch;
import xla.patches;
import xla.registry;
import xla.rom_window;
import xla.savegames;
import xla.skip_launcher;
import xla.userdata;
import xla.windowed;

namespace
{
    int g_failures = 0;
    std::filesystem::path g_workDirectory;

    void ReportFailure(const char* file, int line, const char* expression)
    {
        std::fprintf(stderr, "check failed: %s:%d: %s\n", file, line, expression);
        ++g_failures;
    }

#define CHECK(x)                                                                                   \
    do                                                                                             \
    {                                                                                              \
        if (!(x))                                                                                  \
        {                                                                                          \
            ReportFailure(__FILE__, __LINE__, #x);                                                 \
        }                                                                                          \
    } while (false)

#define CHECK_EQ(a, b)                                                                             \
    do                                                                                             \
    {                                                                                              \
        if (!((a) == (b)))                                                                         \
        {                                                                                          \
            ReportFailure(__FILE__, __LINE__, #a " == " #b);                                       \
        }                                                                                          \
    } while (false)

    std::filesystem::path MakeTempDirectory(std::string_view name)
    {
        const auto directory = g_workDirectory /
                               std::format("xla-tests-{}-{}", name, ::GetCurrentProcessId());
        std::error_code error;
        std::filesystem::remove_all(directory, error);
        std::filesystem::create_directories(directory, error);
        return directory;
    }

    void WriteFile(const std::filesystem::path& path, std::string_view text)
    {
        std::ofstream out{path, std::ios::binary | std::ios::trunc};
        out.write(text.data(), static_cast<std::streamsize>(text.size()));
    }

    std::string ReadFile(const std::filesystem::path& path)
    {
        std::ifstream in{path, std::ios::binary};
        return std::string{std::istreambuf_iterator<char>{in},
                           std::istreambuf_iterator<char>{}};
    }

    // Parses "key=value" lines; comments and sections are ignored.
    std::map<std::string, std::string> ParseIniKeys(std::string_view text)
    {
        std::map<std::string, std::string> values;
        std::size_t offset = 0;
        while (offset < text.size())
        {
            const std::size_t end = text.find_first_of("\r\n", offset);
            std::string line{text.substr(offset, end == std::string_view::npos ? std::string_view::npos
                                                                              : end - offset)};
            offset = end == std::string_view::npos ? text.size() : end + 1;

            if (line.empty() || line.front() == ';' || line.front() == '[')
            {
                continue;
            }
            const std::size_t equals = line.find('=');
            if (equals == std::string::npos)
            {
                continue;
            }
            std::string key = line.substr(0, equals);
            std::string value = line.substr(equals + 1);
            while (!key.empty() && (key.back() == ' ' || key.back() == '\t'))
            {
                key.pop_back();
            }
            values[key] = value;
        }
        return values;
    }

    void TestDefaultIniMatchesShippedFile(const std::filesystem::path& dataDirectory)
    {
        const auto shipped = ParseIniKeys(ReadFile(dataDirectory / "XLivelessAddon.ini"));
        const auto embedded = ParseIniKeys(xla::config::DefaultIniText());
        CHECK(!shipped.empty());
        CHECK_EQ(shipped.size(), embedded.size());
        for (const auto& [key, value] : shipped)
        {
            const auto it = embedded.find(key);
            CHECK(it != embedded.end());
            if (it != embedded.end())
            {
                CHECK_EQ(it->second, value);
            }
        }
    }

    void TestConfigPrecedenceAndGates()
    {
        const auto directory = MakeTempDirectory("config");
        WriteFile(directory / "XLivelessAddon.ini",
                  "[Options]\n"
                  "SkipIntro=1\n"
                  "SkipMenu=1\n"
                  "BorderlessWindowed=1\n"
                  "DoNotPauseOnMinimize=1\n"
                  "VRAMFix=1\n"
                  "LocalSettingsPath=1\n"
                  "CustomSavePath=C:\\Saves\n"
                  "CustomSettingsPath=C:\\Settings\n"
                  "SkipWebConnect=1\n");
        WriteFile(directory / "ZolikaPatch.ini",
                  "[MAIN]\n"
                  "SkipLauncher=0\n"
                  "SkipIntro=0\n");

        auto loaded = xla::config::Load(directory);
        CHECK(loaded.legacyPresent);
        CHECK(loaded.iniPath.filename() == "XLivelessAddon.ini");
        CHECK_EQ(loaded.options.skipIntro, true);   // own INI wins over the legacy one
        CHECK_EQ(loaded.options.skipMenu, true);
        CHECK_EQ(loaded.options.skipLauncher, false); // legacy fallback
        CHECK_EQ(loaded.options.skipWebConnect, true);
        CHECK_EQ(loaded.options.removeRegistryPathDependency, true); // code default
        CHECK_EQ(loaded.options.customSavePath, std::string{"C:\\Saves"});

        const auto gated = xla::config::ApplyFusionFixGates(loaded.options);
        CHECK_EQ(gated.size(), std::size_t{8});
        CHECK_EQ(loaded.options.skipIntro, false);
        CHECK_EQ(loaded.options.skipMenu, false);
        CHECK_EQ(loaded.options.borderlessWindowed, false);
        CHECK_EQ(loaded.options.doNotPauseOnMinimize, false);
        CHECK_EQ(loaded.options.vramFix, false);
        CHECK_EQ(loaded.options.localSettingsPath, false);
        CHECK(loaded.options.customSavePath.empty());
        CHECK(loaded.options.customSettingsPath.empty());

        // Gating is idempotent: a second pass has nothing left to switch off.
        CHECK(xla::config::ApplyFusionFixGates(loaded.options).empty());

        std::error_code error;
        std::filesystem::remove_all(directory, error);
    }

    void TestConfigDefaultsAndEnsureIni()
    {
        const auto directory = MakeTempDirectory("defaults");
        const auto ini = xla::config::EnsureIni(directory);
        CHECK(std::filesystem::exists(ini));

        // EnsureIni writes the shipped defaults, which explicitly enable four keys
        // the code defaults leave off (skipWebConnect, skipIntro, doNotPauseOnMinimize,
        // borderlessWindowed).
        auto loaded = xla::config::Load(directory);
        CHECK_EQ(loaded.legacyPresent, false);
        CHECK_EQ(loaded.iniReadable, true);
        CHECK_EQ(loaded.options.skipLauncher, true);
        CHECK_EQ(loaded.options.removeRegistryPathDependency, true);
        CHECK_EQ(loaded.options.skipWebConnect, true);
        CHECK_EQ(loaded.options.skipIntro, true);
        CHECK_EQ(loaded.options.doNotPauseOnMinimize, true);
        CHECK_EQ(loaded.options.borderlessWindowed, true);
        CHECK_EQ(loaded.options.vramFix, true);
        CHECK_EQ(loaded.options.localSettingsPath, false);
        CHECK(loaded.options.customSavePath.empty());

        // An existing INI is never rewritten.
        WriteFile(ini, "[Options]\nSkipMenu=1\n");
        loaded = xla::config::Load(directory);
        CHECK_EQ(loaded.options.skipMenu, true);
        CHECK_EQ(loaded.options.skipIntro, false); // absent keys use the code defaults
        CHECK_EQ(loaded.options.borderlessWindowed, false);
        CHECK(ReadFile(ini).find("SkipMenu=1") != std::string::npos);

        std::error_code error;
        std::filesystem::remove_all(directory, error);
    }

    void TestConfigFlagGrammar()
    {
        struct Case
        {
            std::string_view text;
            bool expected;
        };
        // The original add-on's rule is `atoi(value) != 0`: a non-zero integer prefix
        // enables, an empty or non-numeric value disables (it does not use the
        // default), and there is no boolean vocabulary.
        constexpr std::array<Case, 16> cases{{
            {"1", true},   {"01", true},  {" 1 ", true}, {"1abc", true},
            {"+1", true},  {"-1", true},  {"2", true},   {"-2", true},
            {"0", false},  {"-0", false}, {"", false},   {"   ", false},
            {"abc", false}, {"0x1", false}, {"1.0", true}, {"--1", false},
        }};
        for (const Case& test : cases)
        {
            CHECK_EQ(xla::config::ParseFlag(test.text), test.expected);
        }
    }

    void TestConfigOptionTable()
    {
        const auto directory = MakeTempDirectory("option-table");

        // An INI with no keys keeps every member's initializer.
        WriteFile(directory / "XLivelessAddon.ini", "[Options]\n");
        auto loaded = xla::config::Load(directory);
        CHECK_EQ(loaded.options.skipLauncher, true);
        CHECK_EQ(loaded.options.removeRegistryPathDependency, true);
        CHECK_EQ(loaded.options.skipWebConnect, false);
        CHECK_EQ(loaded.options.skipIntro, false);
        CHECK_EQ(loaded.options.skipMenu, false);
        CHECK_EQ(loaded.options.doNotPauseOnMinimize, false);
        CHECK_EQ(loaded.options.borderlessWindowed, false);
        CHECK_EQ(loaded.options.vramFix, true);
        CHECK_EQ(loaded.options.localSettingsPath, false);
        CHECK(loaded.options.customSavePath.empty());
        CHECK(loaded.options.customSettingsPath.empty());

        // Every option set to the opposite of its default: a key missing from the
        // key->member table would leave its member at the default and fail here.
        WriteFile(directory / "XLivelessAddon.ini",
                  "[Options]\n"
                  "SkipLauncher=0\n"
                  "RemoveRegistryPathDependency=0\n"
                  "SkipWebConnect=1\n"
                  "SkipIntro=1\n"
                  "SkipMenu=1\n"
                  "DoNotPauseOnMinimize=1\n"
                  "BorderlessWindowed=1\n"
                  "VRAMFix=0\n"
                  "LocalSettingsPath=1\n"
                  "CustomSavePath=Saves\n"
                  "CustomSettingsPath=Settings\n");
        loaded = xla::config::Load(directory);
        CHECK_EQ(loaded.options.skipLauncher, false);
        CHECK_EQ(loaded.options.removeRegistryPathDependency, false);
        CHECK_EQ(loaded.options.skipWebConnect, true);
        CHECK_EQ(loaded.options.skipIntro, true);
        CHECK_EQ(loaded.options.skipMenu, true);
        CHECK_EQ(loaded.options.doNotPauseOnMinimize, true);
        CHECK_EQ(loaded.options.borderlessWindowed, true);
        CHECK_EQ(loaded.options.vramFix, false);
        CHECK_EQ(loaded.options.localSettingsPath, true);
        CHECK_EQ(loaded.options.customSavePath, std::string{"Saves"});
        CHECK_EQ(loaded.options.customSettingsPath, std::string{"Settings"});

        std::error_code error;
        std::filesystem::remove_all(directory, error);
    }

    void TestConfigSectionOrderAndDuplicates()
    {
        // kSections order decides precedence, not the order of the blocks in the
        // file: MAIN, then Options, then the legacy groups.
        constexpr std::string_view first =
            "[STABILITY]\n"
            "SkipIntro=0\n"      // also in Options: Options wins
            "SkipMenu=1\n"       // only here: found by the section scan
            "[MAIN]\n"
            "SkipWebConnect=1\n" // MAIN is searched first
            "[Options]\n"
            "SkipIntro=1\n"
            "SkipWebConnect=0\n"
            "[FIXES]\n";
        constexpr std::string_view second =
            "[Options]\n"
            "SkipIntro=1\n"
            "SkipWebConnect=0\n"
            "[MAIN]\n"
            "SkipWebConnect=1\n"
            "[STABILITY]\n"
            "SkipIntro=0\n"
            "SkipMenu=1\n";

        for (const std::string_view text : {first, second})
        {
            const auto directory = MakeTempDirectory("section-order");
            WriteFile(directory / "XLivelessAddon.ini", text);
            const auto loaded = xla::config::Load(directory);
            CHECK_EQ(loaded.options.skipIntro, true);     // Options beats STABILITY
            CHECK_EQ(loaded.options.skipWebConnect, true); // MAIN beats Options
            CHECK_EQ(loaded.options.skipMenu, true);      // found outside Options
            std::error_code error;
            std::filesystem::remove_all(directory, error);
        }

        // Last value wins for a duplicated key, and a value in one of the group
        // sections is found after the earlier sections.
        const auto directory = MakeTempDirectory("duplicates");
        WriteFile(directory / "XLivelessAddon.ini",
                  "[Options]\n"
                  "SkipIntro=1\n"
                  "SkipIntro=0\n"
                  "[FIXES]\n"
                  "SkipMenu=1\n");
        auto loaded = xla::config::Load(directory);
        CHECK_EQ(loaded.options.skipIntro, false);
        CHECK_EQ(loaded.options.skipMenu, true);

        // A per-key value in the legacy file fills only what the own file lacks.
        WriteFile(directory / "XLivelessAddon.ini", "[Options]\nSkipIntro=0\n");
        WriteFile(directory / "ZolikaPatch.ini",
                  "[Options]\nSkipWebConnect=0\n"
                  "[MAIN]\n"
                  "SkipWebConnect=1\n"
                  "SkipMenu=1\n"
                  "SkipLauncher=0\n");
        loaded = xla::config::Load(directory);
        CHECK_EQ(loaded.legacyPresent, true);
        CHECK_EQ(loaded.options.skipIntro, false);     // own INI wins
        CHECK_EQ(loaded.options.skipWebConnect, true); // legacy MAIN beats legacy Options
        CHECK_EQ(loaded.options.skipMenu, true);       // legacy fills the gap
        CHECK_EQ(loaded.options.skipLauncher, false);  // legacy value, not the default

        std::error_code error;
        std::filesystem::remove_all(directory, error);
    }

    void TestConfigWhitespaceCommentsQuotes()
    {
        const auto directory = MakeTempDirectory("ini-lexical");
        WriteFile(directory / "XLivelessAddon.ini",
                  "[Options]\n"
                  "   SkipIntro   =   1    // trailing comment\n"
                  "CustomSavePath = C:\\Saves\n"
                  "CustomSettingsPath=C:\\Semi;colon\n");
        const auto loaded = xla::config::Load(directory);
        CHECK_EQ(loaded.options.skipIntro, true);
        CHECK_EQ(loaded.options.customSavePath, std::string{"C:\\Saves"});
        // ';' without a preceding space is not a comment marker.
        CHECK_EQ(loaded.options.customSettingsPath, std::string{"C:\\Semi;colon"});

        WriteFile(directory / "XLivelessAddon.ini",
                  "[Options]\n"
                  "CustomSavePath=\"C:\\Quoted\"\n");
        const auto quoted = xla::config::Load(directory);
        CHECK_EQ(quoted.options.customSavePath, std::string{"C:\\Quoted"});

        std::error_code error;
        std::filesystem::remove_all(directory, error);
    }

    void TestConfigLineEndings()
    {
        const auto directory = MakeTempDirectory("line-endings");
        const auto ini = directory / "XLivelessAddon.ini";
        // WriteFile uses binary mode, so this file really has bare LF line endings.
        WriteFile(ini, "[Options]\nSkipIntro=1\nSkipMenu=1\n");
        const auto loaded = xla::config::Load(directory);
        CHECK_EQ(loaded.options.skipIntro, true);
        CHECK_EQ(loaded.options.skipMenu, true);
        // The loader normalises the file once. mINI actually splits on '\n', so
        // this rewrite is inherited editor-compatibility, not a parse requirement.
        CHECK(ReadFile(ini).find("\r\n") != std::string::npos);

        std::error_code error;
        std::filesystem::remove_all(directory, error);
    }

    void TestOpcodeCatalogue()
    {
        // Independent copy of the recovered windows: every table write goes
        // through these bytes, so a change here is a write-set change.
        const auto check = [](std::span<const std::uint8_t> actual,
                              std::span<const std::uint8_t> expected, const char* name) {
            if (actual.size() != expected.size() ||
                std::memcmp(actual.data(), expected.data(), actual.size()) != 0)
            {
                std::fprintf(stderr, "opcode catalogue: %s differs\n", name);
                ++g_failures;
            }
        };

        constexpr std::array<std::uint8_t, 1> kJmpRel8{0xEB};
        constexpr std::array<std::uint8_t, 1> kJmpRel32{0xE9};
        constexpr std::array<std::uint8_t, 1> kRet{0xC3};
        constexpr std::array<std::uint8_t, 2> kNopMovMoffsEax{0x90, 0xA3};
        constexpr std::array<std::uint8_t, 2> kXorEaxEax{0x33, 0xC0};
        constexpr std::array<std::uint8_t, 4> kXorEaxRetNop{0x33, 0xC0, 0xC3, 0x90};
        constexpr std::array<std::uint8_t, 4> kMovAl1RetNop{0xB0, 0x01, 0xC3, 0x90};
        constexpr std::array<std::uint8_t, 3> kRet8{0xC2, 0x08, 0x00};
        constexpr std::array<std::uint8_t, 2> kNop2{0x90, 0x90};
        constexpr std::array<std::uint8_t, 3> kNop3{0x90, 0x90, 0x90};
        constexpr std::array<std::uint8_t, 4> kNop4{0x90, 0x90, 0x90, 0x90};
        constexpr std::array<std::uint8_t, 6> kNop6{0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
        constexpr std::array<std::uint8_t, 8> kNop8{0x90, 0x90, 0x90, 0x90,
                                                    0x90, 0x90, 0x90, 0x90};
        constexpr std::array<std::uint8_t, 11> kNop11{0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                                                      0x90, 0x90, 0x90, 0x90, 0x90};
        constexpr std::array<std::uint8_t, 14> kNop14{0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                                                      0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                                                      0x90, 0x90};

        check(xla::ops::kJmpRel8, kJmpRel8, "kJmpRel8");
        check(xla::ops::kJmpRel32, kJmpRel32, "kJmpRel32");
        check(xla::ops::kRet, kRet, "kRet");
        check(xla::ops::kNopMovMoffsEax, kNopMovMoffsEax, "kNopMovMoffsEax");
        check(xla::ops::kXorEaxEax, kXorEaxEax, "kXorEaxEax");
        check(xla::ops::kXorEaxRetNop, kXorEaxRetNop, "kXorEaxRetNop");
        check(xla::ops::kMovAl1RetNop, kMovAl1RetNop, "kMovAl1RetNop");
        check(xla::ops::kRet8, kRet8, "kRet8");
        check(xla::ops::kNop2, kNop2, "kNop2");
        check(xla::ops::kNop3, kNop3, "kNop3");
        check(xla::ops::kNop4, kNop4, "kNop4");
        check(xla::ops::kNop6, kNop6, "kNop6");
        check(xla::ops::kNop8, kNop8, "kNop8");
        check(xla::ops::kNop11, kNop11, "kNop11");
        check(xla::ops::kNop14, kNop14, "kNop14");

        CHECK_EQ(xla::Byte(xla::Opcode::kNop), std::uint8_t{0x90});
        CHECK_EQ(xla::Byte(xla::Opcode::kCallRel32), std::uint8_t{0xE8});
        CHECK_EQ(xla::Byte(xla::Opcode::kJmpRel32), std::uint8_t{0xE9});
        CHECK_EQ(xla::JmpShort(-0x37), std::uint16_t{0xC9EB});
        CHECK_EQ(xla::JmpShort(0x0D), std::uint16_t{0x0DEB});
        CHECK_EQ(xla::Dword(kMovAl1RetNop), std::uint32_t{0x90C301B0});
        CHECK_EQ(xla::Word(kXorEaxEax), std::uint16_t{0xC033});
    }

    void TestMissingTestTailNops()
    {
        // The [v1005] 2/9 and 3/9 rows are ONE scan followed by two NOPs: the
        // 3-byte head at +0 and the 11-byte tail at +6. Re-scanning after the head
        // (the old bug) cannot match again, because the head overwrote the
        // signature; the helpers must simply compose the two writes.
        std::array<std::byte, 24> buffer{};
        buffer.fill(std::byte{0xCC});
        const xla::patch::Site site{buffer.data() + 4};
        CHECK(xla::patch::Nop(site, 0, 3, "test: v1005 head"));
        CHECK(xla::patch::Nop(site, 6, 11, "test: v1005 tail"));
        for (std::size_t index = 0; index < buffer.size(); ++index)
        {
            const bool nop = (index >= 4 && index < 7) || (index >= 10 && index < 21);
            CHECK_EQ(buffer[index], nop ? std::byte{0x90} : std::byte{0xCC});
        }
    }

    void TestShippedLauncherStages()
    {
        // The shipping path must never apply the recovered main table; it broke
        // the GFWL session in the original (see the rationale in skip_launcher.ixx).
        CHECK(!xla::HasStage(xla::kShippedStages, xla::SkipLauncherStage::main));
        CHECK(xla::HasStage(xla::kShippedStages, xla::SkipLauncherStage::dfa));
        CHECK(xla::HasStage(xla::kShippedStages, xla::SkipLauncherStage::rom));
        CHECK_EQ(static_cast<int>(xla::kShippedStages), 6);
    }

    // The exact effective init order, frozen. This list is the behavioural
    // contract of the pipeline: any insertion, removal or reordering has to be a
    // reviewed change to the registration table (and this array), not a silent
    // one.
    constexpr std::array<std::string_view, 25> kPipelineGolden{{
        "banner",           "console",        "probe",           "paths",
        "config",           "fusionfix",      "report-config",   "image",
        "writable",         "build",          "local-settings",  "savegames",
        "skip-launcher",    "borderless-hooks", "focus-loss",    "core-patches",
        "launcher-stage",   "web-connect",    "intro",           "menu",
        "do-not-pause",     "defwindow-shims", "registry",       "vram",
        "complete",
    }};

    void TestPipelineOrder()
    {
        const std::span<const std::string_view> order = xla::StepOrder();
        CHECK_EQ(order.size(), kPipelineGolden.size());
        if (order.size() != kPipelineGolden.size())
        {
            return;
        }

        for (std::size_t index = 0; index < order.size(); ++index)
        {
            if (order[index] != kPipelineGolden[index])
            {
                std::fprintf(stderr, "pipeline #%zu: expected %s, got %s\n", index,
                             std::string{kPipelineGolden[index]}.c_str(),
                             std::string{order[index]}.c_str());
                ++g_failures;
            }
        }
    }

    void TestBuildDetection()
    {
        for (const auto& entry : xla::build::kSignatures)
        {
            const auto id = xla::build::FromSignature(entry.value);
            CHECK(id.has_value());
            if (id)
            {
                CHECK_EQ(*id, entry.id);
            }
        }
        CHECK(!xla::build::FromSignature(0xDEADBEEFu).has_value());
        CHECK_EQ(xla::build::kSignatures.size(), std::size_t{13});

        std::vector<std::byte> image(xla::build::kSignatureOffset + 8);
        const std::uint32_t signature = 0x110FF300u; // 1.0.4.0
        std::memcpy(image.data() + xla::build::kSignatureOffset, &signature, sizeof(signature));

        const auto detected =
            xla::build::Detect(xla::Image{image.data(), image.size()});
        CHECK(detected.has_value());
        if (detected)
        {
            CHECK_EQ(*detected, xla::build::Id::v1040);
            CHECK_EQ(xla::build::Label(*detected), std::string{"1040"});
        }

        // A view that does not cover the signature offset is an unknown build.
        CHECK(!xla::build::Detect(xla::Image{image.data(), 16}).has_value());
        CHECK(!xla::build::Detect(xla::Image{}).has_value());

        // The raw dword is what the unsupported-build log prints.
        const auto raw = xla::build::ReadSignature(xla::Image{image.data(), image.size()});
        CHECK(raw.has_value());
        if (raw)
        {
            CHECK_EQ(*raw, signature);
        }
        CHECK(!xla::build::ReadSignature(xla::Image{image.data(), 16}).has_value());
        CHECK(!xla::build::ReadSignature(xla::Image{}).has_value());
        CHECK_EQ(xla::build::IsEflc(xla::build::Id::v1120), true);
        CHECK_EQ(xla::build::IsEflc(xla::build::Id::v1080), false);
    }

    void TestPatchPrimitives()
    {
        std::array<std::byte, 48> buffer{};
        const xla::patch::Site site{buffer.data()};

        CHECK(xla::patch::Write(site, 0, std::uint8_t{0x12}, "test: byte"));
        CHECK_EQ(buffer[0], std::byte{0x12});
        CHECK(xla::patch::Write(site, 2, std::uint16_t{0x3456}, "test: word"));
        CHECK_EQ(buffer[2], std::byte{0x56});
        CHECK_EQ(buffer[3], std::byte{0x34});

        CHECK(xla::patch::Nop(site, 8, 3, "test: nop"));
        CHECK_EQ(buffer[8], std::byte{0x90});
        CHECK_EQ(buffer[10], std::byte{0x90});

        // Ret imm16: exactly three bytes (C2 imm16), not MakeRET's four. The
        // sentinel after the instruction must survive.
        buffer[15] = std::byte{0xCC};
        CHECK(xla::patch::Ret(site, 12, 8, "test: ret 8"));
        CHECK_EQ(buffer[12], std::byte{0xC2});
        CHECK_EQ(buffer[13], std::byte{0x08});
        CHECK_EQ(buffer[14], std::byte{0x00});
        CHECK_EQ(buffer[15], std::byte{0xCC}); // 4th byte untouched

        // Ret: exactly one byte (C3); both following sentinels must survive.
        buffer[31] = std::byte{0xCC};
        buffer[32] = std::byte{0xCC};
        CHECK(xla::patch::Ret(site, 30, 0, "test: ret"));
        CHECK_EQ(buffer[30], std::byte{0xC3});
        CHECK_EQ(buffer[31], std::byte{0xCC});
        CHECK_EQ(buffer[32], std::byte{0xCC});

        // Jump: E9 + rel32 measured from the end of the instruction.
        const auto* destination = reinterpret_cast<const void*>(buffer.data() + 32);
        CHECK(xla::patch::Jump(site, 16, destination, "test: jump"));
        CHECK_EQ(buffer[16], std::byte{0xE9});
        std::int32_t displacement = 0;
        std::memcpy(&displacement, buffer.data() + 17, sizeof(displacement));
        CHECK_EQ(displacement, static_cast<std::int32_t>(
                                   reinterpret_cast<std::uintptr_t>(destination) -
                                   (reinterpret_cast<std::uintptr_t>(buffer.data()) + 16 + 5)));

        // Call: the helper reports the previously targeted function.
        auto* first = reinterpret_cast<void*>(buffer.data() + 40);
        auto* second = reinterpret_cast<void*>(buffer.data() + 44);
        CHECK_EQ(xla::patch::Call(site, 24, first, "test: call"), nullptr);
        CHECK(xla::patch::Call(site, 24, second, "test: call") == first);
        CHECK_EQ(buffer[24], std::byte{0xE8});

        // An empty site is a clean no-op.
        CHECK(!xla::patch::Write(xla::patch::Site{}, 0, std::uint8_t{1}, "test: empty"));
        CHECK(!xla::patch::Nop(xla::patch::Site{}, 0, 1, "test: empty"));
        CHECK_EQ(xla::patch::Call(xla::patch::Site{}, 0, first, "test: empty"), nullptr);
    }

    // Defined with the skip-launcher helpers below; declared here for the
    // settings-path install test.
    std::vector<std::byte> BytesOf(std::string_view signature);

    void TestCustomSettingsPathComposition()
    {
        using xla::patches::ComposeSettingsPath;

        // Relative configured path: game folder, configured part, per-profile
        // folder, trailing separator (the recovered order).
        CHECK_EQ(ComposeSettingsPath("C:\\Games\\GTA IV\\", "Saves", "GTAIV"),
                 std::string{"C:\\Games\\GTA IV\\Saves\\GTAIV\\"});
        // A game directory without a trailing separator gains one.
        CHECK_EQ(ComposeSettingsPath("C:\\Games\\GTA IV", "Saves", "GTAIV"),
                 std::string{"C:\\Games\\GTA IV\\Saves\\GTAIV\\"});
        // A configured value ending in a separator is not doubled before the
        // profile folder.
        CHECK_EQ(ComposeSettingsPath("C:\\Games\\GTA IV\\", "Saves\\", "GTAIV"),
                 std::string{"C:\\Games\\GTA IV\\Saves\\GTAIV\\"});
        // Absolute configured path: the documented intent (the original's empty
        // s.back() is undefined).
        CHECK_EQ(ComposeSettingsPath("C:\\Games\\GTA IV\\", "D:\\Saves", "GTAIV"),
                 std::string{"D:\\Saves\\GTAIV\\"});
    }

    void TestCustomSettingsPathInstall()
    {
        // The recovered four-hit pattern; matches 1 and 2 lose their `mov ecx,
        // <global>` to a 5-byte call to the assembled body, matches 0 and 3 stay.
        constexpr std::string_view signature =
            "68 ? ? ? ? B9 ? ? ? ? E8 ? ? ? ? 8D 4C 24 04 E8 ? ? ? ? 5B 83 C4 08 C3";
        const auto bytes = BytesOf(signature);
        std::vector<std::byte> image(0x800, std::byte{0});
        constexpr std::size_t kStride = 0x100;
        constexpr std::size_t kBase = 0x100;
        for (std::size_t index = 0; index < 4; ++index)
        {
            const std::size_t offset = kBase + index * kStride;
            std::copy(bytes.begin(), bytes.end(), image.begin() + offset);
            const std::uint32_t buffer = static_cast<std::uint32_t>(0x1000 + index);
            std::memcpy(image.data() + offset + 1, &buffer, sizeof(buffer));
            const std::uint32_t global = static_cast<std::uint32_t>(0x2000 + index);
            std::memcpy(image.data() + offset + 6, &global, sizeof(global));
        }

        const xla::Image view{image.data(), image.size()};
        xla::patches::InstallCustomSettingsPath(view, "Saves");

        for (std::size_t index = 0; index < 4; ++index)
        {
            const std::size_t opcode = kBase + index * kStride + 5;
            const bool patched = index == 1 || index == 2;
            CHECK_EQ(image[opcode], patched ? std::byte{0xE8} : std::byte{0xB9});
        }

        // The patched site's rel32 names the assembled body; the fixed opcodes,
        // the buffer operand, the global operand and the return are pinned.
        const std::size_t site = kBase + kStride + 5;
        std::int32_t displacement = 0;
        std::memcpy(&displacement, image.data() + site + 1, sizeof(displacement));
        const auto target = reinterpret_cast<std::uintptr_t>(image.data() + site + 5) +
                            static_cast<std::uintptr_t>(displacement);
        const auto* stub = reinterpret_cast<const std::uint8_t*>(target);
        CHECK_EQ(stub[0], std::uint8_t{0x9C}); // pushfd
        CHECK_EQ(stub[1], std::uint8_t{0x60}); // pushad
        CHECK_EQ(stub[2], std::uint8_t{0xFF}); // push [esp+0x10] (saved EBX)
        CHECK_EQ(stub[3], std::uint8_t{0x74});
        CHECK_EQ(stub[4], std::uint8_t{0x24});
        CHECK_EQ(stub[5], std::uint8_t{0x10});
        CHECK_EQ(stub[6], std::uint8_t{0x68}); // push buffer
        std::uint32_t buffer = 0;
        std::memcpy(&buffer, stub + 7, sizeof(buffer));
        CHECK_EQ(buffer, 0x1001u); // match 1's pushed settings buffer
        CHECK_EQ(stub[11], std::uint8_t{0xE8}); // call helper
        CHECK_EQ(stub[16], std::uint8_t{0x83}); // add esp, 8
        CHECK_EQ(stub[19], std::uint8_t{0xC7}); // mov [esp+0x18], global
        CHECK_EQ(stub[20], std::uint8_t{0x44});
        CHECK_EQ(stub[21], std::uint8_t{0x24});
        CHECK_EQ(stub[22], std::uint8_t{0x18});
        std::uint32_t global = 0;
        std::memcpy(&global, stub + 23, sizeof(global));
        CHECK_EQ(global, 0x2001u); // match 1's original ecx operand
        CHECK_EQ(stub[27], std::uint8_t{0x61}); // popad
        CHECK_EQ(stub[28], std::uint8_t{0x9D}); // popfd
        CHECK_EQ(stub[29], std::uint8_t{0xC3}); // ret
    }

    char* g_settingsBuffer = nullptr;
    const char* g_settingsSubfolder = nullptr;
    std::uintptr_t g_stubEbx = 0;
    std::uintptr_t g_stubEsi = 0;
    std::uintptr_t g_stubEcx = 0;
    std::uintptr_t g_stubEdx = 0;
    std::uintptr_t g_stubEax = 0;
    std::uintptr_t g_stubOutEbx = 0;
    std::uintptr_t g_stubOutEsi = 0;
    std::uintptr_t g_stubOutEcx = 0;
    std::uintptr_t g_stubOutEax = 0;
    std::uintptr_t g_stubOutEdx = 0;
    std::uint8_t g_stubOutCarry = 0;
    void* g_stubCode = nullptr;

    void __cdecl RecordSettingsCall(char* buffer, const char* subfolder)
    {
        g_settingsBuffer = buffer;
        g_settingsSubfolder = subfolder;
    }

    // Executes the exact assembled body with controlled registers: saved EBX must
    // reach the helper as the profile folder, saved ECX must become the global,
    // EBX/ESI/EDX/EAX must survive, and the carry flag must be preserved.
    extern "C" void __declspec(naked) RunSettingsStub()
    {
        __asm {
            pushad
            mov eax, dword ptr [g_stubEbx]
            mov ebx, eax
            mov eax, dword ptr [g_stubEsi]
            mov esi, eax
            mov eax, dword ptr [g_stubEcx]
            mov ecx, eax
            mov eax, dword ptr [g_stubEdx]
            mov edx, eax
            mov eax, dword ptr [g_stubEax]
            stc
            call dword ptr [g_stubCode]
            mov dword ptr [g_stubOutEbx], ebx
            mov dword ptr [g_stubOutEsi], esi
            mov dword ptr [g_stubOutEcx], ecx
            mov dword ptr [g_stubOutEax], eax
            mov dword ptr [g_stubOutEdx], edx
            setc byte ptr [g_stubOutCarry]
            popad
            ret
        }
    }

    void TestCustomSettingsPathRegisterContract()
    {
        std::array<char, 300> buffer{};
        constexpr std::uint32_t kGlobal = 0x12345678u;
        constexpr std::uintptr_t kEbx = 0x5000u; // fake profile-folder pointer
        constexpr std::uintptr_t kEsi = 0xAAAAu;
        constexpr std::uintptr_t kEcx = 0x1111u;
        constexpr std::uintptr_t kEdx = 0x2222u;
        constexpr std::uintptr_t kEax = 0x3333u;

        g_stubCode = xla::patches::MakeSettingsStub(
            static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(buffer.data())), kGlobal,
            static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(&RecordSettingsCall)));
        CHECK(g_stubCode != nullptr);
        if (g_stubCode == nullptr)
        {
            return;
        }

        g_stubEbx = kEbx;
        g_stubEsi = kEsi;
        g_stubEcx = kEcx;
        g_stubEdx = kEdx;
        g_stubEax = kEax;
        g_settingsBuffer = nullptr;
        g_settingsSubfolder = nullptr;
        g_stubOutCarry = 0;
        RunSettingsStub();

        CHECK(g_settingsBuffer == buffer.data());
        CHECK(g_settingsSubfolder == reinterpret_cast<const char*>(kEbx));
        CHECK_EQ(g_stubOutEcx, static_cast<std::uintptr_t>(kGlobal));
        CHECK_EQ(g_stubOutEsi, kEsi);
        CHECK_EQ(g_stubOutEbx, kEbx);
        CHECK_EQ(g_stubOutEax, kEax);
        CHECK_EQ(g_stubOutEdx, kEdx);
        CHECK_EQ(g_stubOutCarry, std::uint8_t{1});
    }

    void TestSavegamePaths()
    {
        CHECK_EQ(xla::savegames::BaseSavePath("C:\\Games\\GTA IV\\", ""),
                 std::string{"C:\\Games\\GTA IV\\savegames"});
        CHECK_EQ(xla::savegames::BaseSavePath("C:\\Games\\GTA IV\\", "D:\\Saves"),
                 std::string{"D:\\Saves"});
        CHECK_EQ(xla::savegames::JoinSaveName("C:\\Saves", "SGTA400"),
                 std::string{"C:\\Saves\\SGTA400"});
        CHECK_EQ(xla::savegames::JoinSaveName("C:\\Saves\\", "SGTA400"),
                 std::string{"C:\\Saves\\SGTA400"});
        CHECK_EQ(xla::savegames::JoinSaveName("C:\\Saves", ""), std::string{"C:\\Saves"});

        std::array<char, 16> text{};
        std::memcpy(text.data(), "savegames", 10);
        const xla::Image image{reinterpret_cast<std::byte*>(text.data()), text.size()};
        CHECK_EQ(xla::savegames::ReadCString(image, text.data(), text.size()),
                 std::string{"savegames"});
        CHECK_EQ(xla::savegames::ReadCString(image, text.data(), 4), std::string{"save"});
        CHECK(xla::savegames::ReadCString(image, nullptr, 4).empty());
        CHECK(xla::savegames::ReadCString(image, text.data() + text.size(), 4).empty());
    }

    void TestRegistryHelpers()
    {
        CHECK(xla::registry::IsRockstarSubKey("Software\\Rockstar Games\\GTAIV"));
        CHECK(!xla::registry::IsRockstarSubKey("Software\\Other"));
        CHECK(xla::registry::IsInstallFolderValue("InstallFolder"));
        CHECK(xla::registry::IsInstallFolderValue("InstallFolderSteam"));
        CHECK(!xla::registry::IsInstallFolderValue("InstallPath"));

        const std::string answer = xla::registry::InstallFolderAnswer();
        CHECK(!answer.empty());
        CHECK_EQ(answer.back(), '\\');
    }

    void TestUserdataFolders()
    {
        CHECK(xla::userdata::ShouldRedirect(CSIDL_APPDATA));
        CHECK(xla::userdata::ShouldRedirect(CSIDL_PERSONAL));
        CHECK(xla::userdata::ShouldRedirect(CSIDL_LOCAL_APPDATA));
        CHECK(!xla::userdata::ShouldRedirect(CSIDL_WINDOWS));
    }

    void TestWindowedGuards()
    {
        // The IAT hooks only ever run inside the real game module.
        const xla::Image foreign{reinterpret_cast<std::byte*>(0x1000), 0x1000};
        CHECK(!xla::windowed::InstallBorderlessHooks(foreign));
        CHECK(!xla::windowed::InstallFocusLossInput(foreign));
    }

    void TestRomSetStubBytes()
    {
        const auto address =
            xla::ResolveSkipHook(xla::SkipHook::rom_set, nullptr);
        CHECK(address != 0);
        if (address == 0)
        {
            return;
        }

        // mov ecx,[esi+1c]; mov [esi+20],ecx; mov al,1; ret 8
        constexpr std::array<std::uint8_t, 11> expected{
            0x8B, 0x4E, 0x1C, 0x89, 0x4E, 0x20, 0xB0, 0x01, 0xC2, 0x08, 0x00};
        CHECK(std::memcmp(reinterpret_cast<const void*>(address), expected.data(),
                          expected.size()) == 0);
    }

    // A fake CreateFileA destination: proves the hook forwards through the slot
    // the DFA stage captured.
    constexpr std::uintptr_t kStubHandle = 0x1234;
    int g_stubCalls = 0;

    HANDLE WINAPI StubCreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD,
                                  HANDLE)
    {
        ++g_stubCalls;
        return reinterpret_cast<HANDLE>(kStubHandle);
    }

    using CreateFileAFn = HANDLE(__cdecl*)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD,
                                           DWORD, HANDLE);

    CreateFileAFn CreateFileBody()
    {
        return reinterpret_cast<CreateFileAFn>(
            xla::ResolveSkipHook(xla::SkipHook::create_file, nullptr));
    }

    // Writes `signature`'s literal bytes at `offset` and rewrites the "?" bytes
    // with 0x90, which is enough for a scan (the tables only ever compare bytes).
    std::size_t WritePatternBytes(std::vector<std::byte>& image, std::size_t offset,
                                  std::span<const std::byte> signature)
    {
        std::copy(signature.begin(), signature.end(), image.begin() + offset);
        return signature.size();
    }

    std::vector<std::byte> BytesOf(std::string_view signature)
    {
        std::vector<std::byte> bytes;
        std::size_t offset = 0;
        while (offset < signature.size())
        {
            const std::size_t end = signature.find(' ', offset);
            const std::string token{
                signature.substr(offset, end == std::string_view::npos ? std::string_view::npos
                                                                      : end - offset)};
            offset = end == std::string_view::npos ? signature.size() : end + 1;
            if (token.empty())
            {
                continue;
            }
            bytes.push_back(token == "?" ? std::byte{0}
                                         : static_cast<std::byte>(
                                               std::stoul(token, nullptr, 16)));
        }
        return bytes;
    }

    void TestSkipLauncherMissingSignatures()
    {
        std::vector<std::byte> image(0x2000, std::byte{0});
        const auto result = xla::ApplySkipLauncher(image, &xla::ResolveSkipHook, nullptr,
                                                   xla::SkipLauncherStage::all);
        CHECK(result.has_value());
        if (!result)
        {
            return;
        }

        CHECK_EQ(result->entriesFound, std::size_t{0});
        CHECK_EQ(result->entriesMissing, xla::SkipLauncherEntries().size());
        CHECK_EQ(result->writes, std::size_t{0});
        CHECK_EQ(result->jumpInstalled, false);
        CHECK_EQ(result->createFileSlot, 0u);
        CHECK_EQ(result->dfaInstalls, std::size_t{0});
        CHECK_EQ(result->dfaMissing, xla::SkipLauncherDfaInstalls().size());
        CHECK_EQ(result->romInstalls, std::size_t{0});
        CHECK_EQ(result->romMissing, xla::SkipLauncherRomInstalls().size());
        CHECK_EQ(result->collectedInstalls, std::size_t{0});

        // An empty image is invalid input, not a partial install.
        const auto invalid = xla::ApplySkipLauncher({}, &xla::ResolveSkipHook, nullptr,
                                                    xla::SkipLauncherStage::all);
        CHECK(!invalid.has_value());
        if (!invalid)
        {
            CHECK_EQ(static_cast<int>(invalid.error().code),
                     static_cast<int>(xla::PatchErrorCode::invalid_input));
        }
    }

    void TestSkipLauncherTableShape()
    {
        const auto entries = xla::SkipLauncherEntries();
        CHECK_EQ(entries.size(), std::size_t{25});
        CHECK_EQ(entries[0].ops[0].offset, 34);
        CHECK_EQ(entries[0].ops[1].offset, 223);
        CHECK_EQ(entries[8].ops[0].count, static_cast<std::uint16_t>(447));
        CHECK_EQ(entries[9].ops[2].target, xla::kSkipLauncherJumpTargetEntry);
        CHECK_EQ(xla::SkipLauncherCollectors().size(), std::size_t{2});
        CHECK_EQ(xla::SkipLauncherDfaInstalls().size(), std::size_t{6});
        CHECK_EQ(xla::SkipLauncherRomInstalls().size(), std::size_t{2});
        CHECK_EQ(xla::SkipLauncherDfaCollected().size(), std::size_t{1});

        // Shape invariants independent of the byte golden: a write op must carry
        // bytes, a fill op must be a NOP fill with a count, and every jump target
        // must exist. The byte lengths are derived, so there is nothing to compare
        // against a second number.
        std::size_t patchRows = 0;
        for (const xla::EntryPatch& entry : entries)
        {
            CHECK(!entry.signature.empty());
            for (const xla::PatchOp& op : entry.ops)
            {
                ++patchRows;
                CHECK(op.offset >= 0);
                switch (op.kind)
                {
                case xla::PatchOp::Kind::write:
                    CHECK(!op.bytes.empty());
                    break;
                case xla::PatchOp::Kind::fill:
                    CHECK(op.count > 0);
                    CHECK_EQ(op.fill, xla::Byte(xla::Opcode::kNop));
                    break;
                case xla::PatchOp::Kind::jump:
                    CHECK(op.target < entries.size());
                    break;
                }
            }
        }
        CHECK_EQ(patchRows, std::size_t{32});

        for (const xla::SkipLauncherCollector& collector : xla::SkipLauncherCollectors())
        {
            CHECK(!collector.pattern.empty());
            CHECK(collector.bytes != nullptr);
            CHECK_EQ(collector.length, std::size(xla::ops::kMovAl1RetNop));
            CHECK(std::memcmp(collector.bytes, xla::ops::kMovAl1RetNop,
                              std::size(xla::ops::kMovAl1RetNop)) == 0);
        }

        const auto checkInstalls = [](std::span<const xla::SkipLauncherInstall> installs,
                                      std::size_t expected) {
            CHECK_EQ(installs.size(), expected);
            for (const xla::SkipLauncherInstall& install : installs)
            {
                CHECK(!install.signature.empty());
                CHECK(install.opcode == xla::Opcode::kCallRel32 ||
                      install.opcode == xla::Opcode::kJmpRel32);
            }
        };
        checkInstalls(xla::SkipLauncherDfaInstalls(), 6);
        checkInstalls(xla::SkipLauncherRomInstalls(), 2);

        const auto collected = xla::SkipLauncherDfaCollected()[0];
        CHECK(collected.targets != nullptr);
        CHECK_EQ(collected.targetCount, std::size_t{2});
        for (std::size_t index = 0; index < collected.targetCount; ++index)
        {
            CHECK(!collected.targets[index].targetSignature.empty());
            CHECK(collected.targets[index].index < 2);
        }
    }

    void TestShippedLauncherDoesNotApplyMain()
    {
        // The shipping path must never apply the recovered main table (it broke
        // the GFWL session in the original). Seed an image with entry 0's
        // signature; a main pass would write +34, the shipped stages must not.
        const auto signature = BytesOf(xla::SkipLauncherEntries()[0].signature);
        std::vector<std::byte> image(0x1000, std::byte{0});
        const std::size_t offset = 0x100;
        std::copy(signature.begin(), signature.end(), image.begin() + offset);

        const auto result =
            xla::ApplySkipLauncher(image, &xla::ResolveSkipHook, nullptr, xla::kShippedStages);
        CHECK(result.has_value());
        if (!result)
        {
            return;
        }
        CHECK_EQ(result->entriesFound, std::size_t{0});
        // entriesMissing is intentionally not asserted: it is only incremented by
        // the main stage, so it is 0 by construction here and would prove nothing.
        CHECK_EQ(result->writes, std::size_t{0});
        CHECK_EQ(result->jumpInstalled, false);
        CHECK_EQ(image[offset + 34], std::byte{0});
        CHECK_EQ(result->dfaInstalls, std::size_t{0});
        CHECK_EQ(result->dfaMissing, xla::SkipLauncherDfaInstalls().size());
        CHECK_EQ(result->romInstalls, std::size_t{0});
        CHECK_EQ(result->romMissing, xla::SkipLauncherRomInstalls().size());
    }

    void TestSkipLauncherBounds()
    {
        // Entry 0 matches the last 14 bytes of the image, so its +34 write is out of
        // bounds and the pass must fail instead of writing past the view.
        const auto signature = BytesOf(xla::SkipLauncherEntries()[0].signature);
        std::vector<std::byte> image(0x100, std::byte{0});
        WritePatternBytes(image, image.size() - signature.size(), signature);

        const auto result = xla::ApplySkipLauncher(image, &xla::ResolveSkipHook, nullptr,
                                                   xla::SkipLauncherStage::main);
        CHECK(!result.has_value());
        if (!result)
        {
            CHECK_EQ(static_cast<int>(result.error().code),
                     static_cast<int>(xla::PatchErrorCode::out_of_bounds));
        }
    }

    void TestSkipLauncherAppliesMainRows()
    {
        const auto signature = BytesOf(xla::SkipLauncherEntries()[0].signature);
        std::vector<std::byte> image(0x1000, std::byte{0});
        const std::size_t offset = 0x100;
        WritePatternBytes(image, offset, signature);

        const auto result = xla::ApplySkipLauncher(image, &xla::ResolveSkipHook, nullptr,
                                                   xla::SkipLauncherStage::main);
        CHECK(result.has_value());
        if (!result)
        {
            return;
        }
        CHECK_EQ(result->entriesFound, std::size_t{1});
        CHECK_EQ(result->writes, std::size_t{2});
        // Entry 0's write at +34 is outside its 14-byte signature (the signature's
        // own `0F 85` is at +2); the table writes one `EB` byte at that hook site.
        CHECK_EQ(image[offset + 34], std::byte{0xEB});
    }

    void TestSkipLauncherCreateFileSlot()
    {
        // A slot holds the function the game's import table resolved (or a detour
        // another ASI installed). The body must call through it.
        std::uintptr_t slotValue = reinterpret_cast<std::uintptr_t>(&StubCreateFileA);
        std::vector<std::byte> image(0x1000, std::byte{0});

        const auto capture = BytesOf("FF 15 ? ? ? ? 8B F0 83 FE FF 74 24");
        const std::size_t captureOffset = 0x100;
        std::copy(capture.begin(), capture.end(), image.begin() + captureOffset);
        const auto slotVa = static_cast<std::uint32_t>(
            reinterpret_cast<std::uintptr_t>(&slotValue));
        std::memcpy(image.data() + captureOffset + 2, &slotVa, sizeof(slotVa));

        const auto createFile = BytesOf("55 8B EC 6A 00 E8");
        std::copy(createFile.begin(), createFile.end(), image.begin() + 0x200);

        const auto result = xla::ApplySkipLauncher(image, &xla::ResolveSkipHook, nullptr,
                                                   xla::SkipLauncherStage::dfa);
        CHECK(result.has_value());
        if (!result)
        {
            return;
        }
        CHECK_EQ(result->createFileSlot, slotVa);
        CHECK(result->dfaInstalls >= 1);

        const CreateFileAFn body = CreateFileBody();
        CHECK(body != nullptr);
        g_stubCalls = 0;
        const HANDLE forwarded = body("xla-slot-test", 0, 0, nullptr, 0, 0, nullptr);
        CHECK(forwarded == reinterpret_cast<HANDLE>(kStubHandle));
        CHECK_EQ(g_stubCalls, 1);

        // A later pass whose image has no capture clears the slot instead of leaving
        // the previous image's slot behind.
        std::vector<std::byte> plain(0x100, std::byte{0});
        const auto cleared = xla::ApplySkipLauncher(plain, &xla::ResolveSkipHook, nullptr,
                                                     xla::SkipLauncherStage::dfa);
        CHECK(cleared.has_value());
        if (cleared)
        {
            CHECK_EQ(cleared->createFileSlot, 0u);
        }

        const HANDLE direct = body("NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                   nullptr, OPEN_EXISTING, 0, nullptr);
        CHECK(direct != INVALID_HANDLE_VALUE);
        if (direct != INVALID_HANDLE_VALUE)
        {
            ::CloseHandle(direct);
        }
        CHECK_EQ(g_stubCalls, 1); // the stub was not used again
    }
} // namespace

int main(int argc, char** argv)
{
    std::printf("XLivelessAddon %s (%s)\n", std::string{xla::kVersion}.c_str(),
                std::string{xla::kGitSha}.c_str());

    g_workDirectory = argc > 2 ? std::filesystem::absolute(std::filesystem::path{argv[2]})
                               : std::filesystem::current_path() / "xla-test-work";
    std::error_code error;
    std::filesystem::create_directories(g_workDirectory, error);
    if (!std::filesystem::exists(g_workDirectory))
    {
        std::fprintf(stderr, "cannot create the test work directory %s\n",
                     g_workDirectory.string().c_str());
        return 2;
    }

    // Keep the module log inside the work directory instead of next to the test exe.
    xla::log::SetPath(g_workDirectory / "xla_tests.log");

    // Each case is named before it runs, so a crash points at the last line.
    const auto run = [&](const char* name, const auto& test) {
        std::printf("-- %s\n", name);
        std::fflush(stdout);
        test();
    };

    if (argc > 1)
    {
        run("default ini matches the shipped file",
            [&] { TestDefaultIniMatchesShippedFile(argv[1]); });
    }
    else
    {
        // Do not silently drop a test when the suite is run by hand.
        std::printf("-- default ini matches the shipped file: SKIPPED (no data directory "
                    "argument; run via ctest)\n");
    }
    run("config precedence and FusionFix gates", TestConfigPrecedenceAndGates);
    run("config defaults and EnsureIni", TestConfigDefaultsAndEnsureIni);
    run("config flag grammar", TestConfigFlagGrammar);
    run("config option table", TestConfigOptionTable);
    run("config section order and duplicates", TestConfigSectionOrderAndDuplicates);
    run("config whitespace, comments and quotes", TestConfigWhitespaceCommentsQuotes);
    run("config line endings", TestConfigLineEndings);
    run("opcode catalogue", TestOpcodeCatalogue);
    run("missing-test tail NOPs", TestMissingTestTailNops);
    run("shipped launcher stages", TestShippedLauncherStages);
    run("pipeline order", TestPipelineOrder);
    run("build detection", TestBuildDetection);
    run("patch primitives", TestPatchPrimitives);
    run("custom settings path composition", TestCustomSettingsPathComposition);
    run("custom settings path install", TestCustomSettingsPathInstall);
    run("custom settings path register contract", TestCustomSettingsPathRegisterContract);
    run("savegame paths", TestSavegamePaths);
    run("registry helpers", TestRegistryHelpers);
    run("user data folders", TestUserdataFolders);
    run("windowed guards", TestWindowedGuards);
    run("RomSet stub bytes", TestRomSetStubBytes);
    run("skip launcher table shape", TestSkipLauncherTableShape);
    run("skip launcher shipped stages", TestShippedLauncherDoesNotApplyMain);
    run("skip launcher missing signatures", TestSkipLauncherMissingSignatures);
    run("skip launcher bounds", TestSkipLauncherBounds);
    run("skip launcher main rows", TestSkipLauncherAppliesMainRows);
    run("skip launcher create-file slot", TestSkipLauncherCreateFileSlot);

    if (g_failures != 0)
    {
        std::fprintf(stderr, "xla tests: %d failure(s)\n", g_failures);
        return 1;
    }

    std::printf("xla tests: PASS\n");
    return 0;
}
