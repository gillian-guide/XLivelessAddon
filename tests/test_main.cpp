// SPDX-License-Identifier: GPL-3.0-or-later
//
// The native suite: no game needed. One executable, no framework; a check prints
// PASS/FAIL and the process exits non-zero if anything failed.
//
// The suite pins the INI grammar/precedence, the build table, the installer
// primitives and their widths, the recovered SkipLauncher tables and pass, the
// LaunchWithPlayGTAIV slot table and its write/refusal/gate rules, the
// SavegameFix call retargets and bodies, the frontend pair's FusionFix mechanism
// (the intro stub's register contract and the menu body), the VRAMFix call
// retargets and clamp, the SkipWebConnect section, the
// [USERPROFILE] CustomUserProfilePath resolution and shell redirect, the savegame
// CRC32 bypass, the IAT replacement, the startup order and the deliberate
// user-data divergence from the old addon.

#include <common.hxx>
#include <cstdio>

import common;
import patch;
import build;
import config;
import warnings;
import probe;
import savegames;
import registry;
import profile;
import core;
import launcher;
import menu;
import vram;
import windowed;
import startup;

namespace
{
    int failures = 0;
    int checks = 0;

    void Check(bool condition, std::string_view what, std::string_view detail = {})
    {
        ++checks;
        if (condition)
        {
            std::printf("PASS %.*s\n", static_cast<int>(what.size()), what.data());
            return;
        }
        ++failures;
        std::printf("FAIL %.*s", static_cast<int>(what.size()), what.data());
        if (!detail.empty())
        {
            std::printf(" (%s)", std::string(detail).c_str());
        }
        std::printf("\n");
    }

    template <typename T>
    std::string ToString(const T& value)
    {
        if constexpr (std::is_same_v<T, std::filesystem::path>)
        {
            return value.string();
        }
        else
        {
            return std::format("{}", value);
        }
    }

    std::string ReadFile(const std::filesystem::path& path)
    {
        std::ifstream stream(path, std::ios::binary);
        return std::string(std::istreambuf_iterator<char>(stream),
                           std::istreambuf_iterator<char>());
    }

    void WriteFile(const std::filesystem::path& path, std::string_view text)
    {
        std::filesystem::create_directories(path.parent_path());
        std::ofstream stream(path, std::ios::binary | std::ios::trunc);
        stream.write(text.data(), static_cast<std::streamsize>(text.size()));
    }

    class TempDir
    {
    public:
        explicit TempDir(std::string_view name)
            : path(std::filesystem::current_path() /
                   std::format("{}-{}", name, GetCurrentProcessId()))
        {
            std::error_code ignored;
            std::filesystem::remove_all(path, ignored);
            std::filesystem::create_directories(path, ignored);
        }

        ~TempDir()
        {
            std::error_code ignored;
            std::filesystem::remove_all(path, ignored);
        }

        TempDir(const TempDir&) = delete;
        TempDir& operator=(const TempDir&) = delete;

        const std::filesystem::path& Path() const { return path; }
        std::filesystem::path operator/(std::string_view name) const
        {
            return path / std::string(name);
        }

    private:
        std::filesystem::path path;
    };

    // Convert a signature string into bytes for a synthetic image; a wildcard
    // becomes a NOP, which is irrelevant to the scanner's mask.
    std::vector<std::uint8_t> BytesOf(std::string_view signature)
    {
        std::vector<std::uint8_t> bytes;
        std::size_t index = 0;
        while (index < signature.size())
        {
            while (index < signature.size() && signature[index] == ' ')
            {
                ++index;
            }
            if (index >= signature.size())
            {
                break;
            }
            if (signature[index] == '?')
            {
                bytes.push_back(0x90);
                ++index;
                continue;
            }
            const auto hex = [](char character) -> std::uint8_t
            {
                if (character >= '0' && character <= '9')
                {
                    return static_cast<std::uint8_t>(character - '0');
                }
                if (character >= 'A' && character <= 'F')
                {
                    return static_cast<std::uint8_t>(character - 'A' + 10);
                }
                return static_cast<std::uint8_t>(character - 'a' + 10);
            };
            const std::uint8_t value = static_cast<std::uint8_t>(
                (hex(signature[index]) << 4) | hex(signature[index + 1]));
            bytes.push_back(value);
            index += 2;
        }
        return bytes;
    }

    void WriteBytes(std::vector<std::byte>& image, std::size_t offset,
                    const std::vector<std::uint8_t>& bytes)
    {
        std::memcpy(image.data() + offset, bytes.data(), bytes.size());
    }

    void WriteDword(std::vector<std::byte>& image, std::size_t offset, std::uint32_t value)
    {
        std::memcpy(image.data() + offset, &value, sizeof(value));
    }

    // The destination a 5-byte `E8 rel32` at `site` encodes.
    std::uintptr_t CallTarget(const std::vector<std::byte>& image, std::size_t site)
    {
        std::int32_t displacement = 0;
        std::memcpy(&displacement, image.data() + site + 1, sizeof(displacement));
        return reinterpret_cast<std::uintptr_t>(image.data()) + site + 5 +
               static_cast<std::uintptr_t>(static_cast<std::intptr_t>(displacement));
    }

    // The destination a 5-byte `E9 rel32` at `site` encodes.
    std::uintptr_t JumpTarget(const std::vector<std::byte>& image, std::size_t site)
    {
        std::int32_t displacement = 0;
        std::memcpy(&displacement, image.data() + site + 1, sizeof(displacement));
        return reinterpret_cast<std::uintptr_t>(image.data()) + site + 5 +
               static_cast<std::uintptr_t>(static_cast<std::intptr_t>(displacement));
    }

    // Points the `E8 rel32` at `site` at `destination`, so a synthetic image can
    // name the function its call had before the arm retargets it.
    void SetCallTarget(std::vector<std::byte>& image, std::size_t site,
                       std::uintptr_t destination)
    {
        const auto displacement = static_cast<std::int32_t>(
            destination - (reinterpret_cast<std::uintptr_t>(image.data()) + site + 5));
        std::memcpy(image.data() + site + 1, &displacement, sizeof(displacement));
    }

    std::uint32_t DwordAt(const void* bytes, std::size_t at)
    {
        std::uint32_t value = 0;
        std::memcpy(&value, static_cast<const std::uint8_t*>(bytes) + at, sizeof(value));
        return value;
    }

    // True when every byte that differs between `after` and `before` lies inside
    // one of the `[offset, offset + length)` spans: the "exact write set" check.
    bool OnlyChangedWithin(const std::vector<std::byte>& after,
                           const std::vector<std::byte>& before,
                           std::span<const std::pair<std::size_t, std::size_t>> spans)
    {
        if (after.size() != before.size())
        {
            return false;
        }
        for (std::size_t index = 0; index < after.size(); ++index)
        {
            if (after[index] == before[index])
            {
                continue;
            }
            bool allowed = false;
            for (const auto& [offset, length] : spans)
            {
                allowed = allowed || (index >= offset && index < offset + length);
            }
            if (!allowed)
            {
                return false;
            }
        }
        return true;
    }

    // A minimal PE32 image with an import table: enough for patch::ReplaceImports
    // (and therefore the registry/userdata/windowed hooks) to walk.
    struct SyntheticModule
    {
        std::vector<std::uint8_t> image;
        std::size_t count{};

        explicit SyntheticModule(std::string_view library) : image(0x4000, 0)
        {
            const auto base = reinterpret_cast<std::uintptr_t>(image.data());
            auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
            dos->e_magic = IMAGE_DOS_SIGNATURE;
            dos->e_lfanew = 0x40;

            auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
            nt->Signature = IMAGE_NT_SIGNATURE;
            nt->FileHeader.Machine = IMAGE_FILE_MACHINE_I386;
            nt->FileHeader.NumberOfSections = 1;
            nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
            nt->OptionalHeader.NumberOfRvaAndSizes = 16;
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress =
                0x200;

            std::memcpy(image.data() + 0x300, library.data(), library.size());
            auto* descriptor =
                reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(image.data() + 0x200);
            descriptor->Name = 0x300;
            descriptor->OriginalFirstThunk = 0x400;
            descriptor->FirstThunk = 0x500;
        }

        void Add(std::string_view name)
        {
            auto* thunks = reinterpret_cast<IMAGE_THUNK_DATA*>(image.data() + 0x400);
            auto* iat = reinterpret_cast<IMAGE_THUNK_DATA*>(image.data() + 0x500);
            const std::size_t hintAt = 0x600 + count * 0x40;
            std::memcpy(image.data() + hintAt + 2, name.data(), name.size());
            thunks[count].u1.AddressOfData = static_cast<std::uint32_t>(hintAt);
            iat[count].u1.Function = 0xDEAD0000u + count;
            ++count;
        }

        HMODULE Handle() { return reinterpret_cast<HMODULE>(image.data()); }

        void* Slot(std::size_t index)
        {
            auto* iat = reinterpret_cast<IMAGE_THUNK_DATA*>(image.data() + 0x500);
            return reinterpret_cast<void*>(iat[index].u1.Function);
        }
    };

    void TestEvents()
    {
        xla::FusionFix::Event<> event;
        std::string order;
        auto first = event += [&] { order += 'A'; };
        event += [&] { order += 'B'; };
        event.executeAll();
        Check(order == "AB", "event: handlers run in subscription order", order);
        first();
        order.clear();
        event.executeAll();
        Check(order == "B", "event: the returned token unsubscribes its handler", order);

        xla::FusionFix::Event<> nested;
        int runs = 0;
        nested += [&]
        {
            ++runs;
            if (runs == 1)
            {
                nested += [&] { ++runs; };
            }
        };
        nested.executeAll();
        Check(runs == 1, "event: a handler subscribed mid-dispatch waits for the next dispatch");
        nested.executeAll();
        Check(runs == 3, "event: ... and then runs", std::to_string(runs));

        xla::FusionFix::Event<bool> flag;
        int trues = 0;
        int falses = 0;
        flag += [&](bool value) { value ? ++trues : ++falses; };
        flag.executeAll(true);
        flag.executeAll(false);
        Check(trues == 1 && falses == 1, "event: arguments reach every handler");

        std::atomic<int> completed{0};
        xla::FusionFix::Event<> asynchronous;
        asynchronous += [&] { ++completed; };
        asynchronous += [&] { ++completed; };
        for (auto& future : asynchronous.executeAllAsync())
        {
            future.wait();
        }
        Check(completed == 2, "event: executeAllAsync runs every handler");

        Check(&xla::FusionFix::onInitEvent() == &xla::FusionFix::onInitEvent(),
              "event: a tier is one instance");
        Check(&xla::FusionFix::onInitEvent() != &xla::FusionFix::onGameProcessEvent(),
              "event: tiers are distinct");
    }

    void TestConfigGrammar()
    {
        Check(xla::config::ParseFlag("1"), "config: 1 enables");
        Check(!xla::config::ParseFlag("0"), "config: 0 disables");
        Check(xla::config::ParseFlag("2"), "config: 2 enables (atoi grammar)");
        Check(xla::config::ParseFlag(" -1"), "config: -1 enables (atoi grammar)");
        Check(!xla::config::ParseFlag(""), "config: an empty value disables");
        Check(!xla::config::ParseFlag("yes"), "config: a non-numeric value disables");
        Check(xla::config::ParseFlag("1 trailing"), "config: the integer prefix decides");
    }

    void TestConfigDefaultsAndIni(const std::filesystem::path& shippedIni)
    {
        Check(xla::config::DefaultIniText() == ReadFile(shippedIni),
              "config: the built-in default text matches data/XLivelessAddon.ini");

        TempDir work("xla-config-defaults");
        // An existing but empty INI isolates the *code* defaults from the shipped
        // file's explicit enables.
        WriteFile(work / "XLivelessAddon.ini", "[Options]\n");
        xla::config::Publish(xla::config::Load(work.Path()));
        const auto& game = xla::Game::Get();
        Check(game.Option("SkipLauncher"), "config: SkipLauncher defaults on");
        Check(game.Option("LegacyLauncher"), "config: LegacyLauncher defaults on");
        Check(game.Option("LaunchWithPlayGTAIV"),
              "config: LaunchWithPlayGTAIV defaults on");
        Check(game.Option("SavegameFix"), "config: SavegameFix defaults on");
        Check(game.Option("RemoveRegistryPathDependency"),
              "config: RemoveRegistryPathDependency defaults on");
        Check(!game.Option("BorderlessWindowed"), "config: BorderlessWindowed code default is off");
        Check(!game.Option("DoNotPauseOnMinimize"),
              "config: DoNotPauseOnMinimize code default is off");
        Check(game.Option("StartupWarnings"), "config: StartupWarnings defaults on");
        Check(xla::Game::Get().OptionString("CustomUserProfilePath").empty(),
              "config: CustomUserProfilePath code default is empty (feature off)");
        Check(game.Option("RemoveDataIntegrityChecks") && game.Option("SkipTokenActivation") &&
                  game.Option("SkipFirstTimePlayAsk") &&
                  game.Option("SkipInternetConnectionCheck") && game.Option("SkipHealthCheck"),
              "config: the five core fixes default on");
        Check(game.Option("SkipWebConnect"), "config: SkipWebConnect defaults on");
        Check(game.Option("SkipIntro"), "config: SkipIntro defaults on");
        Check(!game.Option("SkipMenu"), "config: SkipMenu defaults off");
        Check(game.Option("VRAMFix"), "config: VRAMFix defaults on");

        TempDir missing("xla-config-missing");
        (void)xla::config::Load(missing.Path());
        Check(std::filesystem::exists(missing / "XLivelessAddon.ini"),
              "config: a missing INI is created");
    }

    void TestConfigPrecedenceAndLegacy()
    {
        TempDir work("xla-config-precedence");
        WriteFile(work / "XLivelessAddon.ini",
                  "[Options]\nSkipLauncher=0\nSavegameFix=0\n"
                  "[USERPROFILE]\nCustomUserProfilePath=D:\\Saves\n"
                  "BorderlessWindowed=1\n");
        WriteFile(work / "ZolikaPatch.ini", "[MAIN]\nSkipLauncher=1\n");

        auto loaded = xla::config::Load(work.Path(), work.Path());
        Check(!loaded.options.skipLauncher, "config: the add-on's own INI wins over the legacy one");
        Check(!loaded.options.savegameFix, "config: a present key is read");
        Check(loaded.options.customUserProfilePath == "D:\\Saves",
              "config: the USERPROFILE section is searched");
        Check(loaded.legacyPresent, "config: the legacy INI is found next to the ASI");

        // The section list order is the precedence: MAIN is searched before Options.
        WriteFile(work / "XLivelessAddon.ini",
                  "[Options]\nSkipLauncher=0\n[MAIN]\nSkipLauncher=1\n");
        loaded = xla::config::Load(work.Path(), work.Path());
        Check(loaded.options.skipLauncher, "config: MAIN precedes Options");

        // A key absent from the own file falls back to the legacy file.
        WriteFile(work / "XLivelessAddon.ini", "[Options]\n");
        WriteFile(work / "ZolikaPatch.ini", "[LOADING]\nSkipLauncher=0\n");
        loaded = xla::config::Load(work.Path(), work.Path());
        Check(!loaded.options.skipLauncher, "config: an absent key falls back to the legacy INI");
    }

    void TestConfigLegacySearch()
    {
        TempDir work("xla-config-legacy");
        const auto game = work / "game";
        const auto asi = work / "asi";
        std::filesystem::create_directories(game / "plugins");
        std::filesystem::create_directories(asi);
        WriteFile(game / "plugins" / "ZolikaPatch.ini", "[MAIN]\nSkipLauncher=0\n");
        Check(xla::config::FindLegacyIni(asi, game) == game / "plugins" / "ZolikaPatch.ini",
              "config: the legacy INI is found in the plugins folder");
    }

    void TestConfigWhitespaceCommentsQuotes()
    {
        TempDir work("xla-config-whitespace");
        WriteFile(work / "XLivelessAddon.ini",
                  "; comment\n[Options]\n  SkipLauncher = 0   ; trailing\n"
                  "[USERPROFILE]\nCustomUserProfilePath = \"D:\\Saves With Spaces\"\n");
        const auto loaded = xla::config::Load(work.Path(), work.Path());
        Check(!loaded.options.skipLauncher, "config: whitespace and a trailing comment are ignored");
        Check(loaded.options.customUserProfilePath == "D:\\Saves With Spaces",
              "config: quotes are stripped from a string value");
    }

    void TestConfigLineEndings()
    {
        TempDir work("xla-config-lines");
        const auto ini = work / "XLivelessAddon.ini";
        WriteFile(ini, "[Options]\nSkipLauncher=1\n");
        (void)xla::config::Load(work.Path(), work.Path());
        const auto text = ReadFile(ini);
        Check(text.find("\r\n") != std::string::npos, "config: a bare-LF INI is normalized to CRLF");
    }

    void TestFusionFixPresenceAndDivergence()
    {
        TempDir work("xla-config-divergence");
        WriteFile(work / "XLivelessAddon.ini",
                  "[USERPROFILE]\nCustomUserProfilePath=D:\\Saves\n"
                  "BorderlessWindowed=1\n"
                  "DoNotPauseOnMinimize=1\n"
                  "SkipMenu=1\n"
                  "VRAMFix=1\n"
                  "SkipWebConnect=1\n");

        // No FusionFix in the process or next to the ASI.
        Check(!xla::config::FusionFixPresent(work.Path()),
              "divergence: FusionFix is absent in the temp install");

        auto loaded = xla::config::Load(work.Path(), work.Path());
        Check(loaded.options.customUserProfilePath == "D:\\Saves",
              "divergence: CustomUserProfilePath works with FusionFix absent");
        Check(loaded.options.borderlessWindowed,
              "divergence: windowed stays on when FusionFix is absent");
        xla::config::Publish(loaded);
        Check(xla::Game::Get().OptionString("CustomUserProfilePath") == "D:\\Saves",
              "divergence: the Game context carries the profile path with FusionFix absent");

        // A FusionFix ASI next to this one is detected; the profile redirect must
        // still survive, and only the frontend pair and the windowed options are
        // gated.
        WriteFile(work / "GTAIV.EFLC.FusionFix.asi", "");
        Check(xla::config::FusionFixPresent(work.Path()),
              "divergence: a FusionFix ASI next to the module is detected");

        loaded = xla::config::Load(work.Path(), work.Path());
        const auto gated = xla::config::ApplyFusionFixGates(loaded.options);
        Check(gated.size() == 4,
              "divergence: the FusionFix gate covers the frontend pair and the windowed options",
              std::to_string(gated.size()));
        bool frontendGated = false;
        bool ownershipLabelled = true;
        for (const auto& gate : gated)
        {
            if (gate.option == "SkipIntro" || gate.option == "SkipMenu")
            {
                frontendGated = true;
                ownershipLabelled = ownershipLabelled && gate.fusionFixModule == "skipintro.ixx";
            }
        }
        Check(frontendGated && ownershipLabelled,
              "divergence: SkipIntro/SkipMenu are gated for FusionFix's skipintro.ixx");
        Check(loaded.options.customUserProfilePath == "D:\\Saves",
              "divergence: CustomUserProfilePath survives with FusionFix present");
        Check(!loaded.options.borderlessWindowed && !loaded.options.doNotPauseOnMinimize,
              "divergence: the windowed options are gated when FusionFix is present");
        Check(loaded.options.vramFix && loaded.options.skipWebConnect,
              "divergence: VRAMFix and SkipWebConnect are never FusionFix-gated");
        xla::config::Publish(loaded);
        Check(xla::Game::Get().OptionString("CustomUserProfilePath") == "D:\\Saves",
              "divergence: the profile path is still published after the gate");
    }

    void TestAllOff()
    {
        TempDir work("xla-all-off");
        WriteFile(work / "XLivelessAddon.ini",
                  "[Options]\nSavegameFix=0\nSkipLauncher=0\nLegacyLauncher=0\n"
                  "LaunchWithPlayGTAIV=0\n"
                  "RemoveRegistryPathDependency=0\nDoNotPauseOnMinimize=0\n"
                  "BorderlessWindowed=0\nStartupWarnings=0\n"
                  "RemoveDataIntegrityChecks=0\nSkipTokenActivation=0\n"
                  "SkipFirstTimePlayAsk=0\nSkipInternetConnectionCheck=0\n"
                  "SkipHealthCheck=0\nSkipWebConnect=0\n"
                  "SkipIntro=0\nSkipMenu=0\nVRAMFix=0\n"
                  "[USERPROFILE]\nCustomUserProfilePath=\n");
        auto loaded = xla::config::Load(work.Path(), work.Path());
        xla::config::Publish(loaded);
        Check(!loaded.options.legacyLauncher && !loaded.options.startupWarnings,
              "all-off: the new toggles are read");
        Check(!loaded.options.skipWebConnect && !loaded.options.skipIntro &&
                  !loaded.options.skipMenu && !loaded.options.vramFix,
              "all-off: the four restored keys are read");
        Check(!xla::startup::AnyInstallEnabled(),
              "all-off: no install is enabled");

        auto& game = xla::Game::Get();
        const auto flip = [&](const char* key)
        {
            game.SetOption(key, "1");
            Check(xla::startup::AnyInstallEnabled(),
                  std::format("all-off: {} alone enables an install", key));
            game.SetOption(key, "0");
        };
        flip("SavegameFix");
        flip("SkipLauncher");
        flip("LegacyLauncher"); // SkipLauncher is 0 here
        flip("LaunchWithPlayGTAIV");
        flip("RemoveRegistryPathDependency");
        flip("RemoveDataIntegrityChecks");
        flip("SkipTokenActivation");
        flip("SkipFirstTimePlayAsk");
        // The family's master switch: it installs through one of the two
        // fine-grained keys, which this all-off file turns off too.
        game.SetOption("SkipInternetConnectionCheck", "1");
        flip("SkipWebConnect");
        game.SetOption("SkipInternetConnectionCheck", "0");
        flip("SkipIntro");
        flip("SkipMenu");
        flip("VRAMFix");
        flip("BorderlessWindowed");
        flip("DoNotPauseOnMinimize");

        // The two fine-grained GFWL keys install through SkipWebConnect; with the
        // master off they are inert, with it on each one enables the family.
        game.SetOption("SkipWebConnect", "1");
        flip("SkipInternetConnectionCheck");
        flip("SkipHealthCheck");
        game.SetOption("SkipWebConnect", "0");
        Check(!xla::startup::AnyInstallEnabled(),
              "all-off: the fine-grained GFWL keys are inert without SkipWebConnect");

        game.SetOption("CustomUserProfilePath", "D:\\Saves");
        Check(xla::startup::AnyInstallEnabled(),
              "all-off: a non-empty CustomUserProfilePath enables its install");
        game.SetOption("CustomUserProfilePath", "");

        // Values, not installs on their own.
        game.SetOption("StartupWarnings", "1");
        Check(!xla::startup::AnyInstallEnabled(),
              "all-off: StartupWarnings alone is not an install");
        game.SetOption("StartupWarnings", "0");
    }

    void TestBuild()
    {
        std::vector<std::byte> image(0x210000, std::byte{0});
        const auto view = xla::Image{image.data(), image.size()};
        Check(!xla::build::Detect(view).has_value(), "build: a zero dword is unknown");
        const std::uint32_t value = 0x404B100Fu;
        std::memcpy(image.data() + xla::build::kSignatureOffset, &value, sizeof(value));
        const auto detected = xla::build::Detect(view);
        Check(detected.has_value() && *detected == xla::GameBuild::v1080,
              "build: 0x404B100F is 1.0.8.0");
        Check(xla::BuildLabel(xla::GameBuild::v1080) == "1080",
              "build: the label is the compact id");
        Check(xla::IsEflc(xla::GameBuild::v1110) && !xla::IsEflc(xla::GameBuild::v1080),
              "build: EFLC ids are recognised");
        Check(!xla::build::Detect(xla::Image{image.data(), 16}).has_value(),
              "build: a short image is unknown, not a fault");
        Check(!xla::build::ReadSignature(xla::Image{}).has_value(),
              "build: an empty image has no signature");
    }

    void TestPatchPrimitives()
    {
        auto* memory = static_cast<std::uint8_t*>(
            VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        if (memory == nullptr)
        {
            Check(false, "patch: the synthetic image was allocated");
            return;
        }
        std::memset(memory, 0xCC, 0x1000);

        const xla::Image image{reinterpret_cast<std::byte*>(memory), 0x1000};
        const xla::patch::Site site{memory + 0x100};
        const xla::patch::Site baseSite{memory};
        Check(xla::patch::Write(site, 0, std::uint8_t{0x12}, "test"),
              "patch: a byte store applies");
        Check(memory[0x100] == 0x12, "patch: the byte landed");
        Check(xla::patch::Write(site, 2, std::uint16_t{0x3456}, "test"),
              "patch: a word store applies");
        Check(memory[0x102] == 0x56 && memory[0x103] == 0x34,
              "patch: the word is little-endian");

        Check(xla::patch::Nop(baseSite, 0x108, 3, "test"), "patch: a NOP run applies");
        Check(memory[0x108] == 0x90 && memory[0x10A] == 0x90, "patch: the NOPs landed");

        Check(xla::patch::Ret(baseSite, 0x120, 8, "test"), "patch: ret 8 applies");
        Check(memory[0x120] == 0xC2 && memory[0x121] == 0x08 && memory[0x122] == 0x00,
              "patch: ret 8 is C2 08 00 (three bytes)");
        Check(memory[0x123] == 0xCC, "patch: ret 8 does not write a fourth byte");

        Check(xla::patch::Ret(baseSite, 0x130, 0, "test"), "patch: ret applies");
        Check(memory[0x130] == 0xC3 && memory[0x131] == 0xCC,
              "patch: ret is C3 only (one byte)");

        Check(xla::patch::Jump(baseSite, 0x140, memory + 0x500, "test"),
              "patch: a jump applies");
        Check(memory[0x140] == 0xE9, "patch: the jump opcode is E9");
        Check(xla::patch::Call(baseSite, 0x150, memory + 0x500, "test") == nullptr,
              "patch: a call at a non-branch site has no previous destination");
        Check(memory[0x150] == 0xE8, "patch: the call opcode is E8");

        Check(xla::patch::WriteRaw(baseSite, 0x160,
                                   std::array<std::uint8_t, 2>{0xEB, 0x00}, "test"),
              "patch: a raw window applies");
        Check(memory[0x160] == 0xEB && memory[0x161] == 0x00, "patch: the raw window landed");
        Check(!xla::patch::WriteRaw(baseSite, 0x160, std::span<const std::uint8_t>{}, "test"),
              "patch: an empty raw window is refused");
        Check(!xla::patch::Write(xla::patch::Site{}, 0, std::uint8_t{1}, "test"),
              "patch: an empty site is refused");
        Check(!xla::patch::WriteRawAt(image, memory + 0xFFF,
                                      std::array<std::uint8_t, 2>{0xEB, 0x00}, "test"),
              "patch: a store past the image is refused");

        VirtualFree(memory, 0, MEM_RELEASE);
    }

    void TestPatchScan()
    {
        auto* memory = static_cast<std::uint8_t*>(
            VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        if (memory == nullptr)
        {
            Check(false, "patch: the scan image was allocated");
            return;
        }
        std::memset(memory, 0xCC, 0x1000);
        const std::uint8_t site[] = {0xE8, 0x11, 0x22, 0x33, 0x44, 0x90, 0x90};
        std::memcpy(memory + 0x100, site, sizeof(site));
        std::memcpy(memory + 0x400, site, sizeof(site));

        const xla::Image image{reinterpret_cast<std::byte*>(memory), 0x1000};
        auto all = xla::patch::FindIn(image, "E8 ? ? ? ? 90 90", 0);
        Check(all.size() == 2, "patch: a multi-hit scan returns every site",
              std::to_string(all.size()));
        auto one = xla::patch::FindIn(image, "E8 ? ? ? ? 90 90", 1);
        Check(one.size() == 1 && one.get_first<std::uint8_t>() == memory + 0x100,
              "patch: the first hit is the first site");
        auto variants = xla::patch::FindIn(image, 1, "DE AD BE EF", "E8 ? ? ? ? 90 90");
        Check(!variants.empty() && variants.get_first<std::uint8_t>() == memory + 0x100,
              "patch: the second build variant is used when the first misses");

        // An omitted fallback is an empty variant, and an empty signature matches at the
        // module start - the regression that handed the focus-loss resolver the DOS bytes.
        auto missing = xla::patch::find_pattern("DE AD BE EF CA FE", "");
        Check(missing.empty(), "patch: an empty variant is never scanned");
        auto emptyOnly = xla::patch::find_pattern("");
        Check(emptyOnly.empty(), "patch: an empty signature alone finds nothing");
        auto mz = xla::patch::find_pattern("DE AD BE EF CA FE", "4D 5A");
        Check(!mz.empty() && mz.get_first<std::uint8_t>() ==
                  reinterpret_cast<std::uint8_t*>(GetModuleHandleW(nullptr)),
              "patch: a real variant still matches at the image start");

        VirtualFree(memory, 0, MEM_RELEASE);
    }

    void TestIatReplacement()
    {
        SyntheticModule module("SHELL32.DLL");
        module.Add("SHGetFolderPathA");
        module.Add("SHGetFolderPathW");

        static int hookA = 0;
        static int hookW = 0;
        const auto originals = xla::patch::ReplaceImports(
            module.Handle(), "SHELL32.DLL",
            {{"SHGetFolderPathA", &hookA}, {"SHGetFolderPathW", &hookW}});

        Check(originals.size() == 2, "iat: both shell imports are replaced");
        Check(module.Slot(0) == &hookA, "iat: the A slot holds the hook");
        Check(module.Slot(1) == &hookW, "iat: the W slot holds the hook");
        Check(originals.at("SHGetFolderPathA") == reinterpret_cast<void*>(0xDEAD0000u),
              "iat: the A original is returned");
        Check(originals.at("SHGetFolderPathW") == reinterpret_cast<void*>(0xDEAD0001u),
              "iat: the W original is returned");

        const auto missing = xla::patch::ReplaceImports(
            module.Handle(), "SHELL32.DLL", {{"GetTickCount", &hookA}});
        Check(missing.empty(), "iat: a name that is not in the table is not reported");
        const auto other = xla::patch::ReplaceImports(
            module.Handle(), "USER32.DLL", {{"SHGetFolderPathA", &hookA}});
        Check(other.empty(), "iat: another library does not match");

        // An image whose import descriptor has no name table: the slots hold
        // resolved addresses and are matched against GetProcAddress.
        HMODULE shell32 = ::GetModuleHandleA("shell32.dll");
        if (shell32 == nullptr)
        {
            shell32 = ::LoadLibraryA("shell32.dll");
        }
        if (shell32 != nullptr)
        {
            SyntheticModule resolved("SHELL32.DLL");
            resolved.Add("SHGetFolderPathA");
            resolved.Add("SHGetFolderPathW");
            auto* descriptor =
                reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(resolved.image.data() + 0x200);
            descriptor->OriginalFirstThunk = 0;
            auto* iat = reinterpret_cast<IMAGE_THUNK_DATA*>(resolved.image.data() + 0x500);
            iat[0].u1.Function = reinterpret_cast<std::uintptr_t>(
                ::GetProcAddress(shell32, "SHGetFolderPathA"));
            iat[1].u1.Function = reinterpret_cast<std::uintptr_t>(
                ::GetProcAddress(shell32, "SHGetFolderPathW"));
            const auto byAddress = xla::patch::ReplaceImports(
                resolved.Handle(), "SHELL32.DLL",
                {{"SHGetFolderPathA", &hookA}, {"SHGetFolderPathW", &hookW}});
            Check(byAddress.size() == 2,
                  "iat: a descriptor without a name table is matched by address");
            Check(resolved.Slot(0) == &hookA && resolved.Slot(1) == &hookW,
                  "iat: the address-matched slots hold the hooks");
        }
    }

    void TestSavegames()
    {
        using namespace xla::savegames;

        // The four transcribed bodies keep their recovered VAs and shapes.
        Check(kNullBodyVa == 0x10038570 && kCloseBodyVa == 0x10045580 &&
                  kCopyBodyVa == 0x100455A0 && kMutexBodyVa == 0x100455E0,
              "savegames: the four body VAs are the recovered ones");
        const auto* nullBody =
            reinterpret_cast<const std::uint8_t*>(ResolveBody(Body::null_path));
        Check(nullBody != nullptr && nullBody[0] == 0x33 && nullBody[1] == 0xC0 &&
                  nullBody[2] == 0xC2 && nullBody[3] == 0x08 && nullBody[4] == 0x00,
              "savegames: the null-path body is xor eax,eax; ret 8");
        for (const Body body : {Body::close_file, Body::copy, Body::mutex})
        {
            const auto* frame = reinterpret_cast<const std::uint8_t*>(ResolveBody(body));
            Check(frame != nullptr && frame[0] == 0x55 && frame[1] == 0x8B && frame[2] == 0xEC,
                  std::format("savegames: body {} opens with push ebp; mov ebp,esp",
                              static_cast<int>(body)));
        }

        // One image holding both anchors: the whole write set must land at the
        // recovered offsets and nowhere else.
        constexpr std::size_t kCrcAnchorAt = 0x400;
        constexpr std::size_t kCopyAnchorAt = 0x800;
        constexpr char kCrcPattern[] = "75 ? 83 C1 01 83 C0 01 83 F9 04";
        constexpr char kCopyPattern[] = "8D 4C 24 18 51 6A 00 6A 0C 57";

        struct ExpectedCall
        {
            bool crcAnchor;
            std::ptrdiff_t offset;
            Body body;
            std::string_view label;
        };
        constexpr std::array<ExpectedCall, 10> expected{{
            {true, -73, Body::close_file, "savegames: crc anchor -73 is the close body"},
            {true, -143, Body::copy, "savegames: crc anchor -143 is the copy body"},
            {true, -176, Body::copy, "savegames: crc anchor -176 is the copy body"},
            {true, -280, Body::mutex, "savegames: crc anchor -280 is the mutex body"},
            {true, -240, Body::null_path, "savegames: crc anchor -240 is the null body"},
            {false, -86, Body::mutex, "savegames: save-path anchor -86 is the mutex body"},
            {false, -47, Body::null_path, "savegames: save-path anchor -47 is the null body"},
            {false, 10, Body::copy, "savegames: save-path anchor +10 is the copy body"},
            {false, 90, Body::copy, "savegames: save-path anchor +90 is the copy body"},
            {false, 128, Body::close_file, "savegames: save-path anchor +128 is the close body"},
        }};

        const auto siteOf = [](const ExpectedCall& call)
        {
            const std::ptrdiff_t base = call.crcAnchor
                                            ? static_cast<std::ptrdiff_t>(kCrcAnchorAt)
                                            : static_cast<std::ptrdiff_t>(kCopyAnchorAt);
            return static_cast<std::size_t>(base + call.offset);
        };

        std::vector<std::byte> image(0x1000, std::byte{0});
        WriteBytes(image, kCrcAnchorAt, BytesOf(kCrcPattern));
        WriteBytes(image, kCopyAnchorAt, BytesOf(kCopyPattern));
        const std::vector<std::byte> pristine = image;
        Install(xla::Image{image.data(), image.size()});

        for (const ExpectedCall& call : expected)
        {
            const std::size_t site = siteOf(call);
            Check(image[site] == std::byte{0xE8} &&
                      CallTarget(image, site) == ResolveBody(call.body),
                  call.label, std::format("E8={} site={:#x}",
                                          image[site] == std::byte{0xE8}, site));
        }

        Check(image[kCrcAnchorAt] == std::byte{0x90} &&
                  image[kCrcAnchorAt + 1] == std::byte{0x90},
              "savegames: the CRC32 branch is NOPed");
        Check(image[kCrcAnchorAt + 2] == std::byte{0x83},
              "savegames: only the two branch bytes are replaced");

        // Every changed byte is inside one of the recovered call spans or the NOP.
        bool onlyRecovered = true;
        for (std::size_t index = 0; index < image.size(); ++index)
        {
            if (image[index] == pristine[index])
            {
                continue;
            }
            bool allowed = index >= kCrcAnchorAt && index < kCrcAnchorAt + 2;
            for (const ExpectedCall& call : expected)
            {
                const std::size_t site = siteOf(call);
                allowed = allowed || (index >= site && index < site + 5);
            }
            onlyRecovered = onlyRecovered && allowed;
        }
        Check(onlyRecovered,
              "savegames: the arm writes only the recovered call sites and the NOP");

        // The CRC anchor alone: its five calls and the NOP, and nothing around the
        // missing save-path anchor. The sites are checked one by one rather than by
        // counting `E8` bytes: a call displacement may itself contain 0xE8, so a raw
        // byte count is address-dependent.
        std::vector<std::byte> crcOnly(0x1000, std::byte{0});
        WriteBytes(crcOnly, kCrcAnchorAt, BytesOf(kCrcPattern));
        Install(xla::Image{crcOnly.data(), crcOnly.size()});
        bool crcAnchorApplied = crcOnly[kCrcAnchorAt] == std::byte{0x90} &&
                                crcOnly[kCrcAnchorAt + 1] == std::byte{0x90};
        for (const ExpectedCall& call : expected)
        {
            if (!call.crcAnchor)
            {
                continue;
            }
            const std::size_t site = siteOf(call);
            crcAnchorApplied = crcAnchorApplied && crcOnly[site] == std::byte{0xE8} &&
                               CallTarget(crcOnly, site) == ResolveBody(call.body);
        }
        Check(crcAnchorApplied,
              "savegames: the CRC anchor alone writes its five calls and the NOP");
        Check(crcOnly[kCopyAnchorAt] == std::byte{0},
              "savegames: a missing save-path anchor is left untouched");

        // The save-path anchor alone: its five calls, no NOP at the missing CRC
        // anchor's match.
        std::vector<std::byte> copyOnly(0x1000, std::byte{0});
        WriteBytes(copyOnly, kCopyAnchorAt, BytesOf(kCopyPattern));
        Install(xla::Image{copyOnly.data(), copyOnly.size()});
        bool copyAnchorApplied = copyOnly[kCrcAnchorAt] == std::byte{0};
        for (const ExpectedCall& call : expected)
        {
            if (call.crcAnchor)
            {
                continue;
            }
            const std::size_t site = siteOf(call);
            copyAnchorApplied = copyAnchorApplied && copyOnly[site] == std::byte{0xE8} &&
                                CallTarget(copyOnly, site) == ResolveBody(call.body);
        }
        Check(copyAnchorApplied,
              "savegames: the save-path anchor alone writes its five calls and no NOP");

        // An anchor whose recovered span leaves the image is refused whole: no
        // partial call set, no NOP.
        std::vector<std::byte> shortImage(0x100, std::byte{0});
        WriteBytes(shortImage, 0x10, BytesOf(kCrcPattern));
        const std::vector<std::byte> shortPristine = shortImage;
        Install(xla::Image{shortImage.data(), shortImage.size()});
        Check(shortImage == shortPristine,
              "savegames: a view too short for the recovered offsets is skipped whole");

        // A missing signature is a logged skip, never a fault.
        std::vector<std::byte> empty(0x100, std::byte{0});
        Install(xla::Image{empty.data(), empty.size()});
        Check(std::all_of(empty.begin(), empty.end(), [](std::byte value)
                          { return value == std::byte{0}; }),
              "savegames: a missing crc32 signature is a clean skip");
    }

    void TestCore()
    {
        // Every recovered row writes its shape at its offset. One synthetic image
        // holds a copy of each signature, far enough apart that the writes cannot
        // collide; `BytesOf` fills the wildcards with NOPs, which the scanner's
        // mask ignores. The web-connect/health-check pair is SkipWebConnect's
        // section and is covered by TestWebConnect.
        constexpr std::size_t kStride = 0x100;
        const std::array<std::span<const xla::core::Row>, 3> tables{
            xla::core::DataIntegrityRows(),
            xla::core::TokenActivationRows(),
            xla::core::FirstTimePlayRows(),
        };
        std::size_t total = 0;
        for (const auto& table : tables)
        {
            total += table.size();
        }

        std::vector<std::byte> image(0x100 * (total + 4), std::byte{0});
        std::vector<std::size_t> offsets;
        std::size_t cursor = 0x100;
        for (const auto& table : tables)
        {
            for (const auto& row : table)
            {
                WriteBytes(image, cursor, BytesOf(row.signature));
                offsets.push_back(cursor);
                cursor += kStride;
            }
        }

        const xla::Image view{image.data(), image.size()};
        const xla::core::Options all{};
        const auto report = xla::core::Install(view, all);
        Check(report.applied == total && report.missing == 0,
              "core: every recovered row applies",
              std::format("{}/{}", report.applied, total));

        std::size_t index = 0;
        for (const auto& table : tables)
        {
            for (const auto& row : table)
            {
                const std::byte* site = image.data() + offsets[index];
                const auto byte = [&](std::ptrdiff_t at)
                { return std::to_integer<std::uint8_t>(site[at]); };
                bool ok = false;
                switch (row.shape)
                {
                case xla::core::Shape::branchToJump:
                    ok = byte(row.offset) == 0xEB;
                    break;
                case xla::core::Shape::shortJump:
                    ok = byte(row.offset) == 0xEB && byte(row.offset + 1) == row.value;
                    break;
                case xla::core::Shape::nop2:
                    ok = byte(row.offset) == 0x90 && byte(row.offset + 1) == 0x90;
                    break;
                case xla::core::Shape::ret:
                    ok = byte(row.offset) == 0xC3;
                    break;
                case xla::core::Shape::movEaxOne:
                    ok = byte(row.offset) == 0xB8 && byte(row.offset + 1) == 0x01 &&
                         byte(row.offset + 2) == 0x00 && byte(row.offset + 3) == 0x00 &&
                         byte(row.offset + 4) == 0x00;
                    break;
                }
                Check(ok, std::format("core: row {} writes its shape", index));
                ++index;
            }
        }

        // An absent signature is a logged skip, never a fault.
        std::vector<std::byte> empty(0x100, std::byte{0});
        const auto skipped = xla::core::Install(xla::Image{empty.data(), empty.size()}, all);
        Check(skipped.applied == 0 && skipped.missing == total,
              "core: a missing signature is a skip");

        // Every key off applies nothing.
        std::vector<std::byte> untouched(image);
        xla::core::Options none{};
        none.dataIntegrity = false;
        none.tokenActivation = false;
        none.firstTimePlay = false;
        const auto off =
            xla::core::Install(xla::Image{untouched.data(), untouched.size()}, none);
        Check(off.applied == 0 && off.missing == 0 && untouched == image,
              "core: all three keys off leaves the image untouched");
    }

    // ---- SkipIntro / SkipMenu ------------------------------------------------
    //
    // FusionFix's Loadsc functor is driven directly: the injector's inline stub
    // saves the register file, calls the functor with `esp` corrected to the game's
    // stack pointer and restores the registers, so a register pack whose `esp`
    // points at a frame with the game's two candidate slots is the functor's whole
    // contract.
    int g_menuRecorderValue = -1;
    int g_menuRecorderCalls = 0;
    void __cdecl MenuRecorder(int value)
    {
        g_menuRecorderValue = value;
        ++g_menuRecorderCalls;
    }

    void TestMenu()
    {
        using namespace xla::menu;

        // The patterns are FusionFix's skipintro.ixx, unchanged, and so are the
        // window, its offsets and the literals the hooks use.
        Check(kIntroPatternV1 ==
                  "8B 0D ? ? ? ? 8B 44 24 18 83 C4 0C 69 C9 ? ? ? ? 89 81 ? ? ? ? 8D 44 24 60 "
                  "68 ? ? ? ? 50 E8 ? ? ? ? 83 C4 08 85 C0 0F 85",
              "menu: the pre-1.0.8.0 intro pattern is FusionFix's v1");
        Check(kIntroPatternV2 == "8B 0D ? ? ? ? 8B 54 24 1C 83 C4 0C",
              "menu: the 1.0.8.0 intro pattern is FusionFix's v2");
        Check(kMenuCallPattern ==
                  "E8 ? ? ? ? 83 C4 04 8B 8C 24 ? ? ? ? 5F 5E 5D 5B 33 CC E8 ? ? ? ? 81 C4 ? ? ? "
                  "? C3",
              "menu: the five-hit menu pattern is FusionFix's");
        Check(kMenuFallbackPattern ==
                  "E8 ? ? ? ? 83 C4 04 5F 5E 5B 8B 8C 24 ? ? ? ? 33 CC E8 ? ? ? ? 8B E5 5D C3 83 "
                  "F8 30",
              "menu: the single-hit menu fallback is FusionFix's");
        Check(kIntroHookLength == 10 && kScreenIdGlobalOperand == 2 &&
                  kIntroArgumentModRmOffset == 7 && kEdxVariantModRm == 0x54,
              "menu: the Loadsc window and its operand offsets are pinned");
        Check(kIntroMillisecondsThreshold == 8000 && kMenuStateSkip == 6,
              "menu: FusionFix's 8000 ms threshold and its a1 = 6 are pinned");

        constexpr std::size_t kIntroAt = 0x200;
        constexpr std::size_t kScreenIdAt = 0x300;
        constexpr std::size_t kMenuAt = 0x400;
        constexpr std::size_t kMenuStride = 0x40;
        constexpr std::uint32_t kImageScreenId = 0x01234567;
        constexpr std::uint32_t kInitialEax = 0x1111;
        constexpr std::uint32_t kInitialEdx = 0x2222;

        // ---- the intro hook and its functor ---------------------------------
        std::vector<std::byte> image(0x1000, std::byte{0});
        WriteBytes(image, kIntroAt, BytesOf("8B 0D ? ? ? ? 8B 54 24 1C 83 C4 0C"));
        WriteDword(image, kIntroAt + 2,
                   static_cast<std::uint32_t>(
                       reinterpret_cast<std::uintptr_t>(image.data()) + kScreenIdAt));
        WriteDword(image, kScreenIdAt, kImageScreenId);
        const std::vector<std::byte> introPristine = image;

        Check(InstallIntro(xla::Image{image.data(), image.size()}, true),
              "menu: the intro hook installs on a 1.0.8.0-shaped window");
        Check(image[kIntroAt] == std::byte{0xE8},
              "menu: the window becomes a call into the register stub");
        Check(CallTarget(image, kIntroAt) != 0,
              "menu: ... whose destination is the injector's stub");
        Check(std::all_of(image.begin() + kIntroAt + 5,
                          image.begin() + kIntroAt + kIntroHookLength,
                          [](std::byte value) { return value == std::byte{0x90}; }),
              "menu: the rest of the window is NOPed");
        Check(image[kIntroAt + kIntroHookLength] ==
                      introPristine[kIntroAt + kIntroHookLength] &&
                  image[kIntroAt + kIntroHookLength + 1] ==
                      introPristine[kIntroAt + kIntroHookLength + 1],
              "menu: the instruction after the window is the resume, untouched");
        const std::array introSpans{
            std::pair<std::size_t, std::size_t>{kIntroAt, kIntroHookLength}};
        Check(OnlyChangedWithin(image, introPristine, introSpans),
              "menu: the intro arm writes only its window");

        // The functor: `regs.esp` is the game's stack pointer, so the frame's
        // [esp+0x18]/[esp+0x1C] are the two candidate slots.
        std::array<std::int32_t, 16> frame{};
        xla::patch::Registers regs{};
        regs.esp = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(frame.data()));
        const auto runFunctor = [&](int milliseconds)
        {
            frame[0x18 / 4] = milliseconds;
            frame[0x1C / 4] = milliseconds;
            regs.ecx = 0;
            regs.eax = kInitialEax;
            regs.edx = kInitialEdx;
            Loadsc{}(regs);
        };

        runFunctor(4000);
        Check(regs.ecx == kImageScreenId,
              "menu: the functor reloads ecx from the screen-id global",
              std::to_string(regs.ecx));
        Check(regs.edx == 0 && regs.eax == kInitialEax,
              "menu: a screen under 8000 ms is zeroed in edx (the 1.0.8.0 variant) and "
              "eax is untouched",
              std::format("edx={:#x} eax={:#x}", regs.edx, regs.eax));

        runFunctor(8000);
        Check(regs.edx == 8000 && regs.eax == kInitialEax,
              "menu: 8000 ms is kept (the test is strictly below)",
              std::to_string(regs.edx));

        // The v1 window is the eax variant.
        std::vector<std::byte> v1Image(0x1000, std::byte{0});
        WriteBytes(v1Image, kIntroAt, BytesOf(kIntroPatternV1));
        WriteDword(v1Image, kIntroAt + 2,
                   static_cast<std::uint32_t>(
                       reinterpret_cast<std::uintptr_t>(v1Image.data()) + kScreenIdAt));
        WriteDword(v1Image, kScreenIdAt, kImageScreenId);
        Check(InstallIntro(xla::Image{v1Image.data(), v1Image.size()}, true),
              "menu: the pre-1.0.8.0 intro pattern installs");
        runFunctor(4000);
        Check(regs.eax == 0 && regs.edx == kInitialEdx,
              "menu: the v1 variant zeroes eax and leaves edx alone",
              std::format("eax={:#x} edx={:#x}", regs.eax, regs.edx));

        // SkipIntro off keeps the screen time. The window is patched, so a fresh copy
        // of the image is the one that still carries the pattern.
        std::vector<std::byte> offImage(introPristine);
        Check(InstallIntro(xla::Image{offImage.data(), offImage.size()}, false),
              "menu: the intro hook installs with the key off");
        runFunctor(4000);
        Check(regs.edx == 4000,
              "menu: SkipIntro off keeps the screen time", std::to_string(regs.edx));

        // Put the intro state back on for the latch check at the end of the test.
        std::vector<std::byte> latchedImage(introPristine);
        Check(InstallIntro(xla::Image{latchedImage.data(), latchedImage.size()}, true),
              "menu: the intro hook installs again on a fresh image");
        runFunctor(4000);
        Check(regs.edx == 0,
              "menu: the reinstalled hook still shortens the screen", std::to_string(regs.edx));

        // A missing pattern is a clean skip, never a write.
        std::vector<std::byte> emptyImage(0x400, std::byte{0});
        const std::vector<std::byte> emptyPristine = emptyImage;
        Check(!InstallIntro(xla::Image{emptyImage.data(), emptyImage.size()}, true),
              "menu: a missing intro pattern is a logged skip");
        Check(!InstallMenu(xla::Image{emptyImage.data(), emptyImage.size()}, true),
              "menu: a missing menu pattern is a logged skip");
        Check(emptyImage == emptyPristine, "menu: neither missing pattern writes anything");

        // The five-hit shape: FusionFix hooks the second hit.
        std::vector<std::byte> menuImage(0x1000, std::byte{0});
        for (std::size_t index = 0; index < 5; ++index)
        {
            const std::size_t at = kMenuAt + index * kMenuStride;
            WriteBytes(menuImage, at, BytesOf(kMenuCallPattern));
            SetCallTarget(menuImage, at,
                          reinterpret_cast<std::uintptr_t>(&MenuRecorder));
        }
        const std::vector<std::byte> menuPristine = menuImage;
        Check(InstallMenu(xla::Image{menuImage.data(), menuImage.size()}, true),
              "menu: the five-hit menu shape installs");
        const auto hookRecorder = reinterpret_cast<std::uintptr_t>(&MenuRecorder);
        for (std::size_t index = 0; index < 5; ++index)
        {
            const std::size_t at = kMenuAt + index * kMenuStride;
            const bool hooked = CallTarget(menuImage, at) != hookRecorder;
            Check(hooked == (index == 1),
                  std::format("menu: hit {} is {}", index, index == 1 ? "hooked" : "left alone"));
        }
        const std::array menuSpans{
            std::pair<std::size_t, std::size_t>{kMenuAt + kMenuStride, 5}};
        Check(OnlyChangedWithin(menuImage, menuPristine, menuSpans),
              "menu: the menu arm writes only the hooked call");

        // The body: the first first-boot call is rewritten to the skip state, the
        // latch means only that call is (FusionFix's bOnce/bSkipIntroNotNeeded).
        const bool shiftHeld = (::GetAsyncKeyState(VK_SHIFT) & static_cast<SHORT>(0xF000)) != 0;
        ResetMenuState();
        g_menuRecorderValue = -1;
        g_menuRecorderCalls = 0;
        MenuBody(0);
        Check(g_menuRecorderCalls == 1 &&
                  g_menuRecorderValue == (shiftHeld ? 0 : kMenuStateSkip),
              "menu: a first-boot call is rewritten to the skip state unless SHIFT is held",
              std::to_string(g_menuRecorderValue));
        Check(IntroNotNeeded(), "menu: the body marks the intro no longer needed");
        MenuBody(0);
        Check(g_menuRecorderCalls == 2 && g_menuRecorderValue == 0,
              "menu: the rewrite happens once, not on every call");
        MenuBody(3);
        Check(g_menuRecorderCalls == 3 && g_menuRecorderValue == 3,
              "menu: a non-first-boot call is passed through");

        // The single-hit fallback, with the menu skip off: the hook still installs
        // (for the intro latch) but the state is never rewritten.
        std::vector<std::byte> fallbackImage(0x400, std::byte{0});
        WriteBytes(fallbackImage, 0x100, BytesOf(kMenuFallbackPattern));
        SetCallTarget(fallbackImage, 0x100, hookRecorder);
        Check(InstallMenu(xla::Image{fallbackImage.data(), fallbackImage.size()}, false),
              "menu: the single-hit fallback installs");
        Check(CallTarget(fallbackImage, 0x100) != hookRecorder,
              "menu: the fallback's call is retargeted");
        ResetMenuState();
        g_menuRecorderCalls = 0;
        g_menuRecorderValue = -1;
        MenuBody(0);
        Check(g_menuRecorderCalls == 1 && g_menuRecorderValue == 0,
              "menu: SkipMenu off passes the first-boot state through");
        Check(IntroNotNeeded(),
              "menu: ... and the intro latch is still set for SkipIntro");

        // With the latched intro the functor keeps the screen time again.
        frame[0x18 / 4] = 4000;
        frame[0x1C / 4] = 4000;
        regs.eax = kInitialEax;
        regs.edx = kInitialEdx;
        Loadsc{}(regs);
        Check(regs.edx == 4000,
              "menu: after the first menu the intro screens are kept", std::to_string(regs.edx));
    }

    // ---- VRAMFix -------------------------------------------------------------
    std::int32_t __cdecl VidMemZero()
    {
        return 0;
    }
    std::int32_t __cdecl VidMemNegative()
    {
        return -4096;
    }
    std::int32_t __cdecl VidMemSmall()
    {
        return 1234;
    }
    std::int32_t __cdecl VidMemLast()
    {
        return 5678;
    }

    std::uint64_t __cdecl FusionFixHighAnswer()
    {
        return 3ull * 1024 * 1024 * 1024;
    }
    std::uint64_t __cdecl FusionFixLowAnswer()
    {
        return 1024ull * 1024 * 1024;
    }

    void TestVram()
    {
        using namespace xla::vram;

        // The recovered reference rows and FusionFix's patterns are pinned.
        Check(Rows().size() == 3, "vram: the three recovered call sites are pinned");
        Check(Rows()[0].signature == "E8 ? ? ? ? D9 E8 85 C0" &&
                  Rows()[1].signature ==
                      "E8 ? ? ? ? F3 0F 10 0D ? ? ? ? F3 0F 5C 0D" &&
                  Rows()[2].signature ==
                      "E8 ? ? ? ? F3 0F 10 05 ? ? ? ? 89 44 24 08 6A 01 8D 44 24",
              "vram: the recovered signatures are unchanged");
        Check(kFusionFixPattern == "8B 0D ? ? ? ? 83 EC ? 33 C0",
              "vram: the FusionFix generation's entry pattern is FusionFix's");
        Check(DevicePatterns().size() == 3 &&
                  DevicePatterns()[0] == "83 3D ? ? ? ? ? 74 17 8B 4D 14" &&
                  DevicePatterns()[1] == "83 3D ? ? ? ? ? 74 15 8B 44 24 1C" &&
                  DevicePatterns()[2] == "83 3D ? ? ? ? ? 74 EF",
              "vram: FusionFix's device-pointer patterns are unchanged");
        Check(kTwoGigabytes == 2147483648ull, "vram: FusionFix's 2 GB floor is pinned");
        Check(PathName(Path::none) == "none" && PathName(Path::reference) == "reference" &&
                  PathName(Path::fusionFix) == "fusionFix",
              "vram: the path names are the log's words");

        // ---- the reference generation ----------------------------------------
        // The body clamps a non-positive answer to INT_MAX and passes the rest.
        SetVidMemOriginal(nullptr);
        Check(GetVidMemBody() == INT_MAX, "vram: a missing original answers INT_MAX");
        SetVidMemOriginal(&VidMemZero);
        Check(GetVidMemBody() == INT_MAX, "vram: a zero answer becomes INT_MAX");
        SetVidMemOriginal(&VidMemNegative);
        Check(GetVidMemBody() == INT_MAX, "vram: a negative answer becomes INT_MAX");
        SetVidMemOriginal(&VidMemSmall);
        Check(GetVidMemBody() == 1234, "vram: a positive answer passes through");
        SetVidMemOriginal(nullptr);

        constexpr std::size_t kStride = 0x80;
        const std::array<std::int32_t(__cdecl*)(), 3> originals{&VidMemZero, &VidMemNegative,
                                                               &VidMemLast};

        std::vector<std::byte> image(0x400, std::byte{0});
        std::vector<std::size_t> sites;
        for (std::size_t index = 0; index < Rows().size(); ++index)
        {
            const std::size_t at = 0x80 + index * kStride;
            WriteBytes(image, at, BytesOf(Rows()[index].signature));
            SetCallTarget(image, at, reinterpret_cast<std::uintptr_t>(originals[index]));
            sites.push_back(at);
        }
        const std::vector<std::byte> pristine = image;
        const auto reference = Install(xla::Image{image.data(), image.size()});
        Check(reference.path == Path::reference && reference.rowsApplied == 3,
              "vram: the reference generation installs its three rows",
              std::format("{} {}", PathName(reference.path), reference.rowsApplied));
        for (const std::size_t at : sites)
        {
            Check(CallTarget(image, at) ==
                      reinterpret_cast<std::uintptr_t>(&GetVidMemBody),
                  std::format("vram: the call at {:#x} runs the clamp body", at));
        }
        const std::array referenceSpans{
            std::pair<std::size_t, std::size_t>{sites[0], 5},
            std::pair<std::size_t, std::size_t>{sites[1], 5},
            std::pair<std::size_t, std::size_t>{sites[2], 5},
        };
        Check(OnlyChangedWithin(image, pristine, referenceSpans),
              "vram: the reference arm writes only the three call displacements");
        Check(HasVidMemOriginal() && GetVidMemBody() == 5678,
              "vram: every body forwards through the last row's original");

        // The recovered overwrite: a later missing row clears the original, so the
        // bodies already installed answer INT_MAX.
        std::vector<std::byte> partial(0x400, std::byte{0});
        WriteBytes(partial, 0x80, BytesOf(Rows()[0].signature));
        SetCallTarget(partial, 0x80, reinterpret_cast<std::uintptr_t>(&VidMemZero));
        WriteBytes(partial, 0x100, BytesOf(Rows()[1].signature));
        SetCallTarget(partial, 0x100, reinterpret_cast<std::uintptr_t>(&VidMemNegative));
        const auto partialReport = Install(xla::Image{partial.data(), partial.size()});
        Check(partialReport.path == Path::reference && partialReport.rowsApplied == 2,
              "vram: two present rows install, the third is a skip");
        Check(CallTarget(partial, 0x80) == reinterpret_cast<std::uintptr_t>(&GetVidMemBody) &&
                  CallTarget(partial, 0x100) == reinterpret_cast<std::uintptr_t>(&GetVidMemBody),
              "vram: ... and both installed calls run the clamp body");
        Check(!HasVidMemOriginal(),
              "vram: a missing row clears the published original (the recovered overwrite)");
        Check(GetVidMemBody() == INT_MAX,
              "vram: ... so the installed bodies then answer INT_MAX");

        // ---- the FusionFix generation ---------------------------------------
        // Its value contract: 2 GB or more stands, otherwise the largest of the
        // preferred GPU memory, the d3d9 texture memory and the 2 GB floor.
        Check(FusionFixVramValue(kTwoGigabytes + 1, 0, 0) == kTwoGigabytes + 1,
              "vram: an answer of 2 GB or more is passed through");
        Check(FusionFixVramValue(FusionFixLowAnswer(), 0, 0) == kTwoGigabytes,
              "vram: a smaller answer is floored at 2 GB");
        Check(FusionFixVramValue(FusionFixLowAnswer(), 4ull * 1024 * 1024 * 1024, 0) ==
                  4ull * 1024 * 1024 * 1024,
              "vram: the preferred GPU memory wins when it is the largest");
        Check(FusionFixVramValue(FusionFixLowAnswer(), 1024ull * 1024 * 1024,
                                 2ull * 1024 * 1024 * 1024) == 2ull * 1024 * 1024 * 1024,
              "vram: the d3d9 texture memory is part of the maximum");

        // A synthetic image with the entry prologue and FusionFix's device site.
        constexpr std::size_t kEntryAt = 0x100;
        constexpr std::size_t kDeviceAt = 0x200;
        constexpr std::size_t kEntryGlobalAt = 0x300;
        constexpr std::size_t kDeviceSlotAt = 0x304;
        constexpr std::size_t kWindow = 6;

        ResetFusionFixState();
        std::vector<std::byte> fusionfix(0x400, std::byte{0});
        WriteBytes(fusionfix, kEntryAt, BytesOf("8B 0D ? ? ? ? 83 EC 14 33 C0"));
        WriteDword(fusionfix, kEntryAt + 2,
                   static_cast<std::uint32_t>(
                       reinterpret_cast<std::uintptr_t>(fusionfix.data()) + kEntryGlobalAt));
        WriteBytes(fusionfix, kDeviceAt, BytesOf("83 3D ? ? ? ? 00 74 EF"));
        WriteDword(fusionfix, kDeviceAt + 2,
                   static_cast<std::uint32_t>(
                       reinterpret_cast<std::uintptr_t>(fusionfix.data()) + kDeviceSlotAt));
        const std::vector<std::byte> fusionfixPristine = fusionfix;

        const auto fusionfixReport = Install(xla::Image{fusionfix.data(), fusionfix.size()});
        Check(fusionfixReport.path == Path::fusionFix && fusionfixReport.rowsApplied == 0,
              "vram: the FusionFix path installs where the reference rows are absent",
              std::format("{} {}", PathName(fusionfixReport.path),
                          fusionfixReport.rowsApplied));
        Check(fusionfix[kEntryAt] == std::byte{0xE9} &&
                  JumpTarget(fusionfix, kEntryAt) ==
                      reinterpret_cast<std::uintptr_t>(&FusionFixGetAvailableVideoMemory),
              "vram: the entry becomes a jump into FusionFix's replacement");
        Check(fusionfix[kEntryAt + 5] == std::byte{0x90},
              "vram: the rest of the replaced window is NOPed");
        Check(FusionFixOriginal() != nullptr,
              "vram: the trampoline is published as the original");
        const auto* trampoline =
            reinterpret_cast<const std::uint8_t*>(FusionFixOriginal());
        Check(trampoline[0] == 0x8B && trampoline[1] == 0x0D &&
                  DwordAt(trampoline, 2) == DwordAt(fusionfixPristine.data(), kEntryAt + 2),
              "vram: the trampoline runs the instruction the hook replaced");
        Check(trampoline[kWindow] == 0xE9 &&
                  reinterpret_cast<std::uintptr_t>(trampoline) + kWindow + 5 +
                          static_cast<std::intptr_t>(DwordAt(trampoline, kWindow + 1)) ==
                      reinterpret_cast<std::uintptr_t>(fusionfix.data()) + kEntryAt + kWindow,
              "vram: the trampoline resumes after the replaced window");
        const std::array fusionfixSpans{
            std::pair<std::size_t, std::size_t>{kEntryAt, kWindow}};
        Check(OnlyChangedWithin(fusionfix, fusionfixPristine, fusionfixSpans),
              "vram: the FusionFix arm writes only the entry window");

        // The generation split: with a reference row on the same image, the reference
        // path wins and the FusionFix entry is left alone.
        {
            ResetFusionFixState();
            std::vector<std::byte> both(0x400, std::byte{0});
            WriteBytes(both, 0x80, BytesOf(Rows()[0].signature));
            SetCallTarget(both, 0x80, reinterpret_cast<std::uintptr_t>(&VidMemZero));
            WriteBytes(both, kEntryAt, BytesOf("8B 0D ? ? ? ? 83 EC 14 33 C0"));
            WriteDword(both, kEntryAt + 2,
                       static_cast<std::uint32_t>(
                           reinterpret_cast<std::uintptr_t>(both.data()) + kEntryGlobalAt));
            const std::vector<std::byte> bothPristine = both;
            const auto bothReport = Install(xla::Image{both.data(), both.size()});
            Check(bothReport.path == Path::reference && bothReport.rowsApplied == 1,
                  "vram: the reference generation owns a build whose rows match",
                  std::format("{} {}", PathName(bothReport.path), bothReport.rowsApplied));
            Check(both[kEntryAt] == bothPristine[kEntryAt] && FusionFixOriginal() == nullptr,
                  "vram: ... and the FusionFix entry is left alone");
            ResetFusionFixState();
        }

        // No path at all: a clean skip, no writes.
        {
            std::vector<std::byte> empty(0x100, std::byte{0});
            const std::vector<std::byte> emptyPristine = empty;
            const auto emptyReport = Install(xla::Image{empty.data(), empty.size()});
            Check(emptyReport.path == Path::none && emptyReport.rowsApplied == 0,
                  "vram: no path matched this build");
            Check(empty == emptyPristine, "vram: the skip writes nothing");
            Check(!HasVidMemOriginal() && FusionFixOriginal() == nullptr,
                  "vram: ... and leaves nothing published");
        }

        // The replacement itself: the original's answer is forwarded or floored.
        ResetFusionFixState();
        SetFusionFixOriginal(&FusionFixHighAnswer);
        Check(FusionFixGetAvailableVideoMemory() == 3ull * 1024 * 1024 * 1024,
              "vram: a 3 GB answer is passed through by the replacement");
        SetFusionFixOriginal(&FusionFixLowAnswer);
        Check(FusionFixGetAvailableVideoMemory() == kTwoGigabytes,
              "vram: a 1 GB answer becomes FusionFix's 2 GB floor (no d3d9 device here)");
        SetFusionFixOriginal(nullptr);
    }

    // ---- SkipWebConnect ------------------------------------------------------
    void TestWebConnect()
    {
        const auto internet = xla::core::InternetConnectionRows();
        const auto health = xla::core::HealthCheckRows();
        Check(internet.size() == 3 && health.size() == 1,
              "webConnect: the recovered sections are the three branches and one health entry",
              std::format("{} + {}", internet.size(), health.size()));
        Check(internet[0].signature == "FF 15 ? ? ? ? 85 C0 75 18" &&
                  internet[1].signature == "FF 15 ? ? ? ? 85 C0 75 04 32" &&
                  internet[2].signature == "FF 15 ? ? ? ? 85 C0 75 07 A0",
              "webConnect: the three InternetGetConnectedState variants are unchanged");
        Check(health[0].signature ==
                  "81 EC ? ? ? ? A1 ? ? ? ? 33 C4 89 84 24 ? ? ? ? 53 ? 6A 3C 33 DB 8D 44 24 "
                  "? 53 50 E8",
              "webConnect: the health-check signature is unchanged");

        constexpr std::size_t kStride = 0x80;
        std::vector<std::size_t> sites;
        std::vector<std::byte> image(0x400, std::byte{0});
        std::size_t at = kStride;
        for (const auto& row : internet)
        {
            WriteBytes(image, at, BytesOf(row.signature));
            sites.push_back(at);
            at += kStride;
        }
        for (const auto& row : health)
        {
            WriteBytes(image, at, BytesOf(row.signature));
            sites.push_back(at);
            at += kStride;
        }

        // Each signature is found exactly once on this image.
        bool foundOnce = true;
        for (const auto& row : internet)
        {
            foundOnce = foundOnce &&
                        xla::patch::FindIn(xla::Image{image.data(), image.size()}, row.signature, 1)
                                .size() == 1;
        }
        for (const auto& row : health)
        {
            foundOnce = foundOnce &&
                        xla::patch::FindIn(xla::Image{image.data(), image.size()}, row.signature, 1)
                                .size() == 1;
        }
        Check(foundOnce, "webConnect: every recovered signature is found exactly once");

        const std::vector<std::byte> pristine = image;
        const auto report = xla::core::InstallWebConnectChecks(
            xla::Image{image.data(), image.size()}, {.internetConnection = true,
                                                     .healthCheck = true});
        Check(report.applied == 4 && report.missing == 0,
              "webConnect: both sections apply",
              std::format("{}/{}", report.applied, report.applied + report.missing));
        for (std::size_t index = 0; index < internet.size(); ++index)
        {
            Check(image[sites[index] + 8] == std::byte{0x90} &&
                      image[sites[index] + 9] == std::byte{0x90},
                  std::format("webConnect: branch {} is NOPed", index));
        }
        Check(image[sites[3]] == std::byte{0xC3},
              "webConnect: the health check's entry becomes ret");
        const std::array<std::pair<std::size_t, std::size_t>, 4> spans{{
            {sites[0] + 8, 2},
            {sites[1] + 8, 2},
            {sites[2] + 8, 2},
            {sites[3], 1},
        }};
        Check(OnlyChangedWithin(image, pristine, spans),
              "webConnect: the section writes only the three branches and the ret");

        // The master switch off: nothing is installed, which is the old add-on's
        // `SkipWebConnect=0` outcome (the two fine-grained keys are refinements).
        std::vector<std::byte> untouched(pristine);
        const auto off = xla::core::InstallWebConnectChecks(
            xla::Image{untouched.data(), untouched.size()},
            {.internetConnection = false, .healthCheck = false});
        Check(off.applied == 0 && off.missing == 0 && untouched == pristine,
              "webConnect: both sections off leaves the image untouched");

        // The fine-grained keys refine the family.
        std::vector<std::byte> healthOnly(pristine);
        Check(xla::core::InstallWebConnectChecks(
                  xla::Image{healthOnly.data(), healthOnly.size()},
                  {.internetConnection = false, .healthCheck = true})
                      .applied == 1 &&
                  healthOnly[sites[3]] == std::byte{0xC3} &&
                  healthOnly[sites[0] + 8] != std::byte{0x90},
              "webConnect: SkipInternetConnectionCheck=0 leaves the branches alone");
        std::vector<std::byte> internetOnly(pristine);
        Check(xla::core::InstallWebConnectChecks(
                  xla::Image{internetOnly.data(), internetOnly.size()},
                  {.internetConnection = true, .healthCheck = false})
                      .applied == 3 &&
                  internetOnly[sites[3]] != std::byte{0xC3} &&
                  internetOnly[sites[2] + 8] == std::byte{0x90},
              "webConnect: SkipHealthCheck=0 leaves the health entry alone");

        // Missing signatures are a clean skip.
        std::vector<std::byte> empty(0x100, std::byte{0});
        const std::vector<std::byte> emptyPristine = empty;
        const auto skipped = xla::core::InstallWebConnectChecks(
            xla::Image{empty.data(), empty.size()},
            {.internetConnection = true, .healthCheck = true});
        Check(skipped.applied == 0 && skipped.missing == 4 && empty == emptyPristine,
              "webConnect: a missing signature is a logged skip");
    }

    void TestRegistry()
    {
        Check(xla::registry::IsRockstarSubKey("Software\\Rockstar Games\\GTAIV"),
              "registry: the Rockstar Games key is recognised");
        Check(!xla::registry::IsRockstarSubKey("Software\\Other"),
              "registry: another key is not");
        Check(xla::registry::IsInstallFolderValue("InstallFolder"),
              "registry: InstallFolder is answered");
        Check(xla::registry::IsInstallFolderValue("InstallFolderSteam"),
              "registry: InstallFolderSteam is answered");
        Check(!xla::registry::IsInstallFolderValue("InstallPath"),
              "registry: InstallPath is not");
        const auto answer = xla::registry::InstallFolderAnswer();
        Check(!answer.empty() && answer.back() == '\\',
              "registry: the install folder answer ends with a separator");
    }

    void TestProfile()
    {
        // The CSIDL set FusionFix redirects; these are the ones the game asks for.
        Check(xla::profile::ShouldRedirect(CSIDL_APPDATA), "profile: APPDATA is redirected");
        Check(xla::profile::ShouldRedirect(CSIDL_PERSONAL), "profile: PERSONAL is redirected");
        Check(xla::profile::ShouldRedirect(CSIDL_LOCAL_APPDATA),
              "profile: LOCAL_APPDATA is redirected");
        Check(!xla::profile::ShouldRedirect(CSIDL_WINDOWS), "profile: WINDOWS is not redirected");

        // Resolution: relative to the game folder, absolute kept, a leading
        // separator read as "under the game folder" (how the replaced keys were
        // written).
        const std::filesystem::path game = "C:\\Games\\GTA IV";
        Check(xla::profile::ResolveProfilePath(game, "").empty(),
              "profile: an empty value is off");
        Check(xla::profile::ResolveProfilePath(game, "./Savefiles") == game / "Savefiles",
              "profile: ./Savefiles is under the game folder");
        Check(xla::profile::ResolveProfilePath(game, "Savefiles\\profiles") ==
                  game / "Savefiles" / "profiles",
              "profile: a relative path nests under the game folder");
        Check(xla::profile::ResolveProfilePath(game, "\\Savefiles") == game / "Savefiles",
              "profile: a leading separator means under the game folder");
        Check(xla::profile::ResolveProfilePath(game, "/Savefiles") == game / "Savefiles",
              "profile: a leading forward slash means the same");
        Check(xla::profile::ResolveProfilePath(game, "D:\\Saves") == "D:\\Saves",
              "profile: an absolute path is used as-is");
        Check(xla::profile::ResolveProfilePath(game, "  ./Savefiles  ") == game / "Savefiles",
              "profile: surrounding spaces are trimmed");

        // The live install refuses a foreign image (a parity dump's copy).
        const xla::Image foreign{reinterpret_cast<std::byte*>(0x1000), 0x1000};
        Check(!xla::profile::Install(foreign, "D:\\Saves"),
              "profile: the live install refuses a foreign image");

        // The redirect itself, with no FusionFix involved: a synthetic module's
        // shell imports are replaced and the installed body answers the profile
        // CSIDLs with the configured root.
        TempDir rootDir("xla-profile-root");
        const auto root = rootDir.Path() / "Savefiles";
        SyntheticModule module("SHELL32.DLL");
        module.Add("SHGetFolderPathA");
        module.Add("SHGetFolderPathW");
        Check(xla::profile::InstallForModule(module.Handle(), root),
              "profile: the redirect installs on a synthetic module");
        Check(std::filesystem::exists(root), "profile: the root folder is created");

        using ShGetFolderPathAFn = HRESULT(WINAPI*)(HWND, int, HANDLE, DWORD, LPSTR);
        const auto shellA = reinterpret_cast<ShGetFolderPathAFn>(module.Slot(0));
        char redirected[MAX_PATH]{};
        const HRESULT result = shellA(nullptr, CSIDL_PERSONAL, nullptr, 0, redirected);
        Check(result == S_OK && std::string{redirected} == root.string(),
              "profile: CSIDL_PERSONAL is answered with the configured root",
              std::format("result={:#x} path={}", static_cast<unsigned>(result), redirected));

        using ShGetFolderPathWFn = HRESULT(WINAPI*)(HWND, int, HANDLE, DWORD, LPWSTR);
        const auto shellW = reinterpret_cast<ShGetFolderPathWFn>(module.Slot(1));
        wchar_t redirectedW[MAX_PATH]{};
        const HRESULT resultW = shellW(nullptr, CSIDL_APPDATA, nullptr, 0, redirectedW);
        Check(resultW == S_OK && std::wstring{redirectedW} == root.wstring(),
              "profile: the wide entry answers CSIDL_APPDATA with the same root");

        // InstallForModule with no root is a logged no-op.
        Check(!xla::profile::InstallForModule(module.Handle(), {}),
              "profile: an empty root is refused");
    }

    void TestSkipLauncherTable()
    {
        using namespace xla::launcher;
        const auto entries = SkipLauncherEntries();
        Check(entries.size() == 25, "skipLauncher: 25 main entries");
        Check(!entries[0].label.empty() && !entries[24].label.empty(),
              "skipLauncher: every row is named");
        Check(entries[0].edits[0].offset == 34 && entries[0].edits[1].offset == 223,
              "skipLauncher: entry 0's two branch offsets");
        Check(entries[8].edits[0].count == 447, "skipLauncher: entry 8's 447-byte NOP fill");
        Check(entries[9].edits[2].target == kSkipLauncherJumpTargetEntry,
              "skipLauncher: entry 9 jumps to entry 1");
        Check(SkipLauncherCollectors().size() == 2, "skipLauncher: two collectors");
        Check(!SkipLauncherCollectors()[0].label.empty(),
              "skipLauncher: the collectors are named");
        Check(SkipLauncherDfaInstalls().size() == 6, "skipLauncher: six DFA hooks");
        Check(SkipLauncherRomInstalls().size() == 2, "skipLauncher: two ROM hooks");
        for (const Install& install : SkipLauncherDfaInstalls())
        {
            Check(!install.label.empty(), "skipLauncher: every DFA hook is named");
        }
        for (const Install& install : SkipLauncherRomInstalls())
        {
            Check(!install.label.empty(), "skipLauncher: every ROM hook is named");
        }
        const auto collected = SkipLauncherDfaCollected();
        Check(collected.size() == 1, "skipLauncher: one collected table");
        Check(!collected[0].label.empty() && collected[0].count == 2,
              "skipLauncher: the collected table has a label and two targets");
        Check(!collected[0].targets[0].label.empty() && !collected[0].targets[1].signature.empty(),
              "skipLauncher: the collected targets are named");
        Check(!HasStage(kShippedStages, SkipLauncherStage::main),
              "skipLauncher: the shipped stages never apply main");
        Check(HasStage(kShippedStages, SkipLauncherStage::dfa) &&
                  HasStage(kShippedStages, SkipLauncherStage::rom),
              "skipLauncher: the shipped stages are DFA+ROM");
        Check(DescribeStages(kShippedStages) == "dfa|rom",
              "skipLauncher: the stage description is dfa|rom");

        std::size_t patchRows = 0;
        for (const Entry& entry : entries)
        {
            Check(!entry.label.empty() && !entry.signature.empty(),
                  "skipLauncher: every entry has a label and a signature");
            for (const Edit& edit : entry.edits)
            {
                ++patchRows;
                Check(edit.offset >= 0, "skipLauncher: every edit has a non-negative offset");
                switch (edit.kind)
                {
                case Edit::Kind::bytes:
                    Check(!edit.bytes.empty(), "skipLauncher: a byte edit carries bytes");
                    break;
                case Edit::Kind::nop:
                    Check(edit.count > 0 && edit.fill == xla::Byte(xla::Opcode::kNop),
                          "skipLauncher: a nop edit is a NOP fill");
                    break;
                case Edit::Kind::jump_to_entry:
                    Check(edit.target < entries.size(), "skipLauncher: a jump target exists");
                    break;
                }
            }
        }
        Check(patchRows == 32, "skipLauncher: the table has 32 patch rows",
              std::to_string(patchRows));
    }

    void TestSkipLauncherPass()
    {
        using namespace xla::launcher;

        // Entry 0's signature: a main pass writes one EB at +34.
        const auto signature = BytesOf(SkipLauncherEntries()[0].signature);
        std::vector<std::byte> image(0x1000, std::byte{0});
        WriteBytes(image, 0x100, signature);
        auto result = ApplySkipLauncher(xla::Image{image.data(), image.size()},
                                        &ResolveSkipHook, nullptr, SkipLauncherStage::main);
        Check(result.has_value(), "skipLauncher: the main stage applies");
        if (result)
        {
            Check(result->entriesFound == 1, "skipLauncher: one entry was found");
            Check(result->writes == 2, "skipLauncher: entry 0 writes two bytes");
            Check(image[0x100 + 34] == std::byte{0xEB},
                  "skipLauncher: the +34 branch byte is EB");
        }

        // The shipped stages must never apply the main table.
        std::vector<std::byte> shipped(0x1000, std::byte{0});
        WriteBytes(shipped, 0x100, signature);
        result = ApplySkipLauncher(xla::Image{shipped.data(), shipped.size()}, &ResolveSkipHook,
                                   nullptr, kShippedStages);
        Check(result.has_value(), "skipLauncher: the shipped stages run");
        if (result)
        {
            Check(result->entriesFound == 0 && result->writes == 0,
                  "skipLauncher: the shipped stages do not touch the main table");
            Check(result->dfaMissing == SkipLauncherDfaInstalls().size(),
                  "skipLauncher: the missing DFA hooks are counted");
        }
        Check(shipped[0x100 + 34] == std::byte{0}, "skipLauncher: the main row is untouched");

        // A store past the image is the pass's one hard failure.
        std::vector<std::byte> bounds(0x100, std::byte{0});
        WriteBytes(bounds, bounds.size() - signature.size(), signature);
        result = ApplySkipLauncher(xla::Image{bounds.data(), bounds.size()}, &ResolveSkipHook,
                                   nullptr, SkipLauncherStage::main);
        Check(!result.has_value() &&
                  result.error().code == PatchError::Code::out_of_bounds,
              "skipLauncher: a store past the image fails cleanly");
    }

    constexpr std::uintptr_t kStubHandle = 0x1234;
    int g_stubCalls = 0;

    HANDLE WINAPI StubCreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD,
                                  HANDLE)
    {
        ++g_stubCalls;
        return reinterpret_cast<HANDLE>(kStubHandle);
    }

    void TestSkipLauncherCreateFileSlot()
    {
        using namespace xla::launcher;
        using CreateFileAFn = HANDLE(WINAPI*)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES,
                                              DWORD, DWORD, HANDLE);

        std::uintptr_t slotValue = reinterpret_cast<std::uintptr_t>(&StubCreateFileA);
        std::vector<std::byte> image(0x1000, std::byte{0});
        const auto capture = BytesOf("FF 15 ? ? ? ? 8B F0 83 FE FF 74 24");
        WriteBytes(image, 0x100, capture);
        const auto slotVa = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(&slotValue));
        WriteDword(image, 0x100 + 2, slotVa);
        WriteBytes(image, 0x200, BytesOf("55 8B EC 6A 00 E8"));

        auto result = ApplySkipLauncher(xla::Image{image.data(), image.size()},
                                        &ResolveSkipHook, nullptr, SkipLauncherStage::dfa);
        Check(result.has_value(), "skipLauncher: the DFA capture runs");
        if (result)
        {
            Check(result->createFileSlot == slotVa,
                  "skipLauncher: the CreateFile IAT slot is captured");
            Check(result->dfaInstalls >= 1, "skipLauncher: the create-file hook is installed");
        }

        const auto body = reinterpret_cast<CreateFileAFn>(
            ResolveSkipHook(SkipHook::create_file, nullptr));
        Check(body != nullptr, "skipLauncher: the CreateFile body resolves");
        g_stubCalls = 0;
        const HANDLE forwarded = body("xla-slot-test", 0, 0, nullptr, 0, 0, nullptr);
        Check(forwarded == reinterpret_cast<HANDLE>(kStubHandle),
              "skipLauncher: CreateFile forwards through the captured slot");
        Check(g_stubCalls == 1, "skipLauncher: the captured slot is called once");

        // A later pass with no capture clears the slot; the body then calls
        // CreateFileA directly.
        std::vector<std::byte> plain(0x100, std::byte{0});
        const auto cleared = ApplySkipLauncher(xla::Image{plain.data(), plain.size()},
                                               &ResolveSkipHook, nullptr,
                                               SkipLauncherStage::dfa);
        Check(cleared.has_value() && cleared->createFileSlot == 0,
              "skipLauncher: a later pass clears the slot");
        const HANDLE direct =
            body("NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                 OPEN_EXISTING, 0, nullptr);
        Check(direct != INVALID_HANDLE_VALUE,
              "skipLauncher: the body falls back to CreateFileA");
        if (direct != INVALID_HANDLE_VALUE)
        {
            ::CloseHandle(direct);
        }
        Check(g_stubCalls == 1, "skipLauncher: the stub is not used again");
    }

    void TestSkipLauncherStub()
    {
        const auto address =
            xla::launcher::ResolveSkipHook(xla::launcher::SkipHook::rom_set, nullptr);
        Check(address != 0, "skipLauncher: the RomSet stub resolved");
        if (address == 0)
        {
            return;
        }
        constexpr std::array<std::uint8_t, 11> expected{
            0x8B, 0x4E, 0x1C, 0x89, 0x4E, 0x20, 0xB0, 0x01, 0xC2, 0x08, 0x00};
        Check(std::memcmp(reinterpret_cast<const void*>(address), expected.data(),
                          expected.size()) == 0,
              "skipLauncher: RomSet is mov ecx,[esi+1C]; mov [esi+20],ecx; mov al,1; ret 8");
        Check(xla::launcher::ResolveSkipHook(
                  xla::launcher::SkipHook::dfa_init, nullptr) != 0,
              "skipLauncher: every DFA body resolves");
    }

    void TestLegacyLauncherStage()
    {
        using namespace xla::launcher::legacy;

        Check(dfa::DfaInit(1, 2, 3) == 1, "dfa: the init body reports success");
        Check(rom::kMessage == 43858, "rom: WM_ROM is 43858");
        Check(rom::kActionTable[0] == 8 && rom::kActionTable[15] == 242,
              "rom: the 16-entry action table is pinned");
        Check(rom::Payload{}.action == 0 && offsetof(rom::Payload, setAddress) == 20,
              "rom: the payload offsets are the protocol");

        HWND window = rom::CreateServiceWindow();
        Check(window != nullptr, "rom: the service window is created");
        if (window == nullptr)
        {
            return;
        }

        struct Payload
        {
            std::array<std::uint32_t, 4> reserved{};
            std::uint32_t action{};
            std::uintptr_t arg0{};
            std::uintptr_t arg1{};
        } payload;
        std::uint32_t copied[16]{};
        payload.action = 18;
        payload.arg1 = reinterpret_cast<std::uintptr_t>(copied);
        ::SendMessageA(window, rom::kMessage, 0,
                       reinterpret_cast<LPARAM>(&payload));
        Check(copied[0] == 8 && copied[15] == 242,
              "rom: action 18 copies the action table");

        std::uint32_t flag = 0;
        payload.action = 100;
        payload.arg0 = reinterpret_cast<std::uintptr_t>(&flag);
        ::SendMessageA(window, rom::kMessage, 0,
                       reinterpret_cast<LPARAM>(&payload));
        Check(flag == 1, "rom: action 100 sets the target");

        payload.action = 51;
        payload.arg0 = 11;
        payload.arg1 = 31;
        const LRESULT sum = ::SendMessageA(window, rom::kMessage, 0,
                                           reinterpret_cast<LPARAM>(&payload));
        Check(sum == 42, "rom: action 51 returns the sum");

        ::DestroyWindow(window);

        // The install sites on a synthetic image: the window/message globals and
        // the SendMessage call slot.
        std::vector<std::byte> image(0x1000, std::byte{0});
        const auto base = reinterpret_cast<std::uintptr_t>(image.data());
        WriteBytes(image, 0x200,
                   BytesOf("A1 ? ? ? ? 8B 0D ? ? ? ? 68 ? ? ? ? 53 50 51 FF 15"));
        WriteDword(image, 0x200 + 1, static_cast<std::uint32_t>(base + 0x100));
        WriteDword(image, 0x200 + 7, static_cast<std::uint32_t>(base + 0x104));
        WriteBytes(image, 0x300,
                   BytesOf("FF 15 ? ? ? ? E8 ? ? ? ? E8 ? ? ? ? E8 ? ? ? ? E8 ? ? ? ? B9 ? ? ? ? "
                           "E8 ? ? ? ? B9 ? ? ? ? E8 ? ? ? ? 83 7C 24"));
        rom::Install(xla::Image{image.data(), image.size()});
        std::uint32_t message = 0;
        std::uint32_t windowSlot = 0;
        std::memcpy(&message, image.data() + 0x100, sizeof(message));
        std::memcpy(&windowSlot, image.data() + 0x104, sizeof(windowSlot));
        Check(message == rom::kMessage, "rom: the message id global is written");
        Check(windowSlot != 0, "rom: the window handle global is written");
        Check(image[0x300] == std::byte{0xE8}, "rom: the SendMessage call is replaced");
    }

    void TestLaunchWithPlayGTAIV()
    {
        using namespace xla::launcher;

        // The recovered scan text and payload.
        Check(kSlotSignature == "4C 61 75 6E 63 68 47 54 41 49 56 2E 65 78 65 00",
              "launchWithPlayGTAIV: the scan text is LaunchGTAIV.exe\\0");
        Check(kName.size() == 16 && kName[0] == 'P' && kName[12] == 'e' && kName[13] == 0 &&
                  kName[14] == 'e' && kName[15] == 0,
              "launchWithPlayGTAIV: the payload is PlayGTAIV.exe\\0e\\0");
        std::array<std::uint32_t, 4> payloadDwords{};
        std::memcpy(payloadDwords.data(), kName.data(), sizeof(payloadDwords));
        Check(payloadDwords[0] == 2036427856u && payloadDwords[1] == 1229018183u &&
                  payloadDwords[2] == 2019896918u && payloadDwords[3] == 6619237u,
              "launchWithPlayGTAIV: the payload is the oracle's four recovered dwords");

        // The switch's five recovered cases, at the recovered RVAs.
        const auto sites1000 = SlotsFor(xla::GameBuild::v1000);
        Check(sites1000.size() == 2 && sites1000[0] == 0x9F043C && sites1000[1] == 0x98FA0C,
              "launchWithPlayGTAIV: 1.0.0.0's slots are the recovered RVAs");
        const auto sites1040 = SlotsFor(xla::GameBuild::v1040);
        Check(sites1040.size() == 2 && sites1040[0] == 0x9EA184 && sites1040[1] == 0x9DD8A0,
              "launchWithPlayGTAIV: 1.0.4.0's slots are the recovered RVAs");
        const auto sites1060 = SlotsFor(xla::GameBuild::v1060);
        Check(sites1060.size() == 2 && sites1060[0] == 0x9F8F40 && sites1060[1] == 0xA9D0D8,
              "launchWithPlayGTAIV: 1.0.6.0's slots are the recovered RVAs");
        const auto sites1070 = SlotsFor(xla::GameBuild::v1070);
        Check(sites1070.size() == 2 && sites1070[0] == 0x9F9F70 && sites1070[1] == 0xA9E118,
              "launchWithPlayGTAIV: 1.0.7.0's slots are the recovered RVAs");
        const auto sites1080 = SlotsFor(xla::GameBuild::v1080);
        Check(sites1080.size() == 2 && sites1080[0] == 0xA508F8 && sites1080[1] == 0xA5A5E4,
              "launchWithPlayGTAIV: 1.0.8.0's slots are the recovered RVAs");

        // Every build the classifier can return has exactly one switch case; the
        // ones outside the recovered switch carry no sites. 1.0.0.4 also carries
        // the two slots and each EFLC image one, and the original rewrites neither.
        bool covered = true;
        for (const xla::build::Signature& signature : xla::build::kSignatures)
        {
            std::size_t rows = 0;
            for (const SlotSet& set : LaunchSlots())
            {
                rows += set.build == signature.build ? 1u : 0u;
            }
            covered = covered && rows == 1;
        }
        Check(covered,
              "launchWithPlayGTAIV: every classified build has exactly one switch case");
        Check(LaunchSlots().size() == xla::build::kSignatures.size(),
              "launchWithPlayGTAIV: the switch has one row per classified build");
        Check(SlotsFor(xla::GameBuild::v1010).empty() &&
                  SlotsFor(xla::GameBuild::v1020).empty() &&
                  SlotsFor(xla::GameBuild::v1030).empty() &&
                  SlotsFor(xla::GameBuild::v1050).empty(),
              "launchWithPlayGTAIV: the pre-1.0.4 builds outside the switch have no sites");
        Check(SlotsFor(xla::GameBuild::v1100).empty() &&
                  SlotsFor(xla::GameBuild::v1110).empty() &&
                  SlotsFor(xla::GameBuild::v1120).empty() &&
                  SlotsFor(xla::GameBuild::v1130).empty(),
              "launchWithPlayGTAIV: the EFLC builds outside the switch have no sites");

        const auto writeSlot = [](std::vector<std::byte>& buffer, std::uint32_t site)
        {
            WriteBytes(buffer, site, BytesOf(xla::launcher::kSlotSignature));
        };
        const auto carriesPayload = [](const std::vector<std::byte>& buffer,
                                       std::uint32_t site)
        {
            for (std::size_t index = 0; index < xla::launcher::kName.size(); ++index)
            {
                if (std::to_integer<std::uint8_t>(buffer[site + index]) !=
                    xla::launcher::kName[index])
                {
                    return false;
                }
            }
            return true;
        };

        // The two 1.0.8.0 slots on an image of the right shape: two stores of the
        // recovered 16 bytes, and nothing else changed.
        std::vector<std::byte> image(0xA60000, std::byte{0});
        writeSlot(image, 0xA508F8);
        writeSlot(image, 0xA5A5E4);
        const std::vector<std::byte> pristine = image;
        Check(RewriteSlots(xla::Image{image.data(), image.size()}, sites1080) == 2,
              "launchWithPlayGTAIV: both 1.0.8.0 slots are two stores");
        Check(carriesPayload(image, 0xA508F8) && carriesPayload(image, 0xA5A5E4),
              "launchWithPlayGTAIV: the write is the 16 recovered bytes");

        const auto oldName = BytesOf(kSlotSignature);
        std::size_t differing = 0;
        for (std::size_t index = 0; index < kName.size(); ++index)
        {
            differing += oldName[index] != kName[index] ? 1u : 0u;
        }
        std::size_t changed = 0;
        for (std::size_t index = 0; index < image.size(); ++index)
        {
            changed += image[index] != pristine[index] ? 1u : 0u;
        }
        Check(changed == differing * 2,
              "launchWithPlayGTAIV: every differing payload byte is stored, in both slots",
              std::format("changed={} differing={}", changed, differing));

        // A shorter view cannot see the second slot: the count check refuses the
        // whole arm.
        {
            std::vector<std::byte> shortView(0xA50908, std::byte{0});
            writeSlot(shortView, 0xA508F8);
            const std::vector<std::byte> shortPristine = shortView;
            Check(RewriteSlots(xla::Image{shortView.data(), shortView.size()}, sites1080) == 0,
                  "launchWithPlayGTAIV: a short view refuses the arm");
            Check(shortView == shortPristine,
                  "launchWithPlayGTAIV: ... and leaves the short view untouched");
        }

        // A longer view (a modded image with a third copy) refuses it too.
        {
            std::vector<std::byte> longView(0xA60000, std::byte{0});
            writeSlot(longView, 0xA508F8);
            writeSlot(longView, 0xA5A5E4);
            writeSlot(longView, 0xA5A800);
            const std::vector<std::byte> longPristine = longView;
            Check(RewriteSlots(xla::Image{longView.data(), longView.size()}, sites1080) == 0,
                  "launchWithPlayGTAIV: a longer view refuses the arm");
            Check(longView == longPristine,
                  "launchWithPlayGTAIV: ... and leaves the longer view untouched");
        }

        // A hit that is not at a recovered RVA is not a slot the original writes.
        {
            std::vector<std::byte> moved(0xA60000, std::byte{0});
            writeSlot(moved, 0xA508F8);
            writeSlot(moved, 0xA5A5E4 + 0x10);
            const std::vector<std::byte> movedPristine = moved;
            Check(RewriteSlots(xla::Image{moved.data(), moved.size()}, sites1080) == 0,
                  "launchWithPlayGTAIV: a slot off its recovered RVA refuses the arm");
            Check(moved == movedPristine,
                  "launchWithPlayGTAIV: ... and leaves the image untouched");
        }

        // The one-slot shape (what each EFLC image carries) writes one store when
        // one site is asked for.
        {
            std::vector<std::byte> one(0x1000, std::byte{0});
            writeSlot(one, 0x40);
            const std::uint32_t site[]{0x40};
            Check(RewriteSlots(xla::Image{one.data(), one.size()}, site) == 1 &&
                      carriesPayload(one, 0x40),
                  "launchWithPlayGTAIV: a one-slot image is written when one site is asked for");
        }

        // No image, no sites: no store, no fault.
        Check(RewriteSlots(xla::Image{}, sites1080) == 0,
              "launchWithPlayGTAIV: a null image is refused");
        Check(RewriteSlots(xla::Image{image.data(), image.size()},
                           std::span<const std::uint32_t>{}) == 0,
              "launchWithPlayGTAIV: an empty site set is refused");

        // The test seam pins the process walk's answer.
        Check(ProbeOverride() == -1,
              "launchWithPlayGTAIV: the probe defaults to the process walk");
        SetProbeOverride(1);
        Check(ProbeOverride() == 1, "launchWithPlayGTAIV: the seam forces the walk on");
        SetProbeOverride(0);
        Check(ProbeOverride() == 0, "launchWithPlayGTAIV: ... and off");
        SetProbeOverride(-1);
        Check(ProbeOverride() == -1, "launchWithPlayGTAIV: ... and back to the process walk");

        // The install step's process gate: forced off, the recovered slots stay
        // alone; forced on, they are rewritten.
        {
            std::vector<std::byte> gated(0xA60000, std::byte{0});
            writeSlot(gated, 0xA508F8);
            writeSlot(gated, 0xA5A5E4);
            const std::vector<std::byte> gatedPristine = gated;

            SetProbeOverride(0);
            InstallLaunchWithPlayGTAIV(xla::Image{gated.data(), gated.size()},
                                       xla::GameBuild::v1080);
            Check(gated == gatedPristine,
                  "launchWithPlayGTAIV: no live PlayGTAIV.exe means no write");

            SetProbeOverride(1);
            InstallLaunchWithPlayGTAIV(xla::Image{gated.data(), gated.size()},
                                       xla::GameBuild::v1080);
            Check(carriesPayload(gated, 0xA508F8) && carriesPayload(gated, 0xA5A5E4),
                  "launchWithPlayGTAIV: the process gate's answer lets the two stores run");
            SetProbeOverride(-1);
        }

        // A build outside the switch stays inert even with the process gate on.
        {
            std::vector<std::byte> eflc(0x1000, std::byte{0});
            writeSlot(eflc, 0x40);
            const std::vector<std::byte> eflcPristine = eflc;
            SetProbeOverride(1);
            InstallLaunchWithPlayGTAIV(xla::Image{eflc.data(), eflc.size()},
                                       xla::GameBuild::v1110);
            SetProbeOverride(-1);
            Check(eflc == eflcPristine,
                  "launchWithPlayGTAIV: a build with no switch case is never rewritten");
        }
    }

    void TestWindowed()
    {
        const xla::Image foreign{reinterpret_cast<std::byte*>(0x1000), 0x1000};
        Check(!xla::windowed::InstallBorderlessHooks(foreign),
              "windowed: the import hooks refuse a foreign image");
        Check(!xla::windowed::InstallFocusLossInput(foreign),
              "windowed: the focus-loss hook refuses a foreign image");
    }

    void TestWarnings()
    {
        Check(xla::warnings::LoaderVersionAccepted(0x00060009, 0),
              "warnings: UAL 6.9.0 is accepted");
        Check(xla::warnings::LoaderVersionAccepted(0x000A0002, 0),
              "warnings: a newer UAL is accepted");
        Check(!xla::warnings::LoaderVersionAccepted(0x00060008, 0xFFFF),
              "warnings: UAL 6.8.x is rejected");
        Check(!xla::warnings::LoaderVersionAccepted(0x00050000, 0),
              "warnings: an old loader is rejected");

        Check(xla::warnings::ClaimSingleInstance(),
              "warnings: the first single-instance claim succeeds");
        Check(!xla::warnings::ClaimSingleInstance(),
              "warnings: a second claim in the same process fails");

        TempDir work("xla-warnings");
        const std::vector<xla::config::FusionFixGate> gated{
            {"BorderlessWindowed", "windowed.ixx"}};
        const auto notice = xla::warnings::WriteFusionFixNotice(work.Path(), gated);
        Check(!notice.empty() && std::filesystem::exists(notice),
              "warnings: the FusionFix notice is written");
        const auto text = ReadFile(notice);
        Check(text.find("BorderlessWindowed") != std::string::npos,
              "warnings: the notice lists the gated option");
        Check(xla::warnings::WriteFusionFixNotice(work.Path(), {}).empty(),
              "warnings: no gate means no notice");

        const auto unsupported = xla::warnings::UnsupportedGameVersionDialog();
        Check(unsupported.error && !unsupported.buttons.empty(),
              "warnings: the unsupported-version dialog is an error dialog");
        const auto twice = xla::warnings::LoadedTwiceDialog();
        Check(twice.error && twice.header.find(L"twice") != std::wstring::npos,
              "warnings: the loaded-twice dialog names the condition");
    }

    void TestProbe()
    {
        Check(xla::probe::kProbeSignature == "B0 04 B2 18 B1 20",
              "probe: the recovered probe signature is pinned");
        Check(xla::probe::kSpinLimit == 10000, "probe: the retry wait is 10,000 ms");
        Check(!xla::probe::ProbePresent(), "probe: the test executable does not carry the probe");
    }

    void TestStartupOrder()
    {
        const auto order = xla::startup::Order();
        const std::array<std::string_view, 28> expected{{
            "Banner", "Console", "SingleInstance", "Loader", "Probe", "Paths", "Config",
            "FusionFix", "ReportConfiguration", "Image", "Writable", "Build", "Profile",
            "Savegames", "SkipLauncher", "LaunchWithPlayGTAIV", "BorderlessWindow", "FocusLoss",
            "CorePatches", "LauncherStage", "WebConnect", "SkipIntro", "SkipMenu",
            "DoNotPauseOnMinimize", "DefWindowProcShims", "Registry", "VramFix", "Complete",
        }};
        Check(order.size() == expected.size(), "startup: the registration count is pinned",
              std::to_string(order.size()));
        bool same = order.size() == expected.size();
        for (std::size_t index = 0; same && index < expected.size(); ++index)
        {
            same = order[index] == expected[index];
        }
        Check(same, "startup: the registration order is pinned");
    }
}

int main()
{
    std::setvbuf(stdout, nullptr, _IONBF, 0);

    // The suite reads the module/exe directories and the game context; point the
    // context at this test executable before any feature test runs.
    xla::Game::Get().Initialise(xla::GetThisModuleHandle());

    TestEvents();
    TestConfigGrammar();
    TestConfigDefaultsAndIni(std::filesystem::path{XLA_DATA_DIR} / "XLivelessAddon.ini");
    TestConfigPrecedenceAndLegacy();
    TestConfigLegacySearch();
    TestConfigWhitespaceCommentsQuotes();
    TestConfigLineEndings();
    TestFusionFixPresenceAndDivergence();
    TestAllOff();
    TestBuild();
    TestPatchPrimitives();
    TestPatchScan();
    TestIatReplacement();
    TestSavegames();
    TestCore();
    TestWebConnect();
    TestMenu();
    TestVram();
    TestRegistry();
    TestProfile();
    TestSkipLauncherTable();
    TestSkipLauncherPass();
    TestSkipLauncherCreateFileSlot();
    TestSkipLauncherStub();
    TestLaunchWithPlayGTAIV();
    TestLegacyLauncherStage();
    TestWindowed();
    TestWarnings();
    TestProbe();
    TestStartupOrder();

    std::printf("%d check(s), %d failure(s)\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
