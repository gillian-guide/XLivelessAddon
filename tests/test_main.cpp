// SPDX-License-Identifier: GPL-3.0-or-later
//
// The native suite: no game needed. One executable, no framework; a check prints
// PASS/FAIL and the process exits non-zero if anything failed.
//
// The suite pins the INI grammar/precedence, the build table, the installer
// primitives and their widths, the recovered SkipLauncher tables and pass, the
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
                  "DoNotPauseOnMinimize=1\n");

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
        // still survive, and only the two windowed options are gated.
        WriteFile(work / "GTAIV.EFLC.FusionFix.asi", "");
        Check(xla::config::FusionFixPresent(work.Path()),
              "divergence: a FusionFix ASI next to the module is detected");

        loaded = xla::config::Load(work.Path(), work.Path());
        const auto gated = xla::config::ApplyFusionFixGates(loaded.options);
        Check(gated.size() == 2, "divergence: the FusionFix gate covers only the windowed options",
              std::to_string(gated.size()));
        Check(loaded.options.customUserProfilePath == "D:\\Saves",
              "divergence: CustomUserProfilePath survives with FusionFix present");
        Check(!loaded.options.borderlessWindowed && !loaded.options.doNotPauseOnMinimize,
              "divergence: the windowed options are gated when FusionFix is present");
        xla::config::Publish(loaded);
        Check(xla::Game::Get().OptionString("CustomUserProfilePath") == "D:\\Saves",
              "divergence: the profile path is still published after the gate");
    }

    void TestAllOff()
    {
        TempDir work("xla-all-off");
        WriteFile(work / "XLivelessAddon.ini",
                  "[Options]\nSavegameFix=0\nSkipLauncher=0\nLegacyLauncher=0\n"
                  "RemoveRegistryPathDependency=0\nDoNotPauseOnMinimize=0\n"
                  "BorderlessWindowed=0\nStartupWarnings=0\n"
                  "RemoveDataIntegrityChecks=0\nSkipTokenActivation=0\n"
                  "SkipFirstTimePlayAsk=0\nSkipInternetConnectionCheck=0\n"
                  "SkipHealthCheck=0\n"
                  "[USERPROFILE]\nCustomUserProfilePath=\n");
        auto loaded = xla::config::Load(work.Path(), work.Path());
        xla::config::Publish(loaded);
        Check(!loaded.options.legacyLauncher && !loaded.options.startupWarnings,
              "all-off: the new toggles are read");
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
        flip("RemoveRegistryPathDependency");
        flip("RemoveDataIntegrityChecks");
        flip("SkipTokenActivation");
        flip("SkipFirstTimePlayAsk");
        flip("SkipInternetConnectionCheck");
        flip("SkipHealthCheck");
        flip("BorderlessWindowed");
        flip("DoNotPauseOnMinimize");

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
        // The CRC32 bypass is the only install left here: the save path moved to
        // [USERPROFILE] CustomUserProfilePath.
        std::vector<std::byte> buffer(0x1000, std::byte{0});
        WriteBytes(buffer, 0x700, BytesOf("75 ? 83 C1 01 83 C0 01 83 F9 04"));
        xla::savegames::Install(xla::Image{buffer.data(), buffer.size()});
        Check(buffer[0x700] == std::byte{0x90} && buffer[0x701] == std::byte{0x90},
              "savegames: the CRC32 branch is NOPed");
        Check(buffer[0x702] == std::byte{0x83},
              "savegames: only the two branch bytes are replaced");

        // A missing signature is a logged skip, never a fault.
        std::vector<std::byte> empty(0x100, std::byte{0});
        xla::savegames::Install(xla::Image{empty.data(), empty.size()});
        Check(true, "savegames: a missing crc32 signature is a clean skip");
    }

    void TestCore()
    {
        // Every recovered row writes its shape at its offset. One synthetic image
        // holds a copy of each signature, far enough apart that the writes cannot
        // collide; `BytesOf` fills the wildcards with NOPs, which the scanner's
        // mask ignores.
        constexpr std::size_t kStride = 0x100;
        const std::array<std::span<const xla::core::Row>, 5> tables{
            xla::core::DataIntegrityRows(),
            xla::core::TokenActivationRows(),
            xla::core::FirstTimePlayRows(),
            xla::core::InternetConnectionRows(),
            xla::core::HealthCheckRows(),
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
        none.internetConnection = false;
        none.healthCheck = false;
        const auto off =
            xla::core::Install(xla::Image{untouched.data(), untouched.size()}, none);
        Check(off.applied == 0 && off.missing == 0 && untouched == image,
              "core: all five keys off leaves the image untouched");
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
        const std::array<std::string_view, 23> expected{{
            "Banner", "Console", "SingleInstance", "Loader", "Probe", "Paths", "Config",
            "FusionFix", "ReportConfiguration", "Image", "Writable", "Build", "Profile",
            "Savegames", "SkipLauncher", "BorderlessWindow", "FocusLoss", "CorePatches",
            "LauncherStage", "DoNotPauseOnMinimize", "DefWindowProcShims", "Registry", "Complete",
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
    TestRegistry();
    TestProfile();
    TestSkipLauncherTable();
    TestSkipLauncherPass();
    TestSkipLauncherCreateFileSlot();
    TestSkipLauncherStub();
    TestLegacyLauncherStage();
    TestWindowed();
    TestWarnings();
    TestProbe();
    TestStartupOrder();

    std::printf("%d check(s), %d failure(s)\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
