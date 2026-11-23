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
// CRC32 bypass, the IAT replacement, the recovered [COMPATIBILITY] family (the two
// file/save arms with their write sets and gates, the GFWL protection byte patch with
// its module-image guard, and the Steam achievement table with its refusal path), the
// startup order and the deliberate user-data divergence from the old addon.

#include <common.hxx>
#include <injector/injector.hpp>
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
import compatibility;
import steam;
import episodes;
import stability;
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

        // An import by ordinal: the thunk names the ordinal, and the slot starts
        // unbound (callers overwrite it with SetSlot when the test needs a value).
        void AddOrdinal(WORD ordinal)
        {
            auto* thunks = reinterpret_cast<IMAGE_THUNK_DATA*>(image.data() + 0x400);
            auto* iat = reinterpret_cast<IMAGE_THUNK_DATA*>(image.data() + 0x500);
            thunks[count].u1.Ordinal =
                static_cast<ULONG_PTR>(IMAGE_ORDINAL_FLAG) | ordinal;
            iat[count].u1.Function = 0;
            ++count;
        }

        void SetSlot(std::size_t index, void* value)
        {
            auto* iat = reinterpret_cast<IMAGE_THUNK_DATA*>(image.data() + 0x500);
            iat[index].u1.Function = reinterpret_cast<ULONG_PTR>(value);
        }

        HMODULE Handle() { return reinterpret_cast<HMODULE>(image.data()); }

        void* Slot(std::size_t index)
        {
            auto* iat = reinterpret_cast<IMAGE_THUNK_DATA*>(image.data() + 0x500);
            return reinterpret_cast<void*>(iat[index].u1.Function);
        }
    };

    // A synthetic PE32 export table with the xlive shapes the classification must
    // separate: the ABI (XLiveInitialize + the XUserWriteAchievements ordinal) with
    // or without the two markers. The buffer is addressed like a mapped image
    // (RVA == offset), which is what ProbeXliveExports assumes of a loaded module.
    struct SyntheticXlive
    {
        static constexpr std::size_t kSize = 0x4000;
        static constexpr std::uint32_t kInitialiseRva = 0x1000;
        static constexpr std::uint32_t kWriteRva = 0x1010;
        static constexpr std::uint32_t kMarkerRva = 0x1020;
        // Ordinal 5278 - 5000 + 1: the smallest table that spans both probe ordinals.
        static constexpr std::uint32_t kFunctionCount = 279;
        static constexpr std::uint32_t kOrdinalBase = 5000;

        std::vector<std::uint8_t> image;

        SyntheticXlive(bool initialiseName, bool loaderMarker, bool exportWrite)
            : image(kSize, 0)
        {
            auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image.data());
            dos->e_magic = IMAGE_DOS_SIGNATURE;
            dos->e_lfanew = 0x40;
            auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(image.data() + dos->e_lfanew);
            nt->Signature = IMAGE_NT_SIGNATURE;
            nt->FileHeader.Machine = IMAGE_FILE_MACHINE_I386;
            nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER32);
            nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
            nt->OptionalHeader.SizeOfImage = static_cast<DWORD>(kSize);
            nt->OptionalHeader.NumberOfRvaAndSizes = 16;
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress =
                0x200;
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size = 0x100;

            auto* exports =
                reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(image.data() + 0x200);
            exports->Name = 0x300;
            exports->Base = kOrdinalBase;
            exports->NumberOfFunctions = kFunctionCount;
            exports->AddressOfFunctions = 0x400;
            exports->AddressOfNames = 0x900;
            exports->AddressOfNameOrdinals = 0xA00;
            std::memcpy(image.data() + 0x300, "xlive.dll", sizeof("xlive.dll"));

            auto* functions = reinterpret_cast<std::uint32_t*>(image.data() + 0x400);
            functions[0] = kInitialiseRva;
            functions[1] = kMarkerRva;
            if (exportWrite)
            {
                functions[kFunctionCount - 1] = kWriteRva;
            }

            auto* names = reinterpret_cast<std::uint32_t*>(image.data() + 0x900);
            auto* ordinals = reinterpret_cast<std::uint16_t*>(image.data() + 0xA00);
            std::uint32_t nameCount = 0;
            std::size_t textAt = 0xB00;
            const auto addName = [&](std::string_view name, std::uint16_t index)
            {
                names[nameCount] = static_cast<std::uint32_t>(textAt);
                ordinals[nameCount] = index;
                std::memcpy(image.data() + textAt, name.data(), name.size());
                textAt += name.size() + 1;
                ++nameCount;
            };
            if (initialiseName)
            {
                addName("XLiveInitialize", 0);
            }
            if (loaderMarker)
            {
                addName("IsUltimateASILoader", 1);
            }
            exports->NumberOfNames = nameCount;
        }
    };

    // The suite's record of the hook's order: 'O' when a synthetic original runs,
    // 'M' when the mirror observes an id. "OM" is the contract (original first).
    std::string g_steamOrder;
    std::vector<std::uint32_t> g_steamMirrored;

    std::uint32_t __stdcall SteamOriginalFirst(std::uint32_t,
                                               const xla::steam::XUserAchievement*,
                                               void*) noexcept
    {
        g_steamOrder += 'O';
        return 0x5A5A;
    }

    std::uint32_t __stdcall SteamOriginalOther(std::uint32_t,
                                               const xla::steam::XUserAchievement*,
                                               void*) noexcept
    {
        g_steamOrder += 'X';
        return 0x1111;
    }

    void RecordSteamMirror(std::uint32_t id) noexcept
    {
        g_steamOrder += 'M';
        g_steamMirrored.push_back(id);
    }

    using SteamWriteSlotFn = std::uint32_t(__stdcall*)(std::uint32_t,
                                                       const xla::steam::XUserAchievement*,
                                                       void*);

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
        Check(game.Option("LoadDLCs") && game.Option("BenchmarkFix") &&
                  game.Option("CombinedRadioFreezeFix"),
              "config: the three ported fixes default on");
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
        Check(game.Option("NewFilesCompatibility") &&
                  game.Option("NewSavesCompatibility") &&
                  game.Option("GFWLProtectionDisabler") &&
                  game.Option("SteamAchievements"),
              "config: the four recovered [COMPATIBILITY] keys default on");

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
                  "NewFilesCompatibility=0\nNewSavesCompatibility=0\n"
                  "GFWLProtectionDisabler=0\nSteamAchievements=0\n"
                  "LoadDLCs=0\nBenchmarkFix=0\nCombinedRadioFreezeFix=0\n"
                  "SkipIntro=0\nSkipMenu=0\nVRAMFix=0\n"
                  "[USERPROFILE]\nCustomUserProfilePath=\n");
        auto loaded = xla::config::Load(work.Path(), work.Path());
        xla::config::Publish(loaded);
        Check(!loaded.options.legacyLauncher && !loaded.options.startupWarnings,
              "all-off: the new toggles are read");
        Check(!loaded.options.skipWebConnect && !loaded.options.skipIntro &&
                  !loaded.options.skipMenu && !loaded.options.vramFix,
              "all-off: the four restored keys are read");
        Check(!loaded.options.newFilesCompatibility &&
                  !loaded.options.newSavesCompatibility &&
                  !loaded.options.gfwlProtectionDisabler &&
                  !loaded.options.steamAchievements,
              "all-off: the four [COMPATIBILITY] keys are read");
        Check(!loaded.options.loadDLCs && !loaded.options.benchmarkFix &&
                  !loaded.options.combinedRadioFreezeFix,
              "all-off: the three ported fixes are read");
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
        flip("NewFilesCompatibility");
        flip("NewSavesCompatibility");
        flip("GFWLProtectionDisabler");
        flip("SteamAchievements");
        flip("LoadDLCs");
        flip("BenchmarkFix");
        flip("CombinedRadioFreezeFix");
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

        // The recovered option masks index the original mod's own build ids, which
        // are not this enum's values: the mapping is pinned per build.
        Check(xla::OriginalBuildId(xla::GameBuild::v1000) == 1u &&
                  xla::OriginalBuildId(xla::GameBuild::v1040) == 5u &&
                  xla::OriginalBuildId(xla::GameBuild::v1050) == 6u &&
                  xla::OriginalBuildId(xla::GameBuild::v1060) == 7u &&
                  xla::OriginalBuildId(xla::GameBuild::v1070) == 8u &&
                  xla::OriginalBuildId(xla::GameBuild::v1080) == 9u &&
                  xla::OriginalBuildId(xla::GameBuild::v1100) == 10u &&
                  xla::OriginalBuildId(xla::GameBuild::v1110) == 11u &&
                  xla::OriginalBuildId(xla::GameBuild::v1120) == 12u &&
                  xla::OriginalBuildId(xla::GameBuild::v1130) == 13u,
              "build: the original ids are the recovered classify switch's");
        Check(!xla::OriginalBuildId(xla::GameBuild::v1010).has_value() &&
                  !xla::OriginalBuildId(xla::GameBuild::unknown).has_value(),
              "build: builds the original mod did not classify have no id");
        Check(xla::BuildInMask(xla::GameBuild::v1080, 0x380u) &&
                  !xla::BuildInMask(xla::GameBuild::v1000, 0x380u) &&
                  !xla::BuildInMask(xla::GameBuild::v1010, 0xFFFFFFFFu) &&
                  !xla::BuildInMask(xla::GameBuild::unknown, 0xFFFFFFFFu),
              "build: a mask tests the original id, and an unknown build no mask");
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

        injector::MakeRET(injector::raw_ptr(memory + 0x120), 8, true);
        Check(memory[0x120] == 0xC2, "patch: ret 8 applies");
        Check(memory[0x120] == 0xC2 && memory[0x121] == 0x08 && memory[0x122] == 0x00,
              "patch: ret 8 is C2 08 00 (three bytes)");
        Check(memory[0x123] == 0xCC, "patch: ret 8 does not write a fourth byte");

        injector::MakeRET(injector::raw_ptr(memory + 0x130), 0, true);
        Check(memory[0x130] == 0xC3, "patch: ret applies");
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

    // A synthetic image whose bytes a real hook may patch must outlive the process:
    // the injector's inline hooks are registered in module state and write the
    // original bytes back when they are destroyed at exit, so a freed heap buffer
    // would fault there. These pages are deliberately never released.
    std::byte* PinnedImage(std::size_t size = 0x1000)
    {
        auto* page = static_cast<std::byte*>(
            ::VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        if (page != nullptr)
        {
            std::memset(page, 0, size);
        }
        return page;
    }

    void WriteBytesAt(std::byte* image, std::size_t offset,
                      const std::vector<std::uint8_t>& bytes)
    {
        std::memcpy(image + offset, bytes.data(), bytes.size());
    }

    void WriteDwordAt(std::byte* image, std::size_t offset, std::uint32_t value)
    {
        std::memcpy(image + offset, &value, sizeof(value));
    }

    std::vector<std::byte> Snapshot(const std::byte* image, std::size_t size)
    {
        return {image, image + size};
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
        // The image must be pinned: the install leaves a live inline hook (and its
        // trampoline) registered in module state, and the injector writes the original
        // bytes back when that hook is destroyed at process exit.
        std::byte* image = PinnedImage();
        Check(image != nullptr, "menu: the synthetic intro image allocates");
        WriteBytesAt(image, kIntroAt, BytesOf("8B 0D ? ? ? ? 8B 54 24 1C 83 C4 0C"));
        WriteDwordAt(image, kIntroAt + 2,
                     static_cast<std::uint32_t>(
                         reinterpret_cast<std::uintptr_t>(image) + kScreenIdAt));
        WriteDwordAt(image, kScreenIdAt, kImageScreenId);
        const auto introPristine = Snapshot(image, 0x1000);

        Check(InstallIntro(xla::Image{image, 0x1000}, true),
              "menu: the intro hook installs on a 1.0.8.0-shaped window");
        const auto introAfter = Snapshot(image, 0x1000);
        Check(introAfter[kIntroAt] != introPristine[kIntroAt],
              "menu: the window's head becomes the injector's jump");
        Check(std::all_of(introAfter.begin() + kIntroAt + 5,
                          introAfter.begin() + kIntroAt + kIntroHookLength,
                          [](std::byte value) { return value == std::byte{0x90}; }),
              "menu: the rest of the window is NOPed");
        Check(introAfter[kIntroAt + kIntroHookLength] ==
                      introPristine[kIntroAt + kIntroHookLength] &&
                  introAfter[kIntroAt + kIntroHookLength + 1] ==
                      introPristine[kIntroAt + kIntroHookLength + 1],
              "menu: the instruction after the window is the resume, untouched");
        const std::array introSpans{
            std::pair<std::size_t, std::size_t>{kIntroAt, kIntroHookLength}};
        Check(OnlyChangedWithin(introAfter, introPristine, introSpans),
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
        std::byte* v1Image = PinnedImage();
        Check(v1Image != nullptr, "menu: the second synthetic intro image allocates");
        WriteBytesAt(v1Image, kIntroAt, BytesOf(kIntroPatternV1));
        WriteDwordAt(v1Image, kIntroAt + 2,
                     static_cast<std::uint32_t>(
                         reinterpret_cast<std::uintptr_t>(v1Image) + kScreenIdAt));
        WriteDwordAt(v1Image, kScreenIdAt, kImageScreenId);
        Check(InstallIntro(xla::Image{v1Image, 0x1000}, true),
              "menu: the pre-1.0.8.0 intro pattern installs");
        runFunctor(4000);
        Check(regs.eax == 0 && regs.edx == kInitialEdx,
              "menu: the v1 variant zeroes eax and leaves edx alone",
              std::format("eax={:#x} edx={:#x}", regs.eax, regs.edx));

        // SkipIntro off keeps the screen time. The window is patched, so a fresh image
        // is the one that still carries the pattern.
        std::byte* offImage = PinnedImage();
        Check(offImage != nullptr, "menu: the third synthetic intro image allocates");
        WriteBytesAt(offImage, kIntroAt, BytesOf("8B 0D ? ? ? ? 8B 54 24 1C 83 C4 0C"));
        WriteDwordAt(offImage, kIntroAt + 2,
                     static_cast<std::uint32_t>(
                         reinterpret_cast<std::uintptr_t>(offImage) + kScreenIdAt));
        WriteDwordAt(offImage, kScreenIdAt, kImageScreenId);
        Check(InstallIntro(xla::Image{offImage, 0x1000}, false),
              "menu: the intro hook installs with the key off");
        runFunctor(4000);
        Check(regs.edx == 4000,
              "menu: SkipIntro off keeps the screen time", std::to_string(regs.edx));

        // Put the intro state back on for the latch check at the end of the test.
        std::byte* latchedImage = PinnedImage();
        Check(latchedImage != nullptr, "menu: the fourth synthetic intro image allocates");
        WriteBytesAt(latchedImage, kIntroAt, BytesOf("8B 0D ? ? ? ? 8B 54 24 1C 83 C4 0C"));
        WriteDwordAt(latchedImage, kIntroAt + 2,
                     static_cast<std::uint32_t>(
                         reinterpret_cast<std::uintptr_t>(latchedImage) + kScreenIdAt));
        WriteDwordAt(latchedImage, kScreenIdAt, kImageScreenId);
        Check(InstallIntro(xla::Image{latchedImage, 0x1000}, true),
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
              "vram: FusionFix's device-slot patterns are unchanged");
        Check(_2048mb == 2147483648ull, "vram: FusionFix's 2 GB floor is pinned");
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

        // ---- the FusionFix generation's value contract ----------------------
        // memory.ixx:210-214 (the replacement) and memory.ixx:197-198 (the GPU read).
        constexpr std::uint64_t gb = 1024ull * 1024 * 1024;
        Check(ReplacementValue(3 * gb, 0, 0) == 3 * gb,
              "vram: an answer of 2 GB or more is passed through");
        Check(ReplacementValue(_2048mb + 1, 0, 0) == _2048mb + 1,
              "vram: the pass-through starts at exactly 2 GB plus one");
        Check(ReplacementValue(1 * gb, 4 * gb, 0) == 4 * gb,
              "vram: the preferred GPU memory is part of the maximum");
        Check(ReplacementValue(1 * gb, 0, 3 * gb) == 3 * gb,
              "vram: the d3d9 texture memory is part of the maximum");
        Check(ReplacementValue(1 * gb, 1 * gb, 1 * gb) == _2048mb,
              "vram: a small answer is floored at 2 GB");
        Check(PreferredGpuValue(0, 0, 8 * gb) == _2048mb,
              "vram: the preferred memory is floored at 2 GB");
        Check(PreferredGpuValue(3 * gb, 0, 8 * gb) == 3 * gb,
              "vram: a 3 GB budget is kept under the half-RAM cap");
        Check(PreferredGpuValue(6 * gb, 0, 8 * gb) == 4 * gb,
              "vram: the preferred memory is capped at half the system RAM");
        Check(PreferredGpuValue(1 * gb, 512ull * 1024 * 1024, 16 * gb) == _2048mb,
              "vram: the 2 GB floor wins over a smaller dedicated answer");
        Check(PreferredGpuValue(1 * gb, 2 * gb + 4096, 16 * gb) == 2 * gb + 4096,
              "vram: the dedicated fallback joins the budget before the caps");

        // The pointer guard the copied code relies on: a loaded module's range is
        // code, a private page is not.
        Check(xla::IsModuleRange(::GetModuleHandleW(nullptr)),
              "vram: the main module lies in a module range");
        Check(!xla::IsModuleRange(nullptr) && !xla::IsModuleRange(reinterpret_cast<const void*>(0xDEADBEEFu)),
              "vram: a null pointer and a private address are outside every module");

        // ---- the install gate ------------------------------------------------
        // Nothing is installed yet, so a build without the patterns stays inert.
        Check(!HookInstalled(), "vram: no FusionFix hook before the install");

        {
            std::vector<std::byte> empty(0x100, std::byte{0});
            Check(Install(xla::Image{empty.data(), empty.size()}).path == Path::none,
                  "vram: no path matched a build without any pattern");
            Check(!HookInstalled(), "vram: ... and nothing was hooked");
        }
        {
            // The entry pattern without the device pattern is a logged skip: the
            // replacement's d3d9 read needs the device slot.
            std::vector<std::byte> noDevice(0x400, std::byte{0});
            WriteBytes(noDevice, 0x100, BytesOf("8B 0D ? ? ? ? 83 EC 14 33 C0"));
            Check(Install(xla::Image{noDevice.data(), noDevice.size()}).path == Path::none,
                  "vram: an entry pattern without the device pattern is a skip");
            Check(!HookInstalled(), "vram: ... and nothing was hooked");
        }
        {
            // A reference row on the same image owns the build: the FusionFix entry
            // is left alone.
            std::vector<std::byte> both(0x400, std::byte{0});
            WriteBytes(both, 0x80, BytesOf(Rows()[0].signature));
            SetCallTarget(both, 0x80, reinterpret_cast<std::uintptr_t>(&VidMemZero));
            WriteBytes(both, 0x100, BytesOf("8B 0D ? ? ? ? 83 EC 14 33 C0"));
            const std::vector<std::byte> bothPristine = both;
            const auto bothReport = Install(xla::Image{both.data(), both.size()});
            Check(bothReport.path == Path::reference && bothReport.rowsApplied == 1,
                  "vram: the reference generation owns a build whose rows match");
            Check(both == bothPristine || both[0x100] == bothPristine[0x100],
                  "vram: ... and the FusionFix entry is not hooked");
            Check(!HookInstalled(), "vram: ... and no FusionFix hook exists");
        }

        {
            // The real install: a page that stays mapped for the process's life, with
            // the entry prologue and FusionFix's device pattern. This is the
            // `safetyhook::create_inline` path, so the check also proves the entry
            // pattern is what installs.
            std::byte* page = PinnedImage(0x2000);
            Check(page != nullptr, "vram: the synthetic image allocates");
            if (page != nullptr)
            {
                constexpr std::size_t kEntryAt = 0x100;
                constexpr std::size_t kDeviceAt = 0x40;
                constexpr std::size_t kSlotAt = 0x180;
                constexpr std::size_t kGlobalAt = 0x1C0;
                const auto base = static_cast<std::uint32_t>(
                    reinterpret_cast<std::uintptr_t>(page));
                WriteBytesAt(page, kEntryAt, BytesOf("8B 0D ? ? ? ? 83 EC 14 33 C0"));
                WriteDwordAt(page, kEntryAt + 2, base + kGlobalAt);
                WriteBytesAt(page, kDeviceAt, BytesOf("83 3D ? ? ? ? 00 74 EF"));
                WriteDwordAt(page, kDeviceAt + 2, base + kSlotAt);
                WriteDwordAt(page, kSlotAt, 0); // no d3d9 device in a test process
                const std::vector<std::byte> pagePristine = Snapshot(page, 0x2000);
                const auto report = Install(xla::Image{page, 0x2000});
                Check(report.path == Path::fusionFix && report.rowsApplied == 0,
                      "vram: the FusionFix path installs where the reference rows are absent",
                      std::format("{} {}", PathName(report.path), report.rowsApplied));
                Check(HookInstalled(),
                      "vram: ... through safetyhook, so the replacement owns the entry");
                const std::vector<std::byte> pageAfter = Snapshot(page, 0x2000);
                Check(pageAfter[kEntryAt] != pagePristine[kEntryAt],
                      "vram: ... and the entry became the hook's jump");

                // No device in a test process: the null slot must read as "no d3d9
                // answer", never as a call, and the value path must still answer.
                Check(D3D9TextureMemory() == 0,
                      "vram: a null device slot gives no d3d9 answer");
                Check(ReplacementForOriginal(3 * gb) == 3 * gb,
                      "vram: ... a 3 GB original is still passed through");
                Check(ReplacementForOriginal(1 * gb) >= _2048mb,
                      "vram: ... and a 1 GB original is raised to at least the 2 GB floor",
                      std::to_string(ReplacementForOriginal(1 * gb)));

                // A device whose vtable is not inside any module is rejected before the
                // copied code calls it: the 08:21 crash was a call through one
                // (0xC0000005 at 0x0649000E, an unmapped private page).
                std::byte* bogusDevice = PinnedImage(0x100);
                Check(bogusDevice != nullptr, "vram: the bogus device allocates");
                if (bogusDevice != nullptr)
                {
                    WriteDwordAt(bogusDevice, 0, 0xDEADBEEFu); // not a module address
                    WriteDwordAt(page, kSlotAt,
                                 static_cast<std::uint32_t>(
                                     reinterpret_cast<std::uintptr_t>(bogusDevice)));
                    Check(D3D9TextureMemory() == 0,
                          "vram: a device whose vtable is not in a module is rejected");
                    Check(ReplacementForOriginal(3 * gb) == 3 * gb,
                          "vram: ... and the pass-through path still answers");
                }
            }
        }
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

    // ---- NewFilesCompatibility / NewSavesCompatibility -----------------------
    //
    // The two recovered file/save path arms, driven exactly as the install pass
    // drives them. The scanner caches hits per signature string for the life of the
    // process, so the missing-anchor pass runs first and the write-set pass runs
    // after it, each on a persistent image (`static` vectors: the injector's writes
    // and the scanner's hints both outlive the test function).

    void TestCompatibility()
    {
        // ---- the missing-anchor pass ----------------------------------------
        // An image with room but no recovered anchor: every arm is a logged skip and
        // nothing is published. It runs first because a later scan of the same string
        // over another image would be answered from these hints if any existed.
        static std::vector<std::byte> bare(0x100, std::byte{0});
        const xla::Image bareView{bare.data(), bare.size()};

        xla::compatibility::Prepare();

        const auto noneFiles = xla::compatibility::InstallNewFiles(bareView, false);
        Check(noneFiles.applied == 0 && noneFiles.missing == 3,
              "compatibility: a missing NewFiles anchor is a skip",
              std::format("{}/{}", noneFiles.applied, noneFiles.missing));
        xla::compatibility::PublishNewFiles(bareView, false);

        const auto noneSaves =
            xla::compatibility::InstallNewSaves(bareView, xla::GameBuild::v1080);
        Check(noneSaves.applied == 0 && noneSaves.missing == 1,
              "compatibility: a missing NewSaves anchor is a skip");
        xla::compatibility::PublishNewSaves(bareView);

        const xla::compatibility::NewSavesSites noSites =
            xla::compatibility::ResolveNewSavesSites(bareView);
        const auto noneSites = xla::compatibility::ApplyNewSavesSites(noSites, 0, 0);
        Check(noSites.branch == nullptr && noSites.read == nullptr && noSites.load == nullptr &&
                  noneSites.applied == 0 && noneSites.missing == 3,
              "compatibility: missing converter sites are skips");

        const auto nothingPublished = xla::compatibility::PublishedForTest();
        Check(nothingPublished.registerSlot == 0 && nothingPublished.saveName == 0 &&
                  nothingPublished.loadResume == 0 && nothingPublished.loadData == 0 &&
                  nothingPublished.secondLoadOriginal == 0,
              "compatibility: a missed anchor publishes nothing");

        // ---- the recovered rows and body VAs --------------------------------
        const auto anchors = xla::compatibility::RecoveredAnchors();
        Check(anchors.updateA ==
                      "E8 ? ? ? ? 8B 36 85 F6 75 ED E8 ? ? ? ? 8B 3F 03 EB 85 FF 0F 85 7B FF "
                      "FF FF" &&
                  anchors.updateB ==
                      "E8 ? ? ? ? 8B 36 85 F6 75 ED E8 ? ? ? ? 8B 3F 03 EB 85 FF 0F 85 6C FF "
                      "FF FF",
              "compatibility: the two update anchors are the recovered rows");
        Check(anchors.registrar == "68 64 28 C8 67 E8",
              "compatibility: the registrar anchor is the recovered row");
        Check(anchors.saveName == "68 ? ? ? ? E8 ? ? ? ? 8B 2D ? ? ? ? 83 C4 08" &&
                  anchors.saveResume == "89 84 24 E0 01 00 00 8B 45 08 53 33 DB",
              "compatibility: the two NewSaves anchors are the recovered rows");
        Check(anchors.branchSite == "74 37 80 3D ? ? ? ? 00 75 2E 8D 84 ? ? ? ? 00 6A 1E" &&
                  anchors.readSite == "68 BE 0C 00 00 50 E8" &&
                  anchors.loadSite ==
                      "56 E8 ? ? ? ? E8 ? ? ? ? A1 ? ? ? ? 8D 0C 85 00 00 00 00",
              "compatibility: the three converter anchors are the recovered rows");

        using xla::compatibility::Body;
        const std::array<std::pair<Body, std::uint32_t>, 9> vas{{
            {Body::register_tail, 0x10051600},
            {Body::update_a, 0x10051890},
            {Body::update_b, 0x100518D0},
            {Body::read_hook, 0x10051A90},
            {Body::second_load, 0x10051AD0},
            {Body::trampoline, 0x100521E0},
            {Body::prepare, 0x10051FD0},
            {Body::convert, 0x10051B30},
            {Body::resolver, 0x10003E50},
        }};
        bool vasMatch = true;
        for (const auto& [body, va] : vas)
        {
            vasMatch = vasMatch && xla::compatibility::BodyVa(body) == va &&
                       xla::compatibility::ResolveBody(body) != 0;
        }
        Check(vasMatch, "compatibility: every body keeps its recovered VA");

        // ---- the write set, on an image that carries every anchor -----------
        constexpr std::size_t kUpdateA = 0x100;
        constexpr std::size_t kUpdateB = 0x200;
        constexpr std::size_t kRegistrar = 0x300;
        constexpr std::size_t kSaveName = 0x400;
        constexpr std::size_t kSaveResume = 0x500;
        constexpr std::size_t kBranchSite = 0x600;
        constexpr std::size_t kReadSite = 0x700;
        constexpr std::size_t kLoadSite = 0x800;
        constexpr std::uint32_t kRegisterEntry = 0x10005000;
        constexpr std::uint32_t kSaveNameBuffer = 0x0012A000;
        constexpr std::uint32_t kReadDataEntry = 0x10006000;
        constexpr std::uint32_t kSecondLoadEntry = 0x10007000;
        constexpr std::uint32_t kSharedReadEntry = 0x10008000;

        static std::vector<std::byte> image(0x1000, std::byte{0});
        WriteBytes(image, kUpdateA, BytesOf(anchors.updateA));
        WriteBytes(image, kUpdateB, BytesOf(anchors.updateB));
        WriteBytes(image, kRegistrar, BytesOf(anchors.registrar));
        SetCallTarget(image, kRegistrar + 5, kRegisterEntry); // the registrar's `call`

        WriteBytes(image, kSaveName, BytesOf(anchors.saveName));
        WriteDword(image, kSaveName + 1, kSaveNameBuffer); // the pushed buffer address
        WriteBytes(image, kSaveResume, BytesOf(anchors.saveResume));

        WriteBytes(image, kBranchSite, BytesOf(anchors.branchSite));
        WriteBytes(image, kReadSite, BytesOf(anchors.readSite));
        SetCallTarget(image, kReadSite + 6, kReadDataEntry); // `call LoadData`
        WriteBytes(image, kLoadSite, BytesOf(anchors.loadSite));
        SetCallTarget(image, kLoadSite + 6, kSecondLoadEntry); // the second LoadData call
        image[kLoadSite + 0x1D] = std::byte{0xE8};             // the function's later call
        SetCallTarget(image, kLoadSite + 0x1D, kSharedReadEntry); // the shared read entry

        const xla::Image view{image.data(), image.size()};

        // ---- NewFilesCompatibility ------------------------------------------
        xla::compatibility::PublishNewFiles(view, false);
        Check(xla::compatibility::PublishedForTest().registerSlot == kRegisterEntry,
              "newFiles: the published slot is the registrar's call target");

        const std::vector<std::byte> pristine = image;
        const auto files = xla::compatibility::InstallNewFiles(view, false);
        Check(files.applied == 3 && files.missing == 0,
              "newFiles: the two update calls and the registrar tail apply",
              std::format("{}/{}", files.applied, files.applied + files.missing));
        Check(image[kUpdateA] == std::byte{0xE8} &&
                  CallTarget(image, kUpdateA) ==
                      xla::compatibility::ResolveBody(Body::update_a),
              "newFiles: the first update call targets its body");
        Check(image[kUpdateB] == std::byte{0xE8} &&
                  CallTarget(image, kUpdateB) ==
                      xla::compatibility::ResolveBody(Body::update_b),
              "newFiles: the second update call targets its body");
        Check(image[kRegistrar + 28] == std::byte{0xE9} &&
                  JumpTarget(image, kRegistrar + 28) ==
                      xla::compatibility::ResolveBody(Body::register_tail),
              "newFiles: the registrar's tail jumps to its body");
        const std::array<std::pair<std::size_t, std::size_t>, 3> fileSpans{{
            {kUpdateA, 5},
            {kUpdateB, 5},
            {kRegistrar + 28, 5},
        }};
        Check(OnlyChangedWithin(image, pristine, fileSpans),
              "newFiles: the arm writes only its three sites");

        // The original's gate: GTAC.dll / JacksIVFixes.asi install the same feature,
        // so the arm is skipped entirely (no scan, no write).
        const std::vector<std::byte> afterFiles = image;
        const auto gatedConflict = xla::compatibility::InstallNewFiles(view, true);
        Check(gatedConflict.applied == 0 && gatedConflict.missing == 0 && image == afterFiles,
              "newFiles: a loaded GTAC.dll/JacksIVFixes.asi skips the arm");

        // ---- NewSavesCompatibility ------------------------------------------
        xla::compatibility::PublishNewSaves(view);
        const auto published = xla::compatibility::PublishedForTest();
        Check(published.saveName == kSaveNameBuffer,
              "newSaves: the published slot is the pushed save-name buffer");
        Check(published.loadResume == static_cast<std::uint32_t>(
                                          reinterpret_cast<std::uintptr_t>(image.data()) +
                                          kSaveResume + 13),
              "newSaves: the load continuation is the anchor's +0xD");

        Check(xla::compatibility::BuildHasNewSaves(xla::GameBuild::v1060) &&
                  xla::compatibility::BuildHasNewSaves(xla::GameBuild::v1070) &&
                  xla::compatibility::BuildHasNewSaves(xla::GameBuild::v1080),
              "newSaves: the recovered [1060-1080] mask is the gate");
        Check(!xla::compatibility::BuildHasNewSaves(xla::GameBuild::v1000) &&
                  !xla::compatibility::BuildHasNewSaves(xla::GameBuild::v1040) &&
                  !xla::compatibility::BuildHasNewSaves(xla::GameBuild::v1100) &&
                  !xla::compatibility::BuildHasNewSaves(xla::GameBuild::v1110) &&
                  !xla::compatibility::BuildHasNewSaves(xla::GameBuild::v1130) &&
                  !xla::compatibility::BuildHasNewSaves(xla::GameBuild::unknown),
              "newSaves: every other build is outside it");

        const std::vector<std::byte> beforeSaves = image;
        const auto gatedBuild =
            xla::compatibility::InstallNewSaves(view, xla::GameBuild::v1040);
        Check(gatedBuild.applied == 0 && gatedBuild.missing == 0 && image == beforeSaves,
              "newSaves: a build outside the mask installs nothing");

        const auto saves = xla::compatibility::InstallNewSaves(view, xla::GameBuild::v1080);
        Check(saves.applied == 1 && saves.missing == 0,
              "newSaves: the load entry jumps to the trampoline");
        Check(image[kSaveResume] == std::byte{0xE9} &&
                  JumpTarget(image, kSaveResume) ==
                      xla::compatibility::ResolveBody(Body::trampoline),
              "newSaves: ... and the destination is the transcribed trampoline");

        // ---- the converter's three sites ------------------------------------
        // The sites are resolved once for the life of the process (the original's
        // TLS-guarded statics), so the suite resolves them once too and applies them
        // repeatedly; a per-load re-scan would lose the branch after the first newer
        // save rewrote it.
        const xla::compatibility::NewSavesSites sites =
            xla::compatibility::ResolveNewSavesSites(view);
        const auto byteAt = [](std::size_t offset)
        { return reinterpret_cast<std::uint8_t*>(image.data() + offset); };
        Check(sites.branch == byteAt(kBranchSite) && sites.read == byteAt(kReadSite) &&
                  sites.load == byteAt(kLoadSite),
              "newSaves: the three converter sites resolve to their anchors");

        // The older layout first: the branch, the pushed size and the branch word stay
        // at the old values (the branch byte is the anchor's own `jz`).
        const std::vector<std::byte> beforeSites = image;
        const auto older = xla::compatibility::ApplyNewSavesSites(sites, 0, 0);
        Check(older.applied == 3 && older.missing == 0,
              "newSaves: the three converter sites patch",
              std::format("{}/{}", older.applied, older.applied + older.missing));
        Check(image[kBranchSite] == std::byte{0x74},
              "newSaves: an older save keeps the jz branch");
        Check(image[kReadSite - 5] == std::byte{0x75} && image[kReadSite - 4] == std::byte{0x26},
              "newSaves: an older save keeps the jne branch");
        Check(DwordAt(image.data(), kReadSite + 1) == 0x0CBE,
              "newSaves: an older save pushes the 0xCBE read size");
        Check(image[kReadSite + 6] == std::byte{0xE8} &&
                  CallTarget(image, kReadSite + 6) ==
                      xla::compatibility::ResolveBody(Body::read_hook),
              "newSaves: the read call targets its transcribed hook");
        Check(image[kLoadSite + 6] == std::byte{0xE8} &&
                  CallTarget(image, kLoadSite + 6) ==
                      xla::compatibility::ResolveBody(Body::second_load),
              "newSaves: the second LoadData call targets its hook");
        const std::vector<std::byte> afterOlder = image;

        // The newer layout: `jmp` instead of `jz`, the 0xE6E read size and NOPs in
        // front of it. The published state keeps the original targets the hooks call.
        const auto newer = xla::compatibility::ApplyNewSavesSites(sites, 1, 1);
        Check(newer.applied == 3 && newer.missing == 0,
              "newSaves: the newer layout patches the same three sites");
        Check(image[kBranchSite] == std::byte{0xEB},
              "newSaves: a newer save forces the longer path");
        Check(image[kReadSite - 5] == std::byte{0x90} && image[kReadSite - 4] == std::byte{0x90},
              "newSaves: ... and NOPs the jne branch");
        Check(DwordAt(image.data(), kReadSite + 1) == 0x0E6E,
              "newSaves: ... pushes the 0xE6E read size");
        const auto state = xla::compatibility::PublishedForTest();
        Check(state.secondLoadOriginal == kSecondLoadEntry,
              "newSaves: the second call's original target is kept");
        Check(state.loadData == kSharedReadEntry,
              "newSaves: the shared read entry is the function's later call target");
        const std::array<std::pair<std::size_t, std::size_t>, 5> siteSpans{{
            {kBranchSite, 1},
            {kReadSite - 5, 2},
            {kReadSite + 1, 4},
            {kReadSite + 6, 5},
            {kLoadSite + 6, 5},
        }};
        Check(OnlyChangedWithin(image, beforeSites, siteSpans),
              "newSaves: the converter writes only its three sites");

        // The sites are cached, not re-scanned: the next older save restores the old
        // triple even though the branch byte no longer matches its own anchor. The
        // choice is a pure function of the two flags, and the walk below asserts the
        // same values on a file.
        const auto restored = xla::compatibility::ApplyNewSavesSites(sites, 0, 0);
        Check(restored.applied == 3 && image == afterOlder,
              "newSaves: a cached site survives the branch it rewrote");
    }

    // A synthetic save: the 0x110-byte header with "SAVE" at +0xC, then one 9-byte
    // chunk header per size with the payload that size implies. The walk reads only
    // the headers; the payload is written so the file really has the layout it
    // declares.
    std::vector<std::uint8_t> SaveBytes(std::span<const std::uint32_t> chunkSizes,
                                        std::string_view tag = "BLOCK")
    {
        std::vector<std::uint8_t> bytes(0x110, 0);
        std::memcpy(bytes.data() + 0x0C, "SAVE", 4);
        for (const std::uint32_t size : chunkSizes)
        {
            const std::size_t at = bytes.size();
            bytes.resize(at + 9, 0);
            std::memcpy(bytes.data() + at, tag.data(),
                        std::min<std::size_t>(tag.size(), 5));
            std::memcpy(bytes.data() + at + 5, &size, sizeof(size));
            const std::uint32_t payload = size > 9 ? size - 9 : 0;
            bytes.resize(bytes.size() + payload, 0);
        }
        return bytes;
    }

    // ---- the savegame-load converter's decisions -----------------------------
    //
    // `WalkSaveFile` runs the converter's own walk (`WalkSaveFileInto`) and its own
    // patch choice (`ChoosePatchValues`) and writes nothing; the values asserted here
    // are the recovered literals. The three site writes themselves are pinned by
    // TestCompatibility above, so a bug in either half cannot hide in the other.
    void TestNewSavesWalk()
    {
        TempDir work("xla-save-walk");
        const auto writeFile = [&](std::string_view name, const std::vector<std::uint8_t>& bytes)
        {
            const auto path = work / name;
            std::ofstream stream{path, std::ios::binary | std::ios::trunc};
            stream.write(reinterpret_cast<const char*>(bytes.data()),
                         static_cast<std::streamsize>(bytes.size()));
            return path.string();
        };

        using xla::compatibility::SaveWalkEnd;

        // The older layout: eighteen minimal chunks, so no flag is set.
        std::vector<std::uint32_t> older(18, 9);
        const std::string olderPath = writeFile("older.sav", SaveBytes(older));
        const auto olderWalk = xla::compatibility::WalkSaveFile(olderPath.c_str());
        Check(olderWalk.end == SaveWalkEnd::walked && olderWalk.chunkCount == 18,
              "saveWalk: the older layout walks eighteen chunk headers",
              std::format("{} chunk(s)", olderWalk.chunkCount));
        Check(olderWalk.forceRead == 0 && olderWalk.extraBlock == 0 &&
                  olderWalk.newChunk16 == 0,
              "saveWalk: none of the three newer chunk sizes is found");
        Check(olderWalk.branchOpcode == 0x74 && olderWalk.readSize == 0x0CBE &&
                  olderWalk.readBranch == 0x2675,
              "saveWalk: an older save selects the old triple");
        Check(std::string_view(olderWalk.chunks[0].id, 5) == "BLOCK" &&
                  olderWalk.chunks[0].size == 9,
              "saveWalk: the chunk tag and size are the file's own");

        // The newer layout: the three size literals.
        std::vector<std::uint32_t> newer(18, 9);
        newer[9] = 0x4C45;
        newer[13] = 0x1741;
        newer[16] = 0x0E77;
        const std::string newerPath = writeFile("newer.sav", SaveBytes(newer));
        const auto newerWalk = xla::compatibility::WalkSaveFile(newerPath.c_str());
        Check(newerWalk.end == SaveWalkEnd::walked &&
                  newerWalk.forceRead == 1 && newerWalk.extraBlock == 1 &&
                  newerWalk.newChunk16 == 1,
              "saveWalk: the newer layout sets all three flags");
        Check(newerWalk.branchOpcode == 0xEB && newerWalk.readSize == 0x0E6E &&
                  newerWalk.readBranch == 0x9090,
              "saveWalk: a newer save selects the new triple");

        // One flag alone: the three are independent and only chunk 16 decides the read
        // size and the branch word.
        std::vector<std::uint32_t> mixed(18, 9);
        mixed[16] = 0x0E77;
        const std::string mixedPath = writeFile("mixed.sav", SaveBytes(mixed));
        const auto mixedWalk = xla::compatibility::WalkSaveFile(mixedPath.c_str());
        Check(mixedWalk.forceRead == 0 && mixedWalk.extraBlock == 0 &&
                  mixedWalk.newChunk16 == 1,
              "saveWalk: the three flags are decided independently");
        Check(mixedWalk.branchOpcode == 0x74 && mixedWalk.readSize == 0x0E6E &&
                  mixedWalk.readBranch == 0x9090,
              "saveWalk: ... and only chunk 16 decides the read triple");

        // The rejection paths. A short header, a header without the magic and a chunk
        // size below the nine-byte header are all "rejected" / "notASave", never a
        // fault: the arm's hardening group.
        std::vector<std::uint8_t> shortHeader(0x20, 0);
        std::memcpy(shortHeader.data() + 0x0C, "SAVE", 4);
        Check(xla::compatibility::WalkSaveFile(
                  writeFile("short-header.sav", shortHeader).c_str())
                      .end == SaveWalkEnd::rejected,
              "saveWalk: a short header is rejected");

        std::vector<std::uint8_t> noMagic(0x110, 0);
        Check(xla::compatibility::WalkSaveFile(
                  writeFile("no-magic.sav", noMagic).c_str())
                      .end == SaveWalkEnd::notASave,
              "saveWalk: a header without SAVE at +0xC is not a save");

        std::vector<std::uint32_t> tooSmall{8};
        Check(xla::compatibility::WalkSaveFile(
                  writeFile("small-chunk.sav", SaveBytes(tooSmall)).c_str())
                      .end == SaveWalkEnd::rejected,
              "saveWalk: a chunk size below nine is rejected");

        std::vector<std::uint32_t> nineGood(9, 9);
        nineGood.push_back(8);
        Check(xla::compatibility::WalkSaveFile(
                  writeFile("ninth-bad.sav", SaveBytes(nineGood)).c_str())
                      .end == SaveWalkEnd::rejected,
              "saveWalk: a bad chunk after good ones is rejected");

        Check(xla::compatibility::WalkSaveFile(
                  writeFile("header-only.sav", SaveBytes({})).c_str())
                      .end == SaveWalkEnd::rejected,
              "saveWalk: a header with no chunk table is rejected");

        Check(xla::compatibility::WalkSaveFile(
                  (work / "does-not-exist.sav").string().c_str())
                      .end == SaveWalkEnd::noFile,
              "saveWalk: a missing file is reported, not faulted");
    }

    // ---- GFWLProtectionDisabler ---------------------------------------------
    //
    // The xlive.dll protection byte patch: the module-image guard (an offset is only
    // readable inside the mapped image and on a committed page) and the pre-image byte
    // rule (only the protection branch is flipped). The install refuses a process
    // without a real Games for Windows LIVE image.
    void TestGfwl()
    {
        Check(xla::core::kGfwlProtectionSiteOffset == 0xF1605,
              "gfwl: the protection site is xlive.dll+0xF1605",
              std::to_string(xla::core::kGfwlProtectionSiteOffset));

        const HMODULE module = ::GetModuleHandleW(nullptr);
        MODULEINFO info{};
        const bool gotInfo =
            module != nullptr &&
            ::GetModuleInformation(::GetCurrentProcess(), module, &info, sizeof(info)) != FALSE;
        Check(gotInfo && info.SizeOfImage != 0, "gfwl: the process image size is known");
        if (gotInfo)
        {
            const auto base = reinterpret_cast<std::uintptr_t>(module);
            Check(xla::core::ModuleImageContains(base, 0, 1),
                  "gfwl: the image start is readable");
            Check(xla::core::ModuleImageContains(base, info.SizeOfImage - 1, 1),
                  "gfwl: the last image byte is readable");
            Check(!xla::core::ModuleImageContains(base, info.SizeOfImage, 1),
                  "gfwl: the first byte past the image is refused");
            Check(!xla::core::ModuleImageContains(base, info.SizeOfImage - 1, 2),
                  "gfwl: a read crossing the image end is refused");
            Check(!xla::core::ModuleImageContains(0, 0, 1),
                  "gfwl: a null module is refused");
        }

        // The arm's only write, on a byte the test owns: the pre-image opcode is the
        // guard, so an already-patched site is idempotent and anything else is left
        // alone.
        std::byte bytes[4] = {std::byte{0x74}, std::byte{0xEB}, std::byte{0x75}, std::byte{0x0F}};
        const auto at = [&](std::size_t index)
        { return reinterpret_cast<std::uint8_t*>(&bytes[index]); };
        Check(xla::core::ApplyGfwlProtectionByte(at(0)) && bytes[0] == std::byte{0xEB},
              "gfwl: a jz site becomes the jmp");
        Check(xla::core::ApplyGfwlProtectionByte(at(1)) && bytes[1] == std::byte{0xEB},
              "gfwl: an already-patched site is idempotent");
        Check(!xla::core::ApplyGfwlProtectionByte(at(2)) && bytes[2] == std::byte{0x75},
              "gfwl: a jnz site is left untouched");
        Check(!xla::core::ApplyGfwlProtectionByte(at(3)) && bytes[3] == std::byte{0x0F},
              "gfwl: an unrelated byte is left untouched");
        Check(!xla::core::ApplyGfwlProtectionByte(nullptr),
              "gfwl: a null site is refused");

        // No real xlive in this process: the install is a logged skip.
        Check(!xla::core::InstallGfwlProtectionDisabler(),
              "gfwl: the install refuses a process without xlive.dll");
    }

    // ---- SteamAchievements ---------------------------------------------------
    //
    // The recovered table, the two real refusals, the export-table classification of
    // the loaded xlive.dll, the one forwarding decision, and the hook itself driven
    // through a synthetic xlive.dll import table: a bound GFWL-style slot forwards
    // first and mirrors after, an unbound slot is never called and answers success,
    // and a missing xlive.dll still installs the mirror.
    //
    // What the suite cannot reach: a real GFWL client or a real Ultimate ASI Loader
    // xlive.dll (neither may be loaded here), a real steam_api.dll (the bridge would
    // then initialise Steam), and the "not the game image" branch of Install(), whose
    // image base is this executable by construction. Those are pinned through the
    // shared decision (RefuseInstall / ProbeXliveExports / DecideForwarding) and the
    // measured export tables the classification was built from.
    void TestSteam()
    {
        using namespace xla::steam;

        const auto table = Achievements();
        Check(table.size() == kMaxAchievementId,
              "steam: the recovered table covers ids 1..65", std::to_string(table.size()));
        Check(table.front().id == 1 && table.back().id == 65,
              "steam: the table starts at id 1 and ends at id 65");

        bool ordered = true;
        for (std::size_t index = 0; index < table.size(); ++index)
        {
            ordered = ordered && table[index].id == index + 1 &&
                      table[index].name != nullptr;
        }
        Check(ordered, "steam: the table is id-ordered and every row has a name");
        Check(kWriteAchievementsOrdinal == 5278,
              "steam: the GFWL import is ordinal 5278");
        Check(kXLiveInitialiseOrdinal == 5000,
              "steam: XLiveInitialize is probed at its recovered ordinal 5000");

        const auto nameOf = [](std::uint32_t id) -> std::string_view
        {
            const char* name = AchievementNameForTest(id);
            return name != nullptr ? std::string_view(name) : std::string_view{};
        };
        Check(nameOf(1) == "THETOUR", "steam: id 1 is THE TOUR");
        Check(nameOf(40) == "GAMECOMPLETION100", "steam: id 40 is 100% completion");
        Check(nameOf(41) == "MPTEAMWIN1", "steam: id 41 starts the multiplayer block");
        Check(nameOf(51) == "E1INTRO", "steam: id 51 starts TLAD");
        Check(nameOf(65) == "E2ALLFLAIR", "steam: id 65 is the last TBoGT achievement");
        Check(AchievementNameForTest(0) == nullptr, "steam: id 0 has no Steam name");
        Check(AchievementNameForTest(66) == nullptr, "steam: id 66 has no Steam name");

        // ---- the two refusals that are real ---------------------------------
        //
        // This process is the game image (the suite points the game context at its own
        // executable) and has no steam_api.dll beside it, so no xlive.dll refusal is
        // left: the Steam-API one is reachable end to end and the offline-dump one
        // through the shared decision that Install() calls.
        Check(RefuseInstall(false, true) == InstallRefusal::NotGameImage,
              "steam: an offline dump image is refused");
        Check(RefuseInstall(true, false) == InstallRefusal::NoSteamApi,
              "steam: a missing steam_api.dll is refused");
        Check(RefuseInstall(true, true) == InstallRefusal::None,
              "steam: the game image with steam_api.dll is not refused");
        Check(!Install(), "steam: the bridge refuses without steam_api.dll");
        Check(!Install(), "steam: the refusal is stable");

        // ---- the classification, from the export table only -----------------
        const SyntheticXlive gfwlImage(/*initialiseName=*/true, /*loaderMarker=*/false,
                                       /*exportWrite=*/true);
        const XliveProbe gfwl =
            ProbeXliveExports(gfwlImage.image.data(), gfwlImage.image.size());
        Check(gfwl.loaded && gfwl.functions == SyntheticXlive::kFunctionCount &&
                  gfwl.names == 1,
              "steam: the probe reads a GFWL-shaped export table",
              std::to_string(gfwl.functions) + "/" + std::to_string(gfwl.names));
        Check(gfwl.xliveInitialise && gfwl.writeAchievements && !gfwl.asiLoader,
              "steam: the GFWL shape exports the ABI and no loader marker");
        Check(ClassifyXlive(gfwl) == XliveKind::GfwlClient,
              "steam: a GFWL client is classified GFWL");
        Check(gfwl.ordinalAddress ==
                  gfwlImage.image.data() + SyntheticXlive::kWriteRva,
              "steam: the probe resolves the ordinal-5278 export target");

        // The packed system client's shape: no named exports at all, so
        // XLiveInitialize is recognised by its ordinal and the ABI still wins.
        const SyntheticXlive packedImage(false, false, true);
        const XliveProbe packed =
            ProbeXliveExports(packedImage.image.data(), packedImage.image.size());
        Check(packed.names == 0 && packed.xliveInitialise && packed.writeAchievements,
              "steam: the packed client exports the ABI by ordinal with no names");
        Check(ClassifyXlive(packed) == XliveKind::GfwlClient,
              "steam: the packed client is classified GFWL");

        // Ultimate ASI Loader's xliveless: the same ABI, filled with local emulation,
        // plus the loader's own marker. It must not be a client.
        const SyntheticXlive proxyImage(true, true, true);
        const XliveProbe proxy =
            ProbeXliveExports(proxyImage.image.data(), proxyImage.image.size());
        Check(proxy.asiLoader && proxy.xliveInitialise && proxy.writeAchievements,
              "steam: the xliveless stand-in exports the ABI and the loader marker");
        Check(ClassifyXlive(proxy) == XliveKind::Proxy,
              "steam: the xliveless stand-in is classified a proxy");

        const SyntheticXlive bareImage(true, false, /*exportWrite=*/false);
        const XliveProbe bare =
            ProbeXliveExports(bareImage.image.data(), bareImage.image.size());
        Check(!bare.writeAchievements && ClassifyXlive(bare) == XliveKind::Proxy,
              "steam: a module without the ordinal is a proxy");
        Check(ClassifyXlive({}) == XliveKind::Absent,
              "steam: no module is classified absent");
        Check(!ProbeXliveExports(nullptr, 0).loaded,
              "steam: a null image is not loaded");
        const std::uint8_t junk[64] = {};
        const XliveProbe junkProbe = ProbeXliveExports(junk, sizeof(junk));
        Check(junkProbe.loaded && !junkProbe.writeAchievements &&
                  ClassifyXlive(junkProbe) == XliveKind::Proxy,
              "steam: an unparseable image is a present, non-client module");
        Check(!ProbeLoadedXlive().loaded,
              "steam: this process maps no xlive.dll, so absent is a real path");

        // ---- the one forwarding decision ------------------------------------
        Check(DecideForwarding(gfwl, &SteamOriginalFirst).forward,
              "steam: a GFWL client's bound thunk is forwarded to");
        Check(!DecideForwarding(gfwl, nullptr).forward,
              "steam: a null slot is never called");
        Check(!DecideForwarding(gfwl, reinterpret_cast<const void*>(&WriteAchievements))
                   .forward,
              "steam: the hook itself is never called");
        const int stackObject = 0;
        Check(!DecideForwarding(gfwl, &stackObject).forward,
              "steam: a pointer outside every module is never called");
        Check(!DecideForwarding({}, &SteamOriginalFirst).forward,
              "steam: no xlive module means no forwarding");

        // A proxy's own ordinal export is a real bound thunk; a foreign stub that
        // merely happens to be code in a module is not.
        XliveProbe ownExport = proxy;
        ownExport.ordinalAddress = reinterpret_cast<const void*>(&SteamOriginalFirst);
        Check(DecideForwarding(ownExport, &SteamOriginalFirst).forward,
              "steam: the proxy's own ordinal export is a real bound thunk");
        XliveProbe foreignStub = proxy;
        foreignStub.ordinalAddress = reinterpret_cast<const void*>(&SteamOriginalOther);
        Check(!DecideForwarding(foreignStub, &SteamOriginalFirst).forward,
              "steam: a proxy's foreign stub is never called");

        // ---- the install and the hook, through a real import table ----------
        //
        // ResetInstallForTest leaves the mirror disabled, so no synthetic install can
        // load a real Steam API; the observer still sees every observed id.
        SetMirrorObserverForTest(&RecordSteamMirror);
        const auto callSlot = [](void* slot)
        {
            const XUserAchievement entry{0, 1};
            return reinterpret_cast<SteamWriteSlotFn>(slot)(1, &entry, nullptr);
        };

        // (a) a bound slot pointing at code, GFWL client: the original runs first,
        // the mirror fires after it, and the original's answer reaches the game.
        {
            ResetInstallForTest();
            SyntheticModule game("xlive.dll");
            game.AddOrdinal(kWriteAchievementsOrdinal);
            game.SetSlot(0, reinterpret_cast<void*>(&SteamOriginalFirst));
            Check(InstallInto(game.Handle(), gfwl),
                  "steam: the mirror installs over the game's ordinal slot");
            Check(game.Slot(0) == reinterpret_cast<void*>(&WriteAchievements),
                  "steam: the slot holds the hook after the install");
            g_steamOrder.clear();
            g_steamMirrored.clear();
            const std::uint32_t answer = callSlot(game.Slot(0));
            Check(g_steamOrder == "OM",
                  "steam: the original is called first and the mirror fires after it",
                  g_steamOrder);
            Check(answer == 0x5A5A,
                  "steam: the original's answer reaches the game",
                  std::to_string(answer));
            Check(g_steamMirrored.size() == 1 && g_steamMirrored[0] == 1,
                  "steam: the mirrored id is the one the call carried");
        }

        // (b) an unbound (null) slot: no forward call, the mirror still fires, and
        // the answer is the success value a completed write returns.
        {
            ResetInstallForTest();
            SyntheticModule game("xlive.dll");
            game.AddOrdinal(kWriteAchievementsOrdinal);
            game.SetSlot(0, nullptr);
            Check(InstallInto(game.Handle(), proxy),
                  "steam: the mirror installs over an unbound ordinal slot");
            Check(game.Slot(0) == reinterpret_cast<void*>(&WriteAchievements),
                  "steam: the unbound slot holds the hook after the install");
            g_steamOrder.clear();
            g_steamMirrored.clear();
            const std::uint32_t answer = callSlot(game.Slot(0));
            Check(answer == 0, "steam: an unbound slot answers success",
                  std::to_string(answer));
            Check(g_steamOrder == "M",
                  "steam: the unbound slot is not called, the mirror still fires",
                  g_steamOrder);
        }

        // (c) xlive absent: the mirror installs, and a valid code pointer is still not
        // called, because no module justifies the forward.
        {
            ResetInstallForTest();
            SyntheticModule game("xlive.dll");
            game.AddOrdinal(kWriteAchievementsOrdinal);
            game.SetSlot(0, reinterpret_cast<void*>(&SteamOriginalFirst));
            Check(InstallInto(game.Handle(), {}),
                  "steam: the mirror installs with no xlive.dll mapped");
            g_steamOrder.clear();
            const std::uint32_t answer = callSlot(game.Slot(0));
            Check(answer == 0 && g_steamOrder == "M",
                  "steam: no xlive module means no call, but the mirror fires",
                  g_steamOrder + " " + std::to_string(answer));
        }

        // The proxy's real bound thunk is the one proxy target that is forwarded to
        // (it is the loaded module's own implementation); a foreign stub is not.
        {
            ResetInstallForTest();
            SyntheticModule game("xlive.dll");
            game.AddOrdinal(kWriteAchievementsOrdinal);
            game.SetSlot(0, reinterpret_cast<void*>(&SteamOriginalFirst));
            XliveProbe boundThunk = proxy;
            boundThunk.ordinalAddress =
                reinterpret_cast<const void*>(&SteamOriginalFirst);
            Check(InstallInto(game.Handle(), boundThunk),
                  "steam: the mirror installs with a proxy's real bound thunk");
            g_steamOrder.clear();
            const std::uint32_t answer = callSlot(game.Slot(0));
            Check(answer == 0x5A5A && g_steamOrder == "OM",
                  "steam: a proxy's real bound thunk keeps its store and then mirrors",
                  g_steamOrder);

            ResetInstallForTest();
            SyntheticModule other("xlive.dll");
            other.AddOrdinal(kWriteAchievementsOrdinal);
            other.SetSlot(0, reinterpret_cast<void*>(&SteamOriginalFirst));
            XliveProbe otherThunk = proxy;
            otherThunk.ordinalAddress =
                reinterpret_cast<const void*>(&SteamOriginalOther);
            Check(InstallInto(other.Handle(), otherThunk),
                  "steam: the mirror installs with a proxy's foreign stub in the slot");
            g_steamOrder.clear();
            const std::uint32_t stubAnswer = callSlot(other.Slot(0));
            Check(stubAnswer == 0 && g_steamOrder == "M",
                  "steam: a proxy's foreign stub is never called, the mirror fires",
                  g_steamOrder + " " + std::to_string(stubAnswer));
        }
    }

    // ---- LoadDLCs -----------------------------------------------------------
    //
    // Two halves: the recovered write set (fixed RVAs, one table per build) and the
    // discovery pass the struct-fixup body calls. The pass walks the folders next to
    // the executable, so its test creates them there and removes them afterwards
    // (the fork's own dlc_full shape; ctest runs this executable alone).

    std::vector<std::pair<int, std::string>> g_dlcRegistrations;
    std::vector<std::string> g_dlcAppliedPaths;
    std::vector<std::uint8_t> g_dlcAppliedFlags;
    std::vector<std::uint8_t> g_dlcAppliedModes;
    void* g_dlcApplyThis = nullptr;

    // The fake apply's second return value, so the `\Episode254\` EDX rule is visible
    // from the test.
    constexpr std::uint32_t kFakeDlcApplyEdx = 0xABCD1234u;

    char __stdcall FakeDlcRegister(int id, const char* path, int)
    {
        g_dlcRegistrations.emplace_back(id, path != nullptr ? path : "");
        return 1;
    }

    void __cdecl RecordDlcApply(void* self, const void* request)
    {
        g_dlcApplyThis = self;
        const auto* bytes = static_cast<const std::uint8_t*>(request);
        g_dlcAppliedPaths.emplace_back(reinterpret_cast<const char*>(bytes));
        g_dlcAppliedFlags.push_back(bytes[xla::episodes::kRequestFlagOffset]);
        g_dlcAppliedModes.push_back(bytes[xla::episodes::kRequestModeOffset]);
    }

    // The game's apply entry: `this` in ECX, the request on the stack, `ret 4`, and
    // its second return value in EDX.
    static __declspec(naked) void FakeDlcApply()
    {
        __asm
        {
            push dword ptr [esp + 4]
            push ecx
            call RecordDlcApply
            add esp, 8
            mov edx, 0ABCD1234h
            ret 4
        }
    }

    void TestLoadDLCs()
    {
        using xla::episodes::Body;
        using xla::episodes::Write;
        using xla::episodes::WriteKind;

        // ---- the recovered data ---------------------------------------------
        Check(xla::episodes::kBuildMask == 0x00000380u,
              "loadDLCs: the build mask is the fork's row (0x380)");
        Check(std::string_view(xla::episodes::kTladContent) == "\\dlc\\tlad\\content\\" &&
                  std::string_view(xla::episodes::kTladLegacy) == "\\TLAD\\" &&
                  std::string_view(xla::episodes::kTbogtContent) == "\\dlc\\TBoGT\\content\\" &&
                  std::string_view(xla::episodes::kTbogtLegacy) == "\\TBoGT\\" &&
                  std::string_view(xla::episodes::kEpisodeFormat) == "\\Episode%d\\",
              "loadDLCs: the discovery literals are the recovered text");
        Check(xla::episodes::kPathCapacity == 0x104 && xla::episodes::kRequestSize == 360 &&
                  xla::episodes::kRequestFlagOffset == 0x158 &&
                  xla::episodes::kRequestModeOffset == 0x166,
              "loadDLCs: the request layout is the recovered one");

        Check(xla::episodes::DlcPathFits(std::string(259, 'a')),
              "dlc_path: a 259-byte path fits the 0x104 buffer");
        Check(!xla::episodes::DlcPathFits(std::string(260, 'a')),
              "dlc_path: a 260-byte path does not fit");
        Check(!xla::episodes::DlcPathFits(""), "dlc_path: an empty path is refused");
        Check(xla::episodes::DlcPathFits("C:\\GTAIV\\GTAIV.exe"),
              "dlc_path: a normal install path fits");

        using xla::GameBuild;
        const std::array<std::pair<Body, std::uint32_t>, 3> vas{{
            {Body::dummy, 0x10023480},
            {Body::struct_fixup, 0x10023490},
            {Body::discovery, 0x10023150},
        }};
        bool vasMatch = true;
        for (const auto& [body, va] : vas)
        {
            vasMatch = vasMatch && xla::episodes::BodyVa(body) == va &&
                       xla::episodes::ResolveBody(body) != 0;
        }
        Check(vasMatch, "loadDLCs: every body keeps its recovered VA");

        // ---- the three recovered rows, byte for byte ------------------------
        const auto writesMatch = [](std::span<const Write> got, std::span<const Write> want)
        {
            if (got.size() != want.size())
            {
                return false;
            }
            for (std::size_t index = 0; index < got.size(); ++index)
            {
                if (got[index].site != want[index].site ||
                    got[index].kind != want[index].kind ||
                    got[index].target != want[index].target)
                {
                    return false;
                }
            }
            return true;
        };
        constexpr Write kWant1060[] = {
            {0x41450Eu, WriteKind::jump_rva, 0x41452Cu},
            {0x41453Au, WriteKind::call_rva, 0x413E30u},
            {0x41453Fu, WriteKind::nop_tail, 0u},
            {0x41445Cu, WriteKind::jump_rva, 0x4144B8u},
            {0x4137CDu, WriteKind::call_body, 0u},
            {0x4144D4u, WriteKind::jump_body, 0u},
        };
        constexpr Write kWant1070[] = {
            {0x4142AEu, WriteKind::jump_rva, 0x4142CCu},
            {0x4142DAu, WriteKind::call_rva, 0x413BD0u},
            {0x4142DFu, WriteKind::nop_tail, 0u},
            {0x4141FCu, WriteKind::jump_rva, 0x414258u},
            {0x41356Du, WriteKind::call_body, 0u},
            {0x414274u, WriteKind::jump_body, 0u},
        };
        constexpr Write kWant1080[] = {
            {0x49040Eu, WriteKind::jump_rva, 0x49042Cu},
            {0x49043Au, WriteKind::call_rva, 0x48FBB0u},
            {0x49043Fu, WriteKind::nop_tail, 0u},
            {0x49035Cu, WriteKind::jump_rva, 0x4903B8u},
            {0x48F558u, WriteKind::call_body, 0u},
            {0x4903D4u, WriteKind::jump_body, 0u},
        };

        const auto builds = xla::episodes::Builds();
        Check(builds.size() == 3, "loadDLCs: the key has three build rows");
        Check(builds.size() == 3 && builds[0].build == GameBuild::v1060 &&
                  builds[0].registerRva == 0x4136E0u && builds[0].applyRva == 0x414080u &&
                  builds[0].loadCallbackRva == 0x414560u &&
                  writesMatch(builds[0].writes, kWant1060),
              "loadDLCs: the 1.0.6.0 row is the fork's table");
        Check(builds.size() == 3 && builds[1].build == GameBuild::v1070 &&
                  builds[1].registerRva == 0x413480u && builds[1].applyRva == 0x413E20u &&
                  builds[1].loadCallbackRva == 0x414300u &&
                  writesMatch(builds[1].writes, kWant1070),
              "loadDLCs: the 1.0.7.0 row is the fork's table");
        Check(builds.size() == 3 && builds[2].build == GameBuild::v1080 &&
                  builds[2].registerRva == 0x48F440u && builds[2].applyRva == 0x48FE00u &&
                  builds[2].loadCallbackRva == 0x490460u &&
                  writesMatch(builds[2].writes, kWant1080),
              "loadDLCs: the 1.0.8.0 row is the fork's table");

        // ---- the mask: [1060,1070,1080] -------------------------------------
        Check(xla::episodes::BuildHasLoadDLCs(GameBuild::v1060) &&
                  xla::episodes::BuildHasLoadDLCs(GameBuild::v1070) &&
                  xla::episodes::BuildHasLoadDLCs(GameBuild::v1080),
              "loadDLCs: 1.0.6.0, 1.0.7.0 and 1.0.8.0 are inside the mask");
        Check(!xla::episodes::BuildHasLoadDLCs(GameBuild::v1000) &&
                  !xla::episodes::BuildHasLoadDLCs(GameBuild::v1040) &&
                  !xla::episodes::BuildHasLoadDLCs(GameBuild::v1050) &&
                  !xla::episodes::BuildHasLoadDLCs(GameBuild::v1100) &&
                  !xla::episodes::BuildHasLoadDLCs(GameBuild::v1110) &&
                  !xla::episodes::BuildHasLoadDLCs(GameBuild::v1120) &&
                  !xla::episodes::BuildHasLoadDLCs(GameBuild::v1130) &&
                  !xla::episodes::BuildHasLoadDLCs(GameBuild::v1010) &&
                  !xla::episodes::BuildHasLoadDLCs(GameBuild::unknown),
              "loadDLCs: every other build is outside it");

        // ---- the publish step ------------------------------------------------
        static std::vector<std::byte> dlcImage(0x491000, std::byte{0});
        const xla::Image dlcView{dlcImage.data(), dlcImage.size()};
        const auto dlcBase = static_cast<std::uint32_t>(
            reinterpret_cast<std::uintptr_t>(dlcImage.data()));

        xla::episodes::Publish(dlcView, GameBuild::v1080);
        const xla::episodes::Published published = xla::episodes::PublishedForTest();
        Check(published.gameBase == dlcBase && published.registerRva == 0x48F440u &&
                  published.applyRva == 0x48FE00u &&
                  published.loadCallback == dlcBase + 0x490460u,
              "loadDLCs: the publish step hands the discovery the build's RVAs");

        const xla::episodes::Published beforePublish = published;
        xla::episodes::Publish(dlcView, GameBuild::v1040);
        const xla::episodes::Published afterPublish = xla::episodes::PublishedForTest();
        Check(afterPublish.gameBase == beforePublish.gameBase &&
                  afterPublish.registerRva == beforePublish.registerRva &&
                  afterPublish.applyRva == beforePublish.applyRva &&
                  afterPublish.loadCallback == beforePublish.loadCallback,
              "loadDLCs: a build without a row publishes nothing");

        // ---- the write set, one synthetic image per build -------------------
        const auto checkWriteSet = [&](GameBuild build, std::vector<std::byte>& image,
                                       std::string_view label)
        {
            const xla::Image view{image.data(), image.size()};
            const std::vector<std::byte> pristine = image;
            xla::episodes::Publish(view, build);
            const xla::episodes::Report report = xla::episodes::Install(view, build);
            Check(report.applied == 6 && report.missing == 0,
                  std::format("loadDLCs: {} applies its six writes", label),
                  std::format("{}/{}", report.applied, report.applied + report.missing));

            const xla::episodes::BuildRow* const row = xla::episodes::BuildFor(build);
            bool bytesMatch = row != nullptr && row->writes.size() == 6;
            std::vector<std::pair<std::size_t, std::size_t>> spans;
            if (row != nullptr)
            {
                for (const Write& write : row->writes)
                {
                    auto* const site = image.data() + write.site;
                    spans.emplace_back(write.site,
                                       write.kind == WriteKind::nop_tail ? 12u : 5u);
                    if (write.kind == WriteKind::nop_tail)
                    {
                        for (std::size_t index = 0; index < 12; ++index)
                        {
                            bytesMatch = bytesMatch && site[index] == std::byte{0x90};
                        }
                        continue;
                    }

                    const bool isCall = write.kind == WriteKind::call_rva ||
                                        write.kind == WriteKind::call_body;
                    bytesMatch = bytesMatch && site[0] == (isCall ? std::byte{0xE8}
                                                                  : std::byte{0xE9});
                    const std::uintptr_t expected =
                        (write.kind == WriteKind::jump_rva ||
                         write.kind == WriteKind::call_rva)
                            ? reinterpret_cast<std::uintptr_t>(image.data()) + write.target
                            : xla::episodes::ResolveBody(
                                  write.kind == WriteKind::jump_body ? Body::struct_fixup
                                                                     : Body::dummy);
                    bytesMatch = bytesMatch && JumpTarget(image, write.site) == expected;
                }
            }
            Check(bytesMatch, std::format("loadDLCs: {}'s writes carry the recovered bytes",
                                          label));
            Check(OnlyChangedWithin(image, pristine, spans),
                  std::format("loadDLCs: {} writes only its six sites", label));
        };
        static std::vector<std::byte> image1060(0x491000, std::byte{0});
        static std::vector<std::byte> image1070(0x491000, std::byte{0});
        static std::vector<std::byte> image1080(0x491000, std::byte{0});
        checkWriteSet(GameBuild::v1060, image1060, "1.0.6.0");
        checkWriteSet(GameBuild::v1070, image1070, "1.0.7.0");
        checkWriteSet(GameBuild::v1080, image1080, "1.0.8.0");

        // ---- refusals --------------------------------------------------------
        // A build outside the mask writes nothing.
        {
            std::vector<std::byte> gated(0x491000, std::byte{0});
            const xla::Image view{gated.data(), gated.size()};
            const std::vector<std::byte> pristine = gated;
            const xla::episodes::Report report =
                xla::episodes::Install(view, GameBuild::v1040);
            Check(report.applied == 0 && report.missing == 0 && gated == pristine,
                  "loadDLCs: a build outside the mask installs nothing");
        }
        // A short view: every fixed-RVA site is outside it, so the arm is six logged
        // skips (this key has no scan, so a short view is its \"missing anchor\").
        {
            std::vector<std::byte> shortView(0x1000, std::byte{0});
            const xla::Image view{shortView.data(), shortView.size()};
            const std::vector<std::byte> pristine = shortView;
            const xla::episodes::Report report =
                xla::episodes::Install(view, GameBuild::v1080);
            Check(report.applied == 0 && report.missing == 6 && shortView == pristine,
                  "loadDLCs: a short view refuses every write",
                  std::format("{}/{}", report.applied, report.applied + report.missing));
        }
    }

    // ---- the DLC discovery pass ----------------------------------------------
    //
    // The fork's dlc_full shape: fake register/apply entries reached through the
    // published base plus RVAs, and folders created next to this executable. The
    // apply fake is `__thiscall` (manager in ECX, request on the stack, `ret 4`), so a
    // cdecl capture of the manager would fail here, and it answers a known EDX so the
    // `\Episode254\` rule is observable.
    void TestLoadDLCsDiscovery()
    {
        const std::filesystem::path base = xla::Game::Get().ExecutableDirectory();
        Check(!base.empty(), "dlc discovery: the test module directory is known");
        if (base.empty())
        {
            return;
        }

        constexpr std::array<std::string_view, 6> kFolders{{
            "TLAD", "TBoGT", "Episode2", "Episode3", "EpisodeX", "Episode254",
        }};
        std::error_code ignored;
        const auto folder = [&base](std::string_view name)
        { return base / std::string(name); };
        for (const std::string_view name : kFolders)
        {
            std::filesystem::remove_all(folder(name), ignored);
        }
        const auto reset = [&]
        {
            g_dlcRegistrations.clear();
            g_dlcAppliedPaths.clear();
            g_dlcAppliedFlags.clear();
            g_dlcAppliedModes.clear();
            g_dlcApplyThis = nullptr;
        };

        const auto imageBase = static_cast<std::uint32_t>(xla::Game::Get().ImageBase());
        const auto rvaOf = [imageBase](const void* function)
        {
            return static_cast<std::uint32_t>(
                reinterpret_cast<std::uintptr_t>(function) - imageBase);
        };
        xla::episodes::SetDiscoveryForTest(imageBase, rvaOf(&FakeDlcRegister),
                                           rvaOf(&FakeDlcApply));

        std::array<std::uint8_t, 0x200> manager{};

        // ---- the three fixed layouts and one addon episode -------------------
        std::filesystem::create_directories(folder("TLAD"), ignored);
        std::filesystem::create_directories(folder("TBoGT"), ignored);
        std::filesystem::create_directories(folder("Episode3"), ignored);
        reset();
        manager.fill(0);
        const std::uint32_t result = xla::episodes::DiscoverResultForTest(manager.data());
        Check(g_dlcRegistrations.size() == 3,
              "dlc discovery: TLAD, TBoGT and Episode3 are registered");
        const bool wantPaths = g_dlcRegistrations.size() == 3 &&
                               g_dlcRegistrations[0].second ==
                                   (base / "TLAD").string() + "\\" &&
                               g_dlcRegistrations[1].second ==
                                   (base / "TBoGT").string() + "\\" &&
                               g_dlcRegistrations[2].second ==
                                   (base / "Episode3").string() + "\\";
        Check(wantPaths, "dlc discovery: each registration carries the folder's own path",
              g_dlcRegistrations.empty() ? std::string{} : g_dlcRegistrations[0].second);
        Check(g_dlcRegistrations.size() == 3 && g_dlcRegistrations[0].first == 2 &&
                  g_dlcRegistrations[1].first == 4 && g_dlcRegistrations[2].first == 6,
              "dlc discovery: the ids are 2, 4 and 2*3 (the setup2.xml rule)");

        bool applyMatches = g_dlcAppliedPaths.size() == g_dlcRegistrations.size() &&
                            !g_dlcAppliedPaths.empty();
        for (std::size_t index = 0; index < g_dlcAppliedPaths.size(); ++index)
        {
            applyMatches = applyMatches &&
                           g_dlcAppliedPaths[index] == g_dlcRegistrations[index].second;
        }
        Check(applyMatches,
              "dlc discovery: the apply call receives the registered request text");
        Check(g_dlcApplyThis == manager.data(),
              "dlc discovery: the apply call passes the manager as `this` (ECX)");
        bool requestTail = !g_dlcAppliedFlags.empty();
        for (const std::uint8_t flag : g_dlcAppliedFlags)
        {
            requestTail = requestTail && flag == 1;
        }
        for (const std::uint8_t mode : g_dlcAppliedModes)
        {
            requestTail = requestTail && mode == 1;
        }
        Check(requestTail,
              "dlc discovery: the request carries the original's flag and mode bytes");
        Check(manager[xla::episodes::kManagerMarkerOffset] == 1 &&
                  manager[xla::episodes::kManagerModeOffset] == 2,
              "dlc discovery: the manager's post-discovery bytes are set");
        Check(result == xla::episodes::kDefaultResult,
              "dlc discovery: without Episode254 the pass leaves 0x40 in EDX",
              std::format("{:#x}", result));

        reset();
        const void* returned = xla::episodes::DiscoverForTest(manager.data());
        Check(returned == manager.data(), "dlc discovery: the pass returns its object");

        // ---- rejections: a missing fixed folder and a non-addon name ---------
        // TLAD is deleted, `Episode2` (the TBoGT id) and `EpisodeX` (not a number)
        // are created: only TBoGT and Episode3 may register.
        std::filesystem::remove_all(folder("TLAD"), ignored);
        std::filesystem::create_directories(folder("Episode2"), ignored);
        std::filesystem::create_directories(folder("EpisodeX"), ignored);
        reset();
        (void)xla::episodes::DiscoverForTest(manager.data());
        Check(g_dlcRegistrations.size() == 2 && g_dlcRegistrations[0].first == 4 &&
                  g_dlcRegistrations[1].first == 6,
              "dlc discovery: a missing folder and a reserved/non-numeric episode are "
              "rejected",
              std::to_string(g_dlcRegistrations.size()));

        // ---- the Episode254 rule --------------------------------------------
        std::filesystem::create_directories(folder("Episode254"), ignored);
        reset();
        const std::uint32_t with254 = xla::episodes::DiscoverResultForTest(manager.data());
        Check(!g_dlcRegistrations.empty() && g_dlcRegistrations.back().first == 508,
              "dlc discovery: Episode254 is registered as id 508 (2*254)");
        Check(with254 == kFakeDlcApplyEdx,
              "dlc discovery: Episode254 forwards the last apply's EDX",
              std::format("{:#x}", with254));

        // ---- no published entry ---------------------------------------------
        xla::episodes::SetDiscoveryForTest(imageBase, 0, 0);
        reset();
        manager.fill(0);
        (void)xla::episodes::DiscoverForTest(manager.data());
        Check(g_dlcRegistrations.empty() &&
                  manager[xla::episodes::kManagerMarkerOffset] == 0 &&
                  manager[xla::episodes::kManagerModeOffset] == 0,
              "dlc discovery: a build with no published entry registers nothing");

        for (const std::string_view name : kFolders)
        {
            std::filesystem::remove_all(folder(name), ignored);
        }
    }

    // ---- BenchmarkFix / CombinedRadioFreezeFix -------------------------------
    //
    // The two recovered crash fixes, driven exactly as the install pass drives them:
    // the masks through the original's build ids, the two benchmark sites (each with
    // its own continuation), the radio call replacement, and the refusals (a missing
    // anchor, a partial multi-hit scan, a short view, a build outside the mask).
    void TestStability()
    {
        using xla::GameBuild;
        using xla::stability::Body;

        // ---- the recovered data ---------------------------------------------
        Check(std::string_view(xla::stability::kBenchmarkAnchor) ==
                  "E8 ? ? ? ? 83 C4 04 57 8B D8 FF D6 8B 77 20",
              "benchmarkFix: the anchor is the recovered row");
        Check(std::string_view(xla::stability::kCombinedRadioAnchor) ==
                  "E8 ? ? ? ? 8B 35 ? ? ? ? 3B F0",
              "combinedRadio: the anchor is the recovered row");
        Check(xla::stability::kBenchmarkBuildMask == 0x00049DE2u &&
                  xla::stability::kCombinedRadioBuildMask == 0x0004BFE2u,
              "stability: the two masks are the fork's option rows");
        Check(xla::stability::kBenchmarkSiteOffset == 8 &&
                  xla::stability::kBenchmarkResumeOffset == 13 &&
                  xla::stability::kBenchmarkSiteCount == 2,
              "benchmarkFix: the site, continuation and count are the recovered ones");

        const std::array<std::pair<Body, std::uint32_t>, 3> vas{{
            {Body::benchmark_a, 0x10005650},
            {Body::benchmark_b, 0x10005670},
            {Body::combined_radio, 0x10005ED0},
        }};
        bool vasMatch = true;
        for (const auto& [body, va] : vas)
        {
            vasMatch = vasMatch && xla::stability::BodyVa(body) == va &&
                       xla::stability::ResolveBody(body) != 0;
        }
        Check(vasMatch, "stability: every body keeps its recovered VA");

        // ---- the masks -------------------------------------------------------
        Check(xla::stability::BuildHasBenchmark(GameBuild::v1000) &&
                  xla::stability::BuildHasBenchmark(GameBuild::v1040) &&
                  xla::stability::BuildHasBenchmark(GameBuild::v1050) &&
                  xla::stability::BuildHasBenchmark(GameBuild::v1060) &&
                  xla::stability::BuildHasBenchmark(GameBuild::v1070) &&
                  xla::stability::BuildHasBenchmark(GameBuild::v1100) &&
                  xla::stability::BuildHasBenchmark(GameBuild::v1110) &&
                  xla::stability::BuildHasBenchmark(GameBuild::v1120),
              "benchmarkFix: every classified build except 1.0.8.0/1.1.3.0 is inside");
        Check(!xla::stability::BuildHasBenchmark(GameBuild::v1080) &&
                  !xla::stability::BuildHasBenchmark(GameBuild::v1130),
              "benchmarkFix: 1.0.8.0 and 1.1.3.0 are outside the mask");
        Check(!xla::stability::BuildHasBenchmark(GameBuild::v1010) &&
                  !xla::stability::BuildHasBenchmark(GameBuild::unknown),
              "benchmarkFix: unclassified builds are outside the mask");
        Check(xla::stability::BuildHasCombinedRadio(GameBuild::v1000) &&
                  xla::stability::BuildHasCombinedRadio(GameBuild::v1080) &&
                  xla::stability::BuildHasCombinedRadio(GameBuild::v1130) &&
                  xla::stability::BuildHasCombinedRadio(GameBuild::v1050),
              "combinedRadio: the original's all-builds mask covers every classified build");
        Check(!xla::stability::BuildHasCombinedRadio(GameBuild::v1010) &&
                  !xla::stability::BuildHasCombinedRadio(GameBuild::v1020) &&
                  !xla::stability::BuildHasCombinedRadio(GameBuild::v1030) &&
                  !xla::stability::BuildHasCombinedRadio(GameBuild::unknown),
              "combinedRadio: unclassified builds are outside it");

        // ---- refusals first (the scanner caches hits per signature string for a
        // whole-image scan, so the missing-anchor pass runs before the real image)
        static std::vector<std::byte> bare(0x100, std::byte{0});
        const xla::Image bareView{bare.data(), bare.size()};
        const auto noneBench = xla::stability::InstallBenchmarkFix(bareView,
                                                                   GameBuild::v1070);
        Check(noneBench.applied == 0 && noneBench.missing == 1,
              "benchmarkFix: a missing anchor is a logged skip");
        Check(xla::stability::PublishedForTest().first == 0 &&
                  xla::stability::PublishedForTest().second == 0,
              "benchmarkFix: a missed anchor publishes nothing");
        const auto noneRadio =
            xla::stability::InstallCombinedRadioFreezeFix(bareView, GameBuild::v1080);
        Check(noneRadio.applied == 0 && noneRadio.missing == 1,
              "combinedRadio: a missing anchor is a logged skip");

        const auto gatedBench = xla::stability::InstallBenchmarkFix(bareView,
                                                                    GameBuild::v1080);
        Check(gatedBench.applied == 0 && gatedBench.missing == 0,
              "benchmarkFix: a build outside the mask installs nothing");
        const auto gatedRadio =
            xla::stability::InstallCombinedRadioFreezeFix(bareView, GameBuild::v1010);
        Check(gatedRadio.applied == 0 && gatedRadio.missing == 0,
              "combinedRadio: a build outside the mask installs nothing");

        // A short view: one byte less than the anchor, so the scan cannot match it.
        {
            std::vector<std::byte> truncated(15, std::byte{0});
            WriteBytes(truncated, 0, BytesOf(xla::stability::kBenchmarkAnchor));
            const xla::Image shortView{truncated.data(), truncated.size() - 1};
            const auto report = xla::stability::InstallBenchmarkFix(shortView,
                                                                    GameBuild::v1070);
            Check(report.applied == 0 && report.missing == 1 &&
                      truncated[8] == std::byte{0x57},
                  "benchmarkFix: a short view refuses to install");
        }

        // A partial multi-hit scan: one site is not the recovered shape, so the arm
        // refuses both writes instead of sending body B to body A's continuation.
        {
            std::vector<std::byte> single(0x200, std::byte{0});
            WriteBytes(single, 0x40, BytesOf(xla::stability::kBenchmarkAnchor));
            const xla::Image singleView{single.data(), single.size()};
            const xla::stability::Resumes before = xla::stability::PublishedForTest();
            const auto report = xla::stability::InstallBenchmarkFix(singleView,
                                                                    GameBuild::v1070);
            const xla::stability::Resumes after = xla::stability::PublishedForTest();
            Check(report.applied == 0 && report.missing == 1 &&
                      single[0x48] == std::byte{0x57} && after.first == before.first &&
                      after.second == before.second,
                  "benchmarkFix: a one-hit scan refuses the arm");
        }

        // ---- the write set ---------------------------------------------------
        constexpr std::size_t kBenchmarkFirst = 0x100;
        constexpr std::size_t kBenchmarkSecond = 0x200;
        constexpr std::size_t kRadioSite = 0x300;
        static std::vector<std::byte> image(0x400, std::byte{0});
        WriteBytes(image, kBenchmarkFirst, BytesOf(xla::stability::kBenchmarkAnchor));
        WriteBytes(image, kBenchmarkSecond, BytesOf(xla::stability::kBenchmarkAnchor));
        WriteBytes(image, kRadioSite, BytesOf(xla::stability::kCombinedRadioAnchor));
        const xla::Image view{image.data(), image.size()};

        const std::vector<std::byte> pristine = image;
        const auto bench = xla::stability::InstallBenchmarkFix(view, GameBuild::v1070);
        Check(bench.applied == 2 && bench.missing == 0,
              "benchmarkFix: both sites are installed",
              std::format("{}/{}", bench.applied, bench.applied + bench.missing));

        const xla::stability::Resumes resumes = xla::stability::PublishedForTest();
        const std::byte* const imageData = image.data();
        const auto baseOf = [imageData](std::size_t offset)
        {
            return static_cast<std::uint32_t>(
                reinterpret_cast<std::uintptr_t>(imageData) + offset);
        };
        Check(resumes.first == baseOf(kBenchmarkFirst + 13) &&
                  resumes.second == baseOf(kBenchmarkSecond + 13),
              "benchmarkFix: each site publishes its own +0xD continuation");
        Check(image[kBenchmarkFirst + 8] == std::byte{0xE9} &&
                  JumpTarget(image, kBenchmarkFirst + 8) ==
                      xla::stability::ResolveBody(Body::benchmark_a),
              "benchmarkFix: the first site jumps to its body");
        Check(image[kBenchmarkSecond + 8] == std::byte{0xE9} &&
                  JumpTarget(image, kBenchmarkSecond + 8) ==
                      xla::stability::ResolveBody(Body::benchmark_b),
              "benchmarkFix: the second site jumps to its own body");
        const std::array<std::pair<std::size_t, std::size_t>, 2> benchSpans{{
            {kBenchmarkFirst + 8, 5},
            {kBenchmarkSecond + 8, 5},
        }};
        Check(OnlyChangedWithin(image, pristine, benchSpans),
              "benchmarkFix: the arm writes only its two sites");

        const std::vector<std::byte> beforeRadio = image;
        const auto radio =
            xla::stability::InstallCombinedRadioFreezeFix(view, GameBuild::v1080);
        Check(radio.applied == 1 && radio.missing == 0,
              "combinedRadio: the call site is installed");
        Check(image[kRadioSite] == std::byte{0xE8} &&
                  CallTarget(image, kRadioSite) ==
                      xla::stability::ResolveBody(Body::combined_radio),
              "combinedRadio: the call targets its body");
        const std::array<std::pair<std::size_t, std::size_t>, 1> radioSpans{{
            {kRadioSite, 5},
        }};
        Check(OnlyChangedWithin(image, beforeRadio, radioSpans),
              "combinedRadio: the arm writes only its one site");
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
        Check(HasStage(kShippedStages, SkipLauncherStage::main) &&
                  HasStage(kShippedStages, SkipLauncherStage::dfa) &&
                  HasStage(kShippedStages, SkipLauncherStage::rom),
              "skipLauncher: the shipped stages are main+DFA+ROM");
        Check(DescribeStages(kShippedStages) == "main|dfa|rom",
              "skipLauncher: the stage description is main|dfa|rom");

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

        // The shipped stages include main, so the same signature is written.
        std::vector<std::byte> shipped(0x1000, std::byte{0});
        WriteBytes(shipped, 0x100, signature);
        result = ApplySkipLauncher(xla::Image{shipped.data(), shipped.size()}, &ResolveSkipHook,
                                   nullptr, kShippedStages);
        Check(result.has_value(), "skipLauncher: the shipped stages run");
        if (result)
        {
            Check(result->entriesFound == 1 && result->writes == 2,
                  "skipLauncher: the shipped stages apply the main table");
            Check(result->dfaMissing == SkipLauncherDfaInstalls().size(),
                  "skipLauncher: the missing DFA hooks are counted");
        }
        Check(shipped[0x100 + 34] == std::byte{0xEB},
              "skipLauncher: the shipped main row is written");

        // A store past the image is the pass's one hard failure.
        std::vector<std::byte> bounds(0x100, std::byte{0});
        WriteBytes(bounds, bounds.size() - signature.size(), signature);
        result = ApplySkipLauncher(xla::Image{bounds.data(), bounds.size()}, &ResolveSkipHook,
                                   nullptr, SkipLauncherStage::main);
        Check(!result.has_value() &&
                  result.error().code == PatchError::Code::out_of_bounds,
              "skipLauncher: a store past the image fails cleanly");
    }

    // The two multi-hit collectors are the SecuROM spot-check bypass: the first
    // two matches of the first pattern and the last two of the second become
    // `mov al,1; ret; nop`. The script natives then report success; the mission
    // scripts gate on them (vlad3.sco's Clean Getaway state 3).
    void TestSkipLauncherCollectors()
    {
        using namespace xla::launcher;

        std::vector<std::byte> image(0x4000, std::byte{0});
        const auto first = BytesOf("A1 ? ? ? ? 85 C0 8B 0D ? ? ? ? 75");
        const auto last = BytesOf("33 C0 83 3D ? ? ? ? 01 0F 94 C0 C3");
        WriteBytes(image, 0x100, first);
        WriteBytes(image, 0x180, first);
        const std::size_t lastSites[] = {0x300, 0x320, 0x340, 0x360, 0x380};
        for (const std::size_t site : lastSites)
        {
            WriteBytes(image, site, last);
        }

        const auto result = ApplySkipLauncher(xla::Image{image.data(), image.size()}, nullptr,
                                              nullptr, SkipLauncherStage::main);
        Check(result.has_value(), "skipLauncher: the collectors' main pass applies");
        if (!result)
        {
            return;
        }
        Check(result->collectorsFound == 2 && result->collectorWrites == 4,
              "skipLauncher: both collectors patch two sites each");

        const std::array<std::byte, 4> stub{std::byte{0xB0}, std::byte{0x01},
                                            std::byte{0xC3}, std::byte{0x90}};
        Check(std::equal(stub.begin(), stub.end(), image.begin() + 0x100) &&
                  std::equal(stub.begin(), stub.end(), image.begin() + 0x180),
              "skipLauncher: the first collector patches the first two matches");
        Check(std::equal(stub.begin(), stub.end(), image.begin() + 0x360) &&
                  std::equal(stub.begin(), stub.end(), image.begin() + 0x380),
              "skipLauncher: the second collector patches the last two matches");
        Check(image[0x300] == std::byte{0x33} && image[0x320] == std::byte{0x33} &&
                  image[0x340] == std::byte{0x33},
              "skipLauncher: the second collector leaves the earlier matches alone");
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
        const std::array<std::string_view, 34> expected{{
            "Banner", "Console", "SingleInstance", "Loader", "Probe", "Paths", "Config",
            "FusionFix", "ReportConfiguration", "Image", "Build", "Profile",
            "Savegames", "SkipLauncher", "LaunchWithPlayGTAIV", "BorderlessWindow", "FocusLoss",
            "CorePatches", "LauncherStage", "WebConnect",
            "NewFilesCompatibility", "NewSavesCompatibility", "GFWLProtectionDisabler",
            "SteamAchievements", "LoadDLCs", "BenchmarkFix", "CombinedRadioFreezeFix",
            "SkipIntro", "SkipMenu",
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
    TestCompatibility();
    TestNewSavesWalk();
    TestGfwl();
    TestSteam();
    TestLoadDLCs();
    TestLoadDLCsDiscovery();
    TestStability();
    TestMenu();
    TestVram();
    TestRegistry();
    TestProfile();
    TestSkipLauncherTable();
    TestSkipLauncherPass();
    TestSkipLauncherCollectors();
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
