// SPDX-License-Identifier: GPL-3.0-or-later
//
// Native tests for the XLivelessAddon successor. No game files are needed: the
// INI loader is driven against temporary directories, the build table against a
// synthetic image, and the recovered SkipLauncher tables against a scratch image
// with the real signatures written into it.

#include "common.hxx"

import xla.build;
import xla.common;
import xla.config;
import xla.patch;
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

        // EnsureIni writes the shipped defaults, which enable the windowed/intro
        // options explicitly (the code defaults below are the original's own).
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

        CHECK(xla::patch::Ret(site, 12, 8, "test: ret"));
        CHECK_EQ(buffer[12], std::byte{0xC2});
        CHECK_EQ(buffer[13], std::byte{0x08});
        CHECK_EQ(buffer[14], std::byte{0x00});

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
        CHECK_EQ(entries[0].writes[0].offset, 34);
        CHECK_EQ(entries[0].writes[1].offset, 223);
        CHECK_EQ(entries[8].writes[0].length, static_cast<std::uint16_t>(447));
        CHECK_EQ(entries[9].writes[2].jumpToEntry, xla::kSkipLauncherJumpTargetEntry);
        CHECK_EQ(xla::SkipLauncherCollectors().size(), std::size_t{2});
        CHECK_EQ(xla::SkipLauncherDfaInstalls().size(), std::size_t{6});
        CHECK_EQ(xla::SkipLauncherRomInstalls().size(), std::size_t{2});
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
        // Offset 34 inside the signature is the `0F 85` of the jcc: patched to EB.
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
    run("config precedence and FusionFix gates", TestConfigPrecedenceAndGates);
    run("config defaults and EnsureIni", TestConfigDefaultsAndEnsureIni);
    run("build detection", TestBuildDetection);
    run("patch primitives", TestPatchPrimitives);
    run("savegame paths", TestSavegamePaths);
    run("registry helpers", TestRegistryHelpers);
    run("user data folders", TestUserdataFolders);
    run("windowed guards", TestWindowedGuards);
    run("RomSet stub bytes", TestRomSetStubBytes);
    run("skip launcher table shape", TestSkipLauncherTableShape);
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
