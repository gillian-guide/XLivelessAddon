// SPDX-License-Identifier: GPL-3.0-or-later
//
// Native tests for the XLivelessAddon successor's recovered SkipLauncher path.
// No game files are needed: the signature tables are driven against a synthetic
// image, and the CreateFile body is exercised through a fake IAT slot.

#include "skip_launcher.h"

#include <windows.h>

#include <cstdio>
#include <cstdint>
#include <vector>

namespace
{
    int failures = 0;

#define CHECK(x)                                                                                   \
    do                                                                                             \
    {                                                                                              \
        if (!(x))                                                                                  \
        {                                                                                          \
            std::fprintf(stderr, "check failed: %s:%d: %s\n", __FILE__, __LINE__, #x);              \
            ++failures;                                                                            \
        }                                                                                          \
    } while (false)

    using CreateFileAFn = HANDLE(__cdecl*)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD,
                                           DWORD, HANDLE);

    constexpr uintptr_t kStubHandle = 0x1234;

    int g_stubCalls = 0;

    HANDLE WINAPI StubCreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE)
    {
        ++g_stubCalls;
        return reinterpret_cast<HANDLE>(kStubHandle);
    }

    CreateFileAFn CreateFileBody()
    {
        return reinterpret_cast<CreateFileAFn>(ResolveSkipHook(SkipHook::create_file, nullptr));
    }

    void TestCreateFileSlotForwarding()
    {
        // A slot holds the function the game's import table resolved (or a detour
        // another ASI installed). The body must call through it.
        uintptr_t slotValue = reinterpret_cast<uintptr_t>(&StubCreateFileA);
        SkipLauncherReport report{};
        report.createFileSlot = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&slotValue));
        CHECK(PublishCreateFileSlot(report));

        const CreateFileAFn body = CreateFileBody();
        CHECK(body != nullptr);
        g_stubCalls = 0;
        const HANDLE forwarded = body("opcep-slot-test", 0, 0, nullptr, 0, 0, nullptr);
        CHECK(forwarded == reinterpret_cast<HANDLE>(kStubHandle));
        CHECK(g_stubCalls == 1);

        // No captured slot (missing signature): fall back to CreateFileA.
        report.createFileSlot = 0;
        CHECK(!PublishCreateFileSlot(report));
        const HANDLE direct =
            body("NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                 OPEN_EXISTING, 0, nullptr);
        CHECK(direct != INVALID_HANDLE_VALUE);
        if (direct != INVALID_HANDLE_VALUE)
            CloseHandle(direct);
        CHECK(g_stubCalls == 1);  // the stub was not used again
    }

    void TestApplySkipLauncherPublishesSlot()
    {
        // End-to-end: the DFA stage captures the CreateFile IAT slot from the
        // `FF 15 <slot>` operand and must publish it, so the create_file body it
        // installs in the same pass forwards through that slot.
        uintptr_t slotValue = reinterpret_cast<uintptr_t>(&StubCreateFileA);
        std::vector<uint8_t> image(0x1000, 0);

        constexpr size_t kCapture = 0x100;
        image[kCapture] = 0xFF;  // call dword ptr [slot]
        image[kCapture + 1] = 0x15;
        const auto slotVa = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&slotValue));
        std::memcpy(image.data() + kCapture + 2, &slotVa, 4);
        const uint8_t captureTail[7] = {0x8B, 0xF0, 0x83, 0xFE, 0xFF, 0x74, 0x24};
        std::memcpy(image.data() + kCapture + 6, captureTail, sizeof(captureTail));

        const uint8_t createFile[6] = {0x55, 0x8B, 0xEC, 0x6A, 0x00, 0xE8};
        std::memcpy(image.data() + 0x200, createFile, sizeof(createFile));

        SkipLauncherReport report{};
        const PatchResult result =
            ApplySkipLauncher({image.data(), image.size()}, &ResolveSkipHook, nullptr, report,
                              SkipLauncherStage::dfa);
        CHECK(result);
        CHECK(report.createFileSlot == slotVa);
        CHECK(report.dfaInstalls >= 1);

        g_stubCalls = 0;
        const HANDLE forwarded =
            CreateFileBody()("opcep-e2e", 0, 0, nullptr, 0, 0, nullptr);
        CHECK(forwarded == reinterpret_cast<HANDLE>(kStubHandle));
        CHECK(g_stubCalls == 1);

        // A later pass whose image has no capture must clear the slot instead of
        // leaving the previous image's slot behind.
        std::vector<uint8_t> plain(0x100, 0);
        SkipLauncherReport cleared{};
        const PatchResult second = ApplySkipLauncher(
            {plain.data(), plain.size()}, &ResolveSkipHook, nullptr, cleared,
            SkipLauncherStage::dfa);
        CHECK(second);
        CHECK(cleared.createFileSlot == 0);
        CHECK(!cleared.entriesFound);

        const HANDLE direct = CreateFileBody()("NUL", GENERIC_READ,
                                               FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                               OPEN_EXISTING, 0, nullptr);
        CHECK(direct != INVALID_HANDLE_VALUE);
        if (direct != INVALID_HANDLE_VALUE)
            CloseHandle(direct);
        CHECK(g_stubCalls == 1);
    }

    void TestMissingSignaturesAreSkipped()
    {
        // An image without any of the tables' signatures must install nothing and
        // report every row missing rather than writing through a null match.
        std::vector<uint8_t> image(0x2000, 0);
        const GameImage view{image.data(), image.size()};

        SkipLauncherReport report{};
        const PatchResult result = ApplySkipLauncher(view, &ResolveSkipHook, nullptr, report,
                                                     SkipLauncherStage::all);
        CHECK(result);

        size_t entries = 0;
        SkipLauncherEntries(entries);
        CHECK(report.entriesFound == 0);
        CHECK(report.entriesMissing == entries);
        CHECK(report.writes == 0);
        CHECK(report.collectorWrites == 0);
        CHECK(report.jumpInstalled == false);
        CHECK(report.createFileSlot == 0);

        size_t dfa = 0;
        SkipLauncherDfaInstalls(dfa);
        CHECK(report.dfaInstalls == 0);
        CHECK(report.dfaMissing == dfa);

        size_t rom = 0;
        SkipLauncherRomInstalls(rom);
        CHECK(report.romInstalls == 0);
        CHECK(report.romMissing == rom);

        CHECK(report.collectedInstalls == 0);

        // An empty image is invalid input, not a partial install.
        SkipLauncherReport empty{};
        const PatchResult invalid =
            ApplySkipLauncher({}, &ResolveSkipHook, nullptr, empty, SkipLauncherStage::all);
        CHECK(!invalid);
    }
} // namespace

int main()
{
    TestCreateFileSlotForwarding();
    TestApplySkipLauncherPublishesSlot();
    TestMissingSignaturesAreSkipped();

    if (failures != 0)
    {
        std::fprintf(stderr, "xla tests: %d failure(s)\n", failures);
        return 1;
    }
    std::printf("xla tests: PASS\n");
    return 0;
}
