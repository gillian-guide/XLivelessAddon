// Differential evidence harness (not compiled by the normal build): built in
// place of tests/test_main.cpp, on the current typed EntryPatch/PatchOp API.
// Prints table contents and the exact effect of ApplySkipLauncher on synthetic
// images, with every address normalised away. Its output must stay identical to
// tests/differential/dump_650df11.txt (the pre-refactor tree's dump); hook-branch
// rel32 bytes are canonicalised by hook name because they name our own bodies.

#include "common.hxx"

import xla.common;
import xla.skip_launcher;

namespace
{
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
                                         : static_cast<std::byte>(std::stoul(token, nullptr, 16)));
        }
        return bytes;
    }

    void Seed(std::vector<std::byte>& image, std::size_t offset, std::string_view signature)
    {
        const auto bytes = BytesOf(signature);
        std::copy(bytes.begin(), bytes.end(), image.begin() + static_cast<std::ptrdiff_t>(offset));
    }

    std::string Hex(const void* data, std::size_t size)
    {
        std::string text;
        const auto* bytes = static_cast<const std::uint8_t*>(data);
        for (std::size_t index = 0; index < size; ++index)
        {
            text += std::format("{:02X}", static_cast<unsigned>(bytes[index]));
        }
        return text;
    }

    std::string_view HookName(xla::SkipHook hook)
    {
        switch (hook)
        {
        case xla::SkipHook::dfa_init:
            return "dfa_init";
        case xla::SkipHook::create_file:
            return "create_file";
        case xla::SkipHook::close_handle:
            return "close_handle";
        case xla::SkipHook::set_file_pointer:
            return "set_file_pointer";
        case xla::SkipHook::get_file_size_ex:
            return "get_file_size_ex";
        case xla::SkipHook::read_file:
            return "read_file";
        case xla::SkipHook::rom_reset:
            return "rom_reset";
        case xla::SkipHook::rom_set:
            return "rom_set";
        }
        return "?";
    }

    constexpr xla::SkipHook kHooks[] = {
        xla::SkipHook::dfa_init,         xla::SkipHook::create_file,
        xla::SkipHook::close_handle,     xla::SkipHook::set_file_pointer,
        xla::SkipHook::get_file_size_ex, xla::SkipHook::read_file,
        xla::SkipHook::rom_reset,        xla::SkipHook::rom_set,
    };

    std::uint32_t HookAddress(xla::SkipHook hook)
    {
        return static_cast<std::uint32_t>(xla::ResolveSkipHook(hook, nullptr));
    }

    bool HookAt(std::uintptr_t address, std::string_view& name)
    {
        for (const xla::SkipHook hook : kHooks)
        {
            if (HookAddress(hook) == address)
            {
                name = HookName(hook);
                return true;
            }
        }
        return false;
    }

    HANDLE WINAPI StubCreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD,
                                  HANDLE)
    {
        return reinterpret_cast<HANDLE>(std::uintptr_t{0x1234});
    }

    constexpr std::uint32_t kStubHandle = 0x1234;

    // The captured slot holds a *pointer to* the function pointer (an IAT slot),
    // not the function address itself.
    HANDLE(WINAPI* g_stubSlotValue)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD,
                                    HANDLE) = &StubCreateFileA;

    std::uint32_t FakeSlot()
    {
        return static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(&g_stubSlotValue));
    }

    void Print(const std::string& line)
    {
        std::printf("%s\n", line.c_str());
    }

    void DumpTables()
    {
        Print(std::format("tables entries={} collectors={} dfa={} rom={} collected={}",
                          xla::SkipLauncherEntries().size(),
                          xla::SkipLauncherCollectors().size(),
                          xla::SkipLauncherDfaInstalls().size(),
                          xla::SkipLauncherRomInstalls().size(),
                          xla::SkipLauncherDfaCollected().size()));
        std::size_t index = 0;
        for (const xla::EntryPatch& entry : xla::SkipLauncherEntries())
        {
            Print(std::format("entry {} sig={} writes={}", index++,
                              std::string{entry.signature}, entry.ops.size()));
            for (std::size_t w = 0; w < entry.ops.size(); ++w)
            {
                const xla::PatchOp& op = entry.ops[w];
                switch (op.kind)
                {
                case xla::PatchOp::Kind::write:
                    Print(std::format("  w{} off={} len={} bytes={} fill=00 jump=-", w,
                                      op.offset, op.bytes.size(),
                                      Hex(op.bytes.data(), op.bytes.size())));
                    break;
                case xla::PatchOp::Kind::fill:
                    Print(std::format("  w{} off={} len={} bytes=- fill={:02X} jump=-", w,
                                      op.offset, op.count,
                                      static_cast<unsigned>(op.fill)));
                    break;
                case xla::PatchOp::Kind::jump:
                    Print(std::format("  w{} off={} len=4 bytes=- fill=00 jump={}", w,
                                      op.offset, op.target));
                    break;
                }
            }
        }
        index = 0;
        for (const xla::SkipLauncherCollector& collector : xla::SkipLauncherCollectors())
        {
            Print(std::format("collector {} pattern={} target={} bytes={} len={}", index++,
                              std::string{collector.pattern},
                              collector.target == xla::SkipLauncherCollector::Target::first_two
                                  ? "first_two"
                                  : "last_two",
                              Hex(collector.bytes, collector.length),
                              collector.length));
        }
        for (const auto& [name, installs] :
             {std::pair<std::string_view, std::span<const xla::SkipLauncherInstall>>{
                  "dfa", xla::SkipLauncherDfaInstalls()},
              std::pair<std::string_view, std::span<const xla::SkipLauncherInstall>>{
                  "rom", xla::SkipLauncherRomInstalls()}})
        {
            index = 0;
            for (const xla::SkipLauncherInstall& install : installs)
            {
                Print(std::format("install {} {} sig={} off={} opcode={:02X} hook={}", name,
                                  index++, std::string{install.signature}, install.offset,
                                  static_cast<unsigned>(xla::Byte(install.opcode)),
                                  HookName(install.hook)));
            }
        }
        index = 0;
        for (const xla::SkipLauncherCollectedInstall& install : xla::SkipLauncherDfaCollected())
        {
            Print(std::format("collected {} collector={} targets={}", index++,
                              std::string{install.collector}, install.targetCount));
            for (std::size_t t = 0; t < install.targetCount; ++t)
            {
                Print(std::format("  target {} index={} sig={}", t, install.targets[t].index,
                                  std::string{install.targets[t].targetSignature}));
            }
        }
    }

    void DumpHooks()
    {
        for (const xla::SkipHook hook : kHooks)
        {
            Print(std::format("hook {} resolved={}", HookName(hook), HookAddress(hook) != 0 ? 1 : 0));
        }
        const auto romSet = xla::ResolveSkipHook(xla::SkipHook::rom_set, nullptr);
        if (romSet != 0)
        {
            Print(std::format("romSet bytes={}",
                              Hex(reinterpret_cast<const void*>(romSet), 11)));
        }
        const auto dfaInit = reinterpret_cast<int(__cdecl*)(int, int, int)>(
            xla::ResolveSkipHook(xla::SkipHook::dfa_init, nullptr));
        if (dfaInit != nullptr)
        {
            Print(std::format("dfaInit returns={}", dfaInit(1, 2, 3)));
        }
        using CreateFileFn = HANDLE(__cdecl*)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD,
                                              DWORD, HANDLE);
        const auto createFile = reinterpret_cast<CreateFileFn>(
            xla::ResolveSkipHook(xla::SkipHook::create_file, nullptr));
        if (createFile != nullptr)
        {
            xla::SetCreateFileSlot(0);
            const HANDLE direct =
                createFile("NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                           OPEN_EXISTING, 0, nullptr);
            Print(std::format("createFile direct valid={}", direct != INVALID_HANDLE_VALUE ? 1 : 0));
            if (direct != INVALID_HANDLE_VALUE)
            {
                ::CloseHandle(direct);
            }
            xla::SetCreateFileSlot(FakeSlot());
            const HANDLE forwarded = createFile("xla", 0, 0, nullptr, 0, 0, nullptr);
            Print(std::format("createFile slot stub={}",
                              reinterpret_cast<std::uintptr_t>(forwarded) == kStubHandle ? 1 : 0));
            xla::SetCreateFileSlot(0);
        }
    }

    void DumpRun(std::string_view label, std::vector<std::byte> image,
                 xla::SkipLauncherStage stages, bool resolver)
    {
        std::vector<std::byte> before = image;
        const auto result = xla::ApplySkipLauncher(image, resolver ? &xla::ResolveSkipHook : nullptr,
                                                   nullptr, stages);
        Print(std::format("run {} stages={} resolver={}", label, static_cast<int>(stages),
                          resolver ? 1 : 0));
        if (!result)
        {
            Print(std::format("  error code={} detail={}", static_cast<int>(result.error().code),
                              result.error().detail));
            return;
        }

        const xla::SkipLauncherReport& report = *result;
        Print(std::format("  report found={} missing={} writes={} collFound={} collWrites={} "
                          "jump={} dfa={}/{} rom={}/{} collected={} slot={} slotStub={}",
                          report.entriesFound, report.entriesMissing, report.writes,
                          report.collectorsFound, report.collectorWrites,
                          report.jumpInstalled ? 1 : 0, report.dfaInstalls, report.dfaMissing,
                          report.romInstalls, report.romMissing, report.collectedInstalls,
                          report.createFileSlot != 0 ? 1 : 0,
                          report.createFileSlot == FakeSlot() ? 1 : 0));

        // A branch to one of our bodies differs only by the body's address, which
        // changes between builds. Canonicalise those sites before diffing and
        // report them by hook name.
        std::vector<std::pair<std::size_t, std::string_view>> branches;
        for (std::size_t at = 0; at + 5 <= image.size(); ++at)
        {
            if (image[at] != std::byte{0xE8} && image[at] != std::byte{0xE9})
            {
                continue;
            }
            std::int32_t displacement = 0;
            std::memcpy(&displacement, image.data() + at + 1, sizeof(displacement));
            const auto target = reinterpret_cast<std::uintptr_t>(image.data() + at + 5) +
                                static_cast<std::uintptr_t>(displacement);
            std::string_view name;
            if (HookAt(target, name))
            {
                branches.emplace_back(at, name);
                for (std::size_t byte = 0; byte < 5; ++byte)
                {
                    image[at + byte] = std::byte{0xCC};
                    before[at + byte] = std::byte{0xCC};
                }
            }
        }
        for (const auto& [at, name] : branches)
        {
            Print(std::format("  [{:X}] branch5 -> {}", at, name));
        }

        std::size_t index = 0;
        while (index < image.size())
        {
            if (image[index] == before[index])
            {
                ++index;
                continue;
            }
            std::size_t end = index;
            while (end < image.size() && image[end] != before[end])
            {
                ++end;
            }

            const std::size_t length = end - index;
            if (length == 5 && (image[index] == std::byte{0xE8} || image[index] == std::byte{0xE9}))
            {
                std::int32_t displacement = 0;
                std::memcpy(&displacement, image.data() + index + 1, sizeof(displacement));
                const auto target = reinterpret_cast<std::uintptr_t>(image.data() + end) +
                                    static_cast<std::uintptr_t>(displacement);
                std::string_view name;
                if (HookAt(target, name))
                {
                    Print(std::format("  [{:X}] branch5 -> {}", index, name));
                    index = end;
                    continue;
                }
            }
            Print(std::format("  [{:X}] {}", index, Hex(image.data() + index, length)));
            index = end;
        }
    }

    std::vector<std::byte> Blank(std::size_t size)
    {
        return std::vector<std::byte>(size, std::byte{0});
    }

    void RunEntryCases()
    {
        for (std::size_t index = 0; index < xla::SkipLauncherEntries().size(); ++index)
        {
            auto image = Blank(0x800);
            Seed(image, 0x100, xla::SkipLauncherEntries()[index].signature);
            if (index == 9)
            {
                auto withTarget = image;
                Seed(withTarget, 0x400, xla::SkipLauncherEntries()[1].signature);
                DumpRun("entry9+target", std::move(withTarget), xla::SkipLauncherStage::main, true);
            }
            DumpRun(std::format("entry{}", index), std::move(image),
                    xla::SkipLauncherStage::main, true);
        }
    }

    void RunAllEntries()
    {
        auto image = Blank(0x8000);
        for (std::size_t index = 0; index < xla::SkipLauncherEntries().size(); ++index)
        {
            Seed(image, 0x100 + index * 0x300, xla::SkipLauncherEntries()[index].signature);
        }
        for (const auto stages : {xla::SkipLauncherStage::main, xla::SkipLauncherStage::all,
                                  xla::SkipLauncherStage::dfa | xla::SkipLauncherStage::rom})
        {
            DumpRun("all-entries", image, stages, true);
            DumpRun("all-entries", image, stages, false);
        }
    }

    void RunCollectors()
    {
        for (const std::size_t count :
             {std::size_t{1}, std::size_t{2}, std::size_t{3}, std::size_t{5}})
        {
            auto image = Blank(0x4000);
            for (std::size_t hit = 0; hit < count; ++hit)
            {
                Seed(image, 0x100 + hit * 0x40, xla::SkipLauncherCollectors()[0].pattern);
                Seed(image, 0x1000 + hit * 0x40, xla::SkipLauncherCollectors()[1].pattern);
            }
            DumpRun(std::format("collectors{}", count), std::move(image),
                    xla::SkipLauncherStage::main, true);
        }
    }

    void RunDfaCases()
    {
        auto capture = Blank(0x1000);
        const std::string_view captureSignature = "FF 15 ? ? ? ? 8B F0 83 FE FF 74 24";
        Seed(capture, 0x100, captureSignature);
        const std::uint32_t slot = FakeSlot();
        std::memcpy(capture.data() + 0x100 + 2, &slot, sizeof(slot));
        Seed(capture, 0x300, "55 8B EC 6A 00 E8");
        DumpRun("dfa-capture", capture, xla::SkipLauncherStage::dfa, true);
        DumpRun("dfa-capture-noresolver", capture, xla::SkipLauncherStage::dfa, false);

        auto installs = Blank(0x2000);
        std::size_t offset = 0x40;
        for (const xla::SkipLauncherInstall& install : xla::SkipLauncherDfaInstalls())
        {
            Seed(installs, offset, install.signature);
            offset += 0x300;
        }
        for (const xla::SkipLauncherInstall& install : xla::SkipLauncherRomInstalls())
        {
            Seed(installs, offset, install.signature);
            offset += 0x300;
        }
        DumpRun("all-installs", installs, xla::SkipLauncherStage::all, true);

        auto collected = Blank(0x2000);
        Seed(collected, 0x100, xla::SkipLauncherDfaCollected()[0].collector);
        Seed(collected, 0x300, xla::SkipLauncherDfaCollected()[0].collector);
        Seed(collected, 0x800, xla::SkipLauncherDfaCollected()[0].targets[0].targetSignature);
        Seed(collected, 0xA00, xla::SkipLauncherDfaCollected()[0].targets[1].targetSignature);
        DumpRun("collected", collected, xla::SkipLauncherStage::dfa, true);

        xla::SetCreateFileSlot(FakeSlot());
        DumpRun("dfa-clear-slot", Blank(0x100), xla::SkipLauncherStage::dfa, true);
        xla::SetCreateFileSlot(0);

        auto readFile = Blank(0x1000);
        Seed(readFile, 0x0, "FF 50 60 83 C4 14 39 75 F8 89 45 FC");
        DumpRun("dfa-readfile-oob", readFile, xla::SkipLauncherStage::dfa, true);
        auto romSet = Blank(0x1000);
        Seed(romSet, 0x0, "0F 85 ? ? ? ? 68 03 01 00 00 68 ? ? ? ? 68 04 01 00 00");
        DumpRun("rom-set-oob", romSet, xla::SkipLauncherStage::rom, true);
        auto tail = Blank(0x800);
        Seed(tail, 0x800 - 14, xla::SkipLauncherEntries()[0].signature);
        DumpRun("entry0-tail-oob", tail, xla::SkipLauncherStage::main, true);
        DumpRun("empty", {}, xla::SkipLauncherStage::all, true);
    }
} // namespace

int main()
{
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::printf("section tables\n");
    DumpTables();
    std::printf("section hooks\n");
    DumpHooks();
    std::printf("section entries\n");
    RunEntryCases();
    std::printf("section all-entries\n");
    RunAllEntries();
    std::printf("section collectors\n");
    RunCollectors();
    std::printf("section dfa\n");
    RunDfaCases();
    std::printf("dump complete\n");
    return 0;
}
