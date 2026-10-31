// SPDX-License-Identifier: GPL-3.0-or-later

// SkipLauncher: XLivelessAddon's launcher/DRM bypass as reimplemented by

// ZolikaPatch 7.65. The tables follow the original handlers' order: the main

// signature table (0x10045CE0), the two multi-hit collectors, the DFA file-API

// hooks (0x10004850) and the ROM message-window patches (0x10004620).

#include "skip_launcher.h"



#include <cstdint>

#include <cstring>

#include <vector>



#include <injector/injector.hpp>



#include <Hooking.Patterns.h>

#include "xla_common.hxx"



#if defined(_WIN32)

#include <windows.h>



#include <atomic>

#endif



namespace

{

constexpr uint8_t kNopByte = 0x90;

constexpr uint8_t kCallOpcode = 0xE8;

constexpr uint8_t kJumpOpcode = 0xE9;

constexpr size_t kDwordLength = 4;

constexpr size_t kBranchLength = 5;  //E8/E9 <rel32>

constexpr uint16_t kCollectorStubLength = 4;



template <typename T, size_t N>

constexpr size_t CountOf(const T (&)[N]) noexcept

{

    return N;

}



// The main table's patches: stores relative to a signature match, in the order

// the original handler (0x10045CE0) applies them. Byte arrays stay literal hex

// so they compare directly against the original handler's data;

// kSkipEntryBytes_<entry>_<write> is the run kSkipEntryWrites_<entry> stores.

constexpr uint8_t kSkipEntryBytes_0_0[] = {0xeb};  //jmp rel8



constexpr uint8_t kSkipEntryBytes_0_1[] = {0xeb};  //jmp rel8



constexpr uint8_t kSkipEntryBytes_2_0[] = {0x90, 0x90};  //nop 2



constexpr uint8_t kSkipEntryBytes_2_1[] = {0x90, 0x90};  //nop 2



constexpr uint8_t kSkipEntryBytes_3_0[] = {0x90, 0x90};  //nop 2



constexpr uint8_t kSkipEntryBytes_4_0[] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90};  //nop 6



constexpr uint8_t kSkipEntryBytes_5_0[] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90};  //nop 6



constexpr uint8_t kSkipEntryBytes_6_0[] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90};  //nop 6



constexpr uint8_t kSkipEntryBytes_7_0[] = {0x33, 0xc0};  //xor eax,eax



constexpr uint8_t kSkipEntryBytes_7_1[] = {0x90, 0xa3};  //nop; mov [imm32],eax



constexpr uint8_t kSkipEntryBytes_9_0[] = {0x33, 0xc0};  //xor eax,eax



constexpr uint8_t kSkipEntryBytes_9_1[] = {0xe9};  //jmp rel32 (the rel32 follows)



constexpr uint8_t kSkipEntryBytes_10_0[] = {0x90, 0xa3};  //nop; mov [imm32],eax



constexpr uint8_t kSkipEntryBytes_11_0[] = {0x33, 0xc0};  //xor eax,eax



constexpr uint8_t kSkipEntryBytes_11_1[] = {0x90, 0x90, 0x90, 0x90};  //nop 4



constexpr uint8_t kSkipEntryBytes_12_0[] = {0x90, 0x90, 0x90};  //nop 3



constexpr uint8_t kSkipEntryBytes_13_0[] = {0x90, 0x90, 0x90};  //nop 3



constexpr uint8_t kSkipEntryBytes_14_0[] = {

    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,

};  //nop 11



constexpr uint8_t kSkipEntryBytes_17_0[] = {

    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,

};  //nop 8



constexpr uint8_t kSkipEntryBytes_18_0[] = {

    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,

};  //nop 8



constexpr uint8_t kSkipEntryBytes_19_0[] = {

    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,

    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,

};  //nop 14



constexpr uint8_t kSkipEntryBytes_20_0[] = {0xc3};  //ret



constexpr uint8_t kSkipEntryBytes_22_0[] = {

    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,

    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,

};  //nop 14



constexpr uint8_t kSkipEntryBytes_23_0[] = {0x33, 0xc0, 0xc3, 0x90};  //xor; ret; nop



constexpr uint8_t kSkipEntryBytes_24_0[] = {0x33, 0xc0, 0xc3, 0x90};  //xor; ret; nop



// The collectors' stub: "mov al,1; ret; nop" over each collected match.

constexpr uint8_t kSkipCollectorBytes_0[] = {0xb0, 0x01, 0xc3, 0x90};



constexpr uint8_t kSkipCollectorBytes_1[] = {0xb0, 0x01, 0xc3, 0x90};



// Entry i's stores: {match-relative offset, length, bytes (null = fill), fill

// byte, jump-target entry (kNoJumpTarget = not a jump)}.

constexpr SkipLauncherWrite kSkipEntryWrites_0[] = {

    {34, 1, kSkipEntryBytes_0_0, 0, kNoJumpTarget},

    {223, 1, kSkipEntryBytes_0_1, 0, kNoJumpTarget},

};



constexpr SkipLauncherWrite kSkipEntryWrites_2[] = {

    {0, 2, kSkipEntryBytes_2_0, 0, kNoJumpTarget},

    {5, 2, kSkipEntryBytes_2_1, 0, kNoJumpTarget},

};



constexpr SkipLauncherWrite kSkipEntryWrites_3[] = {

    {0, 2, kSkipEntryBytes_3_0, 0, kNoJumpTarget},

};



constexpr SkipLauncherWrite kSkipEntryWrites_4[] = {

    {3, 6, kSkipEntryBytes_4_0, 0, kNoJumpTarget},

};



constexpr SkipLauncherWrite kSkipEntryWrites_5[] = {

    {3, 6, kSkipEntryBytes_5_0, 0, kNoJumpTarget},

};



constexpr SkipLauncherWrite kSkipEntryWrites_6[] = {

    {0, 6, kSkipEntryBytes_6_0, 0, kNoJumpTarget},

};



constexpr SkipLauncherWrite kSkipEntryWrites_7[] = {

    {3, 2, kSkipEntryBytes_7_0, 0, kNoJumpTarget},

    {10, 2, kSkipEntryBytes_7_1, 0, kNoJumpTarget},

};



constexpr SkipLauncherWrite kSkipEntryWrites_8[] = {

    {1, 447, nullptr, kNopByte, kNoJumpTarget},

};



constexpr SkipLauncherWrite kSkipEntryWrites_9[] = {

    {0, 2, kSkipEntryBytes_9_0, 0, kNoJumpTarget},

    {2, 1, kSkipEntryBytes_9_1, 0, kNoJumpTarget},

    {3, 4, nullptr, 0, kSkipLauncherJumpTargetEntry},

};



constexpr SkipLauncherWrite kSkipEntryWrites_10[] = {

    {0, 2, kSkipEntryBytes_10_0, 0, kNoJumpTarget},

};



constexpr SkipLauncherWrite kSkipEntryWrites_11[] = {

    {0, 2, kSkipEntryBytes_11_0, 0, kNoJumpTarget},

    {2, 4, kSkipEntryBytes_11_1, 0, kNoJumpTarget},

};



constexpr SkipLauncherWrite kSkipEntryWrites_12[] = {

    {0, 3, kSkipEntryBytes_12_0, 0, kNoJumpTarget},

    {6, 11, nullptr, kNopByte, kNoJumpTarget},

};



constexpr SkipLauncherWrite kSkipEntryWrites_13[] = {

    {0, 3, kSkipEntryBytes_13_0, 0, kNoJumpTarget},

    {6, 11, nullptr, kNopByte, kNoJumpTarget},

};



constexpr SkipLauncherWrite kSkipEntryWrites_14[] = {

    {0, 11, kSkipEntryBytes_14_0, 0, kNoJumpTarget},

};



constexpr SkipLauncherWrite kSkipEntryWrites_15[] = {

    {0, 32, nullptr, kNopByte, kNoJumpTarget},

};



constexpr SkipLauncherWrite kSkipEntryWrites_16[] = {

    {0, 25, nullptr, kNopByte, kNoJumpTarget},

};



constexpr SkipLauncherWrite kSkipEntryWrites_17[] = {

    {0, 8, kSkipEntryBytes_17_0, 0, kNoJumpTarget},

};



constexpr SkipLauncherWrite kSkipEntryWrites_18[] = {

    {0, 8, kSkipEntryBytes_18_0, 0, kNoJumpTarget},

};



constexpr SkipLauncherWrite kSkipEntryWrites_19[] = {

    {0, 14, kSkipEntryBytes_19_0, 0, kNoJumpTarget},

};



constexpr SkipLauncherWrite kSkipEntryWrites_20[] = {

    {0, 1, kSkipEntryBytes_20_0, 0, kNoJumpTarget},

};



constexpr SkipLauncherWrite kSkipEntryWrites_21[] = {

    {0, 16, nullptr, kNopByte, kNoJumpTarget},

};



constexpr SkipLauncherWrite kSkipEntryWrites_22[] = {

    {0, 14, kSkipEntryBytes_22_0, 0, kNoJumpTarget},

};



constexpr SkipLauncherWrite kSkipEntryWrites_23[] = {

    {0, 4, kSkipEntryBytes_23_0, 0, kNoJumpTarget},

};



constexpr SkipLauncherWrite kSkipEntryWrites_24[] = {

    {0, 4, kSkipEntryBytes_24_0, 0, kNoJumpTarget},

};



constexpr SkipLauncherEntry kSkipLauncherEntries[] = {

    {"84 DB 0F 85 43 01 00 00 8D 4C 24 28 8B C1", kSkipEntryWrites_0, CountOf(kSkipEntryWrites_0)},

    {"68 ? ? ? ? 89 35 ? ? ? ? E8 ? ? ? ? 83 C4 04 84 C0 0F 84", nullptr, 0},

    {"74 EC 38 5E 06 74 E7 68", kSkipEntryWrites_2, CountOf(kSkipEntryWrites_2)},

    {"74 C4 8B 07 3B 46 18 75 BD 68", kSkipEntryWrites_3, CountOf(kSkipEntryWrites_3)},

    {"3B 56 18 0F 85", kSkipEntryWrites_4, CountOf(kSkipEntryWrites_4)},

    {"3B 4E 18 0F 85", kSkipEntryWrites_5, CountOf(kSkipEntryWrites_5)},

    {"0F 85 ? ? ? ? 8B 8C 24 ? ? ? ? 5F 5E 5B 33 CC C6", kSkipEntryWrites_6,

        CountOf(kSkipEntryWrites_6)},

    {"3B 46 18 75 BD", kSkipEntryWrites_7, CountOf(kSkipEntryWrites_7)},

    {"57 51 C7 44 24 ? ? ? ? ? C7 44 24 ? ? ? ? ? C7 44 24", kSkipEntryWrites_8,

        CountOf(kSkipEntryWrites_8)},

    {"8B 56 1C 3B 56 20 ? ? 6A 00 6A 00", kSkipEntryWrites_9, CountOf(kSkipEntryWrites_9)},

    {"89 35 ? ? ? ? E8 ? ? ? ? 83 C4 04 84 C0", kSkipEntryWrites_10, CountOf(kSkipEntryWrites_10)},

    {"8B 50 2C 3B 50 30", kSkipEntryWrites_11, CountOf(kSkipEntryWrites_11)},

    {"8B 48 2C 83 EC 78", kSkipEntryWrites_12, CountOf(kSkipEntryWrites_12)},

    {"8B 48 2C 83 EC 74", kSkipEntryWrites_13, CountOf(kSkipEntryWrites_13)},

    {"8B 48 2C 3B 48 30 74 03", kSkipEntryWrites_14, CountOf(kSkipEntryWrites_14)},

    {"8B 48 2C 3B 48 30 53", kSkipEntryWrites_15, CountOf(kSkipEntryWrites_15)},

    {"8B 48 2C 3B 48 30 74 11", kSkipEntryWrites_16, CountOf(kSkipEntryWrites_16)},

    {"8B 48 2C 3B 48 30 75 DC 8D 54 24 18", kSkipEntryWrites_17, CountOf(kSkipEntryWrites_17)},

    {"8B 48 2C 3B 48 30 75 DC 8D 54 24 1C", kSkipEntryWrites_18, CountOf(kSkipEntryWrites_18)},

    {"8B 0D ? ? ? ? 8B 51 2C", kSkipEntryWrites_19, CountOf(kSkipEntryWrites_19)},

    {"51 53 55 56 57 8B 3D ? ? ? ? 8B 47 2C", kSkipEntryWrites_20, CountOf(kSkipEntryWrites_20)},

    {"3B C7 0F 85 ? ? ? ? 85 C0", kSkipEntryWrites_21, CountOf(kSkipEntryWrites_21)},

    {"0F 85 ? ? ? ? 85 C0 0F 84 ? ? ? ? E8 ? ? ? ? 85 D2", kSkipEntryWrites_22,

        CountOf(kSkipEntryWrites_22)},

    {"83 EC 24 A1 ? ? ? ? 8B 48 14 53 55 56 57", kSkipEntryWrites_23, CountOf(kSkipEntryWrites_23)},

    {"83 EC 08 8B 0D ? ? ? ? 8B 51 14 8D 04 24 50 6A 00 52", kSkipEntryWrites_24,

        CountOf(kSkipEntryWrites_24)},

};



constexpr SkipLauncherCollector kSkipLauncherCollectors[] = {

    {"A1 ? ? ? ? 85 C0 8B 0D ? ? ? ? 75", SkipLauncherCollector::Target::first_two,

        kSkipCollectorBytes_0, kCollectorStubLength},

    {"33 C0 83 3D ? ? ? ? 01 0F 94 C0 C3", SkipLauncherCollector::Target::last_two,

        kSkipCollectorBytes_1, kCollectorStubLength},

};



// `FF 15` is a call through an IAT slot; the slot VA is the operand at +2.

constexpr std::string_view kDfaCapturePattern = "FF 15 ? ? ? ? 8B F0 83 FE FF 74 24";

constexpr int32_t kDfaCaptureSlotOffset = 2;



// DFA file-API hooks: the original installs these E8/E9 jumps from 0x10004850.

constexpr SkipLauncherInstall kSkipLauncherDfaInstalls[] = {

    {"E8 ? ? ? ? 83 C4 0C 83 F8 01 74 11 6A 00 6A 00", 0, kCallOpcode,

        SkipHook::dfa_init},

    {"55 8B EC 6A 00 E8", 0, kJumpOpcode, SkipHook::create_file},

    {"6A 00 E8 ? ? ? ? 83 F8 01 59 75 17 FF 15 ? ? ? ? 50 B9 ? ? ? ? E8 ? ? ? ? 8B 40 08 "

     "FF 60 0C 33 C0 C3", 0, kJumpOpcode, SkipHook::close_handle},

    {"6A 00 E8 ? ? ? ? 83 F8 01 59 75 17 FF 15 ? ? ? ? 50 B9 ? ? ? ? E8 ? ? ? ? 8B 40 08 "

     "FF 60 ? 83 C8 FF C3", 0, kJumpOpcode, SkipHook::set_file_pointer},

    {"56 8B 74 24 0C 8D 46 04 50 FF 74 24 0C E8 ? ? ? ? 59 59 33 C9 83 F8 FF 0F 95 C1 89 "

     "06 5E 8B C1 C3", 0, kJumpOpcode, SkipHook::get_file_size_ex},

    {"FF 50 60 83 C4 14 39 75 F8 89 45 FC", -165, kJumpOpcode, SkipHook::read_file},

};



// ROM message-window hooks: the original installs these from 0x10004620.

constexpr SkipLauncherInstall kSkipLauncherRomInstalls[] = {

    {"89 46 3C 89 4E 40 E8", 6, kCallOpcode, SkipHook::rom_reset},

    {"0F 85 ? ? ? ? 68 03 01 00 00 68 ? ? ? ? 68 04 01 00 00", -67, kJumpOpcode,

        SkipHook::rom_set},

};



// The collector's two jump targets: index 0 of the first pattern, index 1 of the

// second.

constexpr SkipLauncherCollectedTarget kDfaCollectedTargets_0[] = {

    {"80 BC 24 ? ? ? ? ? 6A 00", 0},

    {"6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 57", 1},

};



constexpr SkipLauncherCollectedInstall kSkipLauncherDfaCollected[] = {

    {"A1 ? ? ? ? B9 A7 FA DC 5C F7 E1 8B 0D ? ? ? ? 33 F6", kDfaCollectedTargets_0,

        CountOf(kDfaCollectedTargets_0)},

};



// A signature scan over the caller-owned image, in the original's hook::pattern

// style; a miss is the one failure a pass tolerates.

hook::pattern Pattern(const GameImage& image, std::string_view signature)

{

    const uintptr_t begin = reinterpret_cast<uintptr_t>(image.base);

    return hook::make_range_pattern(begin, begin + image.size, signature);

}



// A store outside the mapped image is the pass's one hard failure.

bool InBounds(GameImage image, const uint8_t* site, size_t length) noexcept

{

    return site >= image.base && site + length <= image.base + image.size;

}



} // namespace



const SkipLauncherEntry* SkipLauncherEntries(size_t& count) noexcept

{

    count = CountOf(kSkipLauncherEntries);

    return kSkipLauncherEntries;

}



const SkipLauncherCollector* SkipLauncherCollectors(size_t& count) noexcept

{

    count = CountOf(kSkipLauncherCollectors);

    return kSkipLauncherCollectors;

}



const SkipLauncherInstall* SkipLauncherDfaInstalls(size_t& count) noexcept

{

    count = CountOf(kSkipLauncherDfaInstalls);

    return kSkipLauncherDfaInstalls;

}



const SkipLauncherInstall* SkipLauncherRomInstalls(size_t& count) noexcept

{

    count = CountOf(kSkipLauncherRomInstalls);

    return kSkipLauncherRomInstalls;

}



const SkipLauncherCollectedInstall* SkipLauncherDfaCollected(size_t& count) noexcept

{

    count = CountOf(kSkipLauncherDfaCollected);

    return kSkipLauncherDfaCollected;

}



// The original's main pass (0x10045CE0) plus the DFA (0x10004850) and ROM

// (0x10004620) installers; each stage runs only when its bit is selected.

PatchResult ApplySkipLauncher(GameImage image, SkipHookResolver resolve, void* resolver_user,

                              SkipLauncherReport& report, SkipLauncherStage stages) noexcept

{

    if (!image.base || image.size == 0)

        return {PatchResultCode::invalid_input, "invalid skip launcher input"};



    size_t entryCount = 0;

    const SkipLauncherEntry* entries = SkipLauncherEntries(entryCount);

    std::vector<const uint8_t*> matches(entryCount, nullptr);



    if (HasStage(stages, SkipLauncherStage::main))

    {

        for (size_t i = 0; i < entryCount; ++i)

        {

            const SkipLauncherEntry& entry = entries[i];

            hook::pattern pattern = Pattern(image, entry.signature);

            if (pattern.empty())

            {

                ++report.entriesMissing;

                continue;

            }

            auto* match = pattern.get(0).get<uint8_t>();

            matches[i] = match;

            ++report.entriesFound;

            // The jump-installing entry needs its target entry's match (from the

            // 0x10045CE0 scan); when it is absent the whole block is skipped, not

            // just the jump - 33 C0 + E9 + rel32 share one [ebp-0x1c] guard.

            bool targetAbsent = false;

            for (size_t w = 0; w < entry.writeCount; ++w)

            {

                const uint32_t targetEntry = entry.writes[w].jumpToEntry;

                if (targetEntry != kNoJumpTarget &&

                    (targetEntry >= matches.size() || matches[targetEntry] == nullptr))

                {

                    targetAbsent = true;

                    break;

                }

            }

            if (targetAbsent)

                continue;

            for (size_t w = 0; w < entry.writeCount; ++w)

            {

                const SkipLauncherWrite& write = entry.writes[w];

                auto* site = match + write.offset;

                if (write.jumpToEntry != kNoJumpTarget)

                {

                    const uint8_t* target =

                        write.jumpToEntry < matches.size() ? matches[write.jumpToEntry] : nullptr;

                    if (!target)

                        continue;  // the original skips when the target entry was absent

                    if (!InBounds(image, site, kDwordLength))

                        return {PatchResultCode::out_of_bounds, "site out of bounds"};

                    // The recorded site is the rel32 itself; the E9 opcode sits one

                    // byte before it, so the displacement is measured from the end

                    // of the dword.

                    injector::WriteMemory<uint32_t>(  //jmp rel32

                        site,

                        static_cast<uint32_t>(

                            reinterpret_cast<uintptr_t>(target) -

                            (reinterpret_cast<uintptr_t>(site) + kDwordLength)),

                        true);

                    report.jumpInstalled = true;

                }

                else

                {

                    if (!InBounds(image, site, write.length))

                        return {PatchResultCode::out_of_bounds, "site out of bounds"};

                    if (write.bytes)

                    {

                        injector::WriteMemoryRaw(site,

                                                 const_cast<uint8_t*>(write.bytes),

                                                 write.length,

                                                 true);  //the entry's bytes

                    }

                    else

                    {

                        // Every fill row in the tables is kNopByte.

                        injector::MakeNOP(site, write.length, true);  //nop

                    }

                }

                ++report.writes;

            }

        }



        size_t collectorCount = 0;

        const SkipLauncherCollector* collectors = SkipLauncherCollectors(collectorCount);

        for (size_t i = 0; i < collectorCount; ++i)

        {

            const SkipLauncherCollector& collector = collectors[i];

            hook::pattern pattern = Pattern(image, collector.pattern);

            const size_t hits = pattern.size();

            if (hits == 0)

                continue;

            ++report.collectorsFound;

            for (size_t hit = 0; hit < hits; ++hit)

            {

                // first_two keeps matches 0 and 1; last_two keeps the final two

                // (a lone match is one site for either rule).

                if (collector.target == SkipLauncherCollector::Target::first_two)

                {

                    if (hit >= 2)

                        break;

                }

                else if (hit + 2 < hits)

                {

                    continue;

                }

                auto* site = pattern.get(hit).get<uint8_t>();

                if (!InBounds(image, site, collector.length))

                    return {PatchResultCode::out_of_bounds, "site out of bounds"};

                injector::WriteMemoryRaw(site, const_cast<uint8_t*>(collector.bytes),

                                         collector.length, true);  //mov al,1; ret; nop

                ++report.collectorWrites;

            }

        }

    }



    if (HasStage(stages, SkipLauncherStage::dfa))

    {

        // The create_file hook forwards through this IAT slot, so the capture must

        // happen before the installer writes the hook.

        hook::pattern capture = Pattern(image, kDfaCapturePattern);

        if (!capture.empty())

            report.createFileSlot = injector::ReadMemory<uint32_t>(

                capture.get(0).get<uint8_t>() + kDfaCaptureSlotOffset);



#if defined(_WIN32)

        // Publish (or clear) the captured slot as part of the pass, so the

        // create_file body can never read a stale slot from an earlier image.

        PublishCreateFileSlot(report);

#endif

    }



    if (resolve)

    {

        // Installs an opcode + rel32 to the reimplemented body. A body the resolver

        // does not know, or a missing signature, counts as missing.

        const auto InstallHooks = [&](const SkipLauncherInstall* installs, size_t count,

                                      size_t& applied,

                                      size_t& missing) -> PatchResult

        {

            for (size_t i = 0; i < count; ++i)

            {

                const SkipLauncherInstall& install = installs[i];

                const uintptr_t destination = resolve(install.hook, resolver_user);

                if (!destination)

                {

                    ++missing;

                    continue;

                }

                hook::pattern hookSite = Pattern(image, install.signature);

                if (hookSite.empty())

                {

                    ++missing;

                    continue;

                }

                auto* site = hookSite.get(0).get<uint8_t>() + install.offset;

                if (!InBounds(image, site, kBranchLength))

                    return {PatchResultCode::out_of_bounds, "site out of bounds"};

                injector::WriteMemory<uint8_t>(site, install.opcode, true);  //E8/E9

                injector::WriteMemory<uint32_t>(  //rel32

                    site + 1,

                    static_cast<uint32_t>(

                        destination - (reinterpret_cast<uintptr_t>(site) + kBranchLength)),

                    true);

                ++applied;

            }

            return {};

        };



        if (HasStage(stages, SkipLauncherStage::dfa))

        {

            size_t dfaCount = 0;

            const SkipLauncherInstall* dfa = SkipLauncherDfaInstalls(dfaCount);

            const auto dfaStatus =

                InstallHooks(dfa, dfaCount, report.dfaInstalls, report.dfaMissing);

            if (!dfaStatus)

                return dfaStatus;



            // The collector tail of 0x10004850: each collected site jumps to another

            // pattern's match.

            size_t collectedCount = 0;

            const SkipLauncherCollectedInstall* collected =

                SkipLauncherDfaCollected(collectedCount);

            for (size_t i = 0; i < collectedCount; ++i)

            {

                const SkipLauncherCollectedInstall& install = collected[i];

                hook::pattern hits = Pattern(image, install.collector);

                for (size_t t = 0; t < install.targetCount; ++t)

                {

                    const SkipLauncherCollectedTarget& target = install.targets[t];

                    if (target.index >= hits.size())

                        continue;

                    hook::pattern targetPattern = Pattern(image, target.targetSignature);

                    if (targetPattern.empty())

                        continue;

                    auto* site = hits.get(target.index).get<uint8_t>();

                    if (!InBounds(image, site, kBranchLength))

                        return {PatchResultCode::out_of_bounds, "site out of bounds"};

                    injector::WriteMemory<uint8_t>(site, kJumpOpcode, true);  //jmp

                    injector::WriteMemory<uint32_t>(  //rel32

                        site + 1,

                        static_cast<uint32_t>(

                            reinterpret_cast<uintptr_t>(

                                targetPattern.get(0).get<uint8_t>()) -

                            (reinterpret_cast<uintptr_t>(site) + kBranchLength)),

                        true);

                    ++report.collectedInstalls;

                }

            }

        }



        if (HasStage(stages, SkipLauncherStage::rom))

        {

            size_t romCount = 0;

            const SkipLauncherInstall* rom = SkipLauncherRomInstalls(romCount);

            const auto romStatus = InstallHooks(rom, romCount, report.romInstalls, report.romMissing);

            if (!romStatus)

                return romStatus;

        }

    }



    return {};

}



// ---------------------------------------------------------------------------

// Windows hook bodies

// ---------------------------------------------------------------------------



#if defined(_WIN32)



namespace

{

// The originals live at 0x10004720..0x1000484e (the file API and DFA bodies)

// and 0x100041A0..0x10004570 (the WM_ROM message-window service, ANSI variant).

constexpr UINT kRomMessage = 43858;  // WM_ROM in the original

constexpr char kRomClass[] = "MessageWindow";

constexpr char kRomClassFallback[] = "MessageWindow2";



// xmmword_10104050..0x10104080: the table the ROM service hands to the game.

constexpr uint32_t kRomTable[16] = {

    8, 11, 241, 1, 240, 2, 7, 12, 3, 243, 9, 6, 10, 5, 4, 242,

};



// WM_ROM carries a word array: [4] is the action, [5] and [6] are its operands.

constexpr size_t kRomPayloadAction = 4;

constexpr size_t kRomPayloadArg0 = 5;

constexpr size_t kRomPayloadArg1 = 6;



constexpr uint32_t kRomActionCopyTable = 18;

constexpr uint32_t kRomActionAdd = 51;

constexpr uint32_t kRomActionSet = 100;



// SkipRomReset's object layout: [1] is the window handle, [4] the WM_ROM id;

// [0], [2], [3] and [5..18] are cleared first.

constexpr size_t kRomObjectWindow = 1;

constexpr size_t kRomObjectMessage = 4;

constexpr size_t kRomObjectClearFirst = 5;

constexpr size_t kRomObjectClearLast = 18;



constexpr int kRomReadyPollLimit = 200;

constexpr DWORD kRomReadyPollMs = 1;



std::atomic<uint32_t> gCreateFileSlot{0};

std::atomic<HWND> gRomWindow{nullptr};

std::atomic<bool> gRomReady{false};

std::atomic<bool> gRomStarted{false};



using CreateFileAFn = HANDLE(WINAPI*)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD,

                                      HANDLE);



LRESULT CALLBACK RomWindowProc(HWND window, UINT message, WPARAM wparam, LPARAM lparam)

{

    if (message == WM_NCCREATE)

    {

        gRomWindow.store(window);

        gRomReady.store(true);

    }

    else if (message == WM_DESTROY)

    {

        gRomWindow.store(nullptr);

        PostQuitMessage(0);

        return 0;

    }

    else if (message == kRomMessage)

    {

        auto* payload = reinterpret_cast<uint32_t*>(lparam);

        switch (payload[kRomPayloadAction])

        {

        case kRomActionCopyTable:

            std::memcpy(reinterpret_cast<void*>(

                            static_cast<uintptr_t>(payload[kRomPayloadArg1])),

                        kRomTable, sizeof(kRomTable));

            return 0;

        case kRomActionAdd:

            return static_cast<LRESULT>(payload[kRomPayloadArg0] + payload[kRomPayloadArg1]);

        case kRomActionSet:

            *reinterpret_cast<uint32_t*>(

                static_cast<uintptr_t>(payload[kRomPayloadArg0])) = 1;

            return 0;

        default:

            return 0;

        }

    }

    return DefWindowProcA(window, message, wparam, lparam);

}



DWORD WINAPI RomThread(LPVOID)

{

    WNDCLASSEXA wc{};

    wc.cbSize = sizeof(wc);

    wc.lpfnWndProc = &RomWindowProc;

    wc.hInstance = GetModuleHandleA(nullptr);

    wc.lpszClassName = kRomClass;

    ATOM atom = RegisterClassExA(&wc);

    if (!atom)

    {

        wc.lpszClassName = kRomClassFallback;

        atom = RegisterClassExA(&wc);

        if (!atom)

            return 1;

    }

    CreateWindowExA(0, reinterpret_cast<LPCSTR>(static_cast<uintptr_t>(atom)), "", 0, 0, 0, 0,

                    0, HWND_MESSAGE, nullptr, wc.hInstance, nullptr);

    MSG msg;

    while (GetMessageA(&msg, nullptr, 0, 0))

    {

        TranslateMessage(&msg);

        DispatchMessageA(&msg);

    }

    UnregisterClassA(reinterpret_cast<LPCSTR>(static_cast<uintptr_t>(atom)), wc.hInstance);

    return 0;

}



// 0x100043D0: start the ROM service once and wait until the window exists.

void StartRomService()

{

    if (gRomStarted.exchange(true))

        return;

    const HANDLE thread = CreateThread(nullptr, 0, &RomThread, nullptr, 0, nullptr);

    if (thread)

        CloseHandle(thread);

    for (int i = 0; i < kRomReadyPollLimit && !gRomReady.load(); ++i)

        Sleep(kRomReadyPollMs);

}



// 0x10004780: replaces the DFA init call so it reports success.

int __cdecl SkipDfaInit()

{

    return 1;

}



// 0x10004820: CreateFileA through the captured IAT slot. The original trampoline

// is __cdecl (plain ret; the caller pops the seven arguments), so the ABI must

// match - a stdcall body would corrupt the stack.

HANDLE __cdecl SkipCreateFile(LPCSTR fileName, DWORD desiredAccess, DWORD shareMode,

                              LPSECURITY_ATTRIBUTES security, DWORD creationDisposition,

                              DWORD flags, HANDLE templateFile)

{

    const uint32_t slot = gCreateFileSlot.load();

    if (slot)

    {

        const auto fn = *reinterpret_cast<CreateFileAFn*>(static_cast<uintptr_t>(slot));

        if (fn)

            return fn(fileName, desiredAccess, shareMode, security, creationDisposition, flags,

                      templateFile);

    }

    return CreateFileA(fileName, desiredAccess, shareMode, security, creationDisposition, flags,

                       templateFile);

}



// 0x10004790: the original wraps CloseHandle in SEH and returns -1 (its `or

// eax,-1` filter at 0x100047ec) when it faults. __cdecl like the original

// trampoline; the SEH keywords are MSVC-only.

BOOL __cdecl SkipCloseHandle(HANDLE handle)

{

    __try

    {

        return CloseHandle(handle);

    }

    __except (EXCEPTION_EXECUTE_HANDLER)

    {

        return static_cast<BOOL>(-1);

    }

}



// 0x10004760

DWORD __cdecl SkipSetFilePointer(HANDLE handle, LONG distance, PLONG distanceHigh,

                                 DWORD moveMethod)

{

    return SetFilePointer(handle, distance, distanceHigh, moveMethod);

}



// 0x10004720

BOOL __cdecl SkipGetFileSizeEx(HANDLE handle, PLARGE_INTEGER size)

{

    return GetFileSizeEx(handle, size);

}



// 0x10004740

BOOL __cdecl SkipReadFile(HANDLE handle, LPVOID buffer, DWORD toRead, LPDWORD read,

                          LPOVERLAPPED overlapped)

{

    return ReadFile(handle, buffer, toRead, read, overlapped);

}



// 0x10004570: start the ROM service, reset the object and publish the window

// handle plus the WM_ROM id. __cdecl with one stack argument, returning the

// window handle in eax (plain ret).

int __cdecl SkipRomReset(uint32_t* object)

{

    StartRomService();

    if (!object)

        return 0;

    object[0] = 0;

    object[2] = 0;

    object[3] = 0;

    for (size_t i = kRomObjectClearFirst; i <= kRomObjectClearLast; ++i)

        object[i] = 0;

    object[kRomObjectWindow] =

        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(gRomWindow.load()));

    object[kRomObjectMessage] = kRomMessage;

    return static_cast<int>(object[kRomObjectWindow]);

}



// 0x10004610: the object arrives in ESI (the patched site keeps it there) and

// the site pushed two arguments the callee must pop - the original is

// `mov ecx,[esi+1c]; mov [esi+20],ecx; mov al,1; ret 8`. A C function cannot

// express that, so it is reproduced instruction-for-instruction.

#if defined(_M_IX86)

__declspec(naked) void SkipRomSet()

{

    __asm {

        mov ecx, [esi + 0x1c]

        mov [esi + 0x20], ecx

        mov al, 1

        ret 8

    }

}

#else

void SkipRomSet()

{

}

#endif



} // namespace



void SetCreateFileSlot(uint32_t slot_va) noexcept

{

    gCreateFileSlot.store(slot_va);

}



bool PublishCreateFileSlot(const SkipLauncherReport& report) noexcept

{

    SetCreateFileSlot(report.createFileSlot);

    return report.createFileSlot != 0;

}



uintptr_t ResolveSkipHook(SkipHook hook, void*) noexcept

{

    switch (hook)

    {

    case SkipHook::dfa_init:

        return reinterpret_cast<uintptr_t>(&SkipDfaInit);

    case SkipHook::create_file:

        return reinterpret_cast<uintptr_t>(&SkipCreateFile);

    case SkipHook::close_handle:

        return reinterpret_cast<uintptr_t>(&SkipCloseHandle);

    case SkipHook::set_file_pointer:

        return reinterpret_cast<uintptr_t>(&SkipSetFilePointer);

    case SkipHook::get_file_size_ex:

        return reinterpret_cast<uintptr_t>(&SkipGetFileSizeEx);

    case SkipHook::read_file:

        return reinterpret_cast<uintptr_t>(&SkipReadFile);

    case SkipHook::rom_reset:

        return reinterpret_cast<uintptr_t>(&SkipRomReset);

    case SkipHook::rom_set:

        return reinterpret_cast<uintptr_t>(&SkipRomSet);

    }

    return 0;

}



#endif  // _WIN32

