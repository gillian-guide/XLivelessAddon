// SPDX-License-Identifier: GPL-3.0-or-later
//
// xla.episodes - [Options] LoadDLCs: the episode/DLC discovery pass.
//
// Ported 1:1 from readable-fusion-opcep/source/episodic.ixx, the `LoadDLCs` key's
// whole footprint: the per-build write table (lines 136-198), the publish step
// (274-288), the install step (471-525), the request layout with the apply capture
// (556-603), the discovery pass the struct-fixup body calls (605-672) and the two
// transcribed bodies (674-683, 685-717). That file's own provenance chain is the
// original ZolikaPatch 7.65 ASI: the two bodies are transcriptions of its recovered
// VAs (0x10023480, 0x10023490) and the discovery pass is the fork's checked rebuild
// of sub_10023150. The fork keeps its copy; this is the companion's own.
//
// What the key does, in the original's own terms: the game's DLC manager gets a
// fixed-layout initialisation. The arm replaces the manager's tail with a jump into
// a body that clears the manager's five request slots, and (when the object is not
// yet initialised) runs the game's load callback and then a discovery pass. The
// pass enumerates the episode layouts next to the executable - `\dlc\tlad\content\`
// or the legacy `\TLAD\`, `\dlc\TBoGT\content\` or `\TBoGT\`, and any addon episode
// `\Episode3\` ... `\Episode254\` - registers each existing folder once through the
// game's own register entry (the id is the episode id, so an addon `\EpisodeN\` is
// registered as 2*N, its setup2.xml id), applies it to the manager and sets the
// manager's post-discovery bytes. The key's build mask is the original's
// [1060,1070,1080]: the recovered table has a row for those three builds and for no
// other, so every other image is a logged skip.
//
// The installer only writes through xla.patch. The two bodies are ABI-exact and are
// proved against the original ASI by tools/verify_port_bodies.py; the discovery
// pass is a rebuild (the fork carries no proof row for it either) and the suite
// drives it end to end with fake register/apply entries.

module;

#include <common.hxx>

export module episodes;

import common;
import patch;

export namespace xla::episodes
{
    // ---- recovered data -----------------------------------------------------

    // The key's build mask, byte-identical to the fork's option row
    // (readable-fusion-opcep/source/options.inc:72). Bits 7, 8 and 9 are 1.0.6.0,
    // 1.0.7.0 and 1.0.8.0; every other build is outside it.
    inline constexpr std::uint32_t kBuildMask = 0x00000380u;

    // The transcribed bodies' recovered VAs in the original ASI (its link base is
    // 0x10000000 too, but these are provenance for the suite and the proof, never
    // run-time addresses).
    inline constexpr std::uint32_t kDummyBodyVa = 0x10023480u;       // sub_10023480
    inline constexpr std::uint32_t kStructFixupBodyVa = 0x10023490u; // sub_10023490
    inline constexpr std::uint32_t kDiscoveryBodyVa = 0x10023150u;   // sub_10023150

    // The discovery pass's literals, byte-identical to the original's text (fork
    // episodic.ixx:68-72; original .rdata 0x1012BD08, 0x1012BD60, 0x1012BDB0,
    // 0x1012BE08 and 0x1012BE54). Each starts with the separator the original
    // concatenated onto the executable's directory, so the pass joins them the same
    // way (directory text + literal).
    inline constexpr char kTladContent[] = "\\dlc\\tlad\\content\\";
    inline constexpr char kTladLegacy[] = "\\TLAD\\";
    inline constexpr char kTbogtContent[] = "\\dlc\\TBoGT\\content\\";
    inline constexpr char kTbogtLegacy[] = "\\TBoGT\\";
    inline constexpr char kEpisodeFormat[] = "\\Episode%d\\";

    // The register request's layout (fork episodic.ixx:556-572): a 0x104-byte path,
    // the flag at +0x158, the mode byte at +0x166 and 360 bytes in total. A folder
    // path that does not fit the buffer is not registered (the original's own bound,
    // `DlcPathFits`).
    inline constexpr std::size_t kPathCapacity = 0x104;
    inline constexpr std::size_t kRequestFlagOffset = 0x158;
    inline constexpr std::size_t kRequestModeOffset = 0x166;
    inline constexpr std::size_t kRequestSize = 360;

    // The DLC manager fields the pass sets once the walk is done (fork
    // episodic.ixx:665-666): the initialised marker and the post-discovery mode.
    inline constexpr std::size_t kManagerMarkerOffset = 0xA4;
    inline constexpr std::size_t kManagerModeOffset = 0x166;

    // The addon-episode range and the two fixed layouts' ids. `\EpisodeN\` is
    // registered as 2*N; 3 is the first addon index (2 and 4 belong to TLAD and
    // TBoGT) and 254 is the one episode whose apply result the original forwards
    // through EDX. Every other registration leaves EDX at the original's 0x40.
    inline constexpr int kFirstAddonEpisode = 3;
    inline constexpr int kLastAddonEpisode = 254;
    inline constexpr int kTladId = 2;
    inline constexpr int kTbogtId = 4;
    inline constexpr std::uint32_t kDefaultResult = 0x40u;

    // The 12-byte tail the arm deletes at the build's fourth write (fork
    // episodic.ixx:138) and the five-byte width of a jump/call row.
    inline constexpr std::size_t kNopTailLength = 12;
    inline constexpr std::size_t kBranchWidth = 5;

    // The kind of one recovered write, in the fork's own vocabulary.
    enum class WriteKind : std::uint8_t
    {
        jump_rva,  // `E9` to a game RVA of the same image
        call_rva,  // `E8` to a game RVA of the same image
        jump_body, // `E9` to the transcribed struct-fixup body
        call_body, // `E8` to the transcribed dummy body
        nop_tail,  // the 12-byte fill
    };

    struct Write
    {
        std::uint32_t site;   // game RVA the write lands at
        WriteKind kind;
        std::uint32_t target; // game RVA, for the two *_rva kinds
    };

    // One build's row: the three RVAs the publish step hands the discovery pass and
    // the write set, in the original handler's order.
    struct BuildRow
    {
        GameBuild build;
        std::uint32_t registerRva;
        std::uint32_t applyRva;
        std::uint32_t loadCallbackRva;
        std::span<const Write> writes;
    };

    // The recovered rows, for the install and for the suite's provenance pin.
    std::span<const BuildRow> Builds() noexcept;

    // The row for a build, or null when the build has none.
    const BuildRow* BuildFor(GameBuild build) noexcept;

    // The key's gate: the original's [1060,1070,1080] mask.
    bool BuildHasLoadDLCs(GameBuild build) noexcept;

    // The discovery pass's path buffer is 0x104 bytes including the terminator.
    bool DlcPathFits(std::string_view path) noexcept;

    // The published state the discovery pass reads, for the suite.
    struct Published
    {
        std::uint32_t gameBase;     // dword_1015AD70
        std::uint32_t registerRva;  // dword_1015804C
        std::uint32_t applyRva;     // dword_101580D0
        std::uint32_t loadCallback; // dword_1015BDDC
    };

    Published PublishedForTest() noexcept;

    // The original's publish step: hands the discovery pass the image base, the
    // build's register/apply RVAs and the absolute load callback.
    void Publish(const Image& image, GameBuild build);

    // One install's count: how many recovered writes landed and how many rows were
    // skipped (a missing path bound or a site outside the view is a logged skip,
    // never a fault).
    struct Report
    {
        std::size_t applied{};
        std::size_t missing{};
    };

    // The original's install step, against `image`. The module-path bound is the
    // first refusal (the original's own, fork episodic.ixx:476-487); then the six
    // writes, in table order.
    Report Install(const Image& image, GameBuild build);

    // The bodies the write table branches to, resolvable by name for the suite and
    // the proof tool.
    enum class Body : std::uint8_t
    {
        dummy,        // 0x10023480: the `mov al,1; ret 8` call replacement
        struct_fixup, // 0x10023490: the manager's initialisation tail
        discovery,    // 0x10023150: the checked rebuild the fixup body calls
    };

    std::uintptr_t ResolveBody(Body body) noexcept;
    std::uint32_t BodyVa(Body body) noexcept;

    // Test seams over the discovery pass: it resolves its register/apply entries
    // from a published base plus two RVAs, and the suite substitutes its own fakes
    // through `SetDiscoveryForTest` (nothing is written to the game image).
    void* DiscoverForTest(void* object) noexcept;

    // The pass's second return value (EDX): the one `\Episode254\` registration
    // forwards the last apply result, everything else answers kDefaultResult.
    std::uint32_t DiscoverResultForTest(void* object) noexcept;

    void SetDiscoveryForTest(std::uint32_t gameBase, std::uint32_t registerRva,
                             std::uint32_t applyRva) noexcept;
} // namespace xla::episodes

// The published state, in C linkage because the transcribed fixup body names the
// slot directly (`call DWORD PTR [xla_dlc_load_callback]`, the original's
// `call dword_1015BDDC`). The pass reads the base and the two RVAs; the publish
// step writes all four.
extern "C"
{
    std::uint32_t xla_dlc_game_base = 0;      // dword_1015AD70
    std::uint32_t xla_dlc_register_rva = 0;   // dword_1015804C
    std::uint32_t xla_dlc_apply_rva = 0;      // dword_101580D0
    std::uint32_t xla_dlc_load_callback = 0;  // dword_1015BDDC
}

// The transcribed bodies are defined in the tail of this file. MSVC rejects a
// __declspec(naked) declaration (C2488), so the readable code above them names each
// body through a plain prototype; only the tail definition keeps the attribute.
static void DlcDummyBody();
static void DlcStructFixupBody();

namespace
{
    using xla::episodes::BuildRow;
    using xla::episodes::Write;
    using xla::episodes::WriteKind;

    // The handler's write order, per build (fork episodic.ixx:166-191), byte for
    // byte. Each row's `site`/`target` is a game RVA and its kind is the fork's.
    constexpr Write kDlcWrites1060[] = {
        {0x41450Eu, WriteKind::jump_rva, 0x41452Cu},
        {0x41453Au, WriteKind::call_rva, 0x413E30u},
        {0x41453Fu, WriteKind::nop_tail, 0u},
        {0x41445Cu, WriteKind::jump_rva, 0x4144B8u},
        {0x4137CDu, WriteKind::call_body, 0u},
        {0x4144D4u, WriteKind::jump_body, 0u},
    };

    constexpr Write kDlcWrites1070[] = {
        {0x4142AEu, WriteKind::jump_rva, 0x4142CCu},
        {0x4142DAu, WriteKind::call_rva, 0x413BD0u},
        {0x4142DFu, WriteKind::nop_tail, 0u},
        {0x4141FCu, WriteKind::jump_rva, 0x414258u},
        {0x41356Du, WriteKind::call_body, 0u},
        {0x414274u, WriteKind::jump_body, 0u},
    };

    constexpr Write kDlcWrites1080[] = {
        {0x49040Eu, WriteKind::jump_rva, 0x49042Cu},
        {0x49043Au, WriteKind::call_rva, 0x48FBB0u},
        {0x49043Fu, WriteKind::nop_tail, 0u},
        {0x49035Cu, WriteKind::jump_rva, 0x4903B8u},
        {0x48F558u, WriteKind::call_body, 0u},
        {0x4903D4u, WriteKind::jump_body, 0u},
    };

    // The key's mask is exactly these three builds (fork episodic.ixx:194-198).
    constexpr BuildRow kDlcBuilds[] = {
        {xla::GameBuild::v1060, 0x4136E0u, 0x414080u, 0x414560u, kDlcWrites1060},
        {xla::GameBuild::v1070, 0x413480u, 0x413E20u, 0x414300u, kDlcWrites1070},
        {xla::GameBuild::v1080, 0x48F440u, 0x48FE00u, 0x490460u, kDlcWrites1080},
    };

    // The register request the pass fills (fork episodic.ixx:556-572). The register
    // entry reads the path and the two tail fields; the apply entry receives the
    // whole 360-byte request.
    struct RegisterRequest
    {
        char path[xla::episodes::kPathCapacity];
        std::uint8_t reserved[xla::episodes::kRequestFlagOffset -
                              xla::episodes::kPathCapacity];
        std::uint32_t flag;
        std::uint8_t reserved2[xla::episodes::kRequestModeOffset -
                               (xla::episodes::kRequestFlagOffset +
                                sizeof(std::uint32_t))];
        std::uint8_t mode;
        std::uint8_t tail[xla::episodes::kRequestSize -
                          (xla::episodes::kRequestModeOffset + sizeof(std::uint8_t))];
    };
    static_assert(sizeof(RegisterRequest) == xla::episodes::kRequestSize);

    // The game's two entries, by the calling conventions the oracle's discovery uses
    // (fork episodic.ixx:574-581): the register entry is `__stdcall(int id, const
    // char* path, int flag)`; the apply entry is `__thiscall`, so the DLC manager
    // arrives in ECX and the request pointer on the stack.
    using RegisterFn = char(__stdcall*)(int, const char*, int);
    using ApplyFn = void(__thiscall*)(void*, const void*);

    // The apply function returns its second value in EDX. Capture it for the one
    // caller that observes it (an existing `\Episode254\`): the manager goes to ECX,
    // the request pointer on the stack, the callee pops it (`ret 4`), and
    // `mov esp,ebp` discards any imbalance regardless (fork episodic.ixx:583-603).
    // The parameters are unnamed because the body is the original's stack contract,
    // not a C++ call: the register file is read through [ebp+...].
    static __declspec(naked) void DlcApplyCapture(void*, const void*, ApplyFn,
                                                  std::uint32_t*)
    {
        __asm
        {
            push ebp
            mov ebp, esp
            push DWORD PTR [ebp + 0Ch]
            mov ecx, DWORD PTR [ebp + 8]
            call DWORD PTR [ebp + 10h]
            mov eax, DWORD PTR [ebp + 14h]
            mov DWORD PTR [eax], edx
            mov esp, ebp
            pop ebp
            ret
        }
    }

    // sub_10023150, rebuilt on the checked path API (fork episodic.ixx:605-672): the
    // discovery pass. It enumerates the episode folders next to the executable,
    // registers each existing layout once through the published game RVAs, applies
    // it to the manager and sets the manager's post-discovery bytes. The original's
    // EDX result is kept: the last apply's second value when `\Episode254\` was
    // registered, otherwise 0x40.
    //
    // The path work sits in its own scope on purpose. A `std::filesystem::path` /
    // `std::string` destructor runs after the compiler's last C++ statement, so a
    // rebuild that sets EDX before those destructors gets it clobbered by the
    // allocator's `free` (the fork's rebuild has that shape; nothing in the fork
    // observes EDX, which is why it went unnoticed). Here every non-trivial local is
    // destroyed at the end of the block, and the original's second return value is
    // stored last, so the game's caller always sees what the original stored.
    void* __cdecl Discover(void* object)
    {
        std::uint32_t lastApplyEdx = 0;
        bool episode254 = false;
        {
            char modulePath[xla::episodes::kPathCapacity]{};
            const DWORD moduleLength =
                GetModuleFileNameA(nullptr, modulePath, sizeof(modulePath));
            if (moduleLength == 0 || moduleLength >= sizeof(modulePath))
            {
                return object;
            }
            if (xla_dlc_register_rva == 0 || xla_dlc_apply_rva == 0)
            {
                return object;
            }

            // The original's PathRemoveFileSpecA: drop the executable's file name.
            // The literals carry their leading separator, so the candidate text is
            // the directory plus the literal, exactly what the original's
            // strcpy_s/strcat_s pair built.
            std::string directory(modulePath, moduleLength);
            const std::size_t separator = directory.find_last_of("\\/");
            if (separator == std::string::npos)
            {
                return object;
            }
            directory.resize(separator);

            const auto gameBase = static_cast<std::uintptr_t>(xla_dlc_game_base);
            const auto registerFn =
                reinterpret_cast<RegisterFn>(gameBase + xla_dlc_register_rva);
            const auto applyFn = reinterpret_cast<ApplyFn>(gameBase + xla_dlc_apply_rva);

            std::error_code ignored;
            const auto tryPaths = [&](const char* primary, const char* fallback, int id)
            {
                std::string candidate = directory + primary;
                if (!std::filesystem::exists(std::filesystem::path(candidate), ignored))
                {
                    // An addon episode names one layout, so the second test is the
                    // same path: do not ask the file system twice.
                    if (std::string_view(primary) == std::string_view(fallback))
                    {
                        return;
                    }
                    candidate = directory + fallback;
                    if (!std::filesystem::exists(std::filesystem::path(candidate), ignored))
                    {
                        return;
                    }
                }

                RegisterRequest request{};
                if (candidate.size() >= sizeof(request.path))
                {
                    return;
                }
                std::memcpy(request.path, candidate.c_str(), candidate.size() + 1);
                request.mode = 1;
                request.flag = 1;
                registerFn(id, request.path, 1);
                DlcApplyCapture(object, &request, applyFn, &lastApplyEdx);
                if (id == 2 * xla::episodes::kLastAddonEpisode)
                {
                    episode254 = true;
                }
            };

            tryPaths(xla::episodes::kTladContent, xla::episodes::kTladLegacy,
                     xla::episodes::kTladId);
            tryPaths(xla::episodes::kTbogtContent, xla::episodes::kTbogtLegacy,
                     xla::episodes::kTbogtId);
            for (int index = xla::episodes::kFirstAddonEpisode;
                 index <= xla::episodes::kLastAddonEpisode; ++index)
            {
                char suffix[64]{};
                std::snprintf(suffix, sizeof(suffix), xla::episodes::kEpisodeFormat, index);
                tryPaths(suffix, suffix, 2 * index);
            }

            auto* const bytes = static_cast<std::uint8_t*>(object);
            bytes[xla::episodes::kManagerMarkerOffset] = 1;
            bytes[xla::episodes::kManagerModeOffset] = 2;
        }

        if (episode254)
        {
            __asm mov edx, lastApplyEdx
        }
        else
        {
            __asm mov edx, 40h
        }
        return object;
    }

    // The pass answers its second value in EDX, which a C++ call cannot observe.
    // This capture is the same shape as DlcApplyCapture above and exists for the
    // suite only; it writes nothing. Unnamed parameters for the same reason.
    static __declspec(naked) void DlcDiscoverCapture(void*, std::uint32_t*)
    {
        __asm
        {
            push ebp
            mov ebp, esp
            push DWORD PTR [ebp + 8]
            call Discover
            add esp, 4
            mov eax, DWORD PTR [ebp + 0Ch]
            mov DWORD PTR [eax], edx
            mov esp, ebp
            pop ebp
            ret
        }
    }
} // namespace

namespace xla::episodes
{
    std::span<const BuildRow> Builds() noexcept
    {
        return kDlcBuilds;
    }

    const BuildRow* BuildFor(GameBuild build) noexcept
    {
        for (const BuildRow& row : kDlcBuilds)
        {
            if (row.build == build)
            {
                return &row;
            }
        }
        return nullptr;
    }

    bool BuildHasLoadDLCs(GameBuild build) noexcept
    {
        // The original's mask, through the original's own build ids: an image the
        // original mod did not classify (1.0.1.0-1.0.3.0, which this add-on's own
        // classification does recognise) has no bit, so the key stays inert there,
        // exactly like the original ASI on such an image.
        return BuildInMask(build, kBuildMask);
    }

    bool DlcPathFits(std::string_view path) noexcept
    {
        return !path.empty() && path.size() < kPathCapacity;
    }

    Published PublishedForTest() noexcept
    {
        return {.gameBase = xla_dlc_game_base,
                .registerRva = xla_dlc_register_rva,
                .applyRva = xla_dlc_apply_rva,
                .loadCallback = xla_dlc_load_callback};
    }

    void Publish(const Image& image, GameBuild build)
    {
        const BuildRow* const row = BuildFor(build);
        if (row == nullptr)
        {
            Log::Print("loadDLCs: build {} carries no recovered row; nothing published",
                       BuildLabel(build));
            return;
        }

        const auto base =
            static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(image.base));
        xla_dlc_game_base = base;
        xla_dlc_register_rva = row->registerRva;
        xla_dlc_apply_rva = row->applyRva;
        xla_dlc_load_callback = base + row->loadCallbackRva;
        Log::Print("loadDLCs: published register={:08X} apply={:08X} load={:08X} for build {}",
                   xla_dlc_register_rva, xla_dlc_apply_rva, xla_dlc_load_callback,
                   BuildLabel(build));
    }

    Report Install(const Image& image, GameBuild build)
    {
        Report report;
        if (!BuildHasLoadDLCs(build))
        {
            Log::Print("loadDLCs: build {} is outside the original's [1060,1070,1080] mask; "
                       "skipped",
                       BuildLabel(build));
            return report;
        }

        const BuildRow* const row = BuildFor(build);
        if (row == nullptr)
        {
            ++report.missing;
            return report;
        }

        // The discovery body builds every candidate path in a 0x104-byte buffer; a
        // module path that already fills it would register the wrong content
        // directory, so the arm skips instead (the original's own bound, fork
        // episodic.ixx:476-487).
        char modulePath[kPathCapacity]{};
        const DWORD length = GetModuleFileNameA(nullptr, modulePath, sizeof(modulePath));
        if (length == 0 || !DlcPathFits(std::string_view(modulePath, length)))
        {
            Log::Print("loadDLCs: module path length {} does not fit 0x104; skipped", length);
            ++report.missing;
            return report;
        }

        auto* const base = reinterpret_cast<std::uint8_t*>(image.base);
        for (const Write& write : row->writes)
        {
            const std::size_t width = write.kind == WriteKind::nop_tail ? kNopTailLength
                                                                       : kBranchWidth;
            auto* const site = base + write.site;
            if (!image.contains(site, width))
            {
                ++report.missing;
                Log::Print("loadDLCs: site RVA {:#010x} (+{} byte(s)) is outside the image; "
                           "skipped",
                           write.site, width);
                continue;
            }

            bool applied = false;
            switch (write.kind)
            {
            case WriteKind::jump_rva:
                applied = patch::JumpAt(image, site, base + write.target, "loadDLCs: jump");
                Log::Print("loadDLCs: jump {:08X} -> {:08X}", write.site, write.target);
                break;
            case WriteKind::call_rva:
                applied = patch::CallAt(image, site, base + write.target, "loadDLCs: call");
                Log::Print("loadDLCs: call {:08X} -> {:08X}", write.site, write.target);
                break;
            case WriteKind::jump_body:
                applied = patch::JumpAt(
                    image, site,
                    reinterpret_cast<std::uint8_t*>(ResolveBody(Body::struct_fixup)),
                    "loadDLCs: fixup jump");
                Log::Print("loadDLCs: jump {:08X} -> struct fixup body", write.site);
                break;
            case WriteKind::call_body:
                applied = patch::CallAt(image, site,
                                        reinterpret_cast<void*>(ResolveBody(Body::dummy)),
                                        "loadDLCs: dummy call");
                Log::Print("loadDLCs: call {:08X} -> dummy body", write.site);
                break;
            case WriteKind::nop_tail:
                applied = patch::FillAt(image, site, 0x90, kNopTailLength,
                                        "loadDLCs: nop tail");
                Log::Print("loadDLCs: nop {} byte(s) at {:08X}", kNopTailLength, write.site);
                break;
            }

            if (applied)
            {
                ++report.applied;
            }
            else
            {
                ++report.missing;
            }
        }

        Log::Print("loadDLCs: {}/{} write(s) applied", report.applied,
                   report.applied + report.missing);
        return report;
    }

    std::uintptr_t ResolveBody(Body body) noexcept
    {
        switch (body)
        {
        case Body::dummy:
            return reinterpret_cast<std::uintptr_t>(&DlcDummyBody);
        case Body::struct_fixup:
            return reinterpret_cast<std::uintptr_t>(&DlcStructFixupBody);
        case Body::discovery:
            return reinterpret_cast<std::uintptr_t>(&Discover);
        }
        return 0;
    }

    std::uint32_t BodyVa(Body body) noexcept
    {
        switch (body)
        {
        case Body::dummy:
            return kDummyBodyVa;
        case Body::struct_fixup:
            return kStructFixupBodyVa;
        case Body::discovery:
            return kDiscoveryBodyVa;
        }
        return 0;
    }

    void* DiscoverForTest(void* object) noexcept
    {
        return Discover(object);
    }

    std::uint32_t DiscoverResultForTest(void* object) noexcept
    {
        std::uint32_t result = 0;
        DlcDiscoverCapture(object, &result);
        return result;
    }

    void SetDiscoveryForTest(std::uint32_t gameBase, std::uint32_t registerRva,
                             std::uint32_t applyRva) noexcept
    {
        xla_dlc_game_base = gameBase;
        xla_dlc_register_rva = registerRva;
        xla_dlc_apply_rva = applyRva;
    }
} // namespace xla::episodes

// ---------------------------------------------------------------------------
// Transcribed bodies. Each is the original's instruction stream, kept as asm
// because that is what it is; the code above is what installs it.
// ---------------------------------------------------------------------------

// sub_10023480, recovered VA 0x10023480 (2 instructions): the call replacement a
// file-type update site gets. It sets only AL, so a caller's `test al,al` sees
// success while the upper 24 bits of EAX stay whatever the caller had (fork
// episodic.ixx:674-683).
static __declspec(naked) void DlcDummyBody()
{
    __asm
    {
        mov al, 1
        ret 8
    }
}

// sub_10023490, recovered VA 0x10023490 (19 instructions): the DLC manager's
// initialisation tail. It clears the five request slots the site's loop cleared,
// marks the object initialised when it already was, and otherwise runs the loader
// callback and the discovery pass before setting the loaded byte. Entered through the
// site's jump, so the ESI object is live and the epilogue returns to the game
// function's caller (fork episodic.ixx:685-717).
static __declspec(naked) void DlcStructFixupBody()
{
    __asm
    {
        mov BYTE PTR [esi], 0
        mov BYTE PTR [esi + 40h], 0
        mov BYTE PTR [esi + 80h], 0
        mov BYTE PTR [esi + 0C0h], 0
        mov BYTE PTR [esi + 100h], 0
        cmp BYTE PTR [esi + 167h], 0
        je dlc_fixup_load
        mov BYTE PTR [esi + 168h], 1
    dlc_fixup_exit:
        pop esi
        pop ebx
        add esp, 14h
        ret
    dlc_fixup_load:
        mov ecx, esi
        call DWORD PTR [xla_dlc_load_callback]
        push esi
        call Discover
        pop esi
        mov BYTE PTR [esi + 0A4h], 1
        jmp dlc_fixup_exit
    }
}
