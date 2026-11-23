// SPDX-License-Identifier: GPL-3.0-or-later
//
// xla.stability - the two recovered crash fixes the fork groups under
// [STABILITY]: [Options] BenchmarkFix and [Options] CombinedRadioFreezeFix.
//
// Ported 1:1 from readable-fusion-opcep/source/stability.ixx: the combined-radio
// install (lines 334-346) and its body (355-366), the benchmark install (294-322)
// and its two bodies (571-615), with the two option rows' build masks
// (`source/options.inc`:70 and :59). That file's own provenance chain is the
// original ZolikaPatch 7.65 ASI: the five bodies are transcriptions of its
// recovered VAs (0x10005650, 0x10005670, 0x10005ED0) and the two anchors are the
// recovered signatures. The fork keeps its copy; this is the companion's own.
//
// What the two keys do, in the original's own terms:
//
//   * BenchmarkFix - the benchmark's two interposed callbacks are entered through a
//     five-byte jump each. The body checks the benchmark object, runs the callback
//     with the original's registers (ESI as the callee, EDI saved for it) and then
//     tail-jumps to that site's own continuation (+0xD, which is why each site
//     publishes its own resume and not a shared one); a null object unwinds through
//     the enclosing function's tail. The key's mask is every build except 1.0.8.0
//     and 1.1.3.0, so it is inert on those two.
//   * CombinedRadioFreezeFix - the game's radio update call is replaced by a two
//     instruction body that answers 19. The key's mask is the original's "every
//     build" mask.
//
// The installer only writes through xla.patch. The five bodies are ABI-exact and
// are proved against the original ASI by tools/verify_port_bodies.py.

module;

#include <common.hxx>

export module stability;

import common;
import patch;

export namespace xla::stability
{
    // ---- recovered data -----------------------------------------------------

    // The two option rows' build masks, byte-identical to the fork's catalogue
    // (readable-fusion-opcep/source/options.inc:70 and :59). BenchmarkFix's mask has
    // every bit except 1.0.8.0 (9) and 1.1.3.0 (13); CombinedRadioFreezeFix's is the
    // original's "all builds" mask.
    inline constexpr std::uint32_t kBenchmarkBuildMask = 0x00049DE2u;
    inline constexpr std::uint32_t kCombinedRadioBuildMask = 0x0004BFE2u;

    // The two anchors, byte for byte, and the two offsets the benchmark arm needs:
    // the site it jumps from (the anchor's +8, the interposed callback's call) and
    // the continuation it publishes (the anchor's +0xD, the instruction after the
    // five-byte jump).
    inline constexpr char kBenchmarkAnchor[] =
        "E8 ? ? ? ? 83 C4 04 57 8B D8 FF D6 8B 77 20";
    inline constexpr char kCombinedRadioAnchor[] = "E8 ? ? ? ? 8B 35 ? ? ? ? 3B F0";
    inline constexpr std::ptrdiff_t kBenchmarkSiteOffset = 8;
    inline constexpr std::ptrdiff_t kBenchmarkResumeOffset = 13;

    // The arm expects exactly two matches: the two callback sites sit in different
    // functions, and installing the subset that happens to match would send body B
    // to body A's continuation (fork stability.ixx:302-303, `ExpectMatchCount`).
    inline constexpr std::size_t kBenchmarkSiteCount = 2;

    // The bodies' recovered VAs in the original ASI (provenance and the suite's pin,
    // not run-time addresses).
    inline constexpr std::uint32_t kBenchmarkBodyAVa = 0x10005650u;   // sub_10005650
    inline constexpr std::uint32_t kBenchmarkBodyBVa = 0x10005670u;   // sub_10005670
    inline constexpr std::uint32_t kCombinedRadioBodyVa = 0x10005ED0u; // sub_10005ED0

    // The five bodies, resolvable by name for the suite and the proof tool.
    enum class Body : std::uint8_t
    {
        benchmark_a,   // 0x10005650: the first callback's shim
        benchmark_b,   // 0x10005670: the second callback's shim
        combined_radio // 0x10005ED0: the radio update's `mov eax,19; ret`
    };

    std::uintptr_t ResolveBody(Body body) noexcept;
    std::uint32_t BodyVa(Body body) noexcept;

    // The two benchmark sites a scan found. `count` is every match the anchor has;
    // the arm refuses anything but kBenchmarkSiteCount.
    struct Sites
    {
        std::uint8_t* first{};
        std::uint8_t* second{};
        std::size_t count{};
    };

    Sites ResolveBenchmarkSites(const Image& image) noexcept;

    // The two resumes the bodies tail-jump to, for the suite (the original keeps
    // them in its own words dword_1015AD50 / dword_1015AD54).
    struct Resumes
    {
        std::uint32_t first{};
        std::uint32_t second{};
    };

    Resumes PublishedForTest() noexcept;

    // The two keys' gates, through the original's own build ids.
    bool BuildHasBenchmark(GameBuild build) noexcept;
    bool BuildHasCombinedRadio(GameBuild build) noexcept;

    // One install's count: how many recovered writes landed and how many rows were
    // skipped (a missing anchor, a partial multi-hit scan or a site outside the view
    // is a logged skip, never a fault).
    struct Report
    {
        std::size_t applied{};
        std::size_t missing{};
    };

    // The original's install steps, against `image`. The benchmark arm publishes the
    // two resumes before it writes the two jumps, in the original handler's order.
    Report InstallBenchmarkFix(const Image& image, GameBuild build);
    Report InstallCombinedRadioFreezeFix(const Image& image, GameBuild build);
} // namespace xla::stability

// The two benchmark resumes, in C linkage because the transcribed bodies name the
// slots directly (`jmp DWORD PTR [xla_benchmark_resume_a]`, the original's
// `jmp dword_1015AD50` / `jmp dword_1015AD54`).
extern "C"
{
    std::uint32_t xla_benchmark_resume_a = 0; // dword_1015AD50
    std::uint32_t xla_benchmark_resume_b = 0; // dword_1015AD54
}

// The transcribed bodies are defined in the tail of this file. MSVC rejects a
// __declspec(naked) declaration (C2488), so the readable code above them names each
// body through a plain prototype; only the tail definition keeps the attribute.
static void BenchmarkBodyA();
static void BenchmarkBodyB();
static void CombinedRadioFreezeBody();

namespace
{
    // One site's own continuation, i.e. the instruction after the five-byte jump the
    // arm writes. Read from the match before anything is written.
    std::uint32_t ResumeAt(std::uint8_t* site) noexcept
    {
        return static_cast<std::uint32_t>(
            reinterpret_cast<std::uintptr_t>(site) + xla::stability::kBenchmarkResumeOffset);
    }
} // namespace

namespace xla::stability
{
    std::uintptr_t ResolveBody(Body body) noexcept
    {
        switch (body)
        {
        case Body::benchmark_a:
            return reinterpret_cast<std::uintptr_t>(&BenchmarkBodyA);
        case Body::benchmark_b:
            return reinterpret_cast<std::uintptr_t>(&BenchmarkBodyB);
        case Body::combined_radio:
            return reinterpret_cast<std::uintptr_t>(&CombinedRadioFreezeBody);
        }
        return 0;
    }

    std::uint32_t BodyVa(Body body) noexcept
    {
        switch (body)
        {
        case Body::benchmark_a:
            return kBenchmarkBodyAVa;
        case Body::benchmark_b:
            return kBenchmarkBodyBVa;
        case Body::combined_radio:
            return kCombinedRadioBodyVa;
        }
        return 0;
    }

    Sites ResolveBenchmarkSites(const Image& image) noexcept
    {
        // `count` is the scan hint, not a minimum: `size()` below reports every
        // match, so a one-hit image is refused rather than half-installed.
        patch::Pattern pattern = patch::FindIn(image, kBenchmarkAnchor, kBenchmarkSiteCount);
        Sites sites;
        if (pattern.empty())
        {
            return sites;
        }
        sites.count = pattern.size();
        sites.first = pattern.get<std::uint8_t>(0);
        if (sites.count > 1)
        {
            sites.second = pattern.get<std::uint8_t>(1);
        }
        return sites;
    }

    Resumes PublishedForTest() noexcept
    {
        return {.first = xla_benchmark_resume_a, .second = xla_benchmark_resume_b};
    }

    bool BuildHasBenchmark(GameBuild build) noexcept
    {
        // The original's mask through the original's build ids: 1.0.8.0 and 1.1.3.0
        // are outside it, and an image the original mod did not classify (1.0.1.0-
        // 1.0.3.0) has no bit either, so the key stays inert there exactly like the
        // original ASI on such an image.
        return BuildInMask(build, kBenchmarkBuildMask);
    }

    bool BuildHasCombinedRadio(GameBuild build) noexcept
    {
        return BuildInMask(build, kCombinedRadioBuildMask);
    }

    Report InstallBenchmarkFix(const Image& image, GameBuild build)
    {
        Report report;
        if (!BuildHasBenchmark(build))
        {
            Log::Print("benchmarkFix: build {} is outside the original's all-1080,1130 mask; "
                       "skipped",
                       BuildLabel(build));
            return report;
        }

        const Sites sites = ResolveBenchmarkSites(image);
        if (sites.count == 0)
        {
            Log::Print("benchmarkFix: anchor missing; skipped");
            ++report.missing;
            return report;
        }
        if (sites.count != kBenchmarkSiteCount)
        {
            // A partial scan is not the shape the arm was recovered from: a shared
            // resume would send the second body to the first one's continuation.
            Log::Print("benchmarkFix: {} match(es), expected {}; skipped", sites.count,
                       kBenchmarkSiteCount);
            ++report.missing;
            return report;
        }

        // The resumes are each site's own +0xD, published before the jumps overwrite
        // the sites (fork stability.ixx:307-320).
        xla_benchmark_resume_a = ResumeAt(sites.first);
        xla_benchmark_resume_b = ResumeAt(sites.second);
        Log::Print("benchmarkFix: published resumes {:08X} and {:08X}",
                   xla_benchmark_resume_a, xla_benchmark_resume_b);

        const auto install = [&](std::uint8_t* match, std::uintptr_t body, const char* label)
        {
            auto* const site = match + kBenchmarkSiteOffset;
            if (!image.contains(site, 5))
            {
                ++report.missing;
                Log::Print("benchmarkFix: {} site outside the image; skipped", label);
                return;
            }
            (void)patch::JumpAt(image, site, reinterpret_cast<std::uint8_t*>(body), label);
            ++report.applied;
            Log::Print("benchmarkFix: {} jump at {:08X} -> {:08X}", label,
                       static_cast<std::uint32_t>(
                           reinterpret_cast<std::uintptr_t>(site) -
                           reinterpret_cast<std::uintptr_t>(image.base)),
                       static_cast<std::uint32_t>(body));
        };
        install(sites.first, ResolveBody(Body::benchmark_a), "first");
        install(sites.second, ResolveBody(Body::benchmark_b), "second");

        Log::Print("benchmarkFix: {}/{} site(s) applied", report.applied,
                   report.applied + report.missing);
        return report;
    }

    Report InstallCombinedRadioFreezeFix(const Image& image, GameBuild build)
    {
        Report report;
        if (!BuildHasCombinedRadio(build))
        {
            Log::Print("combinedRadio: build {} is outside the original's mask; skipped",
                       BuildLabel(build));
            return report;
        }

        patch::Pattern pattern = patch::FindIn(image, kCombinedRadioAnchor, 1);
        if (pattern.empty())
        {
            Log::Print("combinedRadio: anchor missing; skipped");
            ++report.missing;
            return report;
        }

        auto* const site = pattern.get_first<std::uint8_t>();
        if (!image.contains(site, 5))
        {
            Log::Print("combinedRadio: call site outside the image; skipped");
            ++report.missing;
            return report;
        }
        (void)patch::CallAt(image, site,
                            reinterpret_cast<void*>(ResolveBody(Body::combined_radio)),
                            "combinedRadio: body");

        ++report.applied;
        Log::Print("combinedRadio: call at {:08X} -> {:08X}",
                   static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(site) -
                                              reinterpret_cast<std::uintptr_t>(image.base)),
                   static_cast<std::uint32_t>(ResolveBody(Body::combined_radio)));
        return report;
    }
} // namespace xla::stability

// ---------------------------------------------------------------------------
// Transcribed bodies. Each is the original's instruction stream, kept as asm
// because that is what it is; the code above is what installs it.
// ---------------------------------------------------------------------------

// sub_10005ED0, recovered VA 0x10005ED0 (2 instructions): the radio freeze value.
// The site is a call into the game's radio update; the body returns 19 in its place
// (fork stability.ixx:355-366).
//
// Naked and internal: an external-linkage naked function is written to the module
// and every importer fails (C2488).
static __declspec(naked) void CombinedRadioFreezeBody()
{
    __asm
    {
        mov eax, 13h
        ret
    }
}

// sub_10005650, recovered VA 0x10005650 (12 instructions): BenchmarkFix's first
// match-site shim. It checks the benchmark object, runs the interposed callback
// (ESI with EDI) and then resumes, or unwinds through the enclosing function's tail
// when the object is null (fork stability.ixx:571-593).
//
// Naked and internal: an external-linkage naked function is written to the module
// and every importer fails (C2488).
static __declspec(naked) void BenchmarkBodyA()
{
    __asm
    {
        test eax, eax
        je benchmark_a_zero
        push edi
        mov ebx, eax
        call esi
        jmp DWORD PTR [xla_benchmark_resume_a]
    benchmark_a_zero:
        xor al, al
        pop esi
        pop ebp
        pop ebx
        add esp, 10h
        ret
    }
}

// sub_10005670, recovered VA 0x10005670 (12 instructions): BenchmarkFix's second
// match-site shim, the same shape as the first with its own resume
// (fork stability.ixx:595-615).
//
// Naked and internal: an external-linkage naked function is written to the module
// and every importer fails (C2488).
static __declspec(naked) void BenchmarkBodyB()
{
    __asm
    {
        test eax, eax
        je benchmark_b_zero
        push edi
        mov ebx, eax
        call esi
        jmp DWORD PTR [xla_benchmark_resume_b]
    benchmark_b_zero:
        xor al, al
        pop esi
        pop ebp
        pop ebx
        add esp, 10h
        ret
    }
}
