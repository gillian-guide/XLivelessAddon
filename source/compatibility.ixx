// SPDX-License-Identifier: GPL-3.0-or-later
//
// xla.compatibility - [Options] NewFilesCompatibility and NewSavesCompatibility,
// the two recovered file/save path compatibility arms.
//
// Ported 1:1 from readable-fusion-opcep/source/compatibility.ixx (the
// `Compatibility` namespace of OpenPreCEPatch's COMPATIBILITY section: the two
// publish steps, the two install steps, the savegame-load trampoline and the
// save-format converter with its three site patches). That file's own provenance
// chain is the original ZolikaPatch 7.65 ASI: the bodies are transcriptions of its
// recovered VAs (0x10051600, 0x10051890/0x100518D0, 0x10051A90, 0x10051AD0,
// 0x10051B30, 0x10051FD0, 0x100521E0) and the two rebuilds are the same writes.
// The signature strings, the offsets into each anchor and the bytes written are
// byte-identical; only the installer names are this tree's (`patch::...`).
//
// What the two keys do, in the original's own words:
//
//   * NewFilesCompatibility - allow script.img and radiohud from newer versions to
//     run on an older executable. The arm retargets the two file-type update calls
//     at bodies that ask the game's container whether the newer name is registered
//     and append it, and replaces the registrar's tail with a pushad/popad frame
//     that registers the callback under the original's key. The arm is skipped
//     entirely when GTAC.dll or JacksIVFixes.asi is loaded, because both install
//     the same feature.
//   * NewSavesCompatibility - allow newer savefiles to load without downgrading
//     them first ([1060-1080] only). The arm jumps the savegame-load entry to a
//     trampoline that converts the file on disk, and the converter walks the save's
//     eighteen chunk headers, reads the three sizes that identify the newer layout
//     and patches the three read-site values for it.
//
// Both arms are build-gated the way the original's option catalogue gates them:
// NewFilesCompatibility on every build the add-on classifies, NewSavesCompatibility
// on the original's own [1060-1080] mask only (a newer save's layout is what those
// executables expect). GFWLProtectionDisabler lives in xla.core with the other GFWL
// checks and SteamAchievements in xla.steam, next to its bridge.
//
// The installer only writes through xla.patch. The bodies are ABI-exact and are
// named through ResolveBody so the suite can pin them.

module;

#include <common.hxx>
// Declares the /GS cookie the transcribed savegame bodies' prologues read and the
// checks their epilogues call.
#include <intrin.h>

export module compatibility;

import common;
import patch;

export namespace xla::compatibility
{
    // The recovered VAs of the transcribed bodies and rebuilds, in the original
    // ASI's coordinates (this tree links at 0x10000000 itself; the VAs are
    // provenance and the native suite pins them, they are not addresses used at run
    // time).
    inline constexpr std::uint32_t kRegisterBodyVa = 0x10051600; // sub_10051600
    inline constexpr std::uint32_t kUpdateABodyVa = 0x10051890;  // sub_10051890
    inline constexpr std::uint32_t kUpdateBBodyVa = 0x100518D0;  // sub_100518D0
    inline constexpr std::uint32_t kReadHookVa = 0x10051A90;     // sub_10051A90
    inline constexpr std::uint32_t kSecondLoadVa = 0x10051AD0;   // sub_10051AD0
    inline constexpr std::uint32_t kTrampolineVa = 0x100521E0;   // sub_100521E0
    inline constexpr std::uint32_t kPrepareVa = 0x10051FD0;      // sub_10051FD0
    inline constexpr std::uint32_t kConvertVa = 0x10051B30;      // sub_10051B30
    inline constexpr std::uint32_t kResolverVa = 0x10003E50;     // sub_10003E50

    enum class Body : std::uint8_t
    {
        register_tail, // 0x10051600: the registrar's pushad/popad tail
        update_a,      // 0x10051890: the first file type's update
        update_b,      // 0x100518D0: the second file type's update
        read_hook,     // 0x10051A90: the save read at game 0x7D8C50
        second_load,   // 0x10051AD0: the second LoadData call at game 0x8DA090
        trampoline,    // 0x100521E0: the savegame-load entry's trampoline
        prepare,       // 0x10051FD0: the trampoline's prepare step
        convert,       // 0x10051B30: the save converter
        resolver,      // 0x10003E50: the file-name hash resolver
    };

    // The address of one body. Install resolves every retarget through this
    // function, and the native suite pins the write set against it.
    std::uintptr_t ResolveBody(Body body) noexcept;

    // The recovered VA of a body, for the suite's provenance pin.
    std::uint32_t BodyVa(Body body) noexcept;

    // True when GTAC.dll or JacksIVFixes.asi is loaded: both install
    // NewFilesCompatibility's feature themselves, so the original skips the arm.
    bool ConflictingFileModulePresent() noexcept;

    // NewSavesCompatibility is the original's [1060-1080] key: newer savefiles only
    // need converting on the executables whose layout they do not fit. `unknown`
    // installs nothing.
    bool BuildHasNewSaves(GameBuild build) noexcept;

    // The decisions the converter makes from a save file, exposed for the native
    // suite. `WalkSaveFile` runs the same walk (`WalkSaveFileInto`) and the same
    // patch choice (`ChoosePatchValues`) the production path runs, and writes
    // nothing.
    struct SaveWalkChunk
    {
        char id[5];         // the 9-byte chunk header's first five bytes (never tested)
        std::uint32_t size; // the dword at +5: the chunk's total size
    };

    enum class SaveWalkEnd : std::uint8_t
    {
        noFile,   // fopen_s answered non-zero
        notASave, // the dword at +0xC is not "SAVE"
        walked,   // all eighteen chunk headers were read
        rejected, // a short read, a size below nine or a seek past the end
    };

    struct SaveWalkDecision
    {
        SaveWalkEnd end{SaveWalkEnd::noFile};
        std::uint32_t chunkCount{}; // eighteen when walked
        SaveWalkChunk chunks[18]{}; // in file order
        std::uint8_t forceRead{};   // byte_1015AD98: chunk 9 is 4C45h
        std::uint8_t extraBlock{};  // byte_1015AD99: chunk 13 is 1741h
        std::uint8_t newChunk16{};  // byte_1015AD9A: chunk 16 is 0E77h
        std::uint8_t branchOpcode{}; // site 872185h: EBh, else 74h
        std::uint32_t readSize{};    // site 7D8C50h: 0E6Eh, else 0CBEh
        std::uint16_t readBranch{};  // site 7D8C50h: 9090h, else 2675h
    };

    SaveWalkDecision WalkSaveFile(const char* path);

    // The published state the transcribed bodies read, for the native suite. The
    // slots themselves are C linkage inside the module (the original keeps them in
    // its own .bss), so the suite reads them through this snapshot.
    struct PublishedState
    {
        std::uint32_t registerSlot;      // dword_10159C08
        std::uint32_t saveName;          // dword_1015AD9C
        std::uint32_t loadResume;        // dword_1015AD88
        std::uint32_t loadData;          // dword_1015AD94
        std::uint32_t secondLoadOriginal; // dword_1015AD8C
        std::uint8_t forceRead;          // byte_1015AD98
        std::uint8_t extraBlock;         // byte_1015AD99
        std::uint8_t newChunk16;         // byte_1015AD9A
    };

    PublishedState PublishedForTest() noexcept;

    // One install's count: how many recovered writes landed and how many rows were
    // skipped (a missing signature or a gated build is a logged skip, never a
    // fault).
    struct Report
    {
        std::size_t applied{};
        std::size_t missing{};
    };

    // The recovered anchor strings, in the order the original scans them. The native
    // suite builds its synthetic image from these and pins them against the fork's
    // rows, so a re-spelled scan cannot slip through.
    struct Anchors
    {
        std::string_view updateA;    // the first file type's update
        std::string_view updateB;    // the second file type's update
        std::string_view registrar;  // the registrar's `push key; call entry`
        std::string_view saveName;   // the `push <save-name buffer>` site
        std::string_view saveResume; // the load entry's continuation anchor
        std::string_view branchSite; // site 872185h
        std::string_view readSite;   // site 7D8C50h
        std::string_view loadSite;   // site 8DA090h
    };

    Anchors RecoveredAnchors() noexcept;

    // Fills the resolver's two CRT slots. The update bodies hash file names through
    // the recovered resolver, so the slots are written before any body can run (the
    // original's shared `Register` did the same at startup, outside every key's gate).
    void Prepare() noexcept;

    // The original's publish steps: the registrar's `call` operand the update bodies
    // register through, and the save-name buffer plus the load entry's continuation.
    // Both read the anchor's operand before any install writes it.
    void PublishNewFiles(const Image& image, bool conflictingFileModule);
    void PublishNewSaves(const Image& image);

    // The original's install steps, against `image`. One scan per anchor; a miss is a
    // logged skip. `InstallNewFiles` is gated on the conflicting-module answer and
    // `InstallNewSaves` on the build, exactly as the original gates them. The startup
    // driver runs each arm's publish before that arm's install (the original's two
    // tiers: every publish before any install, because a site write destroys the
    // signature a later publish scans for).
    Report InstallNewFiles(const Image& image, bool conflictingFileModule);
    Report InstallNewSaves(const Image& image, GameBuild build);

    // The converter's three sites, resolved once per process. The original resolves
    // each through a function-local static whose TLS-guarded initialisation caches a
    // miss as null (the `_Init_thread_header`/`_Init_thread_footer` pairs in
    // sub_10051B30), so a build without the pattern never scans again and a site the
    // previous conversion already rewrote is still the same site - the branch byte in
    // particular no longer matches its own anchor once a newer save has forced it to
    // `EB`.
    struct NewSavesSites
    {
        std::uint8_t* branch; // site 872185h
        std::uint8_t* read;   // site 7D8C50h
        std::uint8_t* load;   // site 8DA090h
    };

    // Resolves the three anchors in `image`; a miss is a null site. The production
    // converter calls this once (its own static) and the suite drives it directly.
    NewSavesSites ResolveNewSavesSites(const Image& image) noexcept;

    // Writes the three sites, in the original's order and with its exact values: the
    // branch opcode, the read call and its pushed size/branch, and the second LoadData
    // call. A null site is a skip and the others still run. Driven by the converter
    // (with its cached sites) and by the suite (with its own).
    Report ApplyNewSavesSites(const NewSavesSites& sites, std::uint8_t forceRead,
                              std::uint8_t newChunk16);
} // namespace xla::compatibility

// The published state, in C linkage because the transcribed code names the slots
// directly (the original keeps them in its own .bss beside its bodies).

extern "C"
{
    // dword_10159C08: the game's file-registration entry, published from the
    // registrar's `call` operand.
    std::uint32_t xla_newfiles_register_slot = 0;

    // The NewSaves published state, by the names the original keeps in its own
    // .bss: dword_1015AD9C (the game's save-name buffer), dword_1015AD88 (the load
    // entry's +0xD), dword_1015AD94 (the game's LoadData entry), dword_1015AD8C
    // (the second LoadData call) and byte_1015AD98/99/9A (the walked layout's three
    // size flags).
    std::uint32_t xla_new_saves_src = 0;
    std::uint32_t xla_new_saves_resume = 0;
    std::uint32_t xla_new_saves_loaddata = 0;
    std::uint32_t xla_new_saves_p3_original = 0;
    std::uint8_t xla_new_saves_force_read = 0;
    std::uint8_t xla_new_saves_extra_block = 0;
    std::uint8_t xla_new_saves_new_chunk16 = 0;

    // The file-name resolver's two CRT calls, through pointer slots because the
    // original's calls are memory indirect (`FF 15`); a direct call would be a
    // different instruction. The resolver body hashes a name the way the game hashes
    // model names, so a `hash:NNNN` name resolves through the same body the
    // original's shared resolver uses.
    std::uintptr_t xla_resolver_strnicmp = 0;
    std::uintptr_t xla_resolver_strtoul = 0;
}

// The literal the resolver body compares a name's five-character prefix against
// (original 0x10128CD8).
extern "C" const char xla_resolver_hash_prefix[] = "hash:";

// The transcribed bodies are defined in the tail of this file. MSVC rejects a
// __declspec(naked) declaration (C2488), so the readable code above them names each
// body through a plain prototype; only the definition in the tail keeps the
// attribute.
static void NewfilesRegisterBody();
static void NewSavesReadHook();
static void NewSavesSecondLoadHook();
static void NewSavesTrampoline();
static std::uint32_t __cdecl ResolveFileNameBody();

// The helpers and the two rebuilt bodies, at file scope: the transcribed tails name
// them directly (the original keeps the same helpers beside its bodies).
namespace
{
    // ---------------------------------------------------------------------
    // NewFilesCompatibility
    // ---------------------------------------------------------------------

    // The registrar's anchor and the offsets the arm needs inside it.
    constexpr std::string_view kRegistrarAnchor = "68 64 28 C8 67 E8";
    constexpr std::ptrdiff_t kRegistrarCallOperand = 6; // the `E8`'s rel32
    constexpr std::ptrdiff_t kRegistrarTail = 28;       // the replaced tail

    // The two file-type update sites: the same anchor, one byte of displacement
    // apart at its tail (7B vs 6C).
    constexpr std::string_view kUpdateAAnchor =
        "E8 ? ? ? ? 8B 36 85 F6 75 ED E8 ? ? ? ? 8B 3F 03 EB 85 FF 0F 85 7B FF FF FF";
    constexpr std::string_view kUpdateBAnchor =
        "E8 ? ? ? ? 8B 36 85 F6 75 ED E8 ? ? ? ? 8B 3F 03 EB 85 FF 0F 85 6C FF FF FF";

    // The three helper scans the update bodies use. The original resolves each behind
    // a function-local static guard and re-reads the game state on every call; a scan
    // that misses leaves a null the body then calls or dereferences, which is the
    // original's fault and is preserved.
    std::uintptr_t FirstMatch(std::string_view signature)
    {
        xla::patch::Pattern pattern = xla::patch::find_pattern(signature);
        return pattern.empty()
                   ? 0u
                   : reinterpret_cast<std::uintptr_t>(pattern.get_first<std::byte>(0));
    }

    // sub_10051730, recovered VA 0x10051730: the game's *current texture
    // dictionary*, not a file registry. The scan lands on `mov esi,g_pCurrentTxd`
    // inside CSprite2d::SetTexture, so the operand is that global and the
    // dereference returns the TXD the game has just made current. It is scanned once
    // and dereferenced on every call because the game swaps the dictionary as it
    // streams. A miss reads through the null the scan left behind, as the original's
    // `mov eax,[esi]` with ESI = 0 does.
    void* NewfilesObject()
    {
        static const std::uintptr_t match = FirstMatch(
            "8B 35 ? ? ? ? 6A 00 50 E8 ? ? ? ? 83 C4 08 50 8B CE E8 ? ? ? ? 85 C0 89 07 5E 74 05");
        const std::uint32_t global =
            match != 0 ? *reinterpret_cast<const std::uint32_t*>(match + 2u) : 0u;
        return *reinterpret_cast<void**>(static_cast<std::uintptr_t>(global));
    }

    // sub_10051610, recovered VA 0x10051610: ask the container whether the hash is
    // registered. The original tries one function signature and, on a miss, one
    // older build's; both are cached, and a double miss calls null.
    int NewfilesCallObject(void* object, std::uint32_t hash)
    {
        static const std::uintptr_t function = []() -> std::uintptr_t
        {
            if (const auto direct =
                    FirstMatch("85 C9 53 55 56 57 74 40 8B 6C 24 14 8D 64 24 00");
                direct != 0)
            {
                return direct;
            }
            return FirstMatch("53 55 8B 6C 24 0C 56 57 EB 06");
        }();
        using Fn = int(__fastcall*)(void*, int, std::uint32_t);
        return reinterpret_cast<Fn>(function)(object, 0, hash);
    }

    // sub_100517E0, recovered VA 0x100517E0: append the name to the container. The
    // scan lands twenty bytes inside the function, so its start is match - 0x14.
    int NewfilesCallAdd(void* self, void* name)
    {
        static const std::uintptr_t match =
            FirstMatch("8B 0F 85 C9 74 ? 0F B7 41 0A 66 85 C0");
        static const std::uintptr_t function = match != 0 ? match - 20u : 0u;
        using Fn = int(__fastcall*)(void*, int, void*);
        return reinterpret_cast<Fn>(function)(self, 0, name);
    }

    // The original's gate: NewFilesCompatibility is skipped entirely when GTAC.dll
    // or JacksIVFixes.asi is loaded, because both install the same feature.
    bool ConflictingFileModule() noexcept
    {
        return GetModuleHandleA("GTAC.dll") != nullptr ||
               GetModuleHandleA("JacksIVFixes.asi") != nullptr;
    }

    // sub_10003E50's entry: the file-name resolver the update bodies hash with (the
    // original's shared value resolver, also its "hash:NNNN" syntax).
    std::uint32_t ResolveFileName(const char* name)
    {
        if (name == nullptr)
        {
            return 0;
        }
        // The body is naked and parameterless (its argument is the caller's stack
        // slot, as the original's is), so it is called through its ABI here.
        return reinterpret_cast<std::uint32_t(__cdecl*)(const char*)>(&ResolveFileNameBody)(name);
    }

    // sub_100515D0, recovered VA 0x100515D0 (5 instructions): the registered
    // callback. It marks the object it is handed and returns it.
    void* __cdecl NewfilesCallback(void** object)
    {
        void* const result = *object;
        *reinterpret_cast<int*>(result) = 1;
        return result;
    }

    // sub_100515E0, recovered VA 0x100515E0 (6 instructions): register the callback
    // under the original's key through the published entry. A slot that was never
    // published is a null call, as the original's `call dword_10159C08` is.
    void __cdecl NewfilesRegister()
    {
        using RegisterFn = void(__cdecl*)(std::uint32_t, void*);
        reinterpret_cast<RegisterFn>(static_cast<std::uintptr_t>(xla_newfiles_register_slot))(
            0x2C89A1F9u, reinterpret_cast<void*>(&NewfilesCallback));
    }

    // sub_10051890, recovered VA 0x10051890: the first file type's update, called
    // with the object in ECX. Compiled in the original and rebuilt here: a name at
    // +0x10 means "new file"; resolve it through the container's registry and append
    // it to the +8 list when it is known. AL is the original's answer; the site's
    // caller discards EAX.
    char __fastcall NewfilesUpdateABody(void* self, int)
    {
        auto* base = static_cast<std::uint8_t*>(self);
        if (base[0x10] == 0)
        {
            return 0;
        }

        void* const object = NewfilesObject();
        if (NewfilesCallObject(object, ResolveFileName(reinterpret_cast<const char*>(base + 0x10))))
        {
            NewfilesCallAdd(base + 8, base + 0x10);
        }
        return 1;
    }

    // sub_100518D0, recovered VA 0x100518D0: the second file type's update, the same
    // shape with the name at +0x10F and the list at +4.
    char __fastcall NewfilesUpdateBBody(void* self, int)
    {
        auto* base = static_cast<std::uint8_t*>(self);
        if (base[0x10F] == 0)
        {
            return 0;
        }

        void* const object = NewfilesObject();
        if (NewfilesCallObject(object,
                               ResolveFileName(reinterpret_cast<const char*>(base + 0x10F))))
        {
            NewfilesCallAdd(base + 4, base + 0x10F);
        }
        return 1;
    }

    // ---------------------------------------------------------------------
    // NewSavesCompatibility
    // ---------------------------------------------------------------------

    // The save image: an 0x110-byte header whose dword at +0xC is "SAVE", then
    // eighteen chunks of a 9-byte header whose dword at +5 is the chunk's total size,
    // followed by that minus nine payload bytes.
    constexpr std::uint32_t kNewSavesMagic = 0x45564153u; // "SAVE"
    constexpr std::size_t kNewSavesHeaderSize = 0x110;
    constexpr std::size_t kNewSavesMagicOffset = 0x0C;
    constexpr std::size_t kNewSavesChunkCount = 18;
    constexpr std::size_t kNewSavesChunkHeaderSize = 9;
    constexpr std::size_t kNewSavesChunkSizeOffset = 5;

    // The three chunk sizes that identify the newer layout, and the read size the
    // converter writes for it: 0xE77 is the newer chunk 16 and 0xE6E its payload,
    // nine bytes less because the chunk header is not part of what the game reads.
    constexpr std::uint32_t kNewSavesChunk9Size = 0x4C45;
    constexpr std::uint32_t kNewSavesChunk13Size = 0x1741;
    constexpr std::uint32_t kNewSavesChunk16Size = 0x0E77;
    constexpr std::uint32_t kNewSavesReadSizeOld = 0x0CBE;
    constexpr std::uint32_t kNewSavesReadSizeNew = 0x0E6E;

    // The branch in front of the read site: `jne +0x26`, and the NOP pair that
    // replaces it when the newer chunk 16 is present.
    constexpr std::uint16_t kNewSavesBranchJne = 0x2675;
    constexpr std::uint16_t kNewSavesBranchNop = 0x9090;

    // The save-directory buffer (original byte_101A8308, 312 bytes up to the next
    // .bss object).
    constexpr std::size_t kNewSavesDirectorySize = 312;

    // Where the writes land inside their anchors: the read call and its operand, the
    // pushed read size, the branch in front of the push, and the second LoadData
    // call's operand.
    constexpr std::ptrdiff_t kNewSavesCallSite = 6;
    constexpr std::ptrdiff_t kNewSavesCallOperand = 7;
    constexpr std::ptrdiff_t kNewSavesReadSizeOperand = 1;
    constexpr std::ptrdiff_t kNewSavesBranchSite = -5;
    constexpr std::ptrdiff_t kNewSavesLoadOperand = 0x1E;

    // `jz rel8`: the branch the first site is restored to when the save is not the
    // newer layout.
    constexpr std::uint8_t kNewSavesJumpIfZero = 0x74;
    constexpr std::uint8_t kNewSavesShortJump = 0xEB;

    // The converter's three anchors, byte for byte.
    constexpr std::string_view kNewSavesBranchAnchor =
        "74 37 80 3D ? ? ? ? 00 75 2E 8D 84 ? ? ? ? 00 6A 1E";
    constexpr std::string_view kNewSavesReadAnchor = "68 BE 0C 00 00 50 E8";
    constexpr std::string_view kNewSavesLoadAnchor =
        "56 E8 ? ? ? ? E8 ? ? ? ? A1 ? ? ? ? 8D 0C 85 00 00 00 00";

    // The original's install anchors.
    constexpr std::string_view kSaveNameAnchor =
        "68 ? ? ? ? E8 ? ? ? ? 8B 2D ? ? ? ? 83 C4 08";
    constexpr std::string_view kSaveResumeAnchor = "89 84 24 E0 01 00 00 8B 45 08 53 33 DB";
    constexpr std::ptrdiff_t kSaveNameOperand = 1;
    constexpr std::ptrdiff_t kSaveResumeContinuation = 13;

    // The game's save-directory function (the original's lazily resolved
    // `getDirectory`).
    constexpr std::string_view kSaveDirectoryAnchor =
        "55 8B EC 83 E4 F8 83 EC 4C 56 33 C0 8D 4C 24 28";

    // The three values the patch step writes, chosen from the walk's flags by the two
    // conditions the original's `cmovne`s test. Both callers of this - the patch step
    // and the suite - go through it, so the value a test reads cannot drift from the
    // value that is written.
    struct PatchValues
    {
        std::uint8_t branchOpcode;
        std::uint32_t readSize;
        std::uint16_t readBranch;
    };

    PatchValues ChoosePatchValues(std::uint8_t forceRead, std::uint8_t newChunk16)
    {
        return {
            forceRead != 0 ? kNewSavesShortJump : kNewSavesJumpIfZero,
            newChunk16 != 0 ? kNewSavesReadSizeNew : kNewSavesReadSizeOld,
            newChunk16 != 0 ? kNewSavesBranchNop : kNewSavesBranchJne,
        };
    }

    // sub_10051B30's first half: open the file, check the header's magic, then walk
    // the eighteen 9-byte chunk headers. The original's call sequence is kept: the
    // header read is unchecked (a short file leaves the buffer's tail as the stack
    // held it, and the magic test reads it), and each chunk's payload is skipped with
    // a seek. What the walk decides lands in `walk`; it touches no module state, so
    // the suite can call it without publishing anything.
    xla::compatibility::SaveWalkEnd WalkSaveFileInto(const char* path,
                                                     xla::compatibility::SaveWalkDecision& walk)
    {
        std::FILE* stream = nullptr;
        if (fopen_s(&stream, path, "rb") != 0 || stream == nullptr)
        {
            return xla::compatibility::SaveWalkEnd::noFile;
        }

        std::uint8_t header[kNewSavesHeaderSize];
        if (std::fread(header, kNewSavesHeaderSize, 1, stream) != 1)
        {
            // A short header is not a save this build can read.
            std::fclose(stream);
            return xla::compatibility::SaveWalkEnd::rejected;
        }

        std::uint32_t magic = 0;
        std::memcpy(&magic, header + kNewSavesMagicOffset, sizeof(magic));
        if (magic != kNewSavesMagic)
        {
            std::fclose(stream);
            return xla::compatibility::SaveWalkEnd::notASave;
        }

        // One stack header for all eighteen reads: a short read leaves the previous
        // iteration's bytes in it, which is what the original's reused slot does.
        std::uint8_t chunkHeader[kNewSavesChunkHeaderSize];
        for (std::size_t index = 0; index < kNewSavesChunkCount; ++index)
        {
            if (std::fread(chunkHeader, kNewSavesChunkHeaderSize, 1, stream) != 1)
            {
                std::fclose(stream);
                return xla::compatibility::SaveWalkEnd::rejected;
            }

            std::uint32_t size = 0;
            std::memcpy(&size, chunkHeader + kNewSavesChunkSizeOffset, sizeof(size));
            if (size < static_cast<std::uint32_t>(kNewSavesChunkHeaderSize))
            {
                std::fclose(stream);
                return xla::compatibility::SaveWalkEnd::rejected;
            }

            const std::uint32_t payload =
                size - static_cast<std::uint32_t>(kNewSavesChunkHeaderSize);
            // The scan only needs the headers; seek over the payload. A failed seek
            // means the file is shorter than its own chunk table.
            if (payload > static_cast<std::uint32_t>(std::numeric_limits<long>::max()) ||
                std::fseek(stream, static_cast<long>(payload), SEEK_CUR) != 0)
            {
                std::fclose(stream);
                return xla::compatibility::SaveWalkEnd::rejected;
            }

            std::memcpy(walk.chunks[index].id, chunkHeader, sizeof(walk.chunks[index].id));
            walk.chunks[index].size = size;
            walk.chunkCount = static_cast<std::uint32_t>(index) + 1;

            switch (index)
            {
            case 9:
                walk.forceRead = size == kNewSavesChunk9Size ? 1 : 0;
                break;
            case 13:
                walk.extraBlock = size == kNewSavesChunk13Size ? 1 : 0;
                break;
            case 16:
                walk.newChunk16 = size == kNewSavesChunk16Size ? 1 : 0;
                break;
            default:
                break;
            }
        }
        std::fclose(stream);
        return xla::compatibility::SaveWalkEnd::walked;
    }

    // sub_10051B30, recovered VA 0x10051B30: the converter. The call sequence is the
    // original's: a walk of the file, then the three site patches only after the file
    // is closed. A walk that stops early patches nothing, which is the original's
    // early return.
    void NewSavesConvert(const std::string& path)
    {
        xla::compatibility::SaveWalkDecision walk;
        if (WalkSaveFileInto(path.c_str(), walk) != xla::compatibility::SaveWalkEnd::walked)
        {
            return;
        }

        // The original stores each flag as it walks its chunk (0x1015AD98/99/9A);
        // here they become module state once the walk is over, before the patch step
        // that reads them.
        xla_new_saves_force_read = walk.forceRead;
        xla_new_saves_extra_block = walk.extraBlock;
        xla_new_saves_new_chunk16 = walk.newChunk16;

        // The original resolves each converter site once, through a function-local
        // static whose TLS-guarded initialisation caches a miss as null; resolving per
        // load would lose the branch site after the first newer save rewrote it to
        // `EB`, and the next older save would keep the newer path.
        static const xla::compatibility::NewSavesSites sites =
            xla::compatibility::ResolveNewSavesSites(xla::Game::Get().View());
        (void)xla::compatibility::ApplyNewSavesSites(sites, walk.forceRead, walk.newChunk16);
    }

    // sub_10051FD0, recovered VA 0x10051FD0: the prepare step the trampoline calls.
    // The original's gate is the captured save-name buffer: when the handler never
    // found its anchor, nothing runs. The directory comes from the game's own function
    // (found by signature, called with the original's three arguments); a zero answer
    // skips the conversion. The path is the original's std::string: the directory, one
    // backslash, then the name.
    void NewSavesPrepare()
    {
        const auto* const name =
            reinterpret_cast<const char*>(static_cast<std::uintptr_t>(xla_new_saves_src));
        if (name == nullptr)
        {
            return;
        }

        // The original's lazily resolved directory function: one scan, cached with its
        // null on a miss.
        static const std::uintptr_t getDirectory = FirstMatch(kSaveDirectoryAnchor);
        if (getDirectory == 0)
        {
            return;
        }

        // The original's buffer is the module's .bss object byte_101A8308 (312 bytes up
        // to the next object): it persists across conversions and is zero before the
        // first one.
        static char directory[kNewSavesDirectorySize] = {};
        char suffix = 0;
        using GetSaveDirectoryFn = std::uint8_t(__cdecl*)(int, char*, char*);
        if (reinterpret_cast<GetSaveDirectoryFn>(getDirectory)(0, directory, &suffix) == 0)
        {
            return;
        }

        std::string path(directory);
        path += '\\';
        path += name;
        NewSavesConvert(path);
    }
} // namespace

namespace xla::compatibility
{
    std::uintptr_t ResolveBody(Body body) noexcept
    {
        switch (body)
        {
        case Body::register_tail:
            return reinterpret_cast<std::uintptr_t>(&NewfilesRegisterBody);
        case Body::update_a:
            return reinterpret_cast<std::uintptr_t>(&NewfilesUpdateABody);
        case Body::update_b:
            return reinterpret_cast<std::uintptr_t>(&NewfilesUpdateBBody);
        case Body::read_hook:
            return reinterpret_cast<std::uintptr_t>(&NewSavesReadHook);
        case Body::second_load:
            return reinterpret_cast<std::uintptr_t>(&NewSavesSecondLoadHook);
        case Body::trampoline:
            return reinterpret_cast<std::uintptr_t>(&NewSavesTrampoline);
        case Body::prepare:
            return reinterpret_cast<std::uintptr_t>(&NewSavesPrepare);
        case Body::convert:
            return reinterpret_cast<std::uintptr_t>(&NewSavesConvert);
        case Body::resolver:
            return reinterpret_cast<std::uintptr_t>(&ResolveFileNameBody);
        }
        return 0;
    }

    std::uint32_t BodyVa(Body body) noexcept
    {
        switch (body)
        {
        case Body::register_tail:
            return kRegisterBodyVa;
        case Body::update_a:
            return kUpdateABodyVa;
        case Body::update_b:
            return kUpdateBBodyVa;
        case Body::read_hook:
            return kReadHookVa;
        case Body::second_load:
            return kSecondLoadVa;
        case Body::trampoline:
            return kTrampolineVa;
        case Body::prepare:
            return kPrepareVa;
        case Body::convert:
            return kConvertVa;
        case Body::resolver:
            return kResolverVa;
        }
        return 0;
    }

    bool ConflictingFileModulePresent() noexcept
    {
        return ConflictingFileModule();
    }

    void Prepare() noexcept
    {
        // The original's resolver calls the CRT through memory-indirect slots (`FF
        // 15`), which is what keeps the instruction shape; ours are these two.
        xla_resolver_strnicmp = reinterpret_cast<std::uintptr_t>(&_strnicmp);
        xla_resolver_strtoul = reinterpret_cast<std::uintptr_t>(&strtoul);
    }

    Anchors RecoveredAnchors() noexcept
    {
        return {
            .updateA = kUpdateAAnchor,
            .updateB = kUpdateBAnchor,
            .registrar = kRegistrarAnchor,
            .saveName = kSaveNameAnchor,
            .saveResume = kSaveResumeAnchor,
            .branchSite = kNewSavesBranchAnchor,
            .readSite = kNewSavesReadAnchor,
            .loadSite = kNewSavesLoadAnchor,
        };
    }

    bool BuildHasNewSaves(GameBuild build) noexcept
    {
        // The original's mask 0x00008380: 1.0.6.0, 1.0.6.1, 1.0.7.0 and 1.0.8.0. This
        // tree's classifier knows 1.0.6.0/1.0.7.0/1.0.8.0 of that set (its own table
        // has no 1.0.6.1 row), so the gate is those three.
        return IsBuild(build, {GameBuild::v1060, GameBuild::v1070, GameBuild::v1080});
    }

    SaveWalkDecision WalkSaveFile(const char* path)
    {
        SaveWalkDecision decision;
        decision.end = WalkSaveFileInto(path, decision);
        const PatchValues values = ChoosePatchValues(decision.forceRead, decision.newChunk16);
        decision.branchOpcode = values.branchOpcode;
        decision.readSize = values.readSize;
        decision.readBranch = values.readBranch;
        return decision;
    }

    PublishedState PublishedForTest() noexcept
    {
        return {
            .registerSlot = xla_newfiles_register_slot,
            .saveName = xla_new_saves_src,
            .loadResume = xla_new_saves_resume,
            .loadData = xla_new_saves_loaddata,
            .secondLoadOriginal = xla_new_saves_p3_original,
            .forceRead = xla_new_saves_force_read,
            .extraBlock = xla_new_saves_extra_block,
            .newChunk16 = xla_new_saves_new_chunk16,
        };
    }

    void PublishNewFiles(const Image& image, bool conflictingFileModule)
    {
        if (conflictingFileModule)
        {
            return;
        }

        // The registrar's `call <entry>`: the operand at +6 is the displacement the
        // update bodies register their callback through.
        patch::Pattern pattern = patch::FindIn(image, kRegistrarAnchor, 1);
        if (pattern.empty())
        {
            Log::Line("newFiles: registrar anchor missing; nothing published");
            return;
        }

        auto* const match = pattern.get_first<std::uint8_t>();
        xla_newfiles_register_slot =
            static_cast<std::uint32_t>(patch::RelativeTarget(match, kRegistrarCallOperand));
    }

    void PublishNewSaves(const Image& image)
    {
        // The first anchor: the `push <save-name buffer>` site. Its operand (the
        // anchor's +1) is the game's buffer address, which is what the prepare step
        // appends to the save directory. The second anchor publishes the load entry's
        // continuation, +0xD.
        patch::Pattern primary = patch::FindIn(image, kSaveNameAnchor, 1);
        if (primary.empty())
        {
            Log::Line("newSaves: save-name anchor missing; nothing published");
            return;
        }
        xla_new_saves_src = *primary.get_first<std::uint32_t>(kSaveNameOperand);

        patch::Pattern pattern = patch::FindIn(image, kSaveResumeAnchor, 1);
        if (!pattern.empty())
        {
            xla_new_saves_resume = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(
                pattern.get_first<std::byte>(kSaveResumeContinuation)));
        }
    }

    Report InstallNewFiles(const Image& image, bool conflictingFileModule)
    {
        Report report;
        if (conflictingFileModule)
        {
            Log::Line("newFiles: GTAC.dll or JacksIVFixes.asi is loaded; skipped");
            return report;
        }

        // The two update calls first, in the anchor's order (A then B), then the
        // registrar's tail.
        const auto installUpdate = [&](std::string_view anchor, Body body)
        {
            patch::Pattern pattern = patch::FindIn(image, anchor, 1);
            if (pattern.empty())
            {
                ++report.missing;
                Log::Print("newFiles: update anchor missing ({:08X})", BodyVa(body));
                return;
            }
            if (patch::Call(patch::Site{pattern.get_first<std::uint8_t>()},
                            reinterpret_cast<void*>(ResolveBody(body)), "newFiles: update call"))
            {
                ++report.applied;
            }
            else
            {
                ++report.missing;
            }
        };
        installUpdate(kUpdateAAnchor, Body::update_a);
        installUpdate(kUpdateBAnchor, Body::update_b);

        patch::Pattern registrar = patch::FindIn(image, kRegistrarAnchor, 1);
        if (registrar.empty())
        {
            ++report.missing;
            Log::Line("newFiles: registrar anchor missing; tail skipped");
        }
        else if (patch::Jump(patch::Site{registrar.get_first<std::uint8_t>()}, kRegistrarTail,
                             reinterpret_cast<void*>(ResolveBody(Body::register_tail)),
                             "newFiles: registrar tail"))
        {
            ++report.applied;
        }
        else
        {
            ++report.missing;
        }

        Log::Print("newFiles: {} call/arm(s) applied, {} missing", report.applied, report.missing);
        return report;
    }

    Report InstallNewSaves(const Image& image, GameBuild build)
    {
        Report report;
        if (!BuildHasNewSaves(build))
        {
            Log::Print("newSaves: build {} is outside the original's [1060-1080] mask; skipped",
                       BuildLabel(build));
            return report;
        }

        // The original returns before this scan when the first pattern missed, so the
        // write is gated on the first pattern as well: 1.0.0.4.0 carries the load entry
        // but not the name site, and the original writes nothing there.
        patch::Pattern primary = patch::FindIn(image, kSaveNameAnchor, 1);
        if (primary.empty())
        {
            ++report.missing;
            Log::Line("newSaves: save-name anchor missing; load entry skipped");
            return report;
        }

        patch::Pattern pattern = patch::FindIn(image, kSaveResumeAnchor, 1);
        if (pattern.empty())
        {
            ++report.missing;
            Log::Line("newSaves: load-entry anchor missing; trampoline skipped");
            return report;
        }

        if (patch::Jump(patch::Site{pattern.get_first<std::uint8_t>()}, 0,
                        reinterpret_cast<void*>(ResolveBody(Body::trampoline)),
                        "newSaves: load-entry trampoline"))
        {
            ++report.applied;
        }
        else
        {
            ++report.missing;
        }
        return report;
    }

    Report ApplyNewSavesSites(const NewSavesSites& sites, std::uint8_t forceRead,
                              std::uint8_t newChunk16)
    {
        Report report;
        const PatchValues values = ChoosePatchValues(forceRead, newChunk16);

        // 0x872185's branch: `jz rel8` unless the save has the newer chunk 9, where it
        // becomes `jmp rel8`, forcing the longer path.
        if (sites.branch == nullptr)
        {
            ++report.missing;
            Log::Line("newSaves: branch site missing; chunk 9 patch skipped");
        }
        else if (patch::Write(patch::Site{sites.branch}, 0, values.branchOpcode,
                              "newSaves: chunk 9 branch"))
        {
            ++report.applied;
        }
        else
        {
            ++report.missing;
        }

        // 0x7D8C50: `jne +0x26; push 0xCBE; push eax; call LoadData`. The call becomes
        // the plugin's read hook; the pushed size and the branch follow the save's
        // chunk 16 (`jne` and 0xCBE for the older layout, NOPs and 0xE6E for the newer
        // one). The original target is read before the call is replaced.
        if (sites.read == nullptr)
        {
            ++report.missing;
            Log::Line("newSaves: read site missing; read hook and chunk 16 patch skipped");
        }
        else
        {
            const std::uint32_t originalTarget = static_cast<std::uint32_t>(
                patch::RelativeTarget(sites.read, kNewSavesCallOperand));

            (void)patch::Call(patch::Site{sites.read}, kNewSavesCallSite,
                              reinterpret_cast<void*>(ResolveBody(Body::read_hook)),
                              "newSaves: read hook");
            if (xla_new_saves_loaddata == 0)
            {
                xla_new_saves_loaddata = originalTarget;
            }

            (void)patch::Write(patch::Site{sites.read}, kNewSavesReadSizeOperand, values.readSize,
                               "newSaves: pushed read size");
            (void)patch::Write(patch::Site{sites.read}, kNewSavesBranchSite, values.readBranch,
                               "newSaves: read branch");
            ++report.applied;
        }

        // 0x8DA090: the second LoadData call becomes the plugin's hook, and the shared
        // read entry is repointed at the function's own later call target (the `E8` at
        // the anchor's +0x1D), which is the entry both hooks then use.
        if (sites.load == nullptr)
        {
            ++report.missing;
            Log::Line("newSaves: second load site missing; second hook skipped");
        }
        else
        {
            const std::uint32_t originalTarget = static_cast<std::uint32_t>(
                patch::RelativeTarget(sites.load, kNewSavesCallOperand));

            (void)patch::Call(patch::Site{sites.load}, kNewSavesCallSite,
                              reinterpret_cast<void*>(ResolveBody(Body::second_load)),
                              "newSaves: second load hook");
            if (xla_new_saves_p3_original == 0)
            {
                xla_new_saves_p3_original = originalTarget;
            }

            xla_new_saves_loaddata = static_cast<std::uint32_t>(
                patch::RelativeTarget(sites.load, kNewSavesLoadOperand));
            ++report.applied;
        }

        Log::Print("newSaves: {} patch site(s) applied, {} missing", report.applied,
                   report.missing);
        return report;
    }

    NewSavesSites ResolveNewSavesSites(const Image& image) noexcept
    {
        // One scan per anchor. The original's per-site statics cache a miss as a null
        // site, which is what the converter's own static below does for the three.
        NewSavesSites sites{};
        patch::Pattern branch = patch::FindIn(image, kNewSavesBranchAnchor, 1);
        if (!branch.empty())
        {
            sites.branch = branch.get_first<std::uint8_t>();
        }
        patch::Pattern read = patch::FindIn(image, kNewSavesReadAnchor, 1);
        if (!read.empty())
        {
            sites.read = read.get_first<std::uint8_t>();
        }
        patch::Pattern load = patch::FindIn(image, kNewSavesLoadAnchor, 1);
        if (!load.empty())
        {
            sites.load = load.get_first<std::uint8_t>();
        }
        return sites;
    }
} // namespace xla::compatibility

// ---------------------------------------------------------------------------
// Transcribed bodies. Each is the original's instruction stream, kept as asm
// because that is what it is; the code above is what installs it.
// ---------------------------------------------------------------------------

// sub_10051600, recovered VA 0x10051600 (4 instructions): the registrar's replacement
// tail. The original runs the registration between pushad/popad so the caller's
// registers survive, then returns to the registrar's caller.
static __declspec(naked) void NewfilesRegisterBody()
{
    __asm
    {
        __emit 0x60  // pushad
        call NewfilesRegister
        __emit 0x61  // popad
        ret
    }
}

// sub_10051A90, recovered VA 0x10051A90 (20 instructions): the read at game
// 0x7D8C50. It reads into its own 0xE78-byte local - the caller's buffer, `[ebp+8]`,
// is deliberately left untouched - and answers the read's value; an unpublished read
// entry skips the call and leaves EAX at the zero the test just saw, which is the
// value this returns. The /GS frame and the returned register are the original's.
//
// Naked and internal: an external-linkage naked function is written to the module and
// every importer fails (C2488).
static __declspec(naked) void NewSavesReadHook()
{
    __asm
    {
        push ebp
        mov ebp, esp
        sub esp, 0E7Ch
        mov eax, DWORD PTR [__security_cookie]
        xor eax, ebp
        mov DWORD PTR [ebp - 4], eax
        mov eax, DWORD PTR [xla_new_saves_loaddata]
        test eax, eax
        je newsaves_read_skip
        push DWORD PTR [ebp + 0Ch]
        lea ecx, [ebp - 0E7Ch]
        push ecx
        call eax
        add esp, 8
    newsaves_read_skip:
        mov ecx, DWORD PTR [ebp - 4]
        xor ecx, ebp
        call __security_check_cookie
        mov esp, ebp
        pop ebp
        ret
    }
}

// sub_10051AD0, recovered VA 0x10051AD0 (33 instructions): the second LoadData call
// at game 0x8DA090. When the save has the newer chunk 13 it consumes a twelve-byte
// block before and after the original call - both reads run through the same slot and
// the second one's value is what the body leaves in EAX - and otherwise the original
// call's value passes through. The original call itself is unconditional (a call
// through an unpublished slot faults), and it is the site's own target the installer
// republished.
//
// Naked and internal: an external-linkage naked function is written to the module and
// every importer fails (C2488).
static __declspec(naked) void NewSavesSecondLoadHook()
{
    __asm
    {
        push ebp
        mov ebp, esp
        sub esp, 10h
        mov eax, DWORD PTR [__security_cookie]
        xor eax, ebp
        mov DWORD PTR [ebp - 4], eax
        cmp BYTE PTR [xla_new_saves_extra_block], 0
        je newsaves_second_before
        mov eax, DWORD PTR [xla_new_saves_loaddata]
        test eax, eax
        je newsaves_second_before
        lea ecx, [ebp - 10h]
        push 0Ch
        push ecx
        call eax
        add esp, 8
    newsaves_second_before:
        call DWORD PTR [xla_new_saves_p3_original]
        cmp BYTE PTR [xla_new_saves_extra_block], 0
        je newsaves_second_done
        mov eax, DWORD PTR [xla_new_saves_loaddata]
        test eax, eax
        je newsaves_second_done
        lea ecx, [ebp - 10h]
        push 0Ch
        push ecx
        call eax
        add esp, 8
    newsaves_second_done:
        mov ecx, DWORD PTR [ebp - 4]
        xor ecx, ebp
        call __security_check_cookie
        mov esp, ebp
        pop ebp
        ret
    }
}

// sub_100521E0, recovered VA 0x100521E0 (8 instructions): the savegame-load
// trampoline. pusha/popa keep the caller's registers across the prepare step; the four
// instructions after them are the one the five-byte jump overwrote
// (`mov [esp+0x1E0],eax`) and the three that follow it, and the tail jumps to the
// entry's +0xD. `pusha`/`popa` are emitted as bytes: the assembler renders both with a
// 0x66 operand-size prefix, which the original does not have.
static __declspec(naked) void NewSavesTrampoline()
{
    __asm
    {
        __emit 0x60  // pusha
        call NewSavesPrepare
        __emit 0x61  // popa
        mov dword ptr [esp + 1E0h], eax
        mov eax, dword ptr [ebp + 8]
        push ebx
        xor ebx, ebx
        jmp dword ptr [xla_new_saves_resume]
    }
}

// sub_10003E50, recovered VA 0x10003E50 (162 bytes, 67 instructions): the config-value
// resolver. A string that starts with "hash:" (case-insensitive, five characters) and
// parses to a non-zero number is that number; anything else is hashed the way the game
// hashes model names: 'A'-'Z' lower-cased, '\' read as '/', `* 0x401`, `^ (h >> 6)`,
// then one final mix (`* 9`, `^ (h >> 11)`, `* 0x8001`) with the +2 nudge for a result
// below 2. The original is `__cdecl unsigned int(char *)`; it reads no module word, so
// its only two dependencies are the CRT slots above.
//
// Naked and internal: an external-linkage naked function is written to the module and
// every importer fails (C2488).
static __declspec(naked) std::uint32_t __cdecl ResolveFileNameBody()
{
    __asm
    {
        push ebp
        mov ebp, esp
        push edi
        mov edi, DWORD PTR [ebp + 8]
        push 5
        push OFFSET xla_resolver_hash_prefix
        push edi
        call DWORD PTR [xla_resolver_strnicmp]
        add esp, 0Ch
        test eax, eax
        jnz resolver_hashed
        push eax
        push eax
        lea eax, [edi + 5]
        push eax
        call DWORD PTR [xla_resolver_strtoul]
        add esp, 0Ch
        test eax, eax
        jnz resolver_done
    resolver_hashed:
        push ebx
        mov bl, BYTE PTR [edi]
        push esi
        xor esi, esi
        mov al, bl
        cmp bl, 22h
        jnz resolver_unquoted
        mov al, BYTE PTR [edi + 1]
    resolver_unquoted:
        lea edx, [edi + 1]
        cmovnz edx, edi
        test al, al
        jz resolver_tail
        // The original's loop alignment: 0F 1F 80 00 00 00 00, emitted as bytes so the
        // assembler cannot shorten it to the four-byte form.
        __emit 0x0F
        __emit 0x1F
        __emit 0x80
        __emit 0x00
        __emit 0x00
        __emit 0x00
        __emit 0x00
    resolver_loop:
        cmp bl, 22h
        jnz resolver_not_quote
        cmp al, bl
        jz resolver_tail
    resolver_not_quote:
        lea ecx, [eax - 41h]
        inc edx
        cmp cl, 19h
        jbe resolver_lowercase
        cmp al, 5Ch
        jnz resolver_mixed
        mov al, 2Fh
        jmp resolver_mixed
    resolver_lowercase:
        add al, 20h
    resolver_mixed:
        movsx eax, al
        add eax, esi
        imul eax, eax, 401h
        mov esi, eax
        shr esi, 6
        xor esi, eax
        mov al, BYTE PTR [edx]
        test al, al
        jnz resolver_loop
    resolver_tail:
        lea ecx, [esi + esi * 8]
        mov eax, ecx
        shr eax, 0Bh
        xor eax, ecx
        imul ecx, eax, 8001h
        pop esi
        pop ebx
        cmp ecx, 2
        lea eax, [ecx + 2]
        cmovnb eax, ecx
    resolver_done:
        pop edi
        pop ebp
        ret
    }
}
