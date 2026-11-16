// SPDX-License-Identifier: GPL-3.0-or-later
//
// xla.savegames - [Options] SavegameFix: the save-file CRC32 bypass and the
// hardened save-path call sites.
//
// Ported from readable-fusion-opcep/source/compatibility.ixx (InstallSavegameFix
// and its four transcribed bodies), the OpenPreCEPatch arm that is the original
// handler's whole write set. The old add-on only NOPed the two-byte CRC32 branch;
// the original also retargets the save file's close, copy, mutex and "no
// savegame" call sites at four of its own helper bodies, so this module carries
// that whole set, in the original handler's write order:
//
//   * ten `call` retargets around the two recovered anchors (five each), to the
//     four ABI-exact bodies (recovered VAs 0x10038570, 0x10045580, 0x100455A0,
//     0x100455E0);
//   * the two-byte NOP at the CRC32 branch (the bypass the old add-on had too);
//   * the same two anchor scans: a missing signature is a logged skip.
//
// The save path itself is the user-data family ([USERPROFILE]
// CustomUserProfilePath, xla.profile): the shell's profile folders are redirected
// there, and the game's own savegame resolver (`sub_61E770`, 0x61E770) builds
// `<profile>\Rockstar Games\GTA IV\savegames\user_<xuid>\<name>` from it. This
// family is orthogonal to where the file lives.
//
// The four bodies are the original's instruction streams, kept as asm because
// that is what they are. MSVC rejects `__declspec(naked)` on a declaration
// (C2488), so each body is defined once, only the definition carrying the
// attribute, and the readable code above names them through ResolveBody.

module;

#include <common.hxx>

export module savegames;

import common;
import patch;

export namespace xla::savegames
{
    // The recovered VAs of the four transcribed bodies, in the original ASI's
    // coordinates (this tree links at 0x10000000 itself; the VAs are provenance
    // and the native suite pins them, they are not addresses used at run time).
    inline constexpr std::uint32_t kNullBodyVa = 0x10038570;  // sub_10038570
    inline constexpr std::uint32_t kCloseBodyVa = 0x10045580; // sub_10045580
    inline constexpr std::uint32_t kCopyBodyVa = 0x100455A0;  // sub_100455A0
    inline constexpr std::uint32_t kMutexBodyVa = 0x100455E0; // sub_100455E0

    enum class Body : std::uint8_t
    {
        null_path,  // 0x10038570: the "no savegame" answer
        close_file, // 0x10045580: close the save handle
        copy,       // 0x100455A0: the read/copy path
        mutex,      // 0x100455E0: create the save mutex
    };

    // The address of one transcribed body. Install resolves every retarget through
    // this function, and the native suite pins the write set against it.
    std::uintptr_t ResolveBody(Body body) noexcept;

    // Installs the whole SavegameFix write set: publishes the two import targets
    // the bodies call through, then applies each anchor whose signature is
    // present. A missing signature is a logged skip, never a fault.
    void Install(const Image& image);
} // namespace xla::savegames

// The two imports the transcribed bodies call through, in the original's own IAT
// slot role; Install publishes them before it retargets anything, so no installed
// call can read a zero slot.
extern "C"
{
    std::uintptr_t xla_savegame_close_handle = 0; // &CloseHandle
    std::uintptr_t xla_savegame_create_mutex = 0; // &CreateMutexA
}

// The inline assembler refuses `call memcpy` (it is a compiler intrinsic), so the
// copy path calls this thin wrapper instead; the original calls the CRT directly.
// The call shape is the same (`call imm`), the caller cleans the three arguments,
// and the copy itself is the CRT's.
static void __cdecl SavegameCopyBlock(void* destination, const void* source, std::size_t size)
{
    std::memcpy(destination, source, size);
}

// sub_10038570, recovered VA 0x10038570 (2 instructions): the "no savegame"
// path returns 0.
static __declspec(naked) void SavegameNullBody()
{
    __asm
    {
        xor eax, eax
        ret 8
    }
}

// sub_10045580, recovered VA 0x10045580 (7 instructions): close the save
// handle and report success.
static __declspec(naked) void SavegameCloseBody()
{
    __asm
    {
        push ebp
        mov ebp, esp
        push DWORD PTR [ebp + 8]
        call DWORD PTR [xla_savegame_close_handle]
        xor eax, eax
        pop ebp
        ret 4
    }
}

// sub_100455E0, recovered VA 0x100455E0 (19 instructions): create the save
// mutex into the caller's handle slot; a null slot reports 1.
static __declspec(naked) void SavegameMutexBody()
{
    __asm
    {
        push ebp
        mov ebp, esp
        push esi
        mov esi, DWORD PTR [ebp + 0Ch]
        test esi, esi
        jz savegame_mutex_null
        push 0
        push 0
        push 0
        call DWORD PTR [xla_savegame_create_mutex]
        mov DWORD PTR [esi], eax
        xor eax, eax
        pop esi
        pop ebp
        ret 8
    savegame_mutex_null:
        mov eax, 1
        pop esi
        pop ebp
        ret 8
    }
}

// sub_100455A0, recovered VA 0x100455A0 (28 instructions): the read/copy path.
// It refuses when the destination buffer is smaller than the requested size
// (0x8007007A), otherwise copies through the CRT and records the size.
static __declspec(naked) void SavegameCopyBody()
{
    __asm
    {
        push ebp
        mov ebp, esp
        push esi
        mov esi, DWORD PTR [ebp + 0Ch]
        push edi
        mov edi, DWORD PTR [ebp + 14h]
        cmp DWORD PTR [edi], esi
        jnb savegame_copy_room
        mov DWORD PTR [edi], esi
        mov eax, 8007007Ah
        pop edi
        pop esi
        pop ebp
        ret 14h
    savegame_copy_room:
        mov eax, DWORD PTR [ebp + 10h]
        test eax, eax
        jz savegame_copy_skip
        push esi
        push DWORD PTR [ebp + 8]
        push eax
        call SavegameCopyBlock
        add esp, 0Ch
    savegame_copy_skip:
        mov DWORD PTR [edi], esi
        xor eax, eax
        pop edi
        pop esi
        pop ebp
        ret 14h
    }
}

namespace xla::savegames
{
    std::uintptr_t ResolveBody(Body body) noexcept
    {
        switch (body)
        {
        case Body::null_path:
            return reinterpret_cast<std::uintptr_t>(&SavegameNullBody);
        case Body::close_file:
            return reinterpret_cast<std::uintptr_t>(&SavegameCloseBody);
        case Body::copy:
            return reinterpret_cast<std::uintptr_t>(&SavegameCopyBody);
        case Body::mutex:
            return reinterpret_cast<std::uintptr_t>(&SavegameMutexBody);
        }
        return 0;
    }

    namespace
    {
        // The original handler's two anchors, byte for byte.
        constexpr std::string_view kCrcAnchor = "75 ? 83 C1 01 83 C0 01 83 F9 04";
        constexpr std::string_view kCopyAnchor = "8D 4C 24 18 51 6A 00 6A 0C 57";

        // One `call` retarget: the offset from the anchor's match and the body it
        // names. The offsets, the order and the bodies are the original's.
        struct Retarget
        {
            std::int32_t offset;
            Body body;
        };

        // The CRC anchor's five calls around the branch, then its two-byte NOP.
        constexpr Retarget kCrcRetargets[]{
            {-73, Body::close_file},
            {-143, Body::copy},
            {-176, Body::copy},
            {-280, Body::mutex},
            {-240, Body::null_path},
        };
        static_assert(std::size(kCrcRetargets) == 5);

        // The save-path anchor's five calls after it.
        constexpr Retarget kCopyRetargets[]{
            {-86, Body::mutex},
            {-47, Body::null_path},
            {10, Body::copy},
            {90, Body::copy},
            {128, Body::close_file},
        };
        static_assert(std::size(kCopyRetargets) == 5);

        // Writes one anchor: its calls in the original's order, then `nopBytes` of
        // NOP at the match (the CRC anchor's bypass). The whole span the anchor
        // touches is checked before the first store, so a caller-owned view either
        // gets every recovered write or none; on the game's image every span is in
        // bounds. The offsets are signed (the calls sit before the match), so the
        // check is done in image offsets, never by forming an out-of-range pointer.
        bool ApplyAnchor(const Image& image, std::uint8_t* match,
                         std::span<const Retarget> retargets, std::size_t nopBytes)
        {
            std::int32_t first = 0;
            std::int32_t last = static_cast<std::int32_t>(nopBytes);
            for (const Retarget& retarget : retargets)
            {
                first = std::min(first, retarget.offset);
                last = std::max(last, retarget.offset + 5);
            }

            const auto offset = static_cast<std::ptrdiff_t>(
                reinterpret_cast<std::uintptr_t>(match) -
                reinterpret_cast<std::uintptr_t>(image.base));
            if (offset + first < 0 ||
                static_cast<std::size_t>(offset + last) > image.size)
            {
                Log::Print("savegames: the call sites around {:08X} leave the image: skipped",
                           reinterpret_cast<std::uintptr_t>(match));
                return false;
            }

            for (const Retarget& retarget : retargets)
            {
                patch::Call(patch::Site{match + retarget.offset},
                            reinterpret_cast<void*>(ResolveBody(retarget.body)),
                            "savegames: hardened call site");
            }
            if (nopBytes != 0)
            {
                patch::Nop(patch::Site{match}, 0, nopBytes, "savegames: crc32 bypass");
            }
            return true;
        }
    } // namespace

    void Install(const Image& image)
    {
        // The bodies call these through the original's IAT slots; publish them
        // before the first site is retargeted.
        xla_savegame_close_handle = reinterpret_cast<std::uintptr_t>(&::CloseHandle);
        xla_savegame_create_mutex = reinterpret_cast<std::uintptr_t>(&::CreateMutexA);

        if (image.empty())
        {
            Log::Line("savegames: no image; savegame fix skipped");
            return;
        }

        std::size_t calls = 0;

        patch::Pattern crc = patch::FindIn(image, kCrcAnchor, 1);
        if (crc.empty())
        {
            Log::Line("savegames: crc32 anchor missing; crc32 bypass and five call sites "
                      "skipped");
        }
        else if (ApplyAnchor(image, crc.get_first<std::uint8_t>(), kCrcRetargets, 2))
        {
            calls += std::size(kCrcRetargets);
        }

        patch::Pattern copy = patch::FindIn(image, kCopyAnchor, 1);
        if (copy.empty())
        {
            Log::Line("savegames: save-path anchor missing; five call sites skipped");
        }
        else if (ApplyAnchor(image, copy.get_first<std::uint8_t>(), kCopyRetargets, 0))
        {
            calls += std::size(kCopyRetargets);
        }

        Log::Print("savegames: {} hardened call site(s) retargeted", calls);
    }
} // namespace xla::savegames
