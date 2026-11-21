// SPDX-License-Identifier: GPL-3.0-or-later
//
// xla.steam - [Options] SteamAchievements: the Steam achievement mirror.
//
// Ported whole from readable-fusion-opcep/source/compatibility.ixx (its `Steam`
// namespace and the achievement table beside it), which is where the bridge lived
// before the companion took the COMPATIBILITY surface over. The recovered data - the
// id -> Steam API name table and the ISteamUserStats v012 method indices - is
// OpenPreCEPatch's, itself recovered from the standalone SteamAchievements.asi; every
// executable line here is the fork's, with this tree's installer boundary in place of
// its own IAT walker (`patch::ReplaceImports` instead of naming the injector).
//
// The mirror is implemented at the GFWL API boundary. GTA IV imports
// xlive.dll!XUserWriteAchievements by ordinal 5278 (a three-argument __stdcall), and
// that slot belongs to the game's import table, not to xlive.dll: it exists whether
// the loaded xlive is the GFWL client, xliveless or nothing. The slot is therefore
// replaced whenever steam_api.dll is beside the game, and the previous value is
// called first only when it is a target that may be called (see the policy below).
// Because the hook is at the import, no game-code patch can move or overwrite it.
//
// The mirror does not require GFWL. The loaded xlive.dll is classified from its
// export directory only (`ProbeXliveExports`/`ClassifyXlive`):
//
//   absent      no xlive.dll is mapped;
//   gfwl client the XLive ABI is exported (XLiveInitialize and the
//               XUserWriteAchievements ordinal) and the module is not the ASI loader;
//   proxy       anything else - in particular Ultimate ASI Loader's xliveless
//               stand-in, which exports the same ABI filled with local emulation and
//               adds the IsUltimateASILoader marker.
//
// Evidence for the two shapes (measured 2026-11-21): C:\Windows\SysWOW64\xlive.dll
// (15,453,904 B) has 5,377 ordinal exports and no named exports at all - ordinal 5000
// (XLiveInitialize) and ordinal 5278 are both `call` thunks into its packed code. The
// game directory's Ultimate ASI Loader 9.7.4 xlive.dll (2,407,648 B) exports the same
// 5,377 ordinals plus 1,334 names (XLiveInitialize @5000, XUserWriteAchievements
// @5278, IsUltimateASILoader @544), and its 5278 body is xliveless's local store (it
// marks its achievement array, rewrites Achievements.txt and answers 0). A name probe
// alone would call the stand-in a client; an ordinal probe alone would do the same. So
// the classification needs the ABI *and* the absence of the loader's own marker, and
// the packed client is why XLiveInitialize is also probed by its recovered ordinal
// (5000) and not only by name.
//
// Forwarding policy (`DecideForwarding`, one implementation shared with the suite):
// the previous slot is called only when it is a validated code pointer inside a
// loaded module and either the loaded xlive is the GFWL client, or the pointer is
// that module's own ordinal-5278 export (a real bound thunk). A null or garbage slot
// is never called; the hook then answers 0 - the value a successful GFWL write
// answers, and what xliveless's stub answers - so the game continues.
//
// The bridge refuses only when the process is not the game image (the offline dump
// maps a copy of it) or steam_api.dll is absent. A GFWL client is not required.
//
// The hook is installed synchronously in the install pass. SteamAPI_Init loads
// libraries and starts threads, so it runs lazily on the first achievement write (a
// game thread), never in DllMain; ids observed before it succeeds stay queued and are
// replayed when it does.

module;

#include <common.hxx>

export module steam;

import common;
import patch;

export namespace xla::steam
{
    // One recovered row: the game's achievement id and its Steam API name. Ids 1..40
    // are the base game's single-player achievements, 41..50 the multiplayer ones,
    // 51..55 TLAD and 56..65 TBoGT (the script ACHIEVEMENT_IDS enum and the standalone
    // SteamAchievements.asi agree).
    struct Achievement
    {
        std::uint32_t id;
        const char* name;
    };

    inline constexpr std::uint32_t kMaxAchievementId = 65;

    // The GFWL import the bridge replaces: xlive.dll's ordinal for
    // XUserWriteAchievements.
    inline constexpr WORD kWriteAchievementsOrdinal = 5278;

    // XLiveInitialize's ordinal in the GFWL ABI (the OpenSauce XLive.def lists
    // `XLiveInitialize @5000`, and the packed system client exports 5000 as its
    // initialise thunk). Probed as a classification fact because the packed client
    // has no named exports to ask for.
    inline constexpr WORD kXLiveInitialiseOrdinal = 5000;

    // The argument structure XUserWriteAchievements walks: two dwords per entry.
    struct XUserAchievement
    {
        std::uint32_t userIndex;
        std::uint32_t achievementId;
    };

    // What the mapped xlive.dll is, decided from its export directory only.
    enum class XliveKind
    {
        Absent,     // no xlive.dll is mapped
        GfwlClient, // the XLive ABI is exported and this is not an ASI loader
        Proxy,      // a stand-in: xliveless/Ultimate ASI Loader, or a module exporting
                    // neither (or only part) of the ABI
    };

    // The export-table facts the classification and the forwarding policy use.
    struct XliveProbe
    {
        bool loaded{};             // an image was mapped at the address probed
        bool xliveInitialise{};    // XLiveInitialize is exported (by name or ordinal)
        bool writeAchievements{};  // the XUserWriteAchievements ordinal is exported
        bool asiLoader{};          // IsUltimateASILoader is exported (UAL's marker)
        const void* ordinalAddress{}; // the module's own ordinal-5278 export target
        std::uint32_t functions{}; // exported functions (ordinal range size)
        std::uint32_t names{};     // named exports
    };

    // Reads `image` (`size` bytes at its loaded address, so RVAs are direct offsets)
    // and answers the export-table facts. Every read is bounded by `size`; a malformed
    // or unparseable image answers `loaded = true` with no exports.
    XliveProbe ProbeXliveExports(const void* image, std::size_t size) noexcept;

    // The probe of the process's loaded xlive.dll (absent when it is not mapped).
    XliveProbe ProbeLoadedXlive() noexcept;

    // The one classification: GFWL only when the whole XLive ABI is exported and the
    // module is not the ASI loader's stand-in.
    XliveKind ClassifyXlive(const XliveProbe& probe) noexcept;
    const char* XliveKindName(XliveKind kind) noexcept;

    // The forwarding policy, in one place: call the previous slot only when it may be
    // called. `slot` is the value the import held before the replacement.
    struct Forwarding
    {
        bool forward{};
        const char* reason{}; // one static sentence; the install logs it once
    };
    Forwarding DecideForwarding(const XliveProbe& probe, const void* slot) noexcept;

    // The install refusals that are real: the offline dump (not the game image) and
    // an install without steam_api.dll. Anything else - no GFWL, xliveless, no
    // xlive.dll at all - still installs the mirror.
    enum class InstallRefusal
    {
        None,
        NotGameImage,
        NoSteamApi,
    };
    InstallRefusal RefuseInstall(bool gameImage, bool steamApiPresent) noexcept;

    // Replaces the ordinal-5278 slot in `module`'s xlive.dll import with the hook and
    // arms the forwarding decision. The install core, used by `Install` and by the
    // native suite against a synthetic import table.
    bool InstallInto(HMODULE module, const XliveProbe& xlive) noexcept;

    // The import hook body: calls the previous slot first when the install armed it,
    // then mirrors the ids. The game reaches it through the replaced import slot; the
    // suite calls it directly.
    std::uint32_t __stdcall WriteAchievements(std::uint32_t count,
                                             const XUserAchievement* achievements,
                                             void* overlapped) noexcept;

    // Test seams. The suite watches the mirror observe an id, and drives a second
    // synthetic module through `InstallInto`; the product never calls either.
    void SetMirrorObserverForTest(void (*observer)(std::uint32_t)) noexcept;
    void ResetInstallForTest() noexcept;

    // The recovered id -> Steam name table.
    std::span<const Achievement> Achievements() noexcept;

    // Installs the import hook. Answers false when the process is not the game
    // executable, steam_api.dll is absent, or the import table no longer names the
    // ordinal; otherwise hooks the slot - with or without a GFWL client.
    bool Install() noexcept;

    // The id -> Steam name mapping, exposed for the native test.
    const char* AchievementNameForTest(std::uint32_t id) noexcept;
} // namespace xla::steam

namespace
{
    using xla::steam::Achievement;

    // provenance: the recovered table (OpenPreCEPatch's, from the standalone
    // SteamAchievements.asi); the ids and names are data, the table's order is the
    // original's.
    constexpr Achievement kAchievements[] = {
        {1, "THETOUR"},          {2, "SCOREDARTGAME"},     {3, "POOLWIN"},
        {4, "QUBBEAT"},          {5, "MELEECOUNTER"},      {6, "STREETRACE"},
        {7, "BIKEWHEELIE"},      {8, "TURKEY"},            {9, "SATAXI"},
        {10, "CARROLLS"},        {11, "LOSERATING"},       {12, "DRUGDONE"},
        {13, "SAGUNCAR"},        {14, "CHAINREACTION"},    {15, "WANTEDLEVEL6STARSURVIVAL"},
        {16, "KEYMISSION1"},     {17, "IMPORTDONE"},       {18, "WANTEDDONE"},
        {19, "VIGILDONE"},       {20, "KEYMISSION0"},      {21, "TAXIPASSANGER"},
        {22, "ALLHELITOURTAKEN"}, {23, "DATING"},          {24, "SAHELI"},
        {25, "HALFMILLION"},     {26, "KEYMISSION2"},      {27, "OPENEDALDERNEY"},
        {28, "SMSTHEFTDONE"},    {29, "USJDONE"},          {30, "ASSASSIN"},
        {31, "HIDDENPACKAGES"},  {32, "UNDERALLBRIDGES"},  {33, "SABOMBCAR"},
        {34, "KEYMISSION3"},     {35, "FRIENDSLIKEYOU"},   {36, "METRANDOM"},
        {37, "KEYMISSION4"},     {38, "STORYDONE"},        {39, "STREETLIGHTSDOWN"},
        {40, "GAMECOMPLETION100"}, {41, "MPTEAMWIN1"},     {42, "MPCOMPWIN1"},
        {43, "MPRACEWIN1"},      {44, "MPCOOPWIN1"},       {45, "MPTEAMWINALL"},
        {46, "MPCOMPWINALL"},    {47, "MPRACEWINALL"},     {48, "MPSTARRATING"},
        {49, "MPCOOPWINALL"},    {50, "VIRALKILLME"},      {51, "E1INTRO"},
        {52, "E1BECOMELEADER"},  {53, "E1FINISHSTORY"},    {54, "E1KNOCKOFF"},
        {55, "E1BUDDYSTAT"},     {56, "E2BASEJUMP"},       {57, "E2TRINITY"},
        {58, "E2GOLF"},          {59, "E2FIGHTC"},         {60, "E2DANCE"},
        {61, "E2DRUGS"},         {62, "E2FREEFALL"},       {63, "E2STORY"},
        {64, "E2FAIRFLAIR"},     {65, "E2ALLFLAIR"},
    };
    static_assert(std::size(kAchievements) == xla::steam::kMaxAchievementId);

    constexpr std::uint32_t kMaxMirrorBatch = 16;

    using WriteAchievementsFn =
        std::uint32_t(__stdcall*)(std::uint32_t, const xla::steam::XUserAchievement*,
                                  void*);
    using SetAchievementFn = bool(__thiscall*)(void*, const char*);
    using StoreStatsFn = bool(__thiscall*)(void*);
    using RequestStatsFn = bool(__thiscall*)(void*);
    using RunCallbacksFn = void(__cdecl*)();
    using MirrorObserver = void (*)(std::uint32_t);

    WriteAchievementsFn g_original = nullptr;
    bool g_forward = false;
    SetAchievementFn g_set_achievement = nullptr;
    StoreStatsFn g_store_stats = nullptr;
    RequestStatsFn g_request_stats = nullptr;
    RunCallbacksFn g_run_callbacks = nullptr;
    void* g_user_stats = nullptr;

    std::mutex g_mutex;
    std::mutex g_init_mutex;
    bool g_hook_installed = false;
    std::atomic<bool> g_disabled{false};
    std::atomic<bool> g_ready{false};
    std::atomic<MirrorObserver> g_mirror_observer{nullptr};
    bool g_pending[xla::steam::kMaxAchievementId + 1] = {};
    bool g_sent[xla::steam::kMaxAchievementId + 1] = {};

    const Achievement* AchievementFor(std::uint32_t id) noexcept
    {
        for (const auto& achievement : kAchievements)
        {
            if (achievement.id == id)
            {
                return &achievement;
            }
        }
        return nullptr;
    }

    bool EpisodesExecutable() noexcept
    {
        char module[MAX_PATH] = {};
        if (GetModuleFileNameA(nullptr, module, MAX_PATH) == 0)
        {
            return false;
        }
        const char* name = std::strrchr(module, '\\');
        name = name != nullptr ? name + 1 : module;
        return _strnicmp(name, "EFLC", 4) == 0;
    }

    bool SteamApiPresent() noexcept
    {
        char module[MAX_PATH] = {};
        if (GetModuleFileNameA(nullptr, module, MAX_PATH) == 0)
        {
            return false;
        }
        char* slash = std::strrchr(module, '\\');
        if (slash == nullptr)
        {
            return false;
        }
        slash[1] = '\0';
        char path[MAX_PATH] = {};
        std::snprintf(path, sizeof(path), "%ssteam_api.dll", module);
        return GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES;
    }

    // A bounds-checked view of a loaded image. RVAs are image-relative, so
    // `base + rva` is the mapping address; every read is checked against `size` (the
    // loader's SizeOfImage) so a garbage export directory cannot walk off the image.
    class ImageReader
    {
    public:
        ImageReader(const void* image, std::size_t size) noexcept
            : m_base(static_cast<const std::uint8_t*>(image)), m_size(size)
        {
        }

        [[nodiscard]] bool contains(std::uint64_t offset, std::uint64_t length) const noexcept
        {
            return m_base != nullptr && offset <= m_size && length <= m_size - offset;
        }

        template <typename T>
        [[nodiscard]] const T* at(std::uint64_t offset) const noexcept
        {
            return contains(offset, sizeof(T))
                       ? reinterpret_cast<const T*>(m_base + offset)
                       : nullptr;
        }

        // A NUL-terminated string at `offset`, refusing anything longer than `limit`.
        [[nodiscard]] const char* text(std::uint64_t offset, std::size_t limit) const noexcept
        {
            if (!contains(offset, 1))
            {
                return nullptr;
            }
            const char* start = reinterpret_cast<const char*>(m_base + offset);
            const std::size_t available = m_size - static_cast<std::size_t>(offset);
            return std::memchr(start, '\0', std::min(available, limit)) != nullptr ? start
                                                                                  : nullptr;
        }

        [[nodiscard]] const void* address(std::uint64_t offset) const noexcept
        {
            return contains(offset, 1) ? static_cast<const void*>(m_base + offset) : nullptr;
        }

    private:
        const std::uint8_t* m_base;
        std::size_t m_size;
    };

    void PrepareAppId() noexcept
    {
        char inherited[32] = {};
        const DWORD length = GetEnvironmentVariableA("SteamAppId", inherited, sizeof(inherited));
        if (length != 0)
        {
            return;
        }
        const char* app = EpisodesExecutable() ? "12220" : "12210";
        SetEnvironmentVariableA("SteamAppId", app);
        SetEnvironmentVariableA("SteamGameId", app);
    }

    bool TryInitialise() noexcept
    {
        std::lock_guard initLock(g_init_mutex);
        if (g_ready.load(std::memory_order_acquire))
        {
            return true;
        }
        if (g_disabled.load(std::memory_order_relaxed))
        {
            return false;
        }

        PrepareAppId();

        const HMODULE api = LoadLibraryA("steam_api.dll");
        if (api == nullptr)
        {
            g_disabled = true;
            return false;
        }

        using InitFn = bool(__cdecl*)();
        using GetUserFn = int(__cdecl*)();
        using FindInterfaceFn = void*(__cdecl*)(int, const char*);
        using IsRunningFn = bool(__cdecl*)();

        const auto init = reinterpret_cast<InitFn>(GetProcAddress(api, "SteamAPI_Init"));
        const auto get_user =
            reinterpret_cast<GetUserFn>(GetProcAddress(api, "SteamAPI_GetHSteamUser"));
        const auto find_interface = reinterpret_cast<FindInterfaceFn>(
            GetProcAddress(api, "SteamInternal_FindOrCreateUserInterface"));
        const auto is_running =
            reinterpret_cast<IsRunningFn>(GetProcAddress(api, "SteamAPI_IsSteamRunning"));
        g_run_callbacks =
            reinterpret_cast<RunCallbacksFn>(GetProcAddress(api, "SteamAPI_RunCallbacks"));
        if (init == nullptr || get_user == nullptr || find_interface == nullptr)
        {
            g_disabled = true;
            return false;
        }
        if (is_running != nullptr && !is_running())
        {
            return false;
        }
        if (!init())
        {
            return false;
        }

        // provenance: the ISteamUserStats v012 vtable indices (RequestCurrentStats 0,
        // SetAchievement 7, StoreStats 10) as the standalone SteamAchievements.asi
        // uses them.
        g_user_stats = find_interface(get_user(), "STEAMUSERSTATS_INTERFACE_VERSION012");
        if (g_user_stats == nullptr)
        {
            g_disabled = true;
            return false;
        }
        const void* const* vtable = *reinterpret_cast<const void* const* const*>(g_user_stats);
        if (vtable == nullptr)
        {
            g_disabled = true;
            return false;
        }
        g_request_stats = reinterpret_cast<RequestStatsFn>(vtable[0]);
        g_set_achievement = reinterpret_cast<SetAchievementFn>(vtable[7]);
        g_store_stats = reinterpret_cast<StoreStatsFn>(vtable[10]);
        if (g_set_achievement == nullptr || g_store_stats == nullptr)
        {
            g_disabled = true;
            return false;
        }

        if (g_request_stats != nullptr)
        {
            (void)g_request_stats(g_user_stats);
        }
        for (int i = 0; i < 10 && g_run_callbacks != nullptr; ++i)
        {
            g_run_callbacks();
            Sleep(50);
        }
        g_ready.store(true, std::memory_order_release);
        return true;
    }

    void Apply(std::uint32_t id, const char* name) noexcept
    {
        if (g_set_achievement == nullptr)
        {
            return;
        }
        const bool set = g_set_achievement(g_user_stats, name);
        if (set && g_store_stats != nullptr)
        {
            g_store_stats(g_user_stats);
        }
        if (g_run_callbacks != nullptr)
        {
            g_run_callbacks();
        }
        xla::Log::Print("steam: achievement {} ({}) {}", id, name,
                        set ? "unlocked" : "rejected by Steam");
    }

    void Observe(std::uint32_t id) noexcept
    {
        // The suite's window into the mirror, before any Steam state: it proves the
        // hook mirrored *after* it forwarded (never before).
        if (const MirrorObserver observer = g_mirror_observer.load(std::memory_order_acquire);
            observer != nullptr)
        {
            observer(id);
        }

        const Achievement* achievement = AchievementFor(id);
        if (achievement == nullptr)
        {
            xla::Log::Print("steam: achievement id {} has no Steam name, ignored", id);
            return;
        }

        bool need_init = false;
        {
            std::lock_guard lock(g_mutex);
            if (g_sent[id])
            {
                return;
            }
            g_pending[id] = true;
            need_init = !g_ready.load(std::memory_order_acquire);
        }

        if (need_init)
        {
            // Initialisation is deliberately outside the state mutex: it loads
            // steam_api.dll and pumps callbacks, and a callback can reach this hook on
            // the same thread.
            (void)TryInitialise();
            std::lock_guard lock(g_mutex);
            if (!g_ready.load(std::memory_order_acquire))
            {
                xla::Log::Print("steam: achievement {} ({}) queued until Steam is ready", id,
                                achievement->name);
                return;
            }
        }

        std::uint32_t send[xla::steam::kMaxAchievementId + 1] = {};
        std::size_t send_count = 0;
        {
            std::lock_guard lock(g_mutex);
            if (!g_ready.load(std::memory_order_acquire))
            {
                return;
            }
            for (std::uint32_t queued = 1; queued <= xla::steam::kMaxAchievementId; ++queued)
            {
                if (g_pending[queued] && !g_sent[queued])
                {
                    g_sent[queued] = true;
                    g_pending[queued] = false;
                    send[send_count++] = queued;
                }
            }
        }

        // The Steam calls run without the state mutex; the function pointers are fixed
        // once g_ready was published.
        for (std::size_t index = 0; index < send_count; ++index)
        {
            const Achievement* queued = AchievementFor(send[index]);
            if (queued != nullptr)
            {
                Apply(send[index], queued->name);
            }
        }
    }
} // namespace

namespace xla::steam
{
    XliveProbe ProbeXliveExports(const void* image, std::size_t size) noexcept
    {
        XliveProbe probe;
        if (image == nullptr || size < sizeof(IMAGE_DOS_HEADER))
        {
            return probe;
        }
        probe.loaded = true;

        const ImageReader reader(image, size);
        const auto* dos = reader.at<IMAGE_DOS_HEADER>(0);
        if (dos == nullptr || dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0)
        {
            return probe;
        }

        const auto ntOffset = static_cast<std::uint64_t>(dos->e_lfanew);
        const auto* signature = reader.at<std::uint32_t>(ntOffset);
        const auto* file = reader.at<IMAGE_FILE_HEADER>(ntOffset + sizeof(std::uint32_t));
        if (signature == nullptr || *signature != IMAGE_NT_SIGNATURE || file == nullptr ||
            file->SizeOfOptionalHeader <
                offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory) +
                    sizeof(IMAGE_DATA_DIRECTORY) * (IMAGE_DIRECTORY_ENTRY_EXPORT + 1))
        {
            return probe;
        }
        const auto* optional = reader.at<IMAGE_OPTIONAL_HEADER32>(
            ntOffset + sizeof(std::uint32_t) + sizeof(IMAGE_FILE_HEADER));
        if (optional == nullptr || optional->Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC ||
            optional->NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT)
        {
            return probe;
        }

        const IMAGE_DATA_DIRECTORY directory =
            optional->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (directory.VirtualAddress == 0 || directory.Size < sizeof(IMAGE_EXPORT_DIRECTORY))
        {
            return probe;
        }
        const auto* exports = reader.at<IMAGE_EXPORT_DIRECTORY>(directory.VirtualAddress);
        if (exports == nullptr)
        {
            return probe;
        }

        const std::uint64_t functionCount = exports->NumberOfFunctions;
        const std::uint64_t nameCount = exports->NumberOfNames;
        const std::uint64_t functionsOffset = exports->AddressOfFunctions;
        const std::uint64_t namesOffset = exports->AddressOfNames;
        const std::uint64_t ordinalsOffset = exports->AddressOfNameOrdinals;
        if (!reader.contains(functionsOffset, functionCount * sizeof(std::uint32_t)))
        {
            return probe;
        }
        probe.functions = exports->NumberOfFunctions;
        probe.names = exports->NumberOfNames;

        // The named exports: XLiveInitialize and the ASI loader's own marker. Names
        // are matched exactly, as the export table spells them.
        bool initialiseByName = false;
        if (nameCount != 0 &&
            reader.contains(namesOffset, nameCount * sizeof(std::uint32_t)) &&
            reader.contains(ordinalsOffset, nameCount * sizeof(std::uint16_t)))
        {
            for (std::uint64_t index = 0; index < nameCount; ++index)
            {
                const auto* nameRva =
                    reader.at<std::uint32_t>(namesOffset + index * sizeof(std::uint32_t));
                if (nameRva == nullptr)
                {
                    continue;
                }
                const char* name = reader.text(*nameRva, 64);
                if (name == nullptr)
                {
                    continue;
                }
                if (std::strcmp(name, "XLiveInitialize") == 0)
                {
                    initialiseByName = true;
                }
                else if (std::strcmp(name, "IsUltimateASILoader") == 0)
                {
                    probe.asiLoader = true;
                }
            }
        }

        const auto exportedFunction = [&](WORD ordinal) -> const void*
        {
            if (ordinal < exports->Base)
            {
                return nullptr;
            }
            const std::uint64_t index =
                static_cast<std::uint64_t>(ordinal) - exports->Base;
            if (index >= functionCount)
            {
                return nullptr;
            }
            const auto* rva = reader.at<std::uint32_t>(
                functionsOffset + index * sizeof(std::uint32_t));
            if (rva == nullptr || *rva == 0)
            {
                return nullptr;
            }
            return reader.address(*rva);
        };

        // Ordinal 5278 is the one the slot binds and the hook forwards to; 5000 is
        // XLiveInitialize, which the packed client exports by ordinal only.
        const void* const write = exportedFunction(kWriteAchievementsOrdinal);
        probe.writeAchievements = write != nullptr;
        probe.ordinalAddress = write;
        probe.xliveInitialise =
            initialiseByName || exportedFunction(kXLiveInitialiseOrdinal) != nullptr;
        return probe;
    }

    XliveProbe ProbeLoadedXlive() noexcept
    {
        const HMODULE xlive = GetModuleHandleW(L"xlive.dll");
        if (xlive == nullptr)
        {
            return {};
        }
        MODULEINFO info{};
        if (!GetModuleInformation(GetCurrentProcess(), xlive, &info, sizeof(info)) ||
            info.lpBaseOfDll == nullptr || info.SizeOfImage == 0)
        {
            // Mapped but unreadable: it is present, so nothing about it is a client.
            XliveProbe probe;
            probe.loaded = true;
            return probe;
        }
        return ProbeXliveExports(info.lpBaseOfDll, info.SizeOfImage);
    }

    XliveKind ClassifyXlive(const XliveProbe& probe) noexcept
    {
        if (!probe.loaded)
        {
            return XliveKind::Absent;
        }
        // The stand-in exports the whole XLive ABI (its own local emulation) and
        // UAL adds IsUltimateASILoader, so the marker and the ABI are both needed.
        if (probe.asiLoader || !probe.xliveInitialise || !probe.writeAchievements)
        {
            return XliveKind::Proxy;
        }
        return XliveKind::GfwlClient;
    }

    const char* XliveKindName(XliveKind kind) noexcept
    {
        switch (kind)
        {
        case XliveKind::Absent:
            return "absent";
        case XliveKind::GfwlClient:
            return "gfwl client";
        case XliveKind::Proxy:
            return "xliveless/proxy";
        }
        return "unknown";
    }

    Forwarding DecideForwarding(const XliveProbe& probe, const void* slot) noexcept
    {
        if (slot == nullptr)
        {
            return {false, "the slot is unbound (null), so it is never called"};
        }
        if (slot == reinterpret_cast<const void*>(&WriteAchievements))
        {
            return {false, "the slot already holds this hook, so calling it would recurse"};
        }
        if (!IsModuleRange(slot))
        {
            return {false,
                    "the slot does not point at code inside a loaded module, so it is "
                    "never called"};
        }
        if (ClassifyXlive(probe) == XliveKind::GfwlClient)
        {
            return {true,
                    "the loaded xlive.dll exports the XLive ABI and is not the ASI "
                    "loader's stand-in (GFWL client)"};
        }
        if (probe.ordinalAddress != nullptr && slot == probe.ordinalAddress)
        {
            return {true,
                    "the slot is the loaded xlive.dll's own ordinal-5278 export (a real "
                    "bound thunk)"};
        }
        return {false,
                "the loaded xlive.dll is an xliveless/proxy stand-in and the slot is not "
                "its own export; answering success without a call"};
    }

    InstallRefusal RefuseInstall(bool gameImage, bool steamApiPresent) noexcept
    {
        if (!gameImage)
        {
            return InstallRefusal::NotGameImage;
        }
        if (!steamApiPresent)
        {
            return InstallRefusal::NoSteamApi;
        }
        return InstallRefusal::None;
    }

    bool InstallInto(HMODULE module, const XliveProbe& xlive) noexcept
    {
        if (g_hook_installed)
        {
            return true;
        }
        if (module == nullptr)
        {
            g_disabled = true;
            Log::Line("steam: no game module to hook, skipped");
            return false;
        }

        // The slot is replaced through xla.patch (this tree's only installer). The
        // map tells us the target it held before the write, which the forwarding
        // decision judges; an unbound slot is hooked too, because the mirror must
        // install wherever the game's import table names the ordinal.
        constexpr std::string_view kOrdinalHook = "XUserWriteAchievements@5278";
        const std::map<std::string, void*> originals = patch::ReplaceImports(
            module, "xlive.dll",
            {{kOrdinalHook, reinterpret_cast<void*>(&WriteAchievements)}},
            /*includeUnbound=*/true);
        const auto found = originals.find(std::string(kOrdinalHook));
        if (found == originals.end())
        {
            g_disabled = true;
            Log::Print("steam: XUserWriteAchievements ordinal {} not imported, skipped",
                       kWriteAchievementsOrdinal);
            return false;
        }

        // One decision, shared with the suite: forward only to a target the policy
        // validates, otherwise answer success ourselves. The state is armed just
        // after the slot write: nothing can call the slot from inside this pass, and
        // until it is armed the hook answers success without a call.
        const Forwarding forwarding = DecideForwarding(xlive, found->second);
        g_forward = forwarding.forward;
        g_original = forwarding.forward
                         ? reinterpret_cast<WriteAchievementsFn>(found->second)
                         : nullptr;
        g_hook_installed = true;
        Log::Print("steam: hooked xlive.dll ordinal {} (was {:08X}); forwarding={} ({})",
                   kWriteAchievementsOrdinal,
                   reinterpret_cast<std::uintptr_t>(found->second),
                   forwarding.forward ? "yes" : "no", forwarding.reason);
        return true;
    }

    std::uint32_t __stdcall WriteAchievements(std::uint32_t count,
                                             const XUserAchievement* achievements,
                                             void* overlapped) noexcept
    {
        // The previous slot runs first when the install armed it, so the GFWL store
        // (or a real xliveless export) keeps the write and its answer; otherwise the
        // game gets the success value a completed write answers.
        const std::uint32_t result =
            g_forward && g_original != nullptr ? g_original(count, achievements, overlapped)
                                               : 0;

        if (achievements != nullptr && count != 0)
        {
            const std::uint32_t mirror = count > kMaxMirrorBatch ? kMaxMirrorBatch : count;
            for (std::uint32_t index = 0; index < mirror; ++index)
            {
                Observe(achievements[index].achievementId);
            }
        }
        return result;
    }

    void SetMirrorObserverForTest(MirrorObserver observer) noexcept
    {
        g_mirror_observer.store(observer, std::memory_order_release);
    }

    void ResetInstallForTest() noexcept
    {
        // The suite drives several synthetic import tables through InstallInto. The
        // mirror itself stays disabled: a test run must never load a real Steam API.
        g_hook_installed = false;
        g_forward = false;
        g_original = nullptr;
        g_disabled = true;
    }

    std::span<const Achievement> Achievements() noexcept
    {
        return kAchievements;
    }

    const char* AchievementNameForTest(std::uint32_t id) noexcept
    {
        const Achievement* achievement = AchievementFor(id);
        return achievement != nullptr ? achievement->name : nullptr;
    }

    bool Install() noexcept
    {
        if (g_hook_installed)
        {
            return true;
        }
        if (g_disabled)
        {
            return false;
        }

        // The game image owns the import table this hook rewrites; the offline dump
        // maps a copy of it.
        const bool gameImage = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr)) ==
                               Game::Get().ImageBase();
        switch (RefuseInstall(gameImage, SteamApiPresent()))
        {
        case InstallRefusal::NotGameImage:
            return false;
        case InstallRefusal::NoSteamApi:
            g_disabled = true;
            Log::Line("steam: no steam_api.dll, skipped");
            return false;
        case InstallRefusal::None:
            break;
        }

        // The mirror belongs to the game's import table, so the loaded xlive only
        // decides *forwarding*, never whether the hook installs.
        const XliveProbe xlive = ProbeLoadedXlive();
        const XliveKind kind = ClassifyXlive(xlive);
        Log::Print("steam: xlive.dll={} ({} export(s), {} name(s), XLiveInitialize={}, "
                   "ordinal {}={}, ASI-loader marker={})",
                   XliveKindName(kind), xlive.functions, xlive.names,
                   xlive.xliveInitialise ? "yes" : "no", kWriteAchievementsOrdinal,
                   xlive.writeAchievements ? "yes" : "no", xlive.asiLoader ? "yes" : "no");
        return InstallInto(GetModuleHandleW(nullptr), xlive);
    }
} // namespace xla::steam
