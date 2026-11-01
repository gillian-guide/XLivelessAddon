// SPDX-License-Identifier: GPL-3.0-or-later
//
// xla.dfa — the legacy DFA file-API stage (installed when SkipLauncher=0).
//
// These are the bodies ZolikaPatch's handler jumps to when the recovered
// launcher stage is disabled: DFA init reports success, and the file API
// forwards. The ABIs are part of the contract; do not add parameters.
//
// This is the `SkipLauncher=0` copy (upstream `dcc4f31:source/dllmain.cpp`).
// `skip_launcher.ixx` has a second, live copy for `SkipLauncher=1` (upstream
// `dcc4f31:source/skip_launcher.cpp`); they differ deliberately:
//   CreateFile       direct CreateFileA            | forwards through captured IAT slot
//   CloseHandle      SEH continue -> TRUE          | SEH execute -> -1
//   ReadFile site    `55 8B EC 51 51 53 56 8B C5` (+0) | `FF 50 60 ...` (-165)
//   DfaInit          3 args (original call shape)  | 0 args (body only)
// Do not merge them without deciding which original path each build follows.

module;

#include "common.hxx"

export module xla.dfa;

import xla.common;
import xla.patch;

export namespace xla::dfa
{
    // 0x10004780 in the original handler: the DFA init call reports success.
    // ABI: __cdecl, three integer args per the original call shape; returns 1.
    int __cdecl DfaInit(int, int, int);

    // Installs the six hooks plus the two collected jump targets. Signatures that
    // are absent on this build are logged and skipped.
    void Install(const Image& image);
} // namespace xla::dfa

namespace xla::dfa
{
    namespace
    {
        HANDLE CreateFileHook(LPCSTR fileName, DWORD desiredAccess, DWORD shareMode,
                              LPSECURITY_ATTRIBUTES security, DWORD creationDisposition,
                              DWORD flags, HANDLE templateFile)
        {
            return ::CreateFileA(fileName, desiredAccess, shareMode, security,
                                 creationDisposition, flags, templateFile);
        }

        // The original wraps CloseHandle in SEH and keeps going on a fault.
        BOOL CloseHandleHook(HANDLE handle)
        {
            __try
            {
                return ::CloseHandle(handle);
            }
            __except (EXCEPTION_CONTINUE_EXECUTION)
            {
            }
            return TRUE;
        }

        BOOL GetFileSizeExHook(HANDLE handle, PLARGE_INTEGER size)
        {
            return ::GetFileSizeEx(handle, size);
        }

        BOOL ReadFileHook(HANDLE handle, LPVOID buffer, DWORD toRead, LPDWORD read,
                          LPOVERLAPPED overlapped)
        {
            return ::ReadFile(handle, buffer, toRead, read, overlapped);
        }

        DWORD SetFilePointerHook(HANDLE handle, LONG distance, PLONG distanceHigh,
                                 DWORD moveMethod)
        {
            return ::SetFilePointer(handle, distance, distanceHigh, moveMethod);
        }
    } // namespace

    int __cdecl DfaInit(int, int, int)
    {
        return 1;
    }

    void Install(const Image& image)
    {
        // The rows scan the live game module through patch::; the image handle is
        // the install-time contract, not a gate (see patch.ixx).
        (void)image;
        patch::CallFirst("E8 ? ? ? ? 83 C4 0C 83 F8 01 74 11 6A 00 6A 00", 0,
                         reinterpret_cast<void*>(&DfaInit), "dfa: init");
        patch::JumpFirst("55 8B EC 6A 00 E8", 0, reinterpret_cast<const void*>(&CreateFileHook),
                         "dfa: create file");
        patch::JumpFirst(
            "6A 00 E8 ? ? ? ? 83 F8 01 59 75 17 FF 15 ? ? ? ? 50 B9 ? ? ? ? E8 ? ? ? ? 8B 40 "
            "08 FF 60 0C 33 C0 C3",
            0, reinterpret_cast<const void*>(&CloseHandleHook), "dfa: close handle");
        patch::JumpFirst(
            "6A 00 E8 ? ? ? ? 83 F8 01 59 75 17 FF 15 ? ? ? ? 50 B9 ? ? ? ? E8 ? ? ? ? 8B 40 "
            "08 FF 60 ? 83 C8 FF C3",
            0, reinterpret_cast<const void*>(&SetFilePointerHook), "dfa: set file pointer");
        patch::JumpFirst(
            "56 8B 74 24 0C 8D 46 04 50 FF 74 24 0C E8 ? ? ? ? 59 59 33 C9 83 F8 FF 0F 95 C1 "
            "89 06 5E 8B C1 C3",
            0, reinterpret_cast<const void*>(&GetFileSizeExHook), "dfa: get file size");
        patch::JumpFirst("55 8B EC 51 51 53 56 8B C5", 0,
                         reinterpret_cast<const void*>(&ReadFileHook), "dfa: read file");

        // The original rewrites the first two matches of one pattern into jumps to
        // the first matches of two helper patterns. The names stay here, after the
        // install scans, because the scan order is data (xla_signature_parity).
        constexpr std::string_view kCollectedAnchor =
            "A1 ? ? ? ? B9 A7 FA DC 5C F7 E1 8B 0D ? ? ? ? 33 F6";
        constexpr std::string_view kCollectedFirst = "80 BC 24 ? ? ? ? ? 6A 00";
        constexpr std::string_view kCollectedSecond =
            "6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 57";
        constexpr std::size_t kCollectedSites = 2;

        hook::pattern anchor{kCollectedAnchor};
        if (anchor.size() >= kCollectedSites)
        {
            hook::pattern first{kCollectedFirst};
            hook::pattern second{kCollectedSecond};
            if (!first.empty() && !second.empty())
            {
                injector::MakeJMP(injector::raw_ptr(anchor.get(0).get<void>()),
                                  injector::raw_ptr(first.get(0).get<void>()), true);
                injector::MakeJMP(injector::raw_ptr(anchor.get(1).get<void>()),
                                  injector::raw_ptr(second.get(0).get<void>()), true);
                log::Write("dfa: secondary jump targets installed");
            }
            else
            {
                log::Info("dfa: secondary jump targets missing (first={}, second={})",
                          first.size(), second.size());
            }
        }
        else
        {
            log::Write("dfa: anchor pattern missing; no secondary jumps");
        }
    }
} // namespace xla::dfa
