// SPDX-License-Identifier: GPL-3.0-or-later
//
// XLivelessAddon's entry point. dllmain.cpp is the only plain translation unit in
// source/; it owns startup and nothing else. The first pass runs synchronously at
// process attach: the DRM has already rewritten the game's import-time code by the
// time a deferred worker would get to scan, so the initial scan has to happen now.
// If the probe pattern is absent, xla::probe retries the whole pass once on a
// worker thread instead of blocking attach.

#include <common.hxx>

import startup;

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID /*reserved*/)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        ::DisableThreadLibraryCalls(module);
        xla::startup::Run(module);
    }
    else if (reason == DLL_PROCESS_DETACH)
    {
        xla::startup::Shutdown();
    }
    return TRUE;
}
