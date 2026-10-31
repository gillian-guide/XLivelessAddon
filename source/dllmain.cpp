// SPDX-License-Identifier: GPL-3.0-or-later
//
// XLivelessAddon entry point. Everything runs synchronously at process attach:
// the DRM has already rewritten the game's import-time code by the time a
// deferred worker would get to scan, so signatures have to be matched now.

#include "common.hxx"

import xla.addon;

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID /*reserved*/)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        ::DisableThreadLibraryCalls(module);
        xla::Run(module);
    }
    return TRUE;
}
