#include <windows.h>
#include "hack.h"
#include "winapihook.h"

static void HookSI4(void)
{
    HackSI4();
    //HookWinApi();
}

static void UnhookSI4(void)
{
}


BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
            HookSI4();
            break;

        case DLL_PROCESS_DETACH:
            UnhookSI4();
            break;

        case DLL_THREAD_ATTACH:
            break;

        case DLL_THREAD_DETACH:
            break;
    }
    return TRUE; // succesful
}

