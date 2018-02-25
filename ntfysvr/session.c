/* %%COPYRIGHT%% */

#if !defined(_WIN32)
#error ERROR! Platform not supported!
#endif

/* INCLUDES *******************************************************************/

#include <windows.h>
#include "notify.h"
#include <Wtsapi32.h>

/* FUNCTIONS ******************************************************************/

BOOLEAN
InitFinNotifySession(
    _In_ BOOLEAN Init,
    _Inout_ PINIT_ENTRY InitEntry
    )
{
    BOOL Success = TRUE;

    if (Init)
    {
        if (!RtlInitCtrlInitialize(&InitEntry->InitCtrl, NULL, NULL))
            return TRUE;

        Success = WTSRegisterSessionNotification(NotifyHwnd,
                                                 NOTIFY_FOR_ALL_SESSIONS);
    }
    else
    {
        if (!RtlInitCtrlUninitialize(&InitEntry->InitCtrl, NULL, NULL))
            return TRUE;

        WTSUnRegisterSessionNotification(NotifyHwnd);
    }

    RtlInitCtrlComplete(&InitEntry->InitCtrl, Success);
    return Success;
}
