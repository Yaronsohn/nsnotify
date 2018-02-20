/* %%COPYRIGHT%% */

#if !defined(_WIN32)
#error ERROR! Platform not supported!
#endif

/* INCLUDES *******************************************************************/

#include <windows.h>
#include "notify.h"
#include <dbt.h>

/* GLOBALS ********************************************************************/

static HDEVNOTIFY hDevNotify = 0;

/* FUNCTIONS ******************************************************************/

BOOLEAN
InitFinNotifyDevice(
    _In_ BOOLEAN Init,
    _Inout_ PINIT_ENTRY InitEntry
    )
{
    BOOL Success = TRUE;

    if (Init)
    {
        DEV_BROADCAST_DEVICEINTERFACE filter = { 0 };

        if (!RtlInitCtrlInitialize(&InitEntry->InitCtrl, NULL, NULL))
            return TRUE;

        filter.dbcc_size = sizeof(filter);
        filter.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;

        hDevNotify = RegisterDeviceNotificationW(NotifyHwnd,
                                                 &filter,
                                                 DEVICE_NOTIFY_WINDOW_HANDLE | DEVICE_NOTIFY_ALL_INTERFACE_CLASSES);
        if (!hDevNotify)
        {
            Success = FALSE;
        }
    }
    else
    {
        if (!RtlInitCtrlUninitialize(&InitEntry->InitCtrl, NULL, NULL))
            return TRUE;

        UnregisterDeviceNotification(hDevNotify);
        hDevNotify = 0;
    }

    RtlInitCtrlComplete(&InitEntry->InitCtrl, Success);
    return Success;
}
