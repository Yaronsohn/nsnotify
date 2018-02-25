/* %%COPYRIGHT%% */

#pragma warning(disable : 4996)

/* INCLUDES *******************************************************************/

#include <windows.h>
#include "notify.h"
#include <dbt.h>

/* GLOBALS ********************************************************************/

static const LPCWSTR PrometheusNotificationWindowClass =
    L"PrometheusNotificationWindowClass";

HWND NotifyHwnd = 0;

/* FUNCTIONS ******************************************************************/

static
LRESULT
CALLBACK
NotifyWndProc(
    _In_ HWND hwnd,
    _In_ UINT uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
    )
{
    switch (uMsg)
    {
    case WM_SETTINGCHANGE:
        if (lParam)
        {
            if (wcsicmp((LPCWSTR)lParam, L"Policy") == 0)
            {
                DispatchNotification(NotifyPolicy, wParam, 0, 0, 0);
            }
            else if (wcsicmp((LPCWSTR)lParam, L"intl") == 0)
            {
                DispatchNotification(NotifyLocale, wParam, 0, 0, 0);
            }
            else if (wcsicmp((LPCWSTR)lParam, L"Environment") == 0)
            {
                DispatchNotification(NotifyEnvironment, wParam, 0, 0, 0);
            }
        }
        break;

    case WM_DEVICECHANGE:
        {
            DWORD size = 0;

            switch (wParam)
            {
            case DBT_CUSTOMEVENT:
            case DBT_DEVICEARRIVAL:
            case DBT_DEVICEQUERYREMOVE:
            case DBT_DEVICEQUERYREMOVEFAILED:
            case DBT_DEVICEREMOVECOMPLETE:
            case DBT_DEVICEREMOVEPENDING:
            case DBT_DEVICETYPESPECIFIC:
            case DBT_USERDEFINED:
                size = ((PDEV_BROADCAST_HDR)lParam)->dbch_size;
                break;

            default:
                break;
            }

            DispatchNotification(NotifyDevice, wParam, 0, lParam, size);
        }
        break;

    case WM_POWERBROADCAST:
        {
            DWORD size = 0;

            if (wParam == PBT_POWERSETTINGCHANGE)
            {
                size = sizeof(POWERBROADCAST_SETTING) +
                    ((PPOWERBROADCAST_SETTING) lParam)->DataLength;
            }

            DispatchNotification(NotifyPower, wParam, 0, lParam, size);
        }
        break;

    case WM_WTSSESSION_CHANGE:
        DispatchNotification(NotifySession, wParam, 0, lParam, 0);
        break;

    case WM_TIMECHANGE:
        DispatchNotification(NotifyTime, 0, 0, 0, 0);
        break;
    }

    return DefWindowProcW(hwnd, uMsg, wParam, lParam);
}

static
VOID
NTAPI
CreateNotifyWindowAPC(
    _In_ PVOID NormalContext,
    _In_ PVOID SystemArgument1,
    _In_ PVOID SystemArgument2
    )
{
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (NormalContext)
    {
        /* Create the window */
        NotifyHwnd = CreateWindowExW(0,
                                     PrometheusNotificationWindowClass,
                                     L"",
                                     WS_OVERLAPPEDWINDOW,
                                     CW_USEDEFAULT,
                                     CW_USEDEFAULT,
                                     CW_USEDEFAULT,
                                     CW_USEDEFAULT,
                                     HWND_MESSAGE,
                                     (HMENU)0,
                                     hInst,
                                     NULL);
    }
    else
    {
        DestroyWindow(NotifyHwnd);
        NotifyHwnd = NULL;
    }

    /* Awake the requesting thread */
    NtReleaseKeyedEvent(NULL, CreateNotifyWindowAPC, FALSE, NULL);
}

BOOLEAN
InitFinNotifyWindow(
    _In_ BOOLEAN Init,
    _Inout_ PINIT_ENTRY InitEntry
    )
{
    BOOL Success = FALSE;

    if (Init)
    {
        WNDCLASSEXW wcex = { 0 };

        if (!RtlInitCtrlInitialize(&InitEntry->InitCtrl, NULL, NULL))
            return TRUE;

        if (!InitFinMonitorThread(TRUE))
        {
            RtlInitCtrlComplete(&InitEntry->InitCtrl, FALSE);
            return FALSE;
        }

        wcex.cbSize = sizeof(wcex);
        wcex.style = 0;
        wcex.lpfnWndProc = NotifyWndProc;
        wcex.lpszClassName = PrometheusNotificationWindowClass;

        if (!RegisterClassExW(&wcex))
            goto Leave;

        /* We need the monitor thread to create the window so queue an APC */
        QueueMonitorThreadApc(CreateNotifyWindowAPC, (PVOID)TRUE, NULL, NULL);

        /* Make sure the monitor thread had created the window */
        if (NotifyHwnd)
        {
            RtlInitCtrlComplete(&InitEntry->InitCtrl, TRUE);
            return TRUE;
        }
    }
    else
    {
        if (!RtlInitCtrlUninitialize(&InitEntry->InitCtrl, NULL, NULL))
            return TRUE;

        /* We need to delete the window from the thread that created it */
        QueueMonitorThreadApc(CreateNotifyWindowAPC,
                              (PVOID)FALSE,
                              NULL,
                              NULL);
    }

    UnregisterClassW(PrometheusNotificationWindowClass, NULL);

Leave:
    if (!Success)
    {
        InitFinMonitorThread(FALSE);
    }

    RtlInitCtrlComplete(&InitEntry->InitCtrl, Success);
    return Success;
}
