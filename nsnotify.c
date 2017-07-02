/* %%COPYRIGHT%% */

#if !defined(_WIN32)
#error ERROR! Platform not supported!
#endif

/* INCLUDES *******************************************************************/

#include <windows.h>
#include <apps\ntfysvr\notify.h>
#include <imgbase.h>
#include <winutils.h>
#include <nsutils.h>
#include <ntextapi.h>

/* GLOBALS ********************************************************************/

static REFENTRY_LIST EntryList = { 0 };
static HANDLE hPort = 0;
static const WCHAR ServerName[] =
    { 'N', 'T', 'F', 'Y', 'S', 'V', 'R', '.', 'E', 'X', 'E', 0 };
static HANDLE hNotificationThread = 0;
static BOOL Terminated = FALSE;

/* FUNCTIONS ******************************************************************/

typedef struct _NSNOTIFY_CONNECTION {
    ULONG Signature;
    REFENTRY RefEntry;
    NOTIFICATION_TYPE Types;
    PNOTIFICATION_ROUTINE Routine;
    PVOID Param;
} NSNOTIFY_CONNECTION, *PNSNOTIFY_CONNECTION;

#define CONNECTION_TAG  'YFTN'

#define ALLOC(size) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define FREE(ptr) HeapFree(GetProcessHeap(), 0, ptr)

BOOL
WINAPI
DllMain(
    HINSTANCE hinstDLL,
    DWORD fdwReason,
    LPVOID lpvReserved
    )
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:

        /* Disable thread attached/detached notifications */
        LdrDisableThreadCalloutsForDll(hinstDLL);

        InitializeRefEntryList(&EntryList, NULL);
        break;

    case DLL_PROCESS_DETACH:
        if (hPort)
        {
            CloseHandle(hPort);
        }

        FinalizeRefEntryList(&EntryList);
        break;
    }

    return TRUE;
}

static
BOOL
StartServer(VOID)
{
    PWCHAR ntfysvr;
    BOOL success;
    STARTUPINFOW si = { 0 };
    PROCESS_INFORMATION pi = { 0 };

    ntfysvr = PrependModulePathW((HMODULE)&__ImageBase, ServerName);
    if (!ntfysvr)
        return GetLastError();

    /* Start the server */
    si.cb = sizeof(si);
    success = CreateProcessW(NULL,
                             ntfysvr,
                             NULL,
                             NULL,
                             FALSE,
                             0,
                             NULL,
                             NULL,
                             &si,
                             &pi);
    LocalFree(ntfysvr);
    if (success)
    {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    return success;
}

static
BOOL
ConnectToServer(VOID)
{
    ULONG MaxMsgSize = sizeof(NSNOTIFY_REQUEST);
    ULONG attempts;
    PWCHAR ServerName;

    ServerName = WUSTR_AppendLogonSessionW(NULL, SERVER_NAME);
    if (!ServerName)
        return FALSE;

    attempts = 0;
    do
    {
        /* Try to connect to the server */
        hPort = SecureConnectPortW(ServerName,
                                   NULL,
                                   NULL,
                                   NULL,
                                   NULL,
                                   &MaxMsgSize,
                                   NULL,
                                   NULL);
        if (hPort)
            break;

        if ((attempts % 10) == 0)
        {
            /* In the first attempt we try to start a new server */
            if (!StartServer())
                break;

            attempts++;
        }
        else
        {
            if (!IsDebuggerPresent())
            {
                attempts++;
            }
        }

        /* Try to give the server process time to prepare */
        Sleep(500);

    } while (attempts < 30);

    WUSTR_SetPtrW(&ServerName, NULL);

    return hPort != 0;
}

static
VOID
CALLBACK
NotificationAPC(
    _In_ ULONG_PTR Parameter
    )
{
    PNOTIFICATION_PACKET packet = (PNOTIFICATION_PACKET) Parameter;
    PREFENTRY entry = NULL;
    PNSNOTIFY_CONNECTION Connection;

    if (!packet)
    {
        Terminated = TRUE;
        return;
    }

    while (entry = GetRefEntry(&EntryList, entry))
    {
        Connection = CONTAINING_RECORD(entry, NSNOTIFY_CONNECTION, RefEntry);

        if (Connection->Types & packet->Type)
        {
            Connection->Routine(Connection->Param,
                                packet->Type,
                                packet->Param1,
                                packet->Param2);
        }
    }

    VirtualFreeEx(GetCurrentProcess(),
                  packet,
                  0,
                  MEM_RELEASE);
}

static
DWORD
CALLBACK
NotificationThreadProc(
    __reserved PVOID Parameter
    )
{
    for (;;)
    {
        CURRENT_THREAD_NAME("Notifiction Server Thread");

        if (Terminated)
        {
            TerminateThread(GetCurrentThread(), 0);
        }

        SleepEx(INFINITE, TRUE);
    }
}

static
BOOL
CallServer(
    _Inout_ PNSNOTIFY_REQUEST Request
    )
{
    Request->PortMessage.u1.TotalLength = sizeof(NSNOTIFY_REQUEST);
    Request->PortMessage.u2.ZeroInit = 0;

    if (!RequestWaitReplyPort(hPort,
                              &Request->PortMessage,
                              &Request->PortMessage))
    {
        return FALSE;
    }

    if (Request->u1.Status)
    {
        SetLastError(Request->u1.Status);
        return FALSE;
    }

    return TRUE;
}

static
BOOLEAN
InitializeServer(
    _In_ BOOLEAN Init,
    _Inout_ PINIT_ENTRY InitEntry
    )
{
    BOOLEAN success = FALSE;
    NSNOTIFY_REQUEST request;

    if (Init)
    {
        /* Check if we need to initialize */
        if (!InitCtrlInitialize(&InitEntry->InitCtrl, NULL, NULL))
            return TRUE;

        /* Connect to the notification server */
        if (!ConnectToServer())
            goto leave0;

        /* Make sure the flag is off */
        Terminated = FALSE;

        /* Create the dispatcher thread */
        hNotificationThread = CreateThread(NULL,
                                           0,
                                           NotificationThreadProc,
                                           NULL,
                                           CREATE_SUSPENDED,
                                           NULL);
        if (!hNotificationThread)
            goto cleanup1;

        request.u1.Type = NOTIFY_HANDSHAKE;
        request.u2.Handshake.Routine = NotificationAPC;
        request.u2.Handshake.ThreadHandle = hNotificationThread;

        if (!CallServer(&request))
        {
            /*
             * We need to terminate the notification thread - since we've kept
             * it suspended we can simply terminate it
             */
            TerminateThread(hNotificationThread, GetLastError());
            goto cleanup2;
        }

        ResumeThread(hNotificationThread);

        InitCtrlComplete(&InitEntry->InitCtrl, TRUE);
        return TRUE;
    }
    else
    {
        if (!InitCtrlUninitialize(&InitEntry->InitCtrl, NULL, NULL))
            return TRUE;

        /*
         * Queue an empty APC to signal the dispatcher thread to exit -
         * by this point no one is registered so the server will not
         * queue any additional APC, and because APCs are dispatched
         * first-in first-served style, our APC will be the last
         */
        QueueUserAPC(NotificationAPC, hNotificationThread, 0);

        WaitForSingleObject(hNotificationThread, INFINITE);
    }

cleanup2:
    CloseHandle(hNotificationThread);
    hNotificationThread = 0;
cleanup1:
    CloseHandle(hPort);
    hPort = 0;
leave0:
    InitCtrlComplete(&InitEntry->InitCtrl, success);
    return success;
}

static
BOOLEAN
InitGeneric(
    _In_ BOOLEAN Init,
    _Inout_ PINIT_ENTRY InitEntry
    )
{
    NSNOTIFY_REQUEST request;
    BOOLEAN success = FALSE;

    if (Init)
    {
        if (!InitCtrlInitialize(&InitEntry->InitCtrl, NULL, NULL))
            return TRUE;

        request.u1.Type = NOTIFY_REGISTER;
        request.u2.Register.Type = InitEntry->Type;

        success = CallServer(&request);
    }
    else
    {
        if (!InitCtrlUninitialize(&InitEntry->InitCtrl, NULL, NULL))
            return TRUE;

        request.u1.Type = NOTIFY_UNREGISTER;
        request.u2.Unregister.Type = InitEntry->Type;

        CallServer(&request);
    }

    InitCtrlComplete(&InitEntry->InitCtrl, success);
    return success;
}

static INIT_ENTRY InitArr[] =
{
    { NotifyAll,            { 0 }, InitializeServer },
    { NotifyThreadDied,     { 0 }, InitGeneric      },
    { NotifyPolicy,         { 0 }, InitGeneric      },
    { NotifyLocale,         { 0 }, InitGeneric      },
    { NotifyEnvironment,    { 0 }, InitGeneric      },
    { NotifyDevice,         { 0 }, InitGeneric      },
    { NotifyPower,          { 0 }, InitGeneric      },
    { NotifySession,        { 0 }, InitGeneric      },
    { NotifyTime,           { 0 }, InitGeneric      },
    { NotifyMemory,         { 0 }, InitGeneric      },
};

PVOID
NTAPI
RegisterNotificationRoutine(
    _In_ PNOTIFICATION_ROUTINE Routine,
    _In_ NOTIFICATION_TYPE Type,
    _In_ PVOID Param
    )
{
    PNSNOTIFY_CONNECTION Connection;
    int i;

    /* Make sure the caller has asked for at least one notification */
    if ((Type & NotifyAll) == 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    /* Allocate an entry */
    Connection = ALLOC(sizeof(NSNOTIFY_CONNECTION));
    if (!Connection)
        return NULL;

    /* Initialize the entry */
    Connection->Signature = CONNECTION_TAG;
    Connection->Routine = Routine;
    Connection->Param = Param;
    Connection->Types = Type;

    /* Initialize any uninitialized entry */
    for (i = 0; i < _countof(InitArr); i++)
    {
        if (InitArr[i].Type & Type)
        {
            if (!InitArr[i].InitRoutine(TRUE, &InitArr[i]))
            {
                while (i--)
                {
                    if (InitArr[i].Type & Type)
                    {
                        InitArr[i].InitRoutine(FALSE, &InitArr[i]);
                    }
                }

                FREE(Connection);
                return NULL;
            }
        }
    }

    /* All is ready insert the entry to start receive notifications */
    InsertRefEntry(&EntryList, &Connection->RefEntry);
    return (PVOID)Connection;
}

VOID
NTAPI
UnregisterNotificationRoutine(
    _Inout_ PVOID Routine
    )
{
    PNSNOTIFY_CONNECTION Connection = (PNSNOTIFY_CONNECTION) Routine;
    int i;

    if (Connection->Signature != CONNECTION_TAG)
    {
        RaiseException(ERROR_INVALID_PARAMETER, 0, 0, NULL);
        return;
    }

    /* Remove the entry to stop receive notifications */
    RemoveRefEntry(&Connection->RefEntry);

    /* Uninitialize any entry we've previously started */
    for (i = _countof(InitArr) - 1; i >= 0; i--)
    {
        if (InitArr[i].Type & Connection->Types)
        {
            InitArr[i].InitRoutine(FALSE, &InitArr[i]);
        }
    }

    /* we can now free the entry */
    FREE(Connection);
}

BOOL
NTAPI
RegisterThreadForNotification(VOID)
{
    return RegisterThreadTerminatePort(hPort);
}