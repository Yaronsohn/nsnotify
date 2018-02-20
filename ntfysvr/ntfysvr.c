/* %%COPYRIGHT%% */

#if !defined(_WIN32)
#error ERROR! Platform not supported!
#endif

#pragma warning( disable : 4996 )

/* INCLUDES *******************************************************************/

#include <windows.h>
#include "notify.h"
#include <waitmgr.h>
#include <AccCtrl.h>
#include <ntrtlu.h>
#include <winutils.h>
#include <ntextapi.h>

/* GLOBALS ********************************************************************/

static RTL_REFENTRY_LIST EntryList = { 0 };
static ULONG ConnectionCount = 0;

HINSTANCE hInst = NULL;
HANDLE hWaitManager = 0;

/* FUNCTIONS ******************************************************************/

typedef struct _NSNOTIFY_CONNECTION {
    RTL_REFENTRY RefEntry;
    HANDLE hPort;
    NOTIFICATION_TYPE Types;
    HANDLE ProcessHandle;
    HANDLE ThreadHandle;
    PKNORMAL_ROUTINE Routine;
    USHORT ThreadNumaNode;
} NSNOTIFY_CONNECTION, *PNSNOTIFY_CONNECTION;

#define ALLOC(size) RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define FREE(ptr) RtlFreeHeap(RtlGetProcessHeap(), 0, ptr)

#define NotifyRequiredWindow \
    (NotifyPolicy | NotifyLocale | NotifyEnvironment | \
    NotifyDevice | NotifyPower | NotifySession | \
    NotifyTime)

BOOLEAN InitFinNotifyWindow(BOOLEAN, PINIT_ENTRY);
BOOLEAN InitFinNotifyDevice(BOOLEAN, PINIT_ENTRY);
BOOLEAN InitFinNotifyMemory(BOOLEAN, PINIT_ENTRY);
BOOLEAN InitFinNotifySession(BOOLEAN, PINIT_ENTRY);

static INIT_ENTRY InitArr[] =
{
    { NotifyWindow, { 0 }, InitFinNotifyWindow },
    { NotifyDevice, { 0 }, InitFinNotifyDevice },
    { NotifyMemory, { 0 }, InitFinNotifyMemory },
    { NotifySession,{ 0 }, InitFinNotifySession },
};

VOID
DispatchNotification(
    _In_ NOTIFICATION_TYPE Type,
    _In_ ULONG_PTR Param1,
    _In_opt_ SIZE_T Param1Length,
    _In_ ULONG_PTR Param2,
    _In_opt_ SIZE_T Param2Length
    )
{
    PRTL_REFENTRY entry = NULL;
    PNSNOTIFY_CONNECTION Connection;
    PNOTIFICATION_PACKET packet;
    SIZE_T PacketSize;
    SIZE_T offset;
    PVOID RemotePacket;
    SIZE_T written;
    HANDLE ProcessHandle;
    SIZE_T RegionSize;
    NTSTATUS Status;

    /* Calculate the packet size */
    PacketSize = sizeof(NOTIFICATION_PACKET) + Param1Length + Param2Length;

    /* Allocate a locap*/
    packet = ALLOC(PacketSize);
    if (!packet)
        return;

    offset = sizeof(NOTIFICATION_PACKET);

    /* prepare a packet template */
    packet->Type = Type;

#define SET_PARAM(param) \
{ \
    if (param##Length) \
    { \
        packet->Denormalize##param = TRUE; \
        packet->param = offset; \
        RtlCopyMemory(RtlOffsetToPointer(packet, offset), (PVOID) param, param##Length); \
    } \
    else \
    { \
        packet->param = param; \
    } \
    offset += param##Length; \
} while (0)

    SET_PARAM(Param1);
    SET_PARAM(Param2);

    while (entry = RtlGetRefEntry(&EntryList, entry))
    {
        Connection = CONTAINING_RECORD(entry, NSNOTIFY_CONNECTION, RefEntry);

        /*
         * make sure the callback is interested with this kind of
         * notification
         */
        if (Connection->Types & Type)
        {
            /* Cache the handle */
            ProcessHandle = Connection->ProcessHandle;

            /* Allocate memory in the remote process */
            RemotePacket = NULL;
            RegionSize = PacketSize;
            if (!NT_SUCCESS(NtAllocateVirtualMemory(ProcessHandle,
                                                    &RemotePacket,
                                                    0,
                                                    &RegionSize,
                                                    (MEM_RESERVE | MEM_COMMIT) | (Connection->ThreadNumaNode + 1),
                                                    PAGE_READWRITE)))
            {
                continue;
            }

            Status = NtWriteVirtualMemory(ProcessHandle,
                                          RemotePacket,
                                          packet,
                                          PacketSize,
                                          &written);
            if (NT_SUCCESS(Status) && written == PacketSize)
            {
                Status = NtQueueApcThread(Connection->ThreadHandle,
                                          Connection->Routine,
                                          RemotePacket,
                                          NULL,
                                          NULL);
                if (NT_SUCCESS(Status))
                    continue;
            }

            /* We'll get here on any error */
            NtFreeVirtualMemory(ProcessHandle,
                                &RemotePacket,
                                &RegionSize,
                                MEM_RELEASE);
        }
    }

    FREE(packet);
}

static
BOOL
FORCEINLINE
InitNotificationsByMask(
    _In_ NOTIFICATION_TYPE Mask
    )
{
    UINT i;

    for (i = 0; i < _countof(InitArr); i++)
    {
        if (InitArr[i].Type & Mask)
        {
            if (!InitArr[i].InitRoutine(TRUE, &InitArr[i]))
            {
                while (i--)
                {
                    if (InitArr[i].Type & Mask)
                    {
                        InitArr[i].InitRoutine(FALSE, &InitArr[i]);
                    }
                }

                return FALSE;
            }
        }
    }

    return TRUE;
}

static
VOID
FORCEINLINE
UninitNotificationsByMask(
    _In_ NOTIFICATION_TYPE Mask
    )
{
    int i;

    for (i = _countof(InitArr) - 1; i >= 0; i--)
    {
        if (InitArr[i].Type & Mask)
        {
            InitArr[i].InitRoutine(FALSE, &InitArr[i]);
        }
    }
}

static
LONG
Handshake(
    _In_ PNSNOTIFY_CONNECTION Connection,
    _Inout_ PNSNOTIFY_REQUEST Request
    )
{
    NTSTATUS Status;
    OBJECT_ATTRIBUTES ObjectAttributes;
    CLIENT_ID ClientId;

    if (Connection->ProcessHandle)
        return ERROR_INVALID_FUNCTION;

    if (!Request->u2.Handshake.Routine
        ||
        RtlIsPsedoHandle(Request->u2.Handshake.ThreadHandle))
    {
        return ERROR_INVALID_PARAMETER;
    }

    ClientId.UniqueProcess = Request->PortMessage.u3.ClientId.UniqueProcess;
    ClientId.UniqueThread = 0;

    /*
     * Open a handle to the process that sent the message.
     *
     * N.B. this function will fail if NULL is passed for ObjectAttributes
     */
    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
    Status = NtOpenProcess(&Connection->ProcessHandle,
                           PROCESS_DUP_HANDLE | PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
                           &ObjectAttributes,
                           &ClientId);
    if (NT_SUCCESS(Status))
    {
        Status = NtDuplicateObject(Connection->ProcessHandle,
                                   Request->u2.Handshake.ThreadHandle,
                                   NtCurrentProcess(),
                                   &Connection->ThreadHandle,
                                   THREAD_SET_CONTEXT | THREAD_QUERY_LIMITED_INFORMATION,
                                   0,
                                   0);
        if (NT_SUCCESS(Status))
        {
            Status = RtlGetThreadNumaNode(Connection->ThreadHandle, &Connection->ThreadNumaNode);
            if (NT_SUCCESS(Status))
            {
                Connection->Routine = Request->u2.Handshake.Routine;
                return ERROR_SUCCESS;
            }

            NtClose(Connection->ThreadHandle);
        }

        NtClose(Connection->ProcessHandle);
        Connection->ProcessHandle = 0;
    }

    return RtlNtStatusToDosError(Status);
}

static
LONG
Register(
    _In_ PNSNOTIFY_CONNECTION Connection,
    _Inout_ PNSNOTIFY_REQUEST Request
    )
{
    NOTIFICATION_TYPE mask = Request->u2.Register.Type;

    /* The caller can not specify NotifyWindow */
    mask &= ~NotifyWindow;

    /* If any of the remaining types requires a window - set the window flag */
    if (mask & NotifyRequiredWindow)
    {
        mask |= NotifyWindow;
    }

    /* Mask out the types already specified */
    mask &= ~Connection->Types;

    if (mask)
    {
        if (!InitNotificationsByMask(mask))
            return GetLastError();
    }

    Connection->Types |= mask;
    return ERROR_SUCCESS;
}

static
LONG
Unregister(
    _In_ PNSNOTIFY_CONNECTION Connection,
    _Inout_ PNSNOTIFY_REQUEST Request
    )
{
    NOTIFICATION_TYPE mask = Request->u2.Unregister.Type;

    /* The caller can not specify NotifyWindow */
    mask &= ~NotifyWindow;

    /* Mask out the types not previously specified */
    mask &= Connection->Types;

    /*
     * If all of the remaining types do not require the window - uninit it as
     * well
     */
    if (((Connection->Types & ~mask) & NotifyRequiredWindow) == 0)
    {
        mask |= NotifyWindow;
    }

    Connection->Types &= ~mask;

    UninitNotificationsByMask(mask);
    return ERROR_SUCCESS;
}

static
HANDLE
CreateServerPort(VOID)
{
    PWCHAR ServerName;
    PSECURITY_DESCRIPTOR pSD = NULL;
    SECURITY_ATTRIBUTES sa;
    EXPLICIT_ACCESSW ea[1];
    PTOKEN_USER ptu;
    HANDLE hPort = NULL;

    /* Get the user sid */
    ptu = GetTokenInfo(NULL, TokenUser);
    if (!ptu)
        return NULL;

    /* Create a security descriptor for the port */
    ZeroMemory(&ea, sizeof(ea));
    ea[0].grfAccessPermissions = PORT_CONNECT;
    ea[0].grfAccessMode = SET_ACCESS;
    ea[0].grfInheritance = NO_INHERITANCE;
    ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea[0].Trustee.ptstrName = (LPWSTR)ptu->User.Sid;

    pSD = CreateSecurityDescriptorW(_countof(ea), ea);
    LocalFree(ptu);
    if (!pSD)
        return NULL;

    /* Initialize the object's security attributes */
    RtlZeroMemory(&sa, sizeof(sa));
    sa.nLength = sizeof (SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = pSD;
    sa.bInheritHandle = FALSE;

    ServerName = WUSTR_AppendLogonSessionW(NULL, SERVER_NAME);
    if (ServerName)
    {
        /* Create the server port */
        hPort = CreateWaitablePortW(&sa,
                                    ServerName,
                                    0,
                                    sizeof(NSNOTIFY_REQUEST),
                                    0);
        WUSTR_SetPtrW(&ServerName, NULL);
    }

    LocalFree(pSD);
    return hPort;
}

typedef ULONG (*PREQUEST_HANDLER)(PNSNOTIFY_CONNECTION, PNSNOTIFY_REQUEST);

static const PREQUEST_HANDLER Handlers[] =
{
    Handshake,
    Register,
    Unregister
};

C_ASSERT(_countof(Handlers) == NOTIFY_MAX);

int
WINAPI
WinMain(
    _In_ HINSTANCE hInstance,
    _In_ HINSTANCE hPrevInstance,
    _In_ LPSTR lpCmdLine,
    _In_ int nCmdShow
    )
{
    HANDLE hServerPort;
    NSNOTIFY_REQUEST request;
    PNSNOTIFY_CONNECTION Connection;
    DWORD timeout;
    HANDLE ConnectionPortHandle;

    hInst = hInstance;

    RtlInitializeRefEntryList(&EntryList);

    /* Initialize a wait manager instance */
    hWaitManager = WmCreateManager();
    if (!hWaitManager)
        return GetLastError();

    /* Initialize the server port */
    hServerPort = CreateServerPort();
    if (!hServerPort)
        return GetLastError();

    timeout = IsDebuggerPresent() ? INFINITE : 30000;

    for (;;)
    {
        if (!ReplyWaitReceivePortEx(hServerPort,
                                    (PVOID *)&Connection,
                                    NULL,
                                    &request.PortMessage,
                                    timeout))
        {
            return GetLastError();
        }

        switch (request.PortMessage.u2.Type)
        {
        case LPC_CONNECTION_REQUEST:

            /* Allocate a new client entry */
            Connection = ALLOC(sizeof(NSNOTIFY_CONNECTION));

            /*
             * Accept the connection - this will result with a null handle if
             * the above allocation has failed
             */
            ConnectionPortHandle = AcceptConnectPort(Connection,
                                                     &request.PortMessage,
                                                     Connection != NULL,
                                                     NULL,
                                                     NULL);
            if (ConnectionPortHandle)
            {
                /* Initial the client */
                Connection->hPort = ConnectionPortHandle;
                Connection->Types = NotifyNone;
                Connection->ProcessHandle = 0;
                if (CompleteConnectPort(ConnectionPortHandle))
                {
                    /*
                     * The entry is ready - insert it and wait for the next
                     * message
                     */
                    RtlInsertRefEntry(&EntryList, &Connection->RefEntry);
                    ConnectionCount++;

                    /* From now on we won't specify timeout */
                    timeout = INFINITE;
                    continue;
                }

                CloseHandle(ConnectionPortHandle);
            }

            /* If we're here then something has went wrong */
            if (Connection)
            {
                FREE(Connection);
            }
            continue;

        case LPC_PORT_CLOSED:

            /* Remove the entry */
            RtlRemoveRefEntry(&Connection->RefEntry);

            /* Uninitialize the notifications this client has asked for */
            UninitNotificationsByMask(Connection->Types);

            /* Cleanup... */
            if (Connection->ThreadHandle)
            {
                NtClose(Connection->ThreadHandle);
            }

            if (Connection->ProcessHandle)
            {
                NtClose(Connection->ProcessHandle);
            }

            NtClose(Connection->hPort);
            FREE(Connection);

            /* Decrement the number of clients */
            if (--ConnectionCount)
            {
                /* we still have clients connected! */
                continue;
            }

            /* The last client has disconnected - exit the process */
            return ERROR_SUCCESS;

        case LPC_REQUEST:
            if (request.u1.Type >= 0 && request.u1.Type < _countof(Handlers))
            {
                request.u1.Status = Handlers[request.u1.Type](Connection, &request);
            }
            else
            {
                request.u1.Status = ERROR_INVALID_FUNCTION;
            }

            ReplyPort(hServerPort, &request.PortMessage);
            continue;

        case LPC_CLIENT_DIED:
            DispatchNotification(NotifyThreadDied,
                                 (ULONG_PTR)request.PortMessage.u3.ClientId.UniqueThread,
                                 0,
                                 0,
                                 0);
            continue;

        default:
            break;
        }
    }
}

