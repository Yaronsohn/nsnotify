/* %%COPYRIGHT%% */

#if !defined(_WIN32)
#error ERROR! Platform not supported!
#endif

#pragma warning( disable : 4996 )

/* INCLUDES *******************************************************************/

#include <windows.h>
#include "notify.h"
#include <AccCtrl.h>
#include <ntrtlu.h>
#include <lpccs.h>

/* GLOBALS ********************************************************************/

static const UNICODE_STRING LpcServerName = RTL_CONSTANT_STRING(L"\\" SERVER_NAME);
static LPCSERVER LpcServer = { 0 };
HINSTANCE hInst = NULL;

/* FUNCTIONS ******************************************************************/

typedef struct _NSNOTIFY_CONNECTION {
    NOTIFICATION_TYPE Types;
    HANDLE ProcessHandle;
    HANDLE ThreadHandle;
    PKNORMAL_ROUTINE Routine;
    USHORT ThreadNumaNode;
} NSNOTIFY_CONNECTION, *PNSNOTIFY_CONNECTION;

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
    packet = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, PacketSize);
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

    Connection = NULL;
    while (Connection = (PNSNOTIFY_CONNECTION)LpcGetNextConnection(&LpcServer, Connection))
    {
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

    RtlFreeHeap(RtlGetProcessHeap(), 0, packet);
}

static
BOOLEAN
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
NTSTATUS
Handshake(
    _In_ PNSNOTIFY_CONNECTION Connection,
    _Inout_ PNSNOTIFY_REQUEST Request
    )
{
    NTSTATUS Status;

    if (!Request->u2.Handshake.Routine
        ||
        RtlIsPsedoHandle(Request->u2.Handshake.ThreadHandle))
    {
        return STATUS_INVALID_PARAMETER;
    }

    /*
     * Open a handle to the process that sent the message.
     *
     * N.B. this function will fail if NULL is passed for ObjectAttributes
     */
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
            return STATUS_SUCCESS;
        }

        NtClose(Connection->ThreadHandle);
    }

    return Status;
}

static
NTSTATUS
Register(
    _In_ PNSNOTIFY_CONNECTION Connection,
    _Inout_ PNSNOTIFY_REQUEST Request
    )
{
    NOTIFICATION_TYPE mask = Request->u2.Register.Type;

    if (!Connection->ThreadHandle)
        return STATUS_NOT_FOUND;

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
            return STATUS_UNSUCCESSFUL;
    }

    Connection->Types |= mask;
    return STATUS_SUCCESS;
}

static
NTSTATUS
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
    return STATUS_SUCCESS;
}

static
NTSTATUS
NTAPI
HandleNewConnection(
    _Inout_ struct _LPCSERVER *Server,
    _In_opt_ PNSNOTIFY_REQUEST Request,
    _Inout_ PNSNOTIFY_CONNECTION Connection
    )
{
    OBJECT_ATTRIBUTES ObjectAttributes;

    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, 0, NULL);
    return NtOpenProcess(&Connection->ProcessHandle,
                         PROCESS_DUP_HANDLE | PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
                         &ObjectAttributes,
                         &Request->PortMessage.u3.ClientId);
}

static
NTSTATUS
NTAPI
HandleConnectionCleanup(
    _Inout_ struct _LPCSERVER *Server,
    _In_opt_ PNSNOTIFY_REQUEST Request,
    _Inout_ PNSNOTIFY_CONNECTION Connection
    )
{
    /* Uninitialize the notifications this client has asked for */
    UninitNotificationsByMask(Connection->Types);

    NtClose(Connection->ProcessHandle);

    if (Connection->ThreadHandle)
    {
        NtClose(Connection->ThreadHandle);
    }

    return STATUS_SUCCESS;
}

typedef NTSTATUS(*PREQUEST_HANDLER)(PNSNOTIFY_CONNECTION, PNSNOTIFY_REQUEST);
static const PREQUEST_HANDLER Handlers[] =
{
    Handshake,
    Register,
    Unregister
};

static
NTSTATUS
NTAPI
HandleRequest(
    _Inout_ struct _LPCSERVER *Server,
    _In_opt_ PNSNOTIFY_REQUEST Request,
    _Inout_ PNSNOTIFY_CONNECTION Connection
    )
{
    if (Request->u1.Type < RTL_NUMBER_OF(Handlers))
    {
        Request->u1.Status = Handlers[Request->u1.Type](Connection, Request);
    }
    else
    {
        Request->u1.Status = STATUS_INVALID_PARAMETER;
    }

    return STATUS_SUCCESS;
}

static
NTSTATUS
NTAPI
HandleClientDied(
    _Inout_ struct _LPCSERVER *Server,
    _In_opt_ PNSNOTIFY_REQUEST Request,
    _Inout_ PNSNOTIFY_CONNECTION Connection
    )
{
    DispatchNotification(NotifyThreadDied,
                         (ULONG_PTR)Request->PortMessage.u3.ClientId.UniqueThread,
                         0,
                         0,
                         0);
    return STATUS_SUCCESS;
}

static
NTSTATUS
InitializeServer(
    VOID
    )
{
    NTSTATUS Status;
    UNICODE_STRING PortName;

    /* Embed the session id with the base port name */
    Status = RtlGetNamedObjectDirectoryName(&PortName, &LpcServerName, NULL, TRUE);
    if (!NT_SUCCESS(Status))
        return Status;

    LpcServer.Size = sizeof(LpcServer);
    LpcServer.Timeout = &RtlTimeout30Sec;
    LpcServer.MaxDataLength = sizeof(NSNOTIFY_REQUEST);
    LpcServer.ConnectionLength = sizeof(NSNOTIFY_CONNECTION);
    LpcServer.NewConnection = (PLPC_EVENT)HandleNewConnection;
    LpcServer.ConnectionCleanup = (PLPC_EVENT)HandleConnectionCleanup;
    LpcServer.Request = (PLPC_EVENT)HandleRequest;
    LpcServer.ClientDied = (PLPC_EVENT)HandleClientDied;
    
    return LpcInitializeServer(&LpcServer, &PortName, LpcDefaultPortAccess, 0);
}

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
    NTSTATUS Status;

    hInst = hInstance;

    Status = InitializeServer();
    if (NT_SUCCESS(Status))
    {
        Status = LpcListen(&LpcServer, FALSE);
        FinalizeServer(&LpcServer);
    }

    return Status;
}

