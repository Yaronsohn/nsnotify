/* %%COPYRIGHT%% */

/* INCLUDES *******************************************************************/

#include <windows.h>
#include "notify.h"

/* GLOBALS ********************************************************************/

static RTL_INIT_CTRL InitCtrl = { 0 };
HANDLE MonitorThreadHandle = 0;
CLIENT_ID ClientId = { 0 };

static HANDLE Handles[MAXIMUM_WAIT_OBJECTS - 1] = { 0 };
static PMONITOR_ROUTINE Routines[RTL_NUMBER_OF(Handles)] = { 0 };
static DWORD HandleCount = 0;

/* FUNCTIONS ******************************************************************/

typedef struct _APC_PACKET {
    PKNORMAL_ROUTINE NormalRoutine;
    PVOID NormalContext;
    PVOID SystemArgument1;
    PVOID SystemArgument2;
} APC_PACKET, *PAPC_PACKET;

static
VOID
NTAPI
MonitorThreadApc(
    _In_ PVOID NormalContext,
    _In_ PVOID SystemArgument1,
    _In_ PVOID SystemArgument2
    )
{
    PAPC_PACKET Packet = (PAPC_PACKET)NormalContext;

    UNREFERENCED_PARAMETER(SystemArgument1);

    ASSERT(SystemArgument1 == 0);

    Packet->NormalRoutine(Packet->NormalContext,
                          Packet->SystemArgument1,
                          Packet->SystemArgument2);
    if (SystemArgument2)
    {
        NtReleaseKeyedEvent(NULL, SystemArgument2, FALSE, NULL);
    }
}

VOID
QueueMonitorThreadApc(
    _In_ PKNORMAL_ROUTINE NormalRoutine,
    _In_ PVOID NormalContext,
    _In_ PVOID SystemArgument1,
    _In_ PVOID SystemArgument2
    )
{
    PTEB Teb = NtCurrentTeb();
    APC_PACKET Packet;

    ASSERT(MonitorThreadHandle);

    Packet.NormalRoutine = NormalRoutine;
    Packet.NormalContext = NormalContext;
    Packet.SystemArgument1 = SystemArgument1;
    Packet.SystemArgument2 = SystemArgument2;

    if (Teb->ClientId.UniqueThread == ClientId.UniqueThread)
    {
        MonitorThreadApc(&Packet, NULL, NULL);
    }
    else
    {
        if (NT_SUCCESS(NtQueueApcThread(MonitorThreadHandle,
                                        MonitorThreadApc,
                                        &Packet,
                                        NULL,
                                        Teb)))
        {
            NtWaitForKeyedEvent(NULL, Teb, FALSE, NULL);
        }
    }
}

static
VOID
NTAPI
AddRemoveMonitoredHandleApc(
    _In_opt_ PVOID NormalContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
{
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (SystemArgument1)
    {
        ASSERT(HandleCount < RTL_NUMBER_OF(Handles));

        Handles[HandleCount] = NormalContext;
        Routines[HandleCount] = SystemArgument1;
        HandleCount++;
    }
    else
    {
        ULONG i;

        ASSERT(HandleCount);

        for (i = 0; i < HandleCount; i++)
        {
            if (Handles[i] == NormalContext)
            {
                HandleCount--;
                RtlCopyMemory(&Handles[i],
                              Handles[i + 1],
                              HandleCount - i);
            }
        }
    }
}

VOID
NTAPI
AddRemoveMonitoredHandle(
    _In_ HANDLE Handle,
    _In_opt_ PMONITOR_ROUTINE Routine
    )
{
    QueueMonitorThreadApc(AddRemoveMonitoredHandleApc,
                          Handle,
                          Routine,
                          NULL);
}

static
DWORD
NTAPI
MonitorThreadRoutine(
    _Reserved_ PVOID Parameter
    )
{
    DWORD ret;

    UNREFERENCED_PARAMETER(Parameter);

    while (HandleCount)
    {
        ret = MsgWaitForMultipleObjectsEx(HandleCount,
                                          Handles,
                                          INFINITE,
                                          QS_ALLINPUT,
                                          MWMO_ALERTABLE);
        if (ret >= STATUS_WAIT_0 &&
            ret < (STATUS_WAIT_0 + HandleCount))
        {
            Routines[ret - STATUS_WAIT_0]();
        }
        else if (ret == (STATUS_WAIT_0 + HandleCount))
        {
            MSG msg;

            if (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
            {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
        else if (ret != STATUS_USER_APC)
        {
            DbgBugCheck(UNEXPECTED_VALUE, ret, 0, 0, VALUE_TYPE_RETURNCODE);
        }
    }

    return STATUS_SUCCESS;
}

static
VOID
BreakEventRoutine(
    VOID
    )
{
    AddRemoveMonitoredHandleApc(Handles[0], NULL, NULL);
}

BOOLEAN
InitFinMonitorThread(
    _In_ BOOLEAN Init
    )
{
    BOOL Success = FALSE;
    NTSTATUS Status;
    HANDLE EventHandle;

    if (Init)
    {
        if (RtlInitCtrlInitialize(&InitCtrl, NULL, NULL))
            return TRUE;

        HandleCount = 0;

        Status = NtCreateEvent(&EventHandle,
                               SYNCHRONIZE | EVENT_MODIFY_STATE,
                               NULL,
                               NotificationEvent,
                               FALSE);
        if (NT_SUCCESS(Status))
        {
            Status = RtlCreateUserThread(NtCurrentProcess(),
                                         NULL,
                                         TRUE,
                                         0,
                                         0,
                                         0,
                                         MonitorThreadRoutine,
                                         NULL,
                                         &MonitorThreadHandle,
                                         &ClientId);
            if (NT_SUCCESS(Status))
            {
                AddRemoveMonitoredHandleApc(EventHandle, BreakEventRoutine, NULL);
                NtResumeThread(MonitorThreadRoutine, NULL);
                Success = TRUE;
            }
            else
            {
                NtClose(EventHandle);
            }
        }
    }
    else
    {
        if (!RtlInitCtrlUninitialize(&InitCtrl, NULL, NULL))
            return TRUE;

        NtSetEvent(Handles[0], NULL);
        NtWaitForSingleObject(MonitorThreadHandle, FALSE, NULL);
        NtClose(MonitorThreadHandle);
        NtClose(Handles[0]);

        Success = TRUE;
    }

    RtlInitCtrlComplete(&InitCtrl, Success);
    return Success;
}
