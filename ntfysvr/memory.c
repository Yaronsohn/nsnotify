/* %%COPYRIGHT%% */

/* INCLUDES *******************************************************************/

#include <windows.h>
#include "notify.h"

/* GLOBALS ********************************************************************/

static MEMORY_CONDITION CurrentCondition = MemoryConditionUnknown;

static HANDLE LowMemoryEventHandle = 0;
static HANDLE HighMemoryEventHandle = 0;
static HANDLE TimerHandle = 0;

/* FUNCTIONS ******************************************************************/

VOID
CheckNewMemoryCondition(
    _In_ MEMORY_CONDITION NewCondition
    );

static
VOID
NTAPI
LowMemoryRoutine(
    VOID
    )
{
    CheckNewMemoryCondition(MemoryConditionLow);
}

static
VOID
NTAPI
HighMemoryRoutine(
    VOID
    )
{
    CheckNewMemoryCondition(MemoryConditionHigh);
}

static
VOID
CheckNewMemoryCondition(
    _In_ MEMORY_CONDITION NewCondition
    )
{
    if (CurrentCondition != NewCondition)
    {
        DispatchNotification(NotifyMemory, CurrentCondition, 0, NewCondition, 0);
        CurrentCondition = NewCondition;
    }

    switch (NewCondition)
    {
    case MemoryConditionLow:
        AddRemoveMonitoredHandle(LowMemoryEventHandle, NULL);
        AddRemoveMonitoredHandle(HighMemoryEventHandle, HighMemoryRoutine);
        break;

    case MemoryConditionHigh:
        AddRemoveMonitoredHandle(LowMemoryEventHandle, LowMemoryRoutine);
        AddRemoveMonitoredHandle(HighMemoryEventHandle, NULL);
        break;

    default:
        AddRemoveMonitoredHandle(LowMemoryEventHandle, LowMemoryRoutine);
        AddRemoveMonitoredHandle(HighMemoryEventHandle, HighMemoryRoutine);
        break;
    }
}

static
VOID
NTAPI
TimerRoutine(
    VOID
    )
{
    NTSTATUS Status;
    EVENT_BASIC_INFORMATION BasicInfo;

    Status = NtQueryEvent(LowMemoryEventHandle,
                          EventBasicInformation,
                          &BasicInfo,
                          sizeof(BasicInfo),
                          NULL);
    if (NT_SUCCESS(Status) && BasicInfo.EventState == 1)
    {
        CheckNewMemoryCondition(MemoryConditionLow);
        return;
    }

    Status = NtQueryEvent(HighMemoryEventHandle,
                          EventBasicInformation,
                          &BasicInfo,
                          sizeof(BasicInfo),
                          NULL);
    if (NT_SUCCESS(Status) && BasicInfo.EventState == 1)
    {
        CheckNewMemoryCondition(MemoryConditionHigh);
        return;
    }

    CheckNewMemoryCondition(MemoryConditionNormal);
}

static
BOOLEAN
CreateObjects(
    VOID
    )
{
    NTSTATUS Status;
    UNICODE_STRING NameString;
    OBJECT_ATTRIBUTES ObjectAttributes;

    /*
     * N.B. We do not bother to cleanup in case of an error because
     * InitFinNotifyMemory will call DestroyObjects anyway.
     */

    InitializeObjectAttributes(&ObjectAttributes,
                               &NameString,
                               0,
                               NULL,
                               NULL);

    /* Low memory event */
    RtlInitUnicodeString(&NameString, L"\\KernelObjects\\LowMemoryCondition");
    Status = NtOpenEvent(&LowMemoryEventHandle,
                         EVENT_QUERY_STATE | SYNCHRONIZE,
                         &ObjectAttributes);
    if (!NT_SUCCESS(Status))
        return FALSE;

    AddRemoveMonitoredHandle(LowMemoryEventHandle, LowMemoryRoutine);

    /* High memory event */
    RtlInitUnicodeString(&NameString, L"\\KernelObjects\\HighMemoryCondition");
    Status = NtOpenEvent(&HighMemoryEventHandle,
                         EVENT_QUERY_STATE | SYNCHRONIZE,
                         &ObjectAttributes);
    if (!NT_SUCCESS(Status))
        return FALSE;

    AddRemoveMonitoredHandle(HighMemoryEventHandle, HighMemoryRoutine);

    /* Periodic timer */
    Status = NtCreateTimer(&TimerHandle,
                           TIMER_MODIFY_STATE | SYNCHRONIZE,
                           NULL,
                           SynchronizationTimer);
    if (!NT_SUCCESS(Status))
        return FALSE;

    Status = NtSetTimer(TimerHandle,
                        (PLARGE_INTEGER)&RtlTimeout10Sec,
                        NULL,
                        NULL,
                        TRUE,
                        10000,
                        NULL);
    if (!NT_SUCCESS(Status))
        return FALSE;

    AddRemoveMonitoredHandle(TimerHandle, TimerRoutine);
    return TRUE;
}

static
VOID
DestroyObjects(
    VOID
    )
{
    if (LowMemoryEventHandle)
    {
        AddRemoveMonitoredHandle(LowMemoryEventHandle, NULL);
        NtClose(LowMemoryEventHandle);
        LowMemoryEventHandle = NULL;
    }

    if (HighMemoryEventHandle)
    {
        AddRemoveMonitoredHandle(HighMemoryEventHandle, NULL);
        NtClose(HighMemoryEventHandle);
        HighMemoryEventHandle = NULL;
    }

    if (TimerHandle)
    {
        AddRemoveMonitoredHandle(TimerHandle, NULL);
        NtClose(TimerHandle);
        TimerHandle = NULL;
    }
}

BOOLEAN
InitFinNotifyMemory(
    _In_ BOOLEAN Init,
    _Inout_ PINIT_ENTRY InitEntry
    )
{
    if (Init)
    {
        if (!RtlInitCtrlInitialize(&InitEntry->InitCtrl, NULL, NULL))
            return TRUE;

        if (!InitFinMonitorThread(TRUE))
            goto Cleanup;

        if (CreateObjects())
        {
            RtlInitCtrlComplete(&InitEntry->InitCtrl, TRUE);
            return TRUE;
        }
    }
    else
    {
        if (!RtlInitCtrlUninitialize(&InitEntry->InitCtrl, NULL, NULL))
            return TRUE;
    }

    DestroyObjects();

    InitFinMonitorThread(FALSE);

Cleanup:
    RtlInitCtrlComplete(&InitEntry->InitCtrl, FALSE);
    return FALSE;
}
