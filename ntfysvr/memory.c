/* %%COPYRIGHT%% */

#if !defined(_WIN32)
#error ERROR! Platform not supported!
#endif

/* INCLUDES *******************************************************************/

#include <windows.h>
#include "notify.h"
#include <waitmgr.h>

/* GLOBALS ********************************************************************/

static MEMORY_CONDITION CurrentCondition = MemoryConditionUnknown;

/* FUNCTIONS ******************************************************************/

VOID CALLBACK LowHighMemoryConditionProc(PVOID, ULONG);
VOID CALLBACK TimerMemoryConditionProc(PVOID, ULONG);

typedef enum {
    mchLow = 0,
    mchHigh,
    mchTimer,
    mchMax
} MEMORY_CONDITION_HANDLE;

static struct {
    WAITMGRID HandleId;
    PWAIT_MANAGER_ROUTINE Routine;
    HANDLE Handle;
    PVOID Param;
} Handles[mchMax] =
{
    { 0, LowHighMemoryConditionProc, 0, (PVOID) MemoryConditionLow },
    { 0, LowHighMemoryConditionProc, 0, (PVOID) MemoryConditionHigh },
    { 0, TimerMemoryConditionProc, 0, NULL }
};

static
BOOLEAN
SetMemoryConditionHandle(
    _In_ MEMORY_CONDITION_HANDLE mch,
    _In_ BOOLEAN Set
    )
{
    if (Set)
    {
        if (!Handles[mch].HandleId)
        {
            Handles[mch].HandleId = WmAddHandle(hWaitManager,
                                                Handles[mch].Handle,
                                                Handles[mch].Routine,
                                                Handles[mch].Param);
            if (!Handles[mch].HandleId)
                return FALSE;
        }
    }
    else
    {
        if (Handles[mch].HandleId)
        {
            WmRemoveHandle(hWaitManager, Handles[mch].HandleId);
            Handles[mch].HandleId = 0;
        }
    }

    return TRUE;
}

static
VOID
CheckNewCondition(
    _In_ MEMORY_CONDITION NewCondition
    )
{
    LOCK_OWNER owner;

    /* Make sure the condition has changed */
    if (CurrentCondition == NewCondition)
        return;

    /* Dispatch the new condition */
    DispatchNotification(NotifyMemory, CurrentCondition, 0, NewCondition, 0);

    /* Save the new condition */
    CurrentCondition = NewCondition;

    /* remove the low handle from the list */
    WmAcquireLock(hWaitManager, &owner);
    SetMemoryConditionHandle(mchLow, NewCondition != MemoryConditionLow);
    SetMemoryConditionHandle(mchHigh, NewCondition != MemoryConditionHigh);
    WmReleaseLock(hWaitManager, &owner);
}

static
VOID
CALLBACK
LowHighMemoryConditionProc(
    _In_ PVOID Param,
    _In_ ULONG Flags
    )
{
    CheckNewCondition((MEMORY_CONDITION) Param);
}

static
VOID
CALLBACK
TimerMemoryConditionProc(
    _In_ PVOID Param,
    _In_ ULONG Flags
    )
{
    MEMORY_CONDITION NewCondition;
    BOOL ConditionExists = FALSE;

    /* check if the current memory state is high */
    QueryMemoryResourceNotification(Handles[mchHigh].Handle, &ConditionExists);

    if (ConditionExists)
    {
        NewCondition = MemoryConditionHigh;
    }
    else
    {
        /* OK, the memory state is not high - check if it's low... */
        QueryMemoryResourceNotification(Handles[mchLow].Handle, &ConditionExists);

        if (ConditionExists)
        {
            NewCondition = MemoryConditionLow;
        }
        else
        {
            /* if the current state is not high and not low then it's normal */
            NewCondition = MemoryConditionNormal;
        }
    }

    CheckNewCondition(NewCondition);
}

BOOLEAN
InitFinNotifyMemory(
    _In_ BOOLEAN Init,
    _Inout_ PINIT_ENTRY InitEntry
    )
{
    BOOL success = FALSE;
    MEMORY_CONDITION_HANDLE mch;
    LOCK_OWNER owner;
    BOOLEAN locked = FALSE;

    if (Init)
    {
        LARGE_INTEGER DueTime;

        if (!RtlInitCtrlInitialize(&InitEntry->InitCtrl, NULL, NULL))
            return TRUE;

        /* Create the low memory condition event */
        Handles[mchLow].Handle = CreateMemoryResourceNotification(LowMemoryResourceNotification);
        if (!Handles[mchLow].Handle)
            goto cleanup0;

        /* Create the high memory condition event */
        Handles[mchHigh].Handle = CreateMemoryResourceNotification(HighMemoryResourceNotification);
        if (!Handles[mchHigh].Handle)
            goto cleanup1;

        /* Create the timer */
        Handles[mchTimer].Handle = CreateWaitableTimerW(NULL, FALSE, NULL);
        if (!Handles[mchTimer].Handle)
            goto cleanup1;

        /* Start the timer */
        DueTime.QuadPart = -100000000;
        success = SetWaitableTimer(Handles[mchTimer].Handle,
                                   &DueTime,
                                   1,
                                   NULL,
                                   NULL,
                                   TRUE);
        if (!success)
            goto cleanup1;

        /* Add the handles */
        WmAcquireLock(hWaitManager, &owner);
        locked = TRUE;
        for (mch = mchLow; mch < mchMax; mch++)
        {
            if (!SetMemoryConditionHandle(mch, TRUE))
                goto cleanup1;
        }

        WmReleaseLock(hWaitManager, &owner);

        RtlInitCtrlComplete(&InitEntry->InitCtrl, TRUE);
        return TRUE;
    }
    else
    {
        if (!RtlInitCtrlUninitialize(&InitEntry->InitCtrl, NULL, NULL))
            return TRUE;

        CancelWaitableTimer(Handles[mchTimer].Handle);
    }

cleanup1:
    if (!locked)
    {
        WmAcquireLock(hWaitManager, &owner);
    }

    for (mch = mchLow; mch < mchMax; mch++)
    {
        if (Handles[mch].HandleId)
        {
            SetMemoryConditionHandle(mch, FALSE);
        }

        if (Handles[mch].Handle)
        {
            NtClose(Handles[mch].Handle);
            Handles[mch].Handle = 0;
        }
    }

    WmReleaseLock(hWaitManager, &owner);

cleanup0:
    RtlInitCtrlComplete(&InitEntry->InitCtrl, success);
    return success;
}
