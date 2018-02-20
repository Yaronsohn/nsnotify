/*++ BUILD Version: 0001    Increment this if a change has global effects

Copyright (c) COMPANY_NAME. 2005, All Rights Reserved.

Module Name:

    nsnotify.h

Description:

    New system notification library definitions.

Revision:

    Rev     Date        Programmer          Revision History
    1.0     6/3/2006    Yaron Aronsohn      Original

--*/

#ifndef _NS_NOTIFY_H_
#define _NS_NOTIFY_H_

#include <ntnative.h>

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(_NSNOTIFY_BUILD_)
#define NSNOTIFYAPI DECLSPEC_IMPORT
#else
#define NSNOTIFYAPI
#endif

typedef enum _NOTIFICATION_TYPE {
    NotifyNone = 0x00000000,
    NotifyThreadDied = 0x00000001,
    NotifyPolicy = 0x00000002,
    NotifyLocale = 0x00000004,
    NotifyEnvironment = 0x00000008,
    NotifyDevice = 0x00000010,
    NotifyPower = 0x00000020,
    NotifySession = 0x00000040,
    NotifyTime = 0x00000080,
    NotifyMemory = 0x00000100,
    NotifyAll = 0x00ffffff,
    NotifyWindow = 0x80000000       /* Reserved */
} NOTIFICATION_TYPE, *PNOTIFICATION_TYPE;

typedef
VOID
(NTAPI *PNOTIFICATION_ROUTINE)(
    __in PVOID Param,
    __in NOTIFICATION_TYPE Type,
    __in ULONG_PTR Info1,
    __in ULONG_PTR Info2
    );

NSNOTIFYAPI
PVOID
NTAPI
RegisterNotificationRoutine(
    __in PNOTIFICATION_ROUTINE Routine,
    __in NOTIFICATION_TYPE Type,
    __in PVOID Param
    );

NSNOTIFYAPI
VOID
NTAPI
UnregisterNotificationRoutine(
    __inout PVOID Routine
    );

NSNOTIFYAPI
BOOL
NTAPI
RegisterThreadForNotification(VOID);

typedef enum _MEMORY_CONDITION {
    MemoryConditionUnknown = -1,
    MemoryConditionLow = 0,
    MemoryConditionNormal = 1,
    MemoryConditionHigh = 2
} MEMORY_CONDITION, *PMEMORY_CONDITION;

#ifdef __cplusplus
}
#endif

#endif // _NS_NOTIFY_H_

