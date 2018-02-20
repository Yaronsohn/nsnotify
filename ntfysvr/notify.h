/*++ BUILD Version: 0001    Increment this if a change has global effects

Copyright (c) COMPANY_NAME. 2005, All Rights Reserved.

Module Name:

    nsntfyi.h

Description:

    Internal include file for NS notification library.

Revision:

    Rev		Date		Programmer			Revision History
    1.0		5/4/2007	Yaron Aronsohn 		Original

--*/
#ifndef _NS_NOTIFY_INT_H_
#define _NS_NOTIFY_INT_H_

#include "..\nsnotify.h"
#include <ntrtl.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _NOTIFICATION_PACKET {
    NOTIFICATION_TYPE Type;
    union {

#define NPF_DENORMALIZED_PARAM1 0x00000001
#define NPF_DENORMALIZED_PARAM2 0x00000002

        ULONG Flags;
        struct {
            ULONG DenormalizeParam1 : 1;
            ULONG DenormalizeParam2 : 1;
            ULONG Reserved : 30;
        };
    };
    ULONG_PTR Param1;
    ULONG_PTR Param2;
} NOTIFICATION_PACKET, *PNOTIFICATION_PACKET;

#define NOTIFY_HANDSHAKE                0
#define NOTIFY_REGISTER                 1
#define NOTIFY_UNREGISTER               2
#define NOTIFY_MAX                      3

typedef struct {
    PORT_MESSAGE PortMessage;
    union {
        DWORD Type;
        LONG Status;
    } u1;
    union {
        struct {
            PKNORMAL_ROUTINE Routine;
            HANDLE ThreadHandle;
        } Handshake;

        struct {
            NOTIFICATION_TYPE Type;
        } Register;

        struct {
            NOTIFICATION_TYPE Type;
        } Unregister;
    } u2;
} NSNOTIFY_REQUEST, *PNSNOTIFY_REQUEST;

#ifdef _WIN64
#define SERVER_NAME     L"NSNOTIFY64"
#else
#define SERVER_NAME     L"NSNOTIFY32"
#endif

extern HANDLE hWaitManager;
extern HWND NotifyHwnd;
extern HINSTANCE hInst;

VOID
DispatchNotification(
    __in NOTIFICATION_TYPE Type,
    __in ULONG_PTR Param1,
    __in_opt SIZE_T Param1Length,
    __in ULONG_PTR Param2,
    __in_opt SIZE_T Param2Length
    );

BOOLEAN InitClient(BOOLEAN);

typedef struct _INIT_ENTRY {
    NOTIFICATION_TYPE Type;
    RTL_INIT_CTRL InitCtrl;
    BOOLEAN (*InitRoutine)(BOOLEAN, struct _INIT_ENTRY *);
} INIT_ENTRY, *PINIT_ENTRY;

#ifdef __cplusplus
}
#endif

#endif // _NS_NOTIFY_INT_H_
