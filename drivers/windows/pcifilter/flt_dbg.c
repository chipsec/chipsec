/***
CHIPSEC: Platform Security Assessment Framework
Copyright (c) 2023, Intel Corporation

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; Version 2.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

Contact information:
chipsec@intel.com
*/


#ifdef __cplusplus
extern "C"
{
#endif
#include <wdm.h>
#ifdef __cplusplus
}
#endif

#include "flt_dbg.h"
#include <stdarg.h>	// OK to use this for va_* macros

typedef
PVOID
(*PFN_ExAllocatePool2)(
    ULONG64 Flags,
    SIZE_T     NumberOfBytes,
    ULONG      Tag
    );

typedef
PVOID
(*PFN_ExAllocatePoolWithTag)(
    ULONG64 Flags,
    SIZE_T     NumberOfBytes,
    ULONG      Tag
    );

UNICODE_STRING functionName = { 0 };
PFN_ExAllocatePool2 pfnExAllocatePool2 = NULL;
PFN_ExAllocatePoolWithTag pfnExAllocatePoolWithTag = NULL;


#if DODEBUGPRINT

//////////////////////////////////////////////////////////////////////////////
//	Definitions copied from Wdm.h to make this compile in NT4
//	Cross-fingers - lets hope these definitions do not change

#define Dbp_IRP_MJ_POWER                    0x16
#define Dbp_IRP_MJ_SYSTEM_CONTROL           0x17
#define Dbp_IRP_MJ_PNP                      0x1b

#define Dbp_IRP_MN_QUERY_DEVICE_RELATIONS       0x07

#define Dbp_IRP_MN_SET_POWER                    0x02
#define Dbp_IRP_MN_QUERY_POWER                  0x03

typedef enum Dbp__DEVICE_RELATION_TYPE {
    Dbp_BusRelations,
    Dbp_EjectionRelations,
    Dbp_PowerRelations,
    Dbp_RemovalRelations,
    Dbp_TargetDeviceRelation
} Dbp_DEVICE_RELATION_TYPE, * Dbp_PDEVICE_RELATION_TYPE;

typedef struct _Dbp_QueryDeviceRelations
{
    Dbp_DEVICE_RELATION_TYPE Type;
} Dbp_QueryDeviceRelations, * Dbp_PQueryDeviceRelations;

typedef enum _Dbp_SYSTEM_POWER_STATE {
    Dbp_PowerSystemUnspecified = 0,
    Dbp_PowerSystemWorking,
    Dbp_PowerSystemSleeping1,
    Dbp_PowerSystemSleeping2,
    Dbp_PowerSystemSleeping3,
    Dbp_PowerSystemHibernate,
    Dbp_PowerSystemShutdown,
    Dbp_PowerSystemMaximum
} Dbp_SYSTEM_POWER_STATE, * Dbp_PSYSTEM_POWER_STATE;

typedef enum {
    Dbp_PowerActionNone,
    Dbp_PowerActionReserved,
    Dbp_PowerActionSleep,
    Dbp_PowerActionHibernate,
    Dbp_PowerActionShutdown,
    Dbp_PowerActionShutdownReset,
    Dbp_PowerActionShutdownOff
} Dbp_POWER_ACTION, * Dbp_PPOWER_ACTION;

typedef enum _Dbp_DEVICE_POWER_STATE {
    Dbp_PowerDeviceUnspecified = 0,
    Dbp_PowerDeviceD0,
    Dbp_PowerDeviceD1,
    Dbp_PowerDeviceD2,
    Dbp_PowerDeviceD3,
    Dbp_PowerDeviceMaximum
} Dbp_DEVICE_POWER_STATE, * Dbp_PDEVICE_POWER_STATE;

typedef enum _Dbp_POWER_STATE_TYPE {
    Dbp_SystemPowerState,
    Dbp_DevicePowerState
} Dbp_POWER_STATE_TYPE, * Dbp_PPOWER_STATE_TYPE;

typedef union _Dbp_POWER_STATE {
    Dbp_SYSTEM_POWER_STATE SystemState;
    Dbp_DEVICE_POWER_STATE DeviceState;
} Dbp_POWER_STATE, * Dbp_PPOWER_STATE;

typedef struct _Dbp_Power {
    ULONG SystemContext;
    Dbp_POWER_STATE_TYPE Type;
    Dbp_POWER_STATE State;
    Dbp_POWER_ACTION ShutdownType;
} Dbp_Power, * Dbp_PPower;

//	DebugPrint globals
static BOOLEAN DebugPrintStarted = FALSE;
static char* DriverName = NULL;
static USHORT DriverNameLen = 0;

//	DebugPrint Event structure (put in doubly-linked EventList)
typedef struct _DEBUGPRINT_EVENT
{
    LIST_ENTRY ListEntry;
    ULONG Len;
    UCHAR EventData[1];
} DEBUGPRINT_EVENT, * PDEBUGPRINT_EVENT;

//	Globals to communicate with our system thread
PVOID ThreadObjectPointer = NULL;	// Thread pointer
BOOLEAN ExitNow;				// Set to cause thread to exit
KEVENT ThreadEvent;				// Set to make thread look at ExitNow.
LIST_ENTRY EventList;			// Doubly-linked list of written Events
KSPIN_LOCK EventListLock;		// Spin lock to guard access to EventList
KEVENT ThreadExiting;			// Set when thread exiting

void DebugPrintSystemThread(IN PVOID Context);
NTSTATUS OpenDebugPrintDriver(HANDLE* pDebugPrintDeviceHandle);


//	DebugPrint local functions
HANDLE OpenDebugPrint();
void CloseDebugPrint(HANDLE h);
void DebugSprintf(char* buffer, int max, const char* format, va_list marker);
USHORT ANSIstrlen(char* str);
void ClearEvents();

//	DebugPrintInit:		Initialise DebugPrint
//						Connect to DebugPrint driver at \Device\PHDDebugPrint
//
//	IRQL PASSIVE_LEVEL
void DebugPrintInit(char* _DriverName)
{
    HANDLE threadHandle;
    NTSTATUS status;

    RtlInitUnicodeString(&functionName, L"ExAllocatePool2");
    pfnExAllocatePool2 = (PFN_ExAllocatePool2)MmGetSystemRoutineAddress(&functionName);
    RtlInitUnicodeString(&functionName, L"ExAllocatePoolWithTag");
    pfnExAllocatePoolWithTag = (PFN_ExAllocatePoolWithTag)MmGetSystemRoutineAddress(&functionName);
    if (pfnExAllocatePool2 == NULL && pfnExAllocatePoolWithTag == NULL) {
        DbgPrint("[chipsec] ERROR: couldn't find the correct kernel api\n");
        status = STATUS_NOT_IMPLEMENTED;
        return;
    }

    // Copy the driver's name out of INIT code segment
    DriverNameLen = 1 + ANSIstrlen(_DriverName);
    if (pfnExAllocatePool2 != NULL) {
        DriverName = pfnExAllocatePool2(POOL_FLAG_NON_PAGED, DriverNameLen, 0x3184);
    }
    else if (pfnExAllocatePoolWithTag != NULL) {
        // Fall back to call the old api
        DriverName = pfnExAllocatePoolWithTag(POOL_FLAG_NON_PAGED, DriverNameLen, 0x3184);
    }

    if (DriverName == NULL) return;
    RtlCopyMemory(DriverName, _DriverName, DriverNameLen);


    // Prepare for thread start
    ExitNow = FALSE;
    KeInitializeEvent(&ThreadEvent, SynchronizationEvent, FALSE);
    KeInitializeEvent(&ThreadExiting, SynchronizationEvent, FALSE);
    // Initialise event list
    KeInitializeSpinLock(&EventListLock);
    InitializeListHead(&EventList);

    // Start system thread to write events to DebugPrint driver
    status = PsCreateSystemThread(&threadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL,
        DebugPrintSystemThread, NULL);
    if (!NT_SUCCESS(status))
        return;


    // Save a pointer to thread and close handle.
    status = ObReferenceObjectByHandle(threadHandle, THREAD_ALL_ACCESS, NULL, KernelMode,
        &ThreadObjectPointer, NULL);

    if (NT_SUCCESS(status))
        ZwClose(threadHandle);
    else
    {
        // Uh oh... force thread to exit
        ExitNow = TRUE;
        KeSetEvent(&ThreadEvent, 0, FALSE);
        return;
    }

    DebugPrintStarted = TRUE;

    // Send event that we've started logging
    DebugPrintMsg("DebugPrint logging started");
}


//	DebugPrintClose:	Close connection to DebugPrint
//
//	IRQL PASSIVE_LEVEL
void DebugPrintClose()
{
    if (!DebugPrintStarted) return;

    DebugPrintMsg("DebugPrint logging ended");
    DebugPrintStarted = FALSE;

    // Tell thread to stop, and wait for it to stop
    ExitNow = TRUE;
    KeSetEvent(&ThreadEvent, 0, FALSE);
    KeWaitForSingleObject(&ThreadExiting, Executive, KernelMode, FALSE, NULL);

    // Dereference thread object
    if (ThreadObjectPointer != NULL)
    {
        ObDereferenceObject(&ThreadObjectPointer);
        ThreadObjectPointer = NULL;
    }

    // Release our copy of DriverName
    if (DriverName != NULL)
        ExFreePool(DriverName);
    //	ClearEvents();
}


//	DebugPrintMsg:	Send message event to DebugPrint
//
//	IRQL <= DISPATCH_LEVEL
void DebugPrintMsg(char* Msg)
{
    LARGE_INTEGER Now;
    TIME_FIELDS NowTF;
    USHORT MsgLen;
    ULONG EventDataLen, len;
    PDEBUGPRINT_EVENT pEvent = NULL;

    if (!DebugPrintStarted || DriverName == NULL) return;

    // Get current time
    KeQuerySystemTime(&Now);
    //	LARGE_INTEGER NowLocal;
    //	ExSystemTimeToLocalTime( &Now, &NowLocal);	// NT only
    //	RtlTimeToTimeFields( &NowLocal, &NowTF);
    RtlTimeToTimeFields(&Now, &NowTF);

    // Get size of Msg and complete event
    MsgLen = ANSIstrlen(Msg) + 1;
    EventDataLen = sizeof(TIME_FIELDS) + DriverNameLen + MsgLen;
    len = sizeof(LIST_ENTRY) + sizeof(ULONG) + EventDataLen;

    // Allocate event buffer
    if (pfnExAllocatePool2 != NULL) {
        pEvent = (PDEBUGPRINT_EVENT)pfnExAllocatePool2(POOL_FLAG_NON_PAGED, len, 0x3184);
    }
    else if (pfnExAllocatePoolWithTag != NULL) {
        // Fall back to call the old api
        pEvent = (PDEBUGPRINT_EVENT)pfnExAllocatePoolWithTag(POOL_FLAG_NON_PAGED, len, 0x3184);
    }

    if (pEvent != NULL)
    {
        PUCHAR buffer = (PUCHAR)pEvent->EventData;
        // Copy event info to buffer
        RtlCopyMemory(buffer, &NowTF, sizeof(TIME_FIELDS));
        buffer += sizeof(TIME_FIELDS);
        RtlCopyMemory(buffer, DriverName, DriverNameLen);
        buffer += DriverNameLen;
        RtlCopyMemory(buffer, Msg, MsgLen);

        // Insert event into event list for processing by system thread
        pEvent->Len = EventDataLen;
        ExInterlockedInsertTailList(&EventList, &pEvent->ListEntry, &EventListLock);
    }
}


//*	DebugPrintVA:	Implement DebugPrint calls
void DebugPrintVA(int max, const char* format, va_list marker)
{
    char* Msg;
    Msg = NULL;
    if (!DebugPrintStarted) return;
    if (pfnExAllocatePool2 != NULL) {
        Msg = (char*)pfnExAllocatePool2(POOL_FLAG_NON_PAGED, max, 0x3184);
    }
    else if (pfnExAllocatePoolWithTag != NULL) {
        // Fall back to call the old api
        Msg = (char*)pfnExAllocatePoolWithTag(POOL_FLAG_NON_PAGED, max, 0x3184);
    }
    if (Msg == NULL)
    {
        DebugPrintMsg("DebugPrint: Could not allocate buffer");
        return;
    }
    DebugSprintf(Msg, max, format, marker);
    DebugPrintMsg(Msg);
    ExFreePool(Msg);
}
#endif // DODEBUGPRINT


//	DebugPrint:	Formatted print to DebugPrint, allocating own print buffer
//
//	IRQL <= DISPATCH_LEVEL
void DebugPrint(const char* format, ...)
{
#if DODEBUGPRINT
    va_list marker;
    if (!DebugPrintStarted) return;
    va_start(marker, format);
    DebugPrintVA(100, format, marker);
#endif // DODEBUGPRINT
}


//	DebugPrint:	Formatted print to DebugPrint, giving size of buffer to allocate
//
//	IRQL <= DISPATCH_LEVEL
void DebugPrint2(int max, const char* format, ...)
{
#if DODEBUGPRINT
    va_list marker;
    if (!DebugPrintStarted) return;
    va_start(marker, format);
    DebugPrintVA(max, format, marker);
#endif // DODEBUGPRINT
}

#if DODEBUGPRINT

//	IRP Major and Minor function names
static char* IrpMajorFunctionNames[] =
{
    "IRP_MJ_CREATE",
    "IRP_MJ_CREATE_NAMED_PIPE",
    "IRP_MJ_CLOSE",
    "IRP_MJ_READ",
    "IRP_MJ_WRITE",
    "IRP_MJ_QUERY_INFORMATION",
    "IRP_MJ_SET_INFORMATION",
    "IRP_MJ_QUERY_EA",
    "IRP_MJ_SET_EA",
    "IRP_MJ_FLUSH_BUFFERS",
    "IRP_MJ_QUERY_VOLUME_INFORMATION",
    "IRP_MJ_SET_VOLUME_INFORMATION",
    "IRP_MJ_DIRECTORY_CONTROL",
    "IRP_MJ_FILE_SYSTEM_CONTROL",
    "IRP_MJ_DEVICE_CONTROL",
    "IRP_MJ_INTERNAL_DEVICE_CONTROL",
    "IRP_MJ_SHUTDOWN",
    "IRP_MJ_LOCK_CONTROL",
    "IRP_MJ_CLEANUP",
    "IRP_MJ_CREATE_MAILSLOT",
    "IRP_MJ_QUERY_SECURITY",
    "IRP_MJ_SET_SECURITY",
    "IRP_MJ_POWER",
    "IRP_MJ_SYSTEM_CONTROL",
    "IRP_MJ_DEVICE_CHANGE",
    "IRP_MJ_QUERY_QUOTA",
    "IRP_MJ_SET_QUOTA",
    "IRP_MJ_PNP",
};
static ULONG NUM_IrpMajorFunctionNames = sizeof(IrpMajorFunctionNames) / sizeof(char*);

static char* PnPIrpMinorFunctionNames[] =
{
    "IRP_MN_START_DEVICE",
    "IRP_MN_QUERY_REMOVE_DEVICE",
    "IRP_MN_REMOVE_DEVICE",
    "IRP_MN_CANCEL_REMOVE_DEVICE",
    "IRP_MN_STOP_DEVICE",
    "IRP_MN_QUERY_STOP_DEVICE",
    "IRP_MN_CANCEL_STOP_DEVICE",
    "IRP_MN_QUERY_DEVICE_RELATIONS",
    "IRP_MN_QUERY_INTERFACE",
    "IRP_MN_QUERY_CAPABILITIES",
    "IRP_MN_QUERY_RESOURCES",
    "IRP_MN_QUERY_RESOURCE_REQUIREMENTS",
    "IRP_MN_QUERY_DEVICE_TEXT",
    "IRP_MN_FILTER_RESOURCE_REQUIREMENTS",
    "Nowt",
    "IRP_MN_READ_CONFIG",
    "IRP_MN_WRITE_CONFIG",
    "IRP_MN_EJECT",
    "IRP_MN_SET_LOCK",
    "IRP_MN_QUERY_ID",
    "IRP_MN_QUERY_PNP_DEVICE_STATE",
    "IRP_MN_QUERY_BUS_INFORMATION",
    "IRP_MN_DEVICE_USAGE_NOTIFICATION",
    "IRP_MN_SURPRISE_REMOVAL",
    "IRP_MN_QUERY_LEGACY_BUS_INFORMATION",
};
static ULONG NUM_PnPIrpMinorFunctionNames = sizeof(PnPIrpMinorFunctionNames) / sizeof(char*);

static char* PowerIrpMinorFunctionNames[] =
{
    "IRP_MN_WAIT_WAKE",
    "IRP_MN_POWER_SEQUENCE",
    "IRP_MN_SET_POWER",
    "IRP_MN_QUERY_POWER",
};
static ULONG NUM_PowerIrpMinorFunctionNames = sizeof(PowerIrpMinorFunctionNames) / sizeof(char*);

static char* WMIIrpMinorFunctionNames[] =
{
    "IRP_MN_QUERY_ALL_DATA",
    "IRP_MN_QUERY_SINGLE_INSTANCE",
    "IRP_MN_CHANGE_SINGLE_INSTANCE",
    "IRP_MN_CHANGE_SINGLE_ITEM",
    "IRP_MN_ENABLE_EVENTS",
    "IRP_MN_DISABLE_EVENTS",
    "IRP_MN_ENABLE_COLLECTION",
    "IRP_MN_DISABLE_COLLECTION",
    "IRP_MN_REGINFO",
    "IRP_MN_EXECUTE_METHOD",
};
static ULONG NUM_WMIIrpMinorFunctionNames = sizeof(WMIIrpMinorFunctionNames) / sizeof(char*);

static char* PowerSystemStates[] =
{
    "PowerSystemUnspecified",
    "PowerSystemWorking",
    "PowerSystemSleeping1",
    "PowerSystemSleeping2",
    "PowerSystemSleeping3",
    "PowerSystemHibernate",
    "PowerSystemShutdown",
};
static int NUM_PowerSystemStates = sizeof(PowerSystemStates) / sizeof(char*);

static char* PowerDeviceStates[] =
{
    "PowerDeviceUnspecified",
    "PowerDeviceD0",
    "PowerDeviceD1",
    "PowerDeviceD2",
    "PowerDeviceD3",
};
static int NUM_PowerDeviceStates = sizeof(PowerDeviceStates) / sizeof(char*);

//*	All these PrintXxx routines return TRUE if the buffer is filled
//*	Safe way to put a character in a buffer
#define PHDput(ch) if( (*pbufpos)>=max) return TRUE; else buffer[(*pbufpos)++] = (ch)

//	Digits for decimal and hex conversions
static char hexdigits[] = "0123456789ABCDEF";

BOOLEAN PrintChar(char* buffer, int max, int* pbufpos, char ch)
{
    PHDput(ch);
    return FALSE;
}

BOOLEAN PrintULONG(char* buffer, int max, int* pbufpos, ULONG v)
{
    int digits;
    ULONG v2;
    int digno;

    if (v == 0)
    {
        PHDput('0');
        return FALSE;
    }
    // Get number of digits
    digits = 0;
    v2 = v;
    while (v2 != 0)
    {
        v2 /= 10;
        digits++;
    }
    // Write out
    (*pbufpos) += digits;
    for (digno = 1; digno <= digits; digno++)
    {
        char ch = hexdigits[v % 10];
        if ((*pbufpos) - digno < max) buffer[(*pbufpos) - digno] = ch;
        v /= 10;
    }
    return FALSE;
}

BOOLEAN PrintInt(char* buffer, int max, int* pbufpos, int v)
{
    if (v < 0)
    {
        PHDput('-');
        v = -v;
    }
    return PrintULONG(buffer, max, pbufpos, v);
}

BOOLEAN PrintULONG64(char* buffer, int max, int* pbufpos, unsigned __int64 v)
{
    int digits;
    unsigned __int64 v2;
    int digno;

    if (v == 0)
    {
        PHDput('0');
        return FALSE;
    }
    // Get number of digits
    digits = 0;
    v2 = v;
    while (v2 != 0)
    {
        v2 /= 10;
        digits++;
    }
    // Write out
    (*pbufpos) += digits;
    for (digno = 1; digno <= digits; digno++)
    {
        char ch = hexdigits[v % 10];
        if ((*pbufpos) - digno < max) buffer[(*pbufpos) - digno] = ch;
        v /= 10;
    }
    return FALSE;
}

BOOLEAN PrintInt64(char* buffer, int max, int* pbufpos, __int64 v)
{
    if (v < 0)
    {
        PHDput('-');
        v = -v;
    }
    return PrintULONG64(buffer, max, pbufpos, v);
}

BOOLEAN PrintULONGhex(char* buffer, int max, int* pbufpos, ULONG v, int FormatSize)
{
    ULONG mask = 0xF0000000;
    int shift = 28;
    int digno;
    if (FormatSize > 0 && FormatSize < 8)
    {
        mask >>= 4 * (8 - FormatSize);
        shift -= 4 * (8 - FormatSize);
    }
    else
        FormatSize = 8;
    for (digno = 0; digno < FormatSize; digno++)
    {
        int digit = (v & mask) >> shift;
        PHDput(hexdigits[digit]);
        mask >>= 4;
        shift -= 4;
    }
    return FALSE;
}

BOOLEAN PrintANSIString(char* buffer, int max, int* pbufpos, char* s, int FormatSize)
{
    char ch;
    BOOLEAN sized = (FormatSize > 0);
    while (ch = *s++)
    {
        PHDput(ch);
        if (sized && (--FormatSize == 0))
            break;
    }
    return FALSE;
}

BOOLEAN PrintWideString(char* buffer, int max, int* pbufpos, wchar_t* ws, int FormatSize)
{
    wchar_t ch;
    BOOLEAN sized = (FormatSize > 0);
    while (ch = *ws++)
    {
        PHDput((char)ch);
        if (sized && (--FormatSize == 0))
            break;
    }
    return FALSE;
}

BOOLEAN PrintUnicodeString(char* buffer, int max, int* pbufpos, PUNICODE_STRING pus)
{
    int uslen = (pus->Length) >> 1;
    wchar_t* ws = pus->Buffer;
    int chno;
    for (chno = 0; chno < uslen; chno++)
    {
        wchar_t ch = *ws++;
        if (ch == L'\0') break;
        PHDput((char)ch);
    }

    return FALSE;
}

BOOLEAN PrintIrp(char* buffer, int max, int* pbufpos, PIRP Irp)
{
    PIO_STACK_LOCATION IrpStack = IoGetCurrentIrpStackLocation(Irp);
    ULONG MajorFunction = IrpStack->MajorFunction;
    ULONG MinorFunction = IrpStack->MinorFunction;
    if (MajorFunction < NUM_IrpMajorFunctionNames)
    {
        char* MajorFunctionName = IrpMajorFunctionNames[MajorFunction];
        char* MinorFunctionName = NULL;
        char* ExtraDetails1 = NULL;
        char* ExtraDetails2 = NULL;

        if (PrintANSIString(buffer, max, pbufpos, MajorFunctionName, 0)) return TRUE;

        switch (MajorFunction)
        {
        case Dbp_IRP_MJ_PNP:
            if (MinorFunction < NUM_PnPIrpMinorFunctionNames)
                MinorFunctionName = PnPIrpMinorFunctionNames[MinorFunction];
            else
            {
                PHDput(':');
                if (PrintULONGhex(buffer, max, pbufpos, MinorFunction, 8)) return TRUE;
            }
            if (MinorFunction == Dbp_IRP_MN_QUERY_DEVICE_RELATIONS)
            {
                Dbp_PQueryDeviceRelations pQueryDeviceRelations = (Dbp_PQueryDeviceRelations)&IrpStack->Parameters.Read.Length;
                switch (pQueryDeviceRelations->Type)
                {
                case Dbp_BusRelations:			ExtraDetails1 = "BusRelations"; break;
                case Dbp_EjectionRelations:		ExtraDetails1 = "EjectionRelations"; break;
                case Dbp_PowerRelations:		ExtraDetails1 = "PowerRelations"; break;
                case Dbp_RemovalRelations:		ExtraDetails1 = "RemovalRelations"; break;
                case Dbp_TargetDeviceRelation:	ExtraDetails1 = "TargetDeviceRelation"; break;
                }
            }
            break;
        case Dbp_IRP_MJ_POWER:
            if (MinorFunction < NUM_PowerIrpMinorFunctionNames)
                MinorFunctionName = PowerIrpMinorFunctionNames[MinorFunction];
            if (MinorFunction == Dbp_IRP_MN_SET_POWER || MinorFunction == Dbp_IRP_MN_QUERY_POWER)
            {
                Dbp_PPower pPower = (Dbp_PPower)&IrpStack->Parameters.Read.Length;
                Dbp_POWER_STATE PowerState = pPower->State;
                ExtraDetails1 = (MinorFunction == Dbp_IRP_MN_SET_POWER ? "Set Power" : "Query Power");
                if (pPower->Type == Dbp_SystemPowerState)
                {
                    if (PowerState.SystemState < NUM_PowerSystemStates)
                        ExtraDetails2 = PowerSystemStates[PowerState.SystemState];
                }
                else
                {
                    if (PowerState.DeviceState < NUM_PowerDeviceStates)
                        ExtraDetails2 = PowerDeviceStates[PowerState.DeviceState];
                }
            }
            break;
        case Dbp_IRP_MJ_SYSTEM_CONTROL:
            if (MinorFunction < NUM_WMIIrpMinorFunctionNames)
                MinorFunctionName = WMIIrpMinorFunctionNames[MinorFunction];
            break;
        }
        if (MinorFunctionName != NULL)
        {
            PHDput(':');
            if (PrintANSIString(buffer, max, pbufpos, MinorFunctionName, 0)) return TRUE;
        }
        if (ExtraDetails1 != NULL)
        {
            PHDput(' ');
            if (PrintANSIString(buffer, max, pbufpos, ExtraDetails1, 0)) return TRUE;
        }
        if (ExtraDetails2 != NULL)
        {
            PHDput(' ');
            if (PrintANSIString(buffer, max, pbufpos, ExtraDetails2, 0)) return TRUE;
        }
    }
    return FALSE;
}

//*	PHDsprintf:	Write formatted data to a string
//				PrintXxx routines used to do prints for each type
//				Give up as soon as end of buffer reached
#define PHD_va_arg(ap,t,v)	t v = va_arg(ap,t)

void DebugSprintf(char* buffer, int max, const char* format, va_list marker)
{
    int bufpos = 0;
    char ch;
    // Go through each format character
    while (ch = *format++)
    {
        int FormatSize = 0;
        if (ch != '%')
        {
            if (PrintChar(buffer, max, &bufpos, ch)) goto done;
            continue;
        }
        if ((ch = *format++) == '\0')
            break;
        if (ch == '*')
        {
            PHD_va_arg(marker, int, size);
            if (size > 0)
                FormatSize = size;
            if ((ch = *format++) == '\0')
                break;
        }
        else if (ch >= '1' && ch <= '9')
        {
            FormatSize = 0;
            do
            {
                FormatSize = (FormatSize * 10) + ch - '0';
                if ((ch = *format++) == '\0')
                    break;
            } while (ch >= '1' && ch <= '9');
        }
        // Switch on specification character
        switch (ch)
        {
            //	ANSI char
        case 'c':
        {
            PHD_va_arg(marker, char, ch);
            if (PrintChar(buffer, max, &bufpos, ch)) goto done;
            break;
        }
        //	Wide char
        case 'C':
        {
            PHD_va_arg(marker, wchar_t, ch);
            if (PrintChar(buffer, max, &bufpos, (char)ch)) goto done;
            break;
        }
        //	Integer
        case 'd':
        case 'i':
        {
            PHD_va_arg(marker, int, i);
            if (PrintInt(buffer, max, &bufpos, i)) goto done;
            break;
        }
        //	__int64 in hex
        case 'D':
        {
            PHD_va_arg(marker, __int64, i64);
            if (PrintInt64(buffer, max, &bufpos, i64)) goto done;
            break;
        }
        //	__int64 in hex
        case 'l':
        {
            PHD_va_arg(marker, __int64, i64);
            LARGE_INTEGER li;
            li.QuadPart = i64;
            if (FormatSize == 0) FormatSize = 16;
            if (FormatSize > 8)
            {
                if (PrintULONGhex(buffer, max, &bufpos, li.HighPart, FormatSize - 8)) goto done;
            }
            if (PrintULONGhex(buffer, max, &bufpos, li.LowPart, FormatSize)) goto done;
            break;
        }
        //	LARGE_INTEGER in hex
        case 'L':
        {
            PHD_va_arg(marker, LARGE_INTEGER, li);
            if (FormatSize == 0) FormatSize = 16;
            if (FormatSize > 8)
            {
                if (PrintULONGhex(buffer, max, &bufpos, li.HighPart, FormatSize - 8)) goto done;
            }
            if (PrintULONGhex(buffer, max, &bufpos, li.LowPart, FormatSize)) goto done;
            break;
        }
        //	ULONG
        case 'u':
        {
            PHD_va_arg(marker, ULONG, uv);
            if (PrintULONG(buffer, max, &bufpos, uv)) goto done;
            break;
        }
        // ULONG as hex
        case 'x':
        {
            PHD_va_arg(marker, ULONG, uv);
            if (PrintULONGhex(buffer, max, &bufpos, uv, FormatSize)) goto done;
            break;
        }
        //	ANSI string
        case 's':
        {
            PHD_va_arg(marker, char*, s);
            if (PrintANSIString(buffer, max, &bufpos, s, FormatSize)) goto done;
            break;
        }
        //	Wide string
        case 'S':
        {
            PHD_va_arg(marker, wchar_t*, ws);
            if (PrintWideString(buffer, max, &bufpos, ws, FormatSize)) goto done;
            break;
        }
        //	PUNICODE_STRING
        case 'T':
        {
            PHD_va_arg(marker, PUNICODE_STRING, pus);
            if (PrintUnicodeString(buffer, max, &bufpos, pus)) goto done;
            break;
        }
        //	PIRP
        case 'I':
        {
            PHD_va_arg(marker, PIRP, Irp);
            if (PrintIrp(buffer, max, &bufpos, Irp)) goto done;
            break;
        }
        default:
            if (PrintChar(buffer, max, &bufpos, ch)) goto done;
        }
    }

    // NULL terminate string
    PrintChar(buffer, max, &bufpos, '\0');
done:
    // Ensure string terminated
    buffer[max - 1] = '\0';
}

//*	ANSIstrlen:	Return length of null terminated ANSI string
USHORT ANSIstrlen(char* str)
{
    USHORT len = 0;
    for (; *str++ != '\0';)
        len++;
    return len;
}

//*	DebugPrintSystemThread:
//
// Description:
//		System thread to print device events.
//		Check for events every second, and wait for ThreadEvent ExitNow
//
// IRQL:
//		<= APC_LEVEL_IRQL
//
// Arguments:
//		Context has no meaning
//
// Return Value:
//		(None)

void DebugPrintSystemThread(IN PVOID Context)
{
    HANDLE DebugPrintDeviceHandle = NULL;
    NTSTATUS status;
    LARGE_INTEGER OneSecondTimeout;
    LARGE_INTEGER ByteOffset;

    // Lower thread priority
    KeSetPriorityThread(KeGetCurrentThread(), LOW_REALTIME_PRIORITY);

    // Attempt to open DebugPrt driver for 5 mins
    status = OpenDebugPrintDriver(&DebugPrintDeviceHandle);
    if (!NT_SUCCESS(status) || DebugPrintDeviceHandle == NULL)
        goto exit1;

    // Set up timeout and byte offset values
    OneSecondTimeout.QuadPart = -1i64 * 1000000i64 * 10i64;
    ByteOffset.QuadPart = 0i64;

    // Loop waiting for events or ExitNow to go TRUE
    while (TRUE)
    {
        // Wait for a request from DebugPrintMsg or DebugPrintClose
        KeWaitForSingleObject(&ThreadEvent, Executive, KernelMode, FALSE, &OneSecondTimeout);

        //	Remove any Events from EventList and send to DebugPrint driver
        while (TRUE)
        {
            IO_STATUS_BLOCK IoStatus;
            PDEBUGPRINT_EVENT pEvent;
            ULONG EventDataLen;

            PLIST_ENTRY pListEntry = ExInterlockedRemoveHeadList(&EventList, &EventListLock);
            if (pListEntry == NULL)
                break;

            // Get event as DEBUGPRINT_EVENT
            pEvent = CONTAINING_RECORD(pListEntry, DEBUGPRINT_EVENT, ListEntry);

            // Get length of event data
            EventDataLen = pEvent->Len;

            // Send event to DebugPrint
            status = ZwWriteFile(DebugPrintDeviceHandle, NULL, NULL, NULL,
                &IoStatus, pEvent->EventData, EventDataLen, &ByteOffset, NULL);
            //			if( status!=STATUS_SUCCESS)
            //				return;
            //			if( IoStatus.Information != len)
            //				return;

                        // Free our event buffer
            ExFreePool(pEvent);
        }

        // DebugPrintClose called, so stop the thread now.
        if (ExitNow)
            break;
    }

    // Tidy up and terminate thread
    ZwClose(DebugPrintDeviceHandle);
exit1:
    DebugPrintStarted = FALSE;
    ClearEvents();
    KeSetEvent(&ThreadExiting, 0, FALSE);
    PsTerminateSystemThread(STATUS_SUCCESS);
}

//*	OpenDebugPrintDriver:	Attempt to open DebugPrt driver for 5 mins
//							Try opening every 20 seconds.
//							This gives DebugPrt time to start at boot time

NTSTATUS OpenDebugPrintDriver(HANDLE* pDebugPrintDeviceHandle)
{
    NTSTATUS status;
    UNICODE_STRING DebugPrintName;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatus;
    LARGE_INTEGER OneSecondTimeout;
    int DelaySeconds = 0;

    // Set up timeout
    OneSecondTimeout.QuadPart = -1i64 * 1000000i64 * 10i64;

    // Make DebugPrint device name as UNICODE_STRING
    RtlInitUnicodeString(&DebugPrintName, L"\\Device\\PHDDebugPrint");

    // Make appropriate ObjectAttributes for ZwCreateFile
    InitializeObjectAttributes(&ObjectAttributes, &DebugPrintName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    // Attempt to open DebugPrt handle for 5 minutes

    while (DelaySeconds < 5 * 60)
    {
        int Delay;

        // Open handle to DebugPrint device
        status = ZwCreateFile(pDebugPrintDeviceHandle,
            GENERIC_READ | GENERIC_WRITE,
            &ObjectAttributes,
            &IoStatus,
            0, // alloc size = none
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN,
            0,
            NULL,  // eabuffer
            0);   // ealength

        if (NT_SUCCESS(status) && *pDebugPrintDeviceHandle != NULL)
            return status;

        // Wait for 20 seconds.

        for (Delay = 20; Delay > 0; Delay--)
        {
            KeWaitForSingleObject(&ThreadEvent, Executive, KernelMode, FALSE, &OneSecondTimeout);
            if (ExitNow)
                return status;
            DelaySeconds++;
        }
    }
    return status;
}

//*	ClearEvents:	Clear any remaining events
void ClearEvents()
{
    while (TRUE)
    {
        PDEBUGPRINT_EVENT pEvent;
        PLIST_ENTRY pListEntry = ExInterlockedRemoveHeadList(&EventList, &EventListLock);
        if (pListEntry == NULL)
            break;
        pEvent = CONTAINING_RECORD(pListEntry, DEBUGPRINT_EVENT, ListEntry);
        ExFreePool(pEvent);
    }
}
#endif  // DODEBUGPRINT

