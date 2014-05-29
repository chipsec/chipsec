#ifndef DRIVER_H
#define DRIVER_H


#include "cpu.h"
#include "chipsec.h"
#include "windef.h"

// function prototypes

NTSTATUS
DriverEntry(
    IN PDRIVER_OBJECT DriverObject,
    IN PUNICODE_STRING RegistryPath
    );

NTSTATUS
DriverOpen(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp
    );

NTSTATUS
DriverClose(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp
    );

NTSTATUS
DriverDeviceControl(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp
    );

VOID
DriverUnload(
    IN PDRIVER_OBJECT DriverObject
    );

NTSTATUS
DriverCreateSymbolicLinkObject(
    VOID
    );


//BYTE bPCIRead(WORD target, BYTE offset );
//WORD wPCIRead(WORD target, BYTE offset );
//DWORD lPCIRead(WORD target, BYTE offset );
//BYTE bPCIReadParam(WORD bus, WORD dev, WORD func, BYTE offset );
//WORD wPCIReadParam(WORD bus, WORD dev, WORD func, BYTE offset );
//DWORD lPCIReadParam(WORD bus, WORD dev, WORD func, BYTE offset );
//VOID bPCIWriteParam(WORD bus, WORD dev, WORD func, BYTE offset, BYTE value );
//VOID wPCIWriteParam(WORD bus, WORD dev, WORD func, BYTE offset, WORD value );
//VOID lPCIWriteParam(WORD bus, WORD dev, WORD func, BYTE offset, DWORD value );

BYTE pci_read_byte(WORD bus, WORD dev, WORD func, BYTE offset );
WORD pci_read_word(WORD bus, WORD dev, WORD func, BYTE offset );
DWORD pci_read_dword(WORD bus, WORD dev, WORD func, BYTE offset );

#endif	// DRIVER_H
