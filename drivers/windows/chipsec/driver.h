/*
CHIPSEC: Platform Security Assessment Framework
Copyright (c) 2010-2014, Intel Corporation

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
