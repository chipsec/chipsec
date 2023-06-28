/***
CHIPSEC: Platform Security Assessment Framework
Copyright (c) 2010-2021, Intel Corporation

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


#include <ntddk.h>
#include <wdmsec.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <initguid.h>
#include <wdmguid.h>
#include "driver.h"


//#pragma comment(lib, "wdmsec.lib")
//#pragma comment(lib, "bufferoverflowK.lib")

#pragma comment(linker, "/section:chipsec_code,EWP")

#pragma code_seg("chipsec_code$__c")

PPCI_BUS_INTERFACE_STANDARD PPCIbusInterface=NULL;	//pci driver interface
PFILE_OBJECT pcifo=NULL;		//pci bus filter driver file object
PDEVICE_OBJECT pcifido=NULL;	//pci bus filter driver device object

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

UNICODE_STRING functionName = {0};
PFN_ExAllocatePool2 pfnExAllocatePool2 = NULL;
PFN_ExAllocatePoolWithTag pfnExAllocatePoolWithTag = NULL;

UINT32
ReadPCICfg_Legacy(
  UINT8 bus,
  UINT8 dev,
  UINT8 fun,
  UINT8 off,
  UINT8 len // 1, 2, 4 bytes
  )
{
  unsigned int result = 0;
  unsigned int pci_addr = (0x80000000 | (bus << 16) | (dev << 11) | (fun << 8) | (off & ~3));
  unsigned short cfg_data_port = (UINT16)(0xCFC + ( off & 0x3 ));
  if     ( 1 == len ) result = (ReadPCIByte ( pci_addr, cfg_data_port ) & 0xFF);
  else if( 2 == len ) result = (ReadPCIWord ( pci_addr, cfg_data_port ) & 0xFFFF);
  else if( 4 == len ) result =  ReadPCIDword( pci_addr, cfg_data_port );
  return result;
}

VOID
WritePCICfg_Legacy(
  UINT8 bus,
  UINT8 dev,
  UINT8 fun,
  UINT8 off,
  UINT8 len, // 1, 2, 4 bytes
  UINT32 val
  )
{
  UINT32 pci_addr = (0x80000000 | (bus << 16) | (dev << 11) | (fun << 8) | (off & ~3));
  UINT16 cfg_data_port = (UINT16)(0xCFC + ( off & 0x3 ));
  if     ( 1 == len ) WritePCIByte ( pci_addr, cfg_data_port, (UINT8)(val&0xFF) );
  else if( 2 == len ) WritePCIWord ( pci_addr, cfg_data_port, (UINT16)(val&0xFFFF) );
  else if( 4 == len ) WritePCIDword( pci_addr, cfg_data_port, val );
}

VOID
WriteIOPort(
  UINT32 value,
  UINT16 io_port,
  UINT8 len // 1, 2, 4 bytes
  )
{
  if     ( 1 == len ) WritePortByte ( (UINT8)(value&0xFF), io_port );
  else if( 2 == len ) WritePortWord ( (UINT16)(value&0xFFFF), io_port );
  else if( 4 == len ) WritePortDword( value, io_port );
}

UINT32
ReadIOPort(
  UINT16 io_port,
  UINT8 len // 1, 2, 4 bytes
  )
{
  if     ( 1 == len ) return (ReadPortByte( io_port ) & 0xFF);
  else if( 2 == len ) return (ReadPortWord( io_port ) & 0xFFFF);
  else if( 4 == len ) return ReadPortDword( io_port );
  return 0;
}

// pci_read_.. ARE NOT USED
BYTE pci_read_byte(WORD bus, WORD dev, WORD func, BYTE offset )
{
  WORD target = func + ((dev & 0x1F) << 3) + ((bus & 0xFF) << 8) ;
  _outpd( 0xCF8, (DWORD)( target << 8 ) | 0x80000000UL | ((DWORD)offset & ~3 ) );
  return (BYTE)_inp( 0xCFC + (offset & 0x3) );
}
WORD pci_read_word(WORD bus, WORD dev, WORD func, BYTE offset )
{
  WORD target = func + ((dev & 0x1F) << 3) + ((bus & 0xFF) << 8) ;
  _outpd( 0xCF8, (DWORD)( target << 8 ) | 0x80000000UL | ((DWORD)offset & ~3 ) );
  return (WORD)_inpw( 0xCFC  + (offset & 0x2) );
}
DWORD pci_read_dword(WORD bus, WORD dev, WORD func, BYTE offset )
{
  WORD target = func + ((dev & 0x1F) << 3) + ((bus & 0xFF) << 8) ;
  _outpd( 0xCF8, (DWORD)( target << 8 ) | 0x80000000UL | ((DWORD)offset & ~3 ) );
  return _inpd( 0xCFC );
}


void _dump_buffer( unsigned char * b, unsigned int len )
{
    unsigned int i;
    unsigned int j;

    for( i = 0; i < len; i+=8 ){
        for (j = 0; j < 8; j++) {
            if (i + j >= len)
                DbgPrint("   ");
            else
                DbgPrint("%02X ", b[i + j]);
        }
        DbgPrint(": ");
        for (j = 0; j < 8; j++) {
            if (i + j >= len)
                DbgPrint("   ");
            else
                DbgPrint("%c ", b[i + j]);
        }
        DbgPrint("\n");
    }
}


NTSTATUS PutPciBusInterface()
{
    if (PPCIbusInterface && PPCIbusInterface->InterfaceDereference)
    {
        (*PPCIbusInterface->InterfaceDereference)(PPCIbusInterface->Context);

        ExFreePool(PPCIbusInterface);
    }
    return STATUS_SUCCESS;
}

NTSTATUS GetPciBusInterface()
{
    KEVENT event;
    NTSTATUS ntStatus;
    UNICODE_STRING pcifidoNameU;
    PIRP irp;
    IO_STATUS_BLOCK ioStatus;
    PIO_STACK_LOCATION irpStack;

    if (pfnExAllocatePool2 != NULL) {
        PPCIbusInterface = (PPCI_BUS_INTERFACE_STANDARD)pfnExAllocatePool2( POOL_FLAG_NON_PAGED, sizeof(PCI_BUS_INTERFACE_STANDARD), 0x3184 );
    } else if (pfnExAllocatePoolWithTag != NULL) {
        // Fall back to call the old api
        PPCIbusInterface = (PPCI_BUS_INTERFACE_STANDARD)pfnExAllocatePoolWithTag( POOL_FLAG_NON_PAGED, sizeof(PCI_BUS_INTERFACE_STANDARD), 0x3184 );
    }
    else {
        DbgPrint("[chipsec] ERROR: couldn't find the correct kernel api\n");
        ntStatus = STATUS_NOT_IMPLEMENTED;
        return ntStatus;
    }

    if (PPCIbusInterface == NULL)
    {
        ntStatus = STATUS_INSUFFICIENT_RESOURCES;
        return ntStatus;
    }
    RtlZeroMemory(PPCIbusInterface, sizeof(PCI_BUS_INTERFACE_STANDARD));

    KeInitializeEvent(&event, NotificationEvent, FALSE);

    RtlInitUnicodeString(&pcifidoNameU, L"\\Device\\ChipsecPCIFilter");

    ntStatus = IoGetDeviceObjectPointer(&pcifidoNameU,
        FILE_READ_DATA | FILE_WRITE_DATA,
        &pcifo,
        &pcifido);

    if (NT_SUCCESS(ntStatus))
    {
        DbgPrint("Got pci filter device object: 0x%x", pcifido);
    }
    else
    {
        DbgPrint("Get pci filter device object failed, code=0x%x", ntStatus);

        return STATUS_UNSUCCESSFUL;
    }

    irp=IoBuildSynchronousFsdRequest(IRP_MJ_PNP,
                                     pcifido,
                                     NULL,
                                     0,
                                     NULL,
                                     &event,
                                     &ioStatus);

    if (irp==NULL)
    {
        ntStatus = STATUS_INSUFFICIENT_RESOURCES;
        goto End;
    }

    irpStack=IoGetNextIrpStackLocation(irp);
    irpStack->MinorFunction=IRP_MN_QUERY_INTERFACE;
    irpStack->Parameters.QueryInterface.InterfaceType=(LPGUID)&GUID_PCI_BUS_INTERFACE_STANDARD;
    irpStack->Parameters.QueryInterface.Size=sizeof(PCI_BUS_INTERFACE_STANDARD);
    irpStack->Parameters.QueryInterface.Version=PCI_BUS_INTERFACE_STANDARD_VERSION;
    irpStack->Parameters.QueryInterface.Interface=(PINTERFACE)PPCIbusInterface;
    irpStack->Parameters.QueryInterface.InterfaceSpecificData=NULL;

    irp->IoStatus.Status=STATUS_NOT_SUPPORTED ;

    ntStatus=IoCallDriver(pcifido, irp);

    if (ntStatus==STATUS_PENDING)
    {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        ntStatus=ioStatus.Status;
        if (PPCIbusInterface->ReadConfig == NULL)
        {
            DbgPrint("Get pci filter device object busInterface failed, code=0x%x", ntStatus);
        }
    }
End:
    KeClearEvent(&event);
    return ntStatus;
}

static NTSTATUS ReadPciConfig(BYTE bus, BYTE dev, BYTE fun, BYTE off, BYTE size, DWORD* pValue)
{
    NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;

    PCI_SLOT_NUMBER slot;
    ULONG ulRet;

    slot.u.AsULONG = 0;
    slot.u.bits.DeviceNumber = dev;
    slot.u.bits.FunctionNumber = fun;

    ulRet = (*PPCIbusInterface->ReadConfig)(PPCIbusInterface->Context,
        bus,
        slot.u.AsULONG,
        pValue,
        off,
        size);

    if (ulRet == size)
    {
        ntStatus = STATUS_SUCCESS;
        DbgPrint("Read %d bytes from pci config space", ulRet);
    }
    else{
        ntStatus = STATUS_UNSUCCESSFUL;
    }
    return ntStatus;
}

static NTSTATUS WritePciConfig(BYTE bus, BYTE dev, BYTE fun, BYTE off, BYTE size, DWORD value)
{
    NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
    PVOID pValue = & value;

    PCI_SLOT_NUMBER slot;
    ULONG ulRet;

    slot.u.AsULONG = 0;
    slot.u.bits.DeviceNumber = dev;
    slot.u.bits.FunctionNumber = fun;

    ulRet = (*PPCIbusInterface->WriteConfig)(PPCIbusInterface->Context,
        bus,
        slot.u.AsULONG,
        pValue,
        off,
        size);

    if (ulRet == size)
    {
        ntStatus = STATUS_SUCCESS;
        DbgPrint("Write %d bytes to pci config space", ulRet);
    }
    else{
        ntStatus = STATUS_UNSUCCESSFUL;
    }

    return ntStatus;
}


NTSTATUS
DriverEntry(
    IN PDRIVER_OBJECT  DriverObject,
    IN PUNICODE_STRING RegistryPath )
{
    PDEVICE_OBJECT DeviceObject = NULL;
    NTSTATUS       Status = STATUS_SUCCESS;
    UNICODE_STRING DeviceName;
    UNICODE_STRING DosDeviceName;

    UNREFERENCED_PARAMETER(RegistryPath);

    RtlInitUnicodeString(&functionName, L"ExAllocatePool2");
    pfnExAllocatePool2 = (PFN_ExAllocatePool2)MmGetSystemRoutineAddress(&functionName);
    RtlInitUnicodeString(&functionName, L"ExAllocatePoolWithTag");
    pfnExAllocatePoolWithTag = (PFN_ExAllocatePoolWithTag)MmGetSystemRoutineAddress(&functionName);
    if (pfnExAllocatePool2 == NULL && pfnExAllocatePoolWithTag == NULL) {
        DbgPrint("[chipsec] ERROR: couldn't find the correct kernel api\n");
        Status = STATUS_NOT_IMPLEMENTED;
        return Status;
    }

    // Initialize a unicode string for the drivers object name.
    RtlInitUnicodeString( &DeviceName, DEVICE_NAME_U );

    Status = IoCreateDeviceSecure(
      DriverObject,
      0, // sizeof(DEVICE_EXTENSION),
      &DeviceName,
      FILE_DEVICE_UNKNOWN, // FILE_DEVICE_NOTHING
      FILE_DEVICE_SECURE_OPEN,
      FALSE,
      &SDDL_DEVOBJ_SYS_ALL_ADM_ALL, // &sd
      NULL,
      &DeviceObject
    );

    if( !NT_SUCCESS(Status) )
      {
        DbgPrint( "[chipsec] ERROR: DriverEntry: IoCreateDeviceSecure failed (status = %d)\n", Status );
        return Status;
      }

    // Create the symbolic link that the Win32 app can access the device
    RtlInitUnicodeString (&DosDeviceName, DEVICE_NAME_DOS );
    Status = IoCreateSymbolicLink(&DosDeviceName, &DeviceName);
    if( !NT_SUCCESS(Status) )
      {
        DbgPrint( "[chipsec] ERROR: DriverEntry: IoCreateSymbolicLink failed\n" );
        if(DeviceObject)
          {
            IoDeleteDevice(DeviceObject);
          }
        return Status;
      }

    // Initialize the dispatch table of the driver object.
    // NT sends requests to these routines.
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = DriverOpen;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = DriverClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDeviceControl;
    DriverObject->DriverUnload                         = DriverUnload;

    Status = GetPciBusInterface();
    if (PPCIbusInterface->ReadConfig == NULL)
    {
        //keep using legacy pci access if can't get pci bus interface from filter driver, so return STATUS_SUCCESS
        Status = STATUS_SUCCESS;
    }
    return Status;
}

NTSTATUS
DriverOpen(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp
    )
{
    DbgPrint( "[chipsec] >> DriverOpen (DeviceObject = 0x%p)\n", DeviceObject );

    // Complete the request and return status.
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = FILE_OPENED;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return (STATUS_SUCCESS);
}

NTSTATUS
DriverClose(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp
    )
{

    DbgPrint( "[chipsec] >> DriverClose (DeviceObject = 0x%p)\n", DeviceObject );

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return (STATUS_SUCCESS);
}

VOID
DriverUnload(
    IN PDRIVER_OBJECT DriverObject
    )
{

    NTSTATUS       Status;
    UNICODE_STRING DosDeviceName;

    DbgPrint( "[chipsec] >> DriverUnload (DriverObject = 0x%p)\n", DriverObject );

    PutPciBusInterface();

    RtlInitUnicodeString(&DosDeviceName, DEVICE_NAME_DOS );
    Status = IoDeleteSymbolicLink (&DosDeviceName );
    if( !NT_SUCCESS(Status) )
      {
        DbgPrint( "[chipsec] >> DriverUnload: IoDeleteSymbolicLink failed\n" );
      }

    if( DriverObject->DeviceObject )
      {
        IoDeleteDevice(DriverObject->DeviceObject);
      }
    return;
}


NTSTATUS _read_phys_mem( PHYSICAL_ADDRESS pa, unsigned int len, void * pData )
{
  void * va = MmMapIoSpace( pa, len, MmCached );
  if( !va )
    {
      DbgPrint( "[chipsec] ERROR: no space for mapping\n" );
      return STATUS_UNSUCCESSFUL;
    }
  DbgPrint( "[chipsec] reading %u bytes from physical address 0x%08x_%08x (virtual = %#010x)", len, pa.HighPart, pa.LowPart, (UINTN)va );
  RtlCopyMemory( pData, va, len );
  MmUnmapIoSpace( va, len );
  return STATUS_SUCCESS;
}

NTSTATUS _write_phys_mem( PHYSICAL_ADDRESS pa, unsigned int len, void * pData )
{
  void * va = MmMapIoSpace( pa, len, MmCached );
  if( !va )
    {
      DbgPrint( "[chipsec] ERROR: no space for mapping\n" );
      return STATUS_UNSUCCESSFUL;
    }
  DbgPrint( "[chipsec] writing %u bytes to physical address 0x%08x_%08x (virtual = %#010x)", len, pa.HighPart, pa.LowPart, (UINTN)va );
  RtlCopyMemory( va, pData, len );
  MmUnmapIoSpace( va, len );
  return STATUS_SUCCESS;
}

NTSTATUS _write_mmio_mem(PHYSICAL_ADDRESS pa, unsigned int len, void* pData)
{
    ULONG count = 1;
    void* va = MmMapIoSpace(pa, len, MmNonCached);
    if (!va)
      {
        DbgPrint("[chipsec] ERROR: no space for mapping\n");
        return STATUS_UNSUCCESSFUL;
      }
    DbgPrint("[chipsec] writing %u bytes to MMIO address 0x%08x_%08x (virtual = %#010x)", len, pa.HighPart, pa.LowPart, (UINTN)va);
    
    switch(len)
    {
      case 1:
        WRITE_REGISTER_BUFFER_UCHAR((volatile UCHAR*)(va), (PUCHAR)pData, count);
        break;
      case 2:
        WRITE_REGISTER_BUFFER_USHORT((volatile USHORT*)(va), (PUSHORT)pData, count);
        break;
      case 8:
        count = 2; // Missing break intentionally. 64bit write = 2x 32bit writes. 
      case 4:
        WRITE_REGISTER_BUFFER_ULONG((volatile ULONG*)(va), (PULONG)pData, count);
        break;
    }
    MmUnmapIoSpace(va, len);
    return STATUS_SUCCESS;
}

NTSTATUS _read_mmio_mem(PHYSICAL_ADDRESS pa, unsigned int len, void* pData)
{
    ULONG count = 1;
    void* va = MmMapIoSpace(pa, len, MmNonCached);
    if (!va)
      {
        DbgPrint("[chipsec] ERROR: no space for mapping\n");
        return STATUS_UNSUCCESSFUL;
      }

    DbgPrint("[chipsec] reading %u bytes to MMIO address 0x%08x_%08x (virtual = %#010x)", len, pa.HighPart, pa.LowPart, (UINTN)va);
    switch(len)
    {
      case 1:
        READ_REGISTER_BUFFER_UCHAR((volatile UCHAR*)(va), (PUCHAR)pData, count);
        break;
      case 2:
        READ_REGISTER_BUFFER_USHORT((volatile USHORT*)(va), (PUSHORT)pData, count);
        break;
      case 8:
        count = 2; // Missing break intentionally. 64bit write = 2x 32bit writes. 
      case 4:
        READ_REGISTER_BUFFER_ULONG((volatile ULONG*)(va), (PULONG)pData, count);
        break;
    }
    MmUnmapIoSpace(va, len);
    return STATUS_SUCCESS;
}

NTSTATUS
DriverDeviceControl(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp
    )
{

    NTSTATUS           Status = STATUS_UNSUCCESSFUL;
    PIO_STACK_LOCATION IrpSp;
    ULONG              IOControlCode = 0;
    ULONG              dwBytesWritten = 0;
    PCHAR              pInBuf = NULL, pOutBuf = NULL;
    unsigned int       _cpu_thread_id = 0;
    unsigned int       new_cpu_thread_id = 0;
    ULONG              _num_active_cpus = 0;
    USHORT             _num_groups = 0;
    PROCESSOR_NUMBER   _proc_number = {0, 0, 0};
    KAFFINITY          _kaffinity = 0;

    // Get the current IRP stack location of this request
    IrpSp = IoGetCurrentIrpStackLocation (Irp);
    IOControlCode = IrpSp->Parameters.DeviceIoControl.IoControlCode;

    DbgPrint( "[chipsec] >>>>>>>>>> IOCTL >>>>>>>>>>\n" );
    DbgPrint( "[chipsec] DeviceObject = 0x%p IOCTL = 0x%x\n", DeviceObject, IOControlCode );
    DbgPrint( "[chipsec] InputBufferLength = 0x%x, OutputBufferLength = 0x%x\n", IrpSp->Parameters.DeviceIoControl.InputBufferLength, IrpSp->Parameters.DeviceIoControl.OutputBufferLength );

    // CPU thread ID
    _num_active_cpus = KeQueryActiveProcessorCountEx( ALL_PROCESSOR_GROUPS );
    _num_groups      = KeQueryActiveGroupCount();
    _cpu_thread_id   = KeGetCurrentProcessorNumberEx( &_proc_number );
    _kaffinity       = KeQueryGroupAffinity( _proc_number.Group );

    DbgPrint( "[chipsec] Active CPU threads         : %ul\n", _num_active_cpus );
    DbgPrint( "[chipsec] Active CPU groups          : %ul\n", _num_groups );
    DbgPrint( "[chipsec] Active CPU mask (KAFFINITY): 0x%08X\n", _kaffinity );
    DbgPrint( "[chipsec] Current CPU group          : %u\n", _proc_number.Group );
    DbgPrint( "[chipsec] Current CPU number         : %u\n", _proc_number.Number );
    DbgPrint( "[chipsec] Current CPU thread         : %u\n", _cpu_thread_id );

    // Switch on the IOCTL code that is being requested by the user.  If the
    // operation is a valid one for this device do the needful.
    Irp -> IoStatus.Information = 0;
    switch( IOControlCode )
      {
        case READ_PCI_CFG_REGISTER:
        {
            DWORD val = 0;
            BYTE size = 0;
            WORD bdf[4];
            BYTE bus = 0, dev = 0, fun = 0, off = 0;
            DbgPrint("[chipsec] > READ_PCI_CFG_REGISTER\n");

            RtlCopyBytes(bdf, Irp->AssociatedIrp.SystemBuffer, 4 * sizeof(WORD));
            RtlCopyBytes(&size, (BYTE*)Irp->AssociatedIrp.SystemBuffer + 4 * sizeof(WORD), sizeof(BYTE));
            bus = (UINT8)bdf[0];
            dev = (UINT8)bdf[1];
            fun = (UINT8)bdf[2];
            off = (UINT8)bdf[3];

            if (1 != size && 2 != size && 4 != size)
            {
                DbgPrint("[chipsec] ERROR: STATUS_INVALID_PARAMETER\n");
                Status = STATUS_INVALID_PARAMETER;
                break;
            }
            if (PPCIbusInterface->ReadConfig == NULL)
            {
                val = ReadPCICfg_Legacy( bus, dev, fun, off, size );
                Status = STATUS_SUCCESS;
            }
            else {
                Status = ReadPciConfig(bus, dev, fun, off, size, &val);
            }

            IrpSp->Parameters.Read.Length = size;
            RtlCopyBytes( Irp->AssociatedIrp.SystemBuffer, (VOID*)&val, size );
            DbgPrint( "[chipsec][READ_PCI_CFG_REGISTER] B/D/F: %#04x/%#04x/%#04x, OFFSET: %#04x, value = %#010x (size = 0x%x)\n", bus, dev, fun, off, val, size );

            dwBytesWritten = IrpSp->Parameters.Read.Length;
            break;
          }
        case WRITE_PCI_CFG_REGISTER:
          {
            DWORD val = 0;
            WORD bdf[6];
            BYTE bus = 0, dev = 0, fun = 0, off = 0;
            BYTE size = 0;
            DbgPrint( "[chipsec] > WRITE_PCI_CFG_REGISTER\n" );

            RtlCopyBytes( bdf, Irp->AssociatedIrp.SystemBuffer, 6 * sizeof(WORD) );
            bus = (UINT8)bdf[0];
            dev = (UINT8)bdf[1];
            fun = (UINT8)bdf[2];
            off = (UINT8)bdf[3];
            RtlCopyBytes( &size, (BYTE*)Irp->AssociatedIrp.SystemBuffer + 6*sizeof(WORD), sizeof(BYTE) );

            val = ((DWORD)bdf[5] << 16) | bdf[4];
            DbgPrint( "[chipsec][WRITE_PCI_CFG_REGISTER] B/D/F: %#02x/%#02x/%#02x, OFFSET: %#02x, value = %#010x (size = %#02x)\n", bus, dev, fun, off, val, size );
            if (PPCIbusInterface->WriteConfig == NULL)
            {
                WritePCICfg_Legacy( bus, dev, fun, off, size, val );
                Status = STATUS_SUCCESS;
            }
            else {
                Status = WritePciConfig(bus, dev, fun, off, size, val);
            }
            break;
          }
        case IOCTL_READ_PHYSMEM:
          {
            UINT32 len = 0;
            PHYSICAL_ADDRESS phys_addr = { 0x0, 0x0 };

            DbgPrint( "[chipsec] > IOCTL_READ_PHYSMEM\n" );
            if( !Irp->AssociatedIrp.SystemBuffer ||
                IrpSp->Parameters.DeviceIoControl.InputBufferLength < 3*sizeof(UINT32))
              {
                DbgPrint( "[chipsec][IOCTL_READ_PHYSMEM] ERROR: STATUS_INVALID_PARAMETER\n" );
                Status = STATUS_INVALID_PARAMETER;
                break;
              }

            pInBuf = Irp->AssociatedIrp.SystemBuffer;
            pOutBuf = Irp->AssociatedIrp.SystemBuffer;

            phys_addr.HighPart = ((UINT32*)pInBuf)[0];
            phys_addr.LowPart  = ((UINT32*)pInBuf)[1];
            len                = ((UINT32*)pInBuf)[2];
            if( !len ) len = 4;

            if( IrpSp->Parameters.DeviceIoControl.OutputBufferLength < len )
              {
                DbgPrint( "[chipsec][IOCTL_READ_PHYSMEM] ERROR: STATUS_BUFFER_TOO_SMALL\n" );
                Status = STATUS_BUFFER_TOO_SMALL;
                break;
              }

            __try
              {
                Status = _read_phys_mem( phys_addr, len, pOutBuf );
              }
            __except (EXCEPTION_EXECUTE_HANDLER)
              {
                Status = GetExceptionCode();
                DbgPrint( "[chipsec][IOCTL_READ_PHYSMEM] ERROR: exception code 0x%X\n", Status );
                break;
              }

            if( NT_SUCCESS(Status) )
              {
                DbgPrint( "[chipsec][IOCTL_READ_PHYSMEM] Contents:\n" );
                _dump_buffer( (unsigned char *)pOutBuf, min(len,0x100) );
                dwBytesWritten = len;
              }
            break;
          }
        case IOCTL_WRITE_PHYSMEM:
          {
            UINT32 len = 0;
            PHYSICAL_ADDRESS phys_addr = { 0x0, 0x0 };

            DbgPrint( "[chipsec] > IOCTL_WRITE_PHYSMEM\n" );
            if( Irp->AssociatedIrp.SystemBuffer )
              {
                pInBuf = Irp->AssociatedIrp.SystemBuffer;
                pOutBuf = Irp->AssociatedIrp.SystemBuffer;

                if( IrpSp->Parameters.DeviceIoControl.InputBufferLength < 3*sizeof(UINT32) )
                  {
                    DbgPrint( "[chipsec][IOCTL_WRITE_PHYSMEM] ERROR: STATUS_INVALID_PARAMETER\n" );
                    Status = STATUS_INVALID_PARAMETER;
                    break;
                  }

                phys_addr.HighPart = ((UINT32*)pInBuf)[0];
                phys_addr.LowPart  = ((UINT32*)pInBuf)[1];
                len                = ((UINT32*)pInBuf)[2];

                pInBuf = pInBuf + (3 * sizeof(UINT32));

                if( IrpSp->Parameters.DeviceIoControl.InputBufferLength < len + 3*sizeof(UINT32) )
                  {
                    DbgPrint( "[chipsec][IOCTL_WRITE_PHYSMEM] ERROR: STATUS_INVALID_PARAMETER\n" );
                    Status = STATUS_INVALID_PARAMETER;
                    break;
                  }

                DbgPrint( "[chipsec][IOCTL_WRITE_PHYSMEM] Writing contents:\n" );
                _dump_buffer( (unsigned char *)pInBuf, min(len,0x100) );

                __try
                  {
                    Status = _write_phys_mem( phys_addr, len, pInBuf );
                  }
                __except (EXCEPTION_EXECUTE_HANDLER)
                  {
                    Status = GetExceptionCode();
                    DbgPrint( "[chipsec][IOCTL_WRITE_PHYSMEM] ERROR: exception code 0x%X\n", Status );
                    break;
                  }
              }
            break;
          }
        case IOCTL_WRITE_MMIO:
        {
            UINT32 len = 0;
            PHYSICAL_ADDRESS phys_addr = { 0x0, 0x0 };

            DbgPrint("[chipsec] > IOCTL_WRITE_MMIO\n");
            if (Irp->AssociatedIrp.SystemBuffer)
            {
                pInBuf = Irp->AssociatedIrp.SystemBuffer;
                pOutBuf = Irp->AssociatedIrp.SystemBuffer;

                if (IrpSp->Parameters.DeviceIoControl.InputBufferLength < 3 * sizeof(UINT32))
                {
                    DbgPrint("[chipsec][IOCTL_WRITE_MMIO] ERROR: STATUS_INVALID_PARAMETER\n");
                    Status = STATUS_INVALID_PARAMETER;
                    break;
                }

                phys_addr.HighPart = ((UINT32*)pInBuf)[0];
                phys_addr.LowPart = ((UINT32*)pInBuf)[1];
                len = ((UINT32*)pInBuf)[2];

                pInBuf = pInBuf + (3 * sizeof(UINT32));

                if (IrpSp->Parameters.DeviceIoControl.InputBufferLength < len + 3 * sizeof(UINT32))
                {
                    DbgPrint("[chipsec][IOCTL_WRITE_MMIO] ERROR: STATUS_INVALID_PARAMETER\n");
                    Status = STATUS_INVALID_PARAMETER;
                    break;
                }

                DbgPrint("[chipsec][IOCTL_WRITE_MMIO] Writing contents:\n");
                _dump_buffer((unsigned char*)pInBuf, min(len, 0x100));

                __try
                {
                    Status = _write_mmio_mem(phys_addr, len, pInBuf);
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    Status = GetExceptionCode();
                    DbgPrint("[chipsec][IOCTL_WRITE_MMIO] ERROR: exception code 0x%X\n", Status);
                    break;
                }
            }
          break;
        }
        case IOCTL_READ_MMIO:
          {
            UINT32 len = 0;
            PHYSICAL_ADDRESS phys_addr = { 0x0, 0x0 };

            DbgPrint( "[chipsec] > IOCTL_READ_MMIO\n" );
            if( !Irp->AssociatedIrp.SystemBuffer ||
                IrpSp->Parameters.DeviceIoControl.InputBufferLength < 3*sizeof(UINT32))
              {
                DbgPrint( "[chipsec][IOCTL_READ_MMIO] ERROR: STATUS_INVALID_PARAMETER\n" );
                Status = STATUS_INVALID_PARAMETER;
                break;
              }
            pInBuf = Irp->AssociatedIrp.SystemBuffer;
            pOutBuf = Irp->AssociatedIrp.SystemBuffer;
            phys_addr.HighPart = ((UINT32*)pInBuf)[0];
            phys_addr.LowPart  = ((UINT32*)pInBuf)[1];
            len                = ((UINT32*)pInBuf)[2];
            if( !len ) len = 4;

            if( IrpSp->Parameters.DeviceIoControl.OutputBufferLength < len )
              {
                DbgPrint( "[chipsec][IOCTL_READ_MMIO] ERROR: STATUS_BUFFER_TOO_SMALL\n" );
                Status = STATUS_BUFFER_TOO_SMALL;
                break;
              }
            __try
              {
                Status = _read_mmio_mem( phys_addr, len, pOutBuf );
              }
            __except (EXCEPTION_EXECUTE_HANDLER)
              {
                Status = GetExceptionCode();
                DbgPrint( "[chipsec][IOCTL_READ_MMIO] ERROR: exception code 0x%X\n", Status );
                break;
              }
            if( NT_SUCCESS(Status) )
              {
                DbgPrint( "[chipsec][IOCTL_READ_MMIO] Contents:\n" );
                _dump_buffer( (unsigned char *)pOutBuf, min(len,0x100) );
                dwBytesWritten = len;
              }
              break;
          }
        case IOCTL_ALLOC_PHYSMEM:
          {
            SIZE_T NumberOfBytes = 0;
            PVOID va = 0;
            PHYSICAL_ADDRESS HighestAcceptableAddress = { 0xFFFFFFFF, 0xFFFFFFFF };

            DbgPrint( "[chipsec] > IOCTL_ALLOC_PHYSMEM\n" );
            pInBuf  = Irp->AssociatedIrp.SystemBuffer;
            pOutBuf = Irp->AssociatedIrp.SystemBuffer;
            if( !pInBuf || IrpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(UINT64) + sizeof(UINT32))
              {
                DbgPrint( "[chipsec] ERROR: STATUS_INVALID_PARAMETER\n" );
                Status = STATUS_INVALID_PARAMETER;
                break;
              }
            RtlCopyBytes( &HighestAcceptableAddress.QuadPart, (BYTE*)Irp->AssociatedIrp.SystemBuffer, sizeof(UINT64) );
            RtlCopyBytes( &NumberOfBytes, (BYTE*)Irp->AssociatedIrp.SystemBuffer + sizeof(UINT64), sizeof(UINT32) );
            DbgPrint( "[chipsec] Allocating: NumberOfBytes = 0x%X, PhysAddr = 0x%I64x", NumberOfBytes, HighestAcceptableAddress.QuadPart );
            va = MmAllocateContiguousMemory( NumberOfBytes, HighestAcceptableAddress );
            if( !va )
              {
                DbgPrint( "[chipsec] ERROR: STATUS_UNSUCCESSFUL - could not allocate memory\n" );
                Status = STATUS_UNSUCCESSFUL;
              }
            else if( IrpSp->Parameters.DeviceIoControl.OutputBufferLength < 2*sizeof(UINT64) )
              {
                DbgPrint( "[chipsec] ERROR: STATUS_BUFFER_TOO_SMALL - should be at least 2*UINT64\n" );
                Status = STATUS_BUFFER_TOO_SMALL;
              }
            else
              {
                PHYSICAL_ADDRESS pa   = MmGetPhysicalAddress( va );
                DbgPrint( "[chipsec] Allocated Buffer: VirtAddr = 0x%I64x, PhysAddr = 0x%I64x\n", (UINT64)va, pa.QuadPart );
                ((UINT64*)pOutBuf)[0] = (UINT64)va;
                ((UINT64*)pOutBuf)[1] = pa.QuadPart;

                IrpSp->Parameters.Read.Length = 2*sizeof(UINT64);
                dwBytesWritten = IrpSp->Parameters.Read.Length;
                Status = STATUS_SUCCESS;
              }

            break;
          }

        case IOCTL_FREE_PHYSMEM:
          {
            UINTN va = 0x0;
            pInBuf  = Irp->AssociatedIrp.SystemBuffer;
            pOutBuf = Irp->AssociatedIrp.SystemBuffer;

            DbgPrint( "[chipsec] > IOCTL_FREE_PHYSMEM\n" );
            if( !Irp->AssociatedIrp.SystemBuffer ||
                IrpSp->Parameters.DeviceIoControl.InputBufferLength != sizeof(UINTN))
            {
               DbgPrint( "[chipsec] ERROR: STATUS_INVALID_PARAMETER\n" );
               Status = STATUS_INVALID_PARAMETER;
               break;
            }

            RtlCopyBytes( &va, (BYTE*)Irp->AssociatedIrp.SystemBuffer, sizeof(UINTN) );
            DbgPrint( "[chipsec][IOCTL_FREE_PHYSMEM] Virtual address of the memory being freed: 0x%I64X\n", va );
            MmFreeContiguousMemory( (PVOID)va );

            IrpSp->Parameters.Read.Length = 0;
            dwBytesWritten = IrpSp->Parameters.Read.Length;
            Status = STATUS_SUCCESS;
            break;
          }

        case IOCTL_GET_PHYSADDR:
          {
            UINTN va = 0x0;
            PHYSICAL_ADDRESS pa = { 0x0, 0x0 };

            pInBuf  = Irp->AssociatedIrp.SystemBuffer;
            pOutBuf = Irp->AssociatedIrp.SystemBuffer;

            DbgPrint( "[chipsec] > IOCTL_GET_PHYSADDR\n" );
            if( !Irp->AssociatedIrp.SystemBuffer ||
                IrpSp->Parameters.DeviceIoControl.InputBufferLength != sizeof(UINTN))
            {
               DbgPrint( "[chipsec] ERROR: STATUS_INVALID_PARAMETER\n" );
               Status = STATUS_INVALID_PARAMETER;
               break;
            }

            if( IrpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(UINTN))
            {
               DbgPrint( "[chipsec] ERROR: STATUS_BUFFER_TOO_SMALL\n" );
               Status = STATUS_BUFFER_TOO_SMALL;
               break;
            }

            RtlCopyBytes( &va, (BYTE*)Irp->AssociatedIrp.SystemBuffer, sizeof(UINTN) );
            pa = MmGetPhysicalAddress( (PVOID)va );

            DbgPrint( "[chipsec][IOCTL_GET_PHYSADDR] Translated virtual address 0x%I64X to physical: 0x%I64X\n", va, pa.QuadPart);
            RtlCopyBytes( Irp->AssociatedIrp.SystemBuffer, (void*)&pa, sizeof(UINTN) );
            IrpSp->Parameters.Read.Length = sizeof(UINTN);
            dwBytesWritten = IrpSp->Parameters.Read.Length;
            Status = STATUS_SUCCESS;
            break;
          }

        case IOCTL_MAP_IO_SPACE:
          {
            PVOID va  = 0x0;
            PHYSICAL_ADDRESS pa = { 0x0, 0x0 };
            unsigned int len = 0;
            unsigned int cache_type = 0;

            pInBuf  = Irp->AssociatedIrp.SystemBuffer;
            pOutBuf = Irp->AssociatedIrp.SystemBuffer;

            DbgPrint( "[chipsec] > IOCTL_MAP_IO_SPACE\n" );
            if( !Irp->AssociatedIrp.SystemBuffer ||
                IrpSp->Parameters.DeviceIoControl.InputBufferLength != 3*8)
            {
               DbgPrint( "[chipsec] ERROR: STATUS_INVALID_PARAMETER\n" );
               Status = STATUS_INVALID_PARAMETER;
               break;
            }

            if( IrpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(UINT64))
            {
               DbgPrint( "[chipsec] ERROR: STATUS_BUFFER_TOO_SMALL\n" );
               Status = STATUS_BUFFER_TOO_SMALL;
               break;
            }

            RtlCopyBytes( &pa,         (BYTE*)Irp->AssociatedIrp.SystemBuffer + 0x00, 0x8 );
            RtlCopyBytes( &len,        (BYTE*)Irp->AssociatedIrp.SystemBuffer + 0x08, 0x4 );
            RtlCopyBytes( &cache_type, (BYTE*)Irp->AssociatedIrp.SystemBuffer + 0x10, 0x4 );

            va = MmMapIoSpace(pa, len, cache_type);

            DbgPrint( "[chipsec][IOCTL_MAP_IO_SPACE] Mapping physical address 0x%016llX to virtual 0x%016llX\n", pa, va);
            RtlCopyBytes( Irp->AssociatedIrp.SystemBuffer, (void*)&va, sizeof(va) );
            IrpSp->Parameters.Read.Length = sizeof(va);
            dwBytesWritten = sizeof(va);
            Status = STATUS_SUCCESS;
            break;
          }

        case IOCTL_LOAD_UCODE_PATCH:
          {
            PVOID ucode_buf = NULL;
            UINT64 ucode_start = 0;
            UINT16 ucode_size = 0;
            UINT32 _eax[2] = {0}, _edx[2] = {0};
            int CPUInfo[4] = {-1};

            DbgPrint("[chipsec] > IOCTL_LOAD_UCODE_UPDATE\n" );

            if( !Irp->AssociatedIrp.SystemBuffer ||
                IrpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(UINT32) + sizeof(UINT16) )
            {
               DbgPrint( "[chipsec] ERROR: STATUS_INVALID_PARAMETER (input buffer size < 6)\n" );
               Status = STATUS_INVALID_PARAMETER;
               break;
            }

            RtlCopyBytes( &new_cpu_thread_id, (BYTE*)Irp->AssociatedIrp.SystemBuffer, sizeof(UINT32) );
            if( new_cpu_thread_id >= _num_active_cpus )
            {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }

            _kaffinity = KeSetSystemAffinityThreadEx( (KAFFINITY)(1 << new_cpu_thread_id) );
            DbgPrint( "[chipsec][IOCTL_LOAD_UCODE_UPDATE] Changed CPU thread to %ul\n", KeGetCurrentProcessorNumberEx( NULL ) );

            RtlCopyBytes( &ucode_size, (BYTE*)Irp->AssociatedIrp.SystemBuffer + sizeof(UINT32), sizeof(UINT16) );
            DbgPrint( "[chipsec][IOCTL_LOAD_UCODE_UPDATE] Ucode update size = 0x%X\n", ucode_size );

            if( IrpSp->Parameters.DeviceIoControl.InputBufferLength < ucode_size + sizeof(UINT32) + sizeof(UINT16) )
              {
                DbgPrint( "[chipsec] ERROR: STATUS_INVALID_PARAMETER (input buffer size < ucode_size + 6)\n" );
                Status = STATUS_INVALID_PARAMETER;
                break;
              }

            if (pfnExAllocatePool2 != NULL) {
                ucode_buf = pfnExAllocatePool2( POOL_FLAG_NON_PAGED, ucode_size, 0x3184 );
            } else if (pfnExAllocatePoolWithTag != NULL) {
                // Fall back to call the old api            
                ucode_buf = pfnExAllocatePoolWithTag( POOL_FLAG_NON_PAGED, ucode_size, 0x3184 );
            }
            else {
                DbgPrint("[chipsec] ERROR: couldn't find the correct kernel api\n");
                Status = STATUS_NOT_IMPLEMENTED;
                break;
            }
            
            if( !ucode_buf )
              {
                DbgPrint( "[chipsec] ERROR: couldn't allocate pool for ucode binary\n" );
                Status = STATUS_INSUFFICIENT_RESOURCES;
                break;
              }
            RtlCopyBytes( ucode_buf, (BYTE*)Irp->AssociatedIrp.SystemBuffer + sizeof(UINT32) + sizeof(UINT16), ucode_size );
            ucode_start = (UINT64)ucode_buf;
            DbgPrint( "[chipsec][IOCTL_LOAD_UCODE_UPDATE] ucode update address = 0x%p (eax = 0x%08X, edx = 0x%08X)\n", ucode_start, (UINT32)(ucode_start & 0xFFFFFFFF), (UINT32)((ucode_start >> 32) & 0xFFFFFFFF) );
            DbgPrint( "[chipsec][IOCTL_LOAD_UCODE_UPDATE] ucode update contents:\n" );
            _dump_buffer( (unsigned char *)ucode_buf, min(ucode_size,0x100) );

            // -- read IA32_BIOS_SIGN_ID MSR to save current patch ID
            // -- we'll need this value later to verify the microcode update was successful
            _rdmsr(MSR_IA32_BIOS_SIGN_ID, &_eax[0], &_edx[0]);

            // -- trigger CPU ucode patch update
            // -- pInBuf points to the beginning of ucode update binary
            _wrmsr( MSR_IA32_BIOS_UPDT_TRIG, (UINT32)((ucode_start >> 32) & 0xFFFFFFFF), (UINT32)(ucode_start & 0xFFFFFFFF) );

            ExFreePoolWithTag( ucode_buf, 0x3184 );

            // -- check if patch was loaded
            // --
            // -- need to clear IA32_BIOS_SIGN_ID MSR first
            // -- CPUID will deposit an update ID value in 64-bit MSR at address MSR_IA32_BIOS_SIGN_ID
            // -- read IA32_BIOS_SIGN_ID MSR to check patch ID != previous patch ID
            DbgPrint( "[chipsec][IOCTL_LOAD_UCODE_UPDATE] checking ucode update was loaded..\n" );
            DbgPrint( "[chipsec][IOCTL_LOAD_UCODE_UPDATE] clear IA32_BIOS_SIGN_ID, CPUID EAX=1, read back IA32_BIOS_SIGN_ID\n" );
            _wrmsr( MSR_IA32_BIOS_SIGN_ID, 0, 0 );
            __cpuid(CPUInfo, 1);
            _rdmsr( MSR_IA32_BIOS_SIGN_ID, &_eax[1], &_edx[1] );
            DbgPrint( "[chipsec][IOCTL_LOAD_UCODE_UPDATE] RDMSR( IA32_BIOS_SIGN_ID=0x8b ) = 0x%08x%08x\n", _edx[1], _eax[1] );
            if ( _edx[1] == _edx[0] )
              {
                // same patch ID, microcode update failed
                DbgPrint("[chipsec] ERROR: Microcode update failed\n");
                Status = STATUS_UNSUCCESSFUL;
                break;
              }

            DbgPrint("[chipsec][IOCTL_LOAD_UCODE_UPDATE] Microcode update loaded (ID != %u)\n", _edx[0]);
            Status = STATUS_SUCCESS;
            break;
          }
        case IOCTL_WRMSR:
          {

            UINT32 msrData[3];
            UINT32 _eax = 0, _edx = 0;
            unsigned int _msr_addr;

            DbgPrint("[chipsec] > IOCTL_WRMSR\n");

            pInBuf = Irp->AssociatedIrp.SystemBuffer;
            if( !pInBuf )
              {
                DbgPrint( "[chipsec][IOCTL_WRMSR] ERROR: NO data provided\n" );
                Status = STATUS_INVALID_PARAMETER;
                break;
              }
            if( IrpSp->Parameters.DeviceIoControl.InputBufferLength < 4 * sizeof(UINT32) )
              {
                DbgPrint( "[chipsec][IOCTL_WRMSR] ERROR: STATUS_INVALID_PARAMETER (input buffer size < 4 * sizeof(UINT32))\n" );
                Status = STATUS_INVALID_PARAMETER;
                break;
              }

            RtlCopyBytes( &new_cpu_thread_id, (BYTE*)Irp->AssociatedIrp.SystemBuffer, sizeof(UINT32) );
            if( new_cpu_thread_id >= _num_active_cpus )
            {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }

            _kaffinity = KeSetSystemAffinityThreadEx( (KAFFINITY)(1 << new_cpu_thread_id) );
            DbgPrint( "[chipsec][IOCTL_WRMSR] Changed CPU thread to %ul\n", KeGetCurrentProcessorNumberEx( NULL ) );

            RtlCopyBytes( msrData, (BYTE*)Irp->AssociatedIrp.SystemBuffer + sizeof(UINT32), 3 * sizeof(UINT32) );
            _msr_addr = msrData[0];
            _eax      = msrData[1];
            _edx      = msrData[2];
            DbgPrint( "[chipsec][IOCTL_WRMSR] WRMSR( 0x%x ) <-- 0x%08x%08x\n", _msr_addr, _edx, _eax );

            // -- write MSR
            __try
              {
                _wrmsr( _msr_addr, _edx, _eax );
              }
            __except (EXCEPTION_EXECUTE_HANDLER)
              {
                Status = GetExceptionCode();
                DbgPrint( "[chipsec][IOCTL_WRMSR] ERROR: exception code 0x%X\n", Status );
                break;
              }

            Status = STATUS_SUCCESS;
            break;
          }
        case IOCTL_RDMSR:
          {
            UINT32 msrData[1];
            UINT32 _eax = 0;
            UINT32 _edx = 0;
            UINT32 _msr_addr = 0;

            DbgPrint("[chipsec] > IOCTL_RDMSR\n");

            pInBuf  = Irp->AssociatedIrp.SystemBuffer;
            pOutBuf = Irp->AssociatedIrp.SystemBuffer;
            if( !pInBuf )
              {
                DbgPrint( "[chipsec] ERROR: No input provided\n" );
                Status = STATUS_INVALID_PARAMETER;
                break;
              }
            if( IrpSp->Parameters.DeviceIoControl.InputBufferLength < 2 * sizeof(UINT32) )
              {
                DbgPrint( "[chipsec] ERROR: STATUS_INVALID_PARAMETER - input buffer size < 2 * sizeof(UINT32)\n" );
                Status = STATUS_INVALID_PARAMETER;
                break;
              }

            RtlCopyBytes( &new_cpu_thread_id, (BYTE*)Irp->AssociatedIrp.SystemBuffer, sizeof(UINT32) );
            if( new_cpu_thread_id >= _num_active_cpus )
            {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }

            _kaffinity = KeSetSystemAffinityThreadEx( (KAFFINITY)(1 << new_cpu_thread_id) );
            DbgPrint( "[chipsec][IOCTL_RDMSR] Changed CPU thread to %ul\n", KeGetCurrentProcessorNumberEx( NULL ) );

            RtlCopyBytes( msrData, (BYTE*)Irp->AssociatedIrp.SystemBuffer + sizeof(UINT32), sizeof(UINT32) );
            _msr_addr = msrData[0];

            __try
              {
                _rdmsr( _msr_addr, &_eax, &_edx );
              }
            __except( EXCEPTION_EXECUTE_HANDLER )
              {
                Status = GetExceptionCode();
                DbgPrint( "[chipsec][IOCTL_RDMSR] ERROR: exception code 0x%X\n", Status );
                break;
              }
            DbgPrint( "[chipsec][IOCTL_RDMSR] RDMSR( 0x%x ) --> 0x%08x%08x\n", _msr_addr, _edx, _eax );

            if( IrpSp->Parameters.DeviceIoControl.OutputBufferLength >= 2*sizeof(UINT32) )
              {
                IrpSp->Parameters.Read.Length = 2*sizeof(UINT32);
                RtlCopyBytes( Irp->AssociatedIrp.SystemBuffer, (VOID*)&_eax, sizeof(UINT32) );
                RtlCopyBytes( ((UINT8*)Irp->AssociatedIrp.SystemBuffer) + sizeof(UINT32), (VOID*)&_edx, sizeof(UINT32) );

                dwBytesWritten = 2*sizeof(UINT32);
                Status = STATUS_SUCCESS;
              }
            else
              {
                DbgPrint( "[chipsec] ERROR: STATUS_BUFFER_TOO_SMALL - should be at least 2 UINT32\n" );
                Status = STATUS_BUFFER_TOO_SMALL;
              }

            break;
          }
        case READ_IO_PORT:
          {
            DWORD value;
            BYTE size = 0;
            WORD io_port;
            DbgPrint( "[chipsec] > READ_IO_PORT\n" );

            RtlCopyBytes( &io_port, (BYTE*)Irp->AssociatedIrp.SystemBuffer, sizeof(WORD) );
            RtlCopyBytes( &size, (BYTE*)Irp->AssociatedIrp.SystemBuffer + sizeof(WORD), sizeof(BYTE) );
            if( 1 != size && 2 != size && 4 != size)
              {
              DbgPrint( "[chipsec][READ_IO_PORT] ERROR: STATUS_INVALID_PARAMETER\n" );
              Status = STATUS_INVALID_PARAMETER;
              break;
              }

            __try
              {
                value = ReadIOPort( io_port, size );
              }
            __except( EXCEPTION_EXECUTE_HANDLER )
              {
                Status = GetExceptionCode();
                DbgPrint( "[chipsec][READ_IO_PORT] ERROR: exception code 0x%X\n", Status );
                break;
              }

            IrpSp->Parameters.Read.Length = size;
            RtlCopyBytes( Irp->AssociatedIrp.SystemBuffer, (VOID*)&value, size );
            DbgPrint( "[chipsec][READ_IO_PORT] I/O Port %#04x, value = %#010x (size = %#02x)\n", io_port, value, size );

            dwBytesWritten = IrpSp->Parameters.Read.Length;
            Status = STATUS_SUCCESS;
            break;
          }
        case WRITE_IO_PORT:
          {
            DWORD value = 0;
            WORD io_port = 0;
            BYTE size = 0;
            DbgPrint( "[chipsec] > WRITE_IO_PORT\n" );

            RtlCopyBytes( &io_port, (BYTE*)Irp->AssociatedIrp.SystemBuffer, sizeof(WORD) );
            RtlCopyBytes( &value, (BYTE*)Irp->AssociatedIrp.SystemBuffer + sizeof(WORD), sizeof(DWORD) );
            RtlCopyBytes( &size, (BYTE*)Irp->AssociatedIrp.SystemBuffer + sizeof(WORD) + sizeof(DWORD), sizeof(BYTE) );
            DbgPrint( "[chipsec][WRITE_IO_PORT] I/O Port %#04x, value = %#010x (size = %#02x)\n", io_port, value, size );

            __try
              {
                WriteIOPort( value, io_port, size );
              }
            __except( EXCEPTION_EXECUTE_HANDLER )
              {
                Status = GetExceptionCode();
                DbgPrint( "[chipsec][WRITE_IO_PORT] ERROR: exception code 0x%X\n", Status );
                break;
              }

            Status = STATUS_SUCCESS;
            break;
          }
        case GET_CPU_DESCRIPTOR_TABLE:
          {
            BYTE dt_code = 0;
            DESCRIPTOR_TABLE_RECORD dtr;
            PDESCRIPTOR_TABLE_RECORD pdtr = &dtr;
            PHYSICAL_ADDRESS dt_pa;

            DbgPrint( "[chipsec] > GET_CPU_DESCRIPTOR_TABLE\n" );

            RtlCopyBytes( &new_cpu_thread_id, (BYTE*)Irp->AssociatedIrp.SystemBuffer, sizeof(UINT32) );
            if( new_cpu_thread_id >= _num_active_cpus )
            {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }

            _kaffinity = KeSetSystemAffinityThreadEx( (KAFFINITY)(1 << new_cpu_thread_id) );
            DbgPrint( "[chipsec][GET_CPU_DESCRIPTOR_TABLE] Changed CPU thread to %ul\n", KeGetCurrentProcessorNumberEx( NULL ) );
            RtlCopyBytes( &dt_code, (BYTE*)Irp->AssociatedIrp.SystemBuffer + sizeof(UINT32), sizeof(BYTE) );
            DbgPrint( "[chipsec][GET_CPU_DESCRIPTOR_TABLE] Descriptor table: %x\n", dt_code );

            switch( dt_code )
              {
                case CPU_DT_CODE_GDTR:  { _store_gdtr( (void*)pdtr ); break; }
                case CPU_DT_CODE_LDTR:  { _store_ldtr( (void*)pdtr ); break; }
                case CPU_DT_CODE_IDTR:
                default:                { _store_idtr( (void*)pdtr ); break; }
              }

            DbgPrint( "[chipsec][GET_CPU_DESCRIPTOR_TABLE] Descriptor table register contents:\n" );
            _dump_buffer( (unsigned char *)pdtr, sizeof(DESCRIPTOR_TABLE_RECORD) );
            DbgPrint( "[chipsec][GET_CPU_DESCRIPTOR_TABLE] IDTR: Limit = 0x%04x, Base = 0x%I64x\n", dtr.limit, dtr.base );

            dt_pa = MmGetPhysicalAddress( (PVOID)dtr.base );
            DbgPrint( "[chipsec][GET_CPU_DESCRIPTOR_TABLE] Descriptor table PA: 0x%I64X (0x%08X_%08X)\n", dt_pa.QuadPart, dt_pa.HighPart, dt_pa.LowPart );

            IrpSp->Parameters.Read.Length = sizeof(DESCRIPTOR_TABLE_RECORD) + sizeof(dt_pa.QuadPart);
            RtlCopyBytes( Irp->AssociatedIrp.SystemBuffer, (void*)pdtr, sizeof(DESCRIPTOR_TABLE_RECORD) );
            RtlCopyBytes( (UINT8*)Irp->AssociatedIrp.SystemBuffer + sizeof(DESCRIPTOR_TABLE_RECORD), (VOID*)&dt_pa.QuadPart, sizeof(dt_pa.QuadPart) );

            dwBytesWritten = IrpSp->Parameters.Read.Length;
            Status = STATUS_SUCCESS;
            break;
          }
        case IOCTL_SWSMI:
          {
            swsmi_msg_t smi_msg;

            DbgPrint("[chipsec] > IOCTL_SWSMI\n");
            pInBuf = Irp->AssociatedIrp.SystemBuffer;
            if( !pInBuf )
              {
                DbgPrint( "[chipsec] ERROR: NO data provided\n" );
                Status = STATUS_INVALID_PARAMETER;
                break;
              }
            if( IrpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(smi_msg) )
              {
                DbgPrint( "[chipsec] ERROR: STATUS_INVALID_PARAMETER (input buffer size < sizeof(smi_msg))\n" );
                Status = STATUS_INVALID_PARAMETER;
                break;
              }
            RtlCopyBytes( &smi_msg, (BYTE*)Irp->AssociatedIrp.SystemBuffer, sizeof(smi_msg) );

            DbgPrint( "[chipsec][IOCTL_SWSMI] SW SMI to ports 0x%X-0x%X <- 0x%04X\n", 0xB2, 0xB3, smi_msg.code_data );
            DbgPrint( "                       RAX = 0x%I64x\n", smi_msg.rax );
            DbgPrint( "                       RBX = 0x%I64x\n", smi_msg.rbx );
            DbgPrint( "                       RCX = 0x%I64x\n", smi_msg.rcx );
            DbgPrint( "                       RDX = 0x%I64x\n", smi_msg.rdx );
            DbgPrint( "                       RSI = 0x%I64x\n", smi_msg.rsi );
            DbgPrint( "                       RDI = 0x%I64x\n", smi_msg.rdi );

            // -- send SMI using port 0xB2
            __try
              {
                _swsmi( &smi_msg );
              }
            __except( EXCEPTION_EXECUTE_HANDLER )
              {
                Status = GetExceptionCode();
                break;
              }

            RtlCopyBytes( (BYTE*)Irp->AssociatedIrp.SystemBuffer, &smi_msg, sizeof(smi_msg) );
            dwBytesWritten = sizeof(smi_msg);

            DbgPrint( "[chipsec][IOCTL_SWSMI] SW SMI return from ports 0x%X-0x%X <- 0x%04X\n", 0xB2, 0xB3, smi_msg.code_data );
            DbgPrint( "                       RAX = 0x%I64x\n", smi_msg.rax );
            DbgPrint( "                       RBX = 0x%I64x\n", smi_msg.rbx );
            DbgPrint( "                       RCX = 0x%I64x\n", smi_msg.rcx );
            DbgPrint( "                       RDX = 0x%I64x\n", smi_msg.rdx );
            DbgPrint( "                       RSI = 0x%I64x\n", smi_msg.rsi );
            DbgPrint( "                       RDI = 0x%I64x\n", smi_msg.rdi );

            Status = STATUS_SUCCESS;
            break;
          }
        case IOCTL_CPUID:
          {
            int CPUInfo[4] = {-1};
            int gprs[2] = {0};
            int _rax = 0, _rcx = 0;
            //CPU_REG_TYPE gprs[6];
            //CPU_REG_TYPE _rax = 0, _rbx = 0, _rcx = 0, _rdx = 0, _rsi = 0, _rdi = 0;

            DbgPrint("[chipsec] > IOCTL_CPUID\n");
            pInBuf = Irp->AssociatedIrp.SystemBuffer;
            if( !pInBuf )
              {
                DbgPrint( "[chipsec] ERROR: NO data provided\n" );
                Status = STATUS_INVALID_PARAMETER;
                break;
              }
            if( IrpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(gprs) )
              {
                DbgPrint( "[chipsec] ERROR: STATUS_INVALID_PARAMETER (input buffer size < %zu)\n", sizeof(gprs) );
                Status = STATUS_INVALID_PARAMETER;
                break;
              }
            RtlCopyBytes( gprs, (BYTE*)Irp->AssociatedIrp.SystemBuffer, sizeof(gprs) );
            _rax = gprs[ 0 ];
            _rcx = gprs[ 1 ];
            DbgPrint( "[chipsec][IOCTL_CPUID] CPUID:\n" );
            DbgPrint( "                       EAX = 0x%08X\n", _rax );
            DbgPrint( "                       ECX = 0x%08X\n", _rcx );

            __cpuidex( CPUInfo, _rax, _rcx );

            DbgPrint( "[chipsec][IOCTL_CPUID] CPUID returned:\n" );
            DbgPrint( "                       EAX = 0x%08X\n", CPUInfo[0] );
            DbgPrint( "                       EBX = 0x%08X\n", CPUInfo[1] );
            DbgPrint( "                       ECX = 0x%08X\n", CPUInfo[2] );
            DbgPrint( "                       EDX = 0x%08X\n", CPUInfo[3] );

            IrpSp->Parameters.Read.Length = sizeof(CPUInfo);
            RtlCopyBytes( Irp->AssociatedIrp.SystemBuffer, (void*)CPUInfo, sizeof(CPUInfo) );

            dwBytesWritten = IrpSp->Parameters.Read.Length;
            Status = STATUS_SUCCESS;
            break;
          }

        case IOCTL_WRCR:
          {
            UINT64 val64 = 0;
            CPU_REG_TYPE value = 0;
            WORD cr_reg = 0;
            DbgPrint( "[chipsec] > WRITE_CR\n" );

            if( IrpSp->Parameters.DeviceIoControl.InputBufferLength < (sizeof(cr_reg) + sizeof(val64) + sizeof(UINT32)))
            {
                 Status = STATUS_INVALID_PARAMETER;
                 break;
            }

            RtlCopyBytes( &cr_reg, (BYTE*)Irp->AssociatedIrp.SystemBuffer, sizeof(cr_reg) );
            RtlCopyBytes( &val64, (BYTE*)Irp->AssociatedIrp.SystemBuffer + sizeof(cr_reg), sizeof(val64) );
            new_cpu_thread_id = *((BYTE*)Irp->AssociatedIrp.SystemBuffer + sizeof(cr_reg) + sizeof(val64));
            if( new_cpu_thread_id >= _num_active_cpus )
            {
                 Status = STATUS_INVALID_PARAMETER;
                 break;
            }

            _kaffinity = KeSetSystemAffinityThreadEx( (KAFFINITY)(1 << new_cpu_thread_id) );
            value = (CPU_REG_TYPE)val64;
            DbgPrint( "[chipsec][WRITE_CR] CR Reg %#04x, value = %#010x \n", cr_reg, value );

            switch (cr_reg) {
            case 0: WriteCR0(value);
                Status = STATUS_SUCCESS;
                break;
            case 2: WriteCR2(value);
                Status = STATUS_SUCCESS;
                break;
            case 3: WriteCR3(value);
                Status = STATUS_SUCCESS;
                break;
            case 4: WriteCR4(value);
                Status = STATUS_SUCCESS;
                break;
            case 8:
#if defined(_M_AMD64)
                WriteCR8(value);
                Status = STATUS_SUCCESS;
                break;
#endif
            default:
                Status = STATUS_INVALID_PARAMETER;
                break;
            }

            if( !NT_SUCCESS(Status) ) {
                break;
            }

            dwBytesWritten = 0;
            Status = STATUS_SUCCESS;
            break;
          }
        case IOCTL_RDCR:
          {
            UINT64 val64 = 0;
            CPU_REG_TYPE value = 0;
            WORD cr_reg = 0;
            DbgPrint( "[chipsec] > READ_CR\n" );

            if( IrpSp->Parameters.DeviceIoControl.InputBufferLength < (sizeof(cr_reg)+sizeof(UINT32))
             || IrpSp->Parameters.DeviceIoControl.OutputBufferLength < (sizeof(val64))
              )
            {
                 Status = STATUS_INVALID_PARAMETER;
                 break;
            }

            RtlCopyBytes( &cr_reg, (BYTE*)Irp->AssociatedIrp.SystemBuffer, sizeof(cr_reg) );
            new_cpu_thread_id = *((BYTE*)Irp->AssociatedIrp.SystemBuffer + sizeof(cr_reg));
            if( new_cpu_thread_id >= _num_active_cpus )
            {
                 Status = STATUS_INVALID_PARAMETER;
                 break;
            }

            _kaffinity = KeSetSystemAffinityThreadEx( (KAFFINITY)(1 << new_cpu_thread_id) );

            switch (cr_reg) {
            case 0: value = ReadCR0();
                Status = STATUS_SUCCESS;
                break;
            case 2: value = ReadCR2();
                Status = STATUS_SUCCESS;
                break;
            case 3: value = ReadCR3();
                Status = STATUS_SUCCESS;
                break;
            case 4: value = ReadCR4();
                Status = STATUS_SUCCESS;
                break;
            case 8:
#if defined(_M_AMD64)
                value = ReadCR8();
                Status = STATUS_SUCCESS;
                break;
#endif
            default:
                Status = STATUS_INVALID_PARAMETER;
                break;
            }

            if( !NT_SUCCESS(Status) ) {
                break;
            }

            val64 = value;
            RtlCopyBytes( (BYTE*)Irp->AssociatedIrp.SystemBuffer, &val64, sizeof(val64) );
            dwBytesWritten = sizeof(val64);

            DbgPrint( "[chipsec][READ_CR] CR Reg %#04x, value = %#010x \n", cr_reg, value );

            Status = STATUS_SUCCESS;
            break;

          }
        case IOCTL_HYPERCALL:
          {
            CPU_REG_TYPE regs[11] = {0};
            CPU_REG_TYPE result = 0;
            CPU_REG_TYPE mhypercall = (CPU_REG_TYPE)&hypercall_page;

            DbgPrint("[chipsec] > IOCTL_HYPERCALL\n");
            pInBuf = Irp->AssociatedIrp.SystemBuffer;

            if( !Irp->AssociatedIrp.SystemBuffer ||
                IrpSp->Parameters.DeviceIoControl.InputBufferLength != sizeof(regs))
            {
                DbgPrint( "[chipsec] ERROR: STATUS_INVALID_PARAMETER\n" );
                Status = STATUS_INVALID_PARAMETER;
                break;
            }

            if( IrpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(result))
            {
               DbgPrint( "[chipsec] ERROR: STATUS_BUFFER_TOO_SMALL\n" );
               Status = STATUS_BUFFER_TOO_SMALL;
               break;
            }

            RtlCopyBytes( regs, (BYTE*)Irp->AssociatedIrp.SystemBuffer, sizeof(regs) );
            DbgPrint( "[chipsec][IOCTL_HYPERCALL] HYPERCALL:\n" );
            #if defined(_M_AMD64)
            DbgPrint( "    RCX = 0x%016llX  RDX = 0x%016llX\n", regs[0], regs[1] );
            DbgPrint( "    R8  = 0x%016llX  R9  = 0x%016llX\n", regs[2], regs[3] );
            DbgPrint( "    R10 = 0x%016llX  R11 = 0x%016llX\n", regs[4], regs[5] );
            DbgPrint( "    RAX = 0x%016llX  RBX = 0x%016llX\n", regs[6], regs[7] );
            DbgPrint( "    RDI = 0x%016llX  RSI = 0x%016llX\n", regs[8], regs[9] );
            #endif
            #if defined(_M_IX86)
            DbgPrint( "    EAX = 0x%08X  EBX = 0x%08X  ECX = 0x%08X\n", regs[6], regs[7], regs[0] );
            DbgPrint( "    EDX = 0x%08X  ESI = 0x%08X  EDI = 0x%08X\n", regs[1], regs[8], regs[9] );
            #endif
            DbgPrint( "    XMM0-XMM5 buffer VA = 0x%016llX\n", regs[10] );

            __try
              {
                result = hypercall(regs[0], regs[1], regs[2], regs[3], regs[4], regs[5], regs[6], regs[7], regs[8], regs[9], regs[10], mhypercall);
              }
            __except( EXCEPTION_EXECUTE_HANDLER )
              {
                Status = GetExceptionCode();
                DbgPrint( "[chipsec][IOCTL_HYPERCALL] ERROR: exception code 0x%X\n", Status );
                break;
              }

            DbgPrint( "[chipsec][IOCTL_HYPERCALL] returned: 0x%016llX\n", result);

            IrpSp->Parameters.Read.Length = sizeof(result);
            RtlCopyBytes( Irp->AssociatedIrp.SystemBuffer, (void*)&result, sizeof(result) );

            dwBytesWritten = IrpSp->Parameters.Read.Length;
            Status = STATUS_SUCCESS;
            break;
          }

        default:
            DbgPrint( "[chipsec] ERROR: invalid IOCTL\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

      } // -- switch

    // -- restore current KAFFINITY
    KeRevertToUserAffinityThreadEx( _kaffinity );
    _cpu_thread_id = KeGetCurrentProcessorNumberEx( &_proc_number );
    DbgPrint( "[chipsec] Restored active CPU mask (KAFFINITY): 0x%08X\n", KeQueryGroupAffinity( _proc_number.Group ) );
    DbgPrint( "[chipsec] Current CPU group                   : %u\n", _proc_number.Group );
    DbgPrint( "[chipsec] Current CPU number                  : %u\n", _proc_number.Number );
    DbgPrint( "[chipsec] Current CPU thread                  : %ul\n", _cpu_thread_id );
 
    // -- Complete the I/O request, Record the status of the I/O action.
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = dwBytesWritten;

    DbgPrint( "[chipsec] Irp->IoStatus.Status = 0x%x, Irp->IoStatus.Information = 0x%x\n", Irp->IoStatus.Status, Irp->IoStatus.Information );
    DbgPrint( "[chipsec]\n" );

    IoCompleteRequest( Irp, IO_NO_INCREMENT );
    return Status;

}

#pragma code_seg()

