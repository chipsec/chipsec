/***
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


#include <ntddk.h>
#include <wdmsec.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "driver.h"

//#pragma comment(lib, "wdmsec.lib")
//#pragma comment(lib, "bufferoverflowK.lib") 

#pragma comment(linker, "/section:chipsec_code,EWP")

#pragma code_seg("chipsec_code$__c")

UINT32
ReadPCICfg(
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
WritePCICfg(
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
  unsigned int m = len / 8;
  unsigned int r = len % 8;
  unsigned char line[3*8 + 1];
  unsigned char * line_ptr = line;
  for( i = 0; i < m; i++ )
    DbgPrint( "%02X %02X %02X %02X %02X %02X %02X %02X : %c %c %c %c %c %c %c %c\n", b[i*8], b[i*8+1], b[i*8+2], b[i*8+3], b[i*8+4], b[i*8+5], b[i*8+6], b[i*8+7], b[i*8], b[i*8+1], b[i*8+2], b[i*8+3], b[i*8+4], b[i*8+5], b[i*8+6], b[i*8+7] );

  for( i = 0; i < r; i++ ) line_ptr += sprintf( line_ptr, "%02X ", b[m*8 + i] );
  *(line_ptr + 1) = '\0';
  DbgPrint( "%s\n", line );
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

    //
    // Initialize a unicode string for the drivers object name.
    //
    RtlInitUnicodeString( &DeviceName, DEVICE_NAME_U );

    //
    // Attempt to create a named device object
    // 

//
// SDDL_DEVOBJ_SYS_ALL_ADM_ALL allows the kernel, system, and admin complete
// control over the device. No other users may access the device
//
/*
DECLARE_CONST_UNICODE_STRING(
    SDDL_DEVOBJ_SYS_ALL_ADM_ALL,
    L"D:P(A;;GA;;;SY)(A;;GA;;;BA)"
    );
*/

// -- Security descriptor
//RtlInitUnicodeString(&sd,
//  _T("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;BU)(A;;GA;;;WD)"));

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

    //
    // Create the symbolic link that the Win32 app can access the device
    //
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

    //
    // Initialize the dispatch table of the driver object.
    // NT sends requests to these routines.
    //
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = DriverOpen;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = DriverClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDeviceControl;
    DriverObject->DriverUnload                         = DriverUnload;

    return Status;

}


NTSTATUS
DriverOpen(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp
    )
{

    DbgPrint( "[chipsec] >> DriverOpen (DeviceObject = 0x%x)\n", DeviceObject );

    //
    // Complete the request and return status.
    //
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
    
    DbgPrint( "[chipsec] >> DriverClose (DeviceObject = 0x%x)\n", DeviceObject );

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

    DbgPrint( "[chipsec] >> DriverUnload (DriverObject = 0x%x)\n", DriverObject );

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
  DbgPrint( "[chipsec] reading %d bytes from physical address 0x%08x_%08x (virtual = %#010x)", len, pa.HighPart, pa.LowPart, (unsigned int)va );
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
  DbgPrint( "[chipsec] writing %d bytes to physical address 0x%08x_%08x (virtual = %#010x)", len, pa.HighPart, pa.LowPart, (unsigned int)va );
  RtlCopyMemory( va, pData, len );
  MmUnmapIoSpace( va, len );
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
    KAFFINITY          _kaffinity = 0;
    UINT32             core_id = 0;

    //
    // Get the current IRP stack location of this request
    //
    IrpSp = IoGetCurrentIrpStackLocation (Irp);
    IOControlCode = IrpSp->Parameters.DeviceIoControl.IoControlCode;

    DbgPrint( "[chipsec] >>>>>>>>>> IOCTL >>>>>>>>>>\n" );
    DbgPrint( "[chipsec] DeviceObject = 0x%x IOCTL = 0x%x\n", DeviceObject, IOControlCode );
    DbgPrint( "[chipsec] InputBufferLength = 0x%x, OutputBufferLength = 0x%x\n", IrpSp->Parameters.DeviceIoControl.InputBufferLength, IrpSp->Parameters.DeviceIoControl.OutputBufferLength );

    //
    // CPU thread ID
    // 
    _num_active_cpus = KeQueryActiveProcessorCount( NULL );
    _kaffinity       = KeQueryActiveProcessors();
    _cpu_thread_id   = KeGetCurrentProcessorNumber();
    DbgPrint( "[chipsec] Active CPU threads         : %d (KeNumberProcessors = %d)\n", _num_active_cpus, KeNumberProcessors );
    DbgPrint( "[chipsec] Active CPU mask (KAFFINITY): 0x%08X\n", _kaffinity );
    DbgPrint( "[chipsec] Current CPU thread         : %d\n", _cpu_thread_id );

    //
    // Switch on the IOCTL code that is being requested by the user.  If the
    // operation is a valid one for this device do the needful.
    //
    Irp -> IoStatus.Information = 0;
    switch( IOControlCode )
      {
        case READ_PCI_CFG_REGISTER:
          {
            DWORD val;
            BYTE size = 0;
            WORD bdf[4];
            BYTE bus = 0, dev = 0, fun = 0, off = 0;
            DbgPrint( "[chipsec] > READ_PCI_CFG_REGISTER\n" );

            RtlCopyBytes( bdf,Irp->AssociatedIrp.SystemBuffer, 4*sizeof(WORD) );
            RtlCopyBytes( &size, (BYTE*)Irp->AssociatedIrp.SystemBuffer + 4*sizeof(WORD), sizeof(BYTE) );
            bus = (UINT8)bdf[0];
            dev = (UINT8)bdf[1];
            fun = (UINT8)bdf[2];
            off = (UINT8)bdf[3];

            if( 1 != size && 2 != size && 4 != size)
              {
              DbgPrint( "[chipsec] ERROR: STATUS_INVALID_PARAMETER\n" );
              Status = STATUS_INVALID_PARAMETER;
              break;
              }
            val = ReadPCICfg( bus, dev, fun, off, size );             

            IrpSp->Parameters.Read.Length = size;
            RtlCopyBytes( Irp->AssociatedIrp.SystemBuffer, (VOID*)&val, size );
            DbgPrint( "[chipsec][READ_PCI_CFG_REGISTER] B/D/F: %#04x/%#04x/%#04x, OFFSET: %#04x, value = %#010x (size = 0x%x)\n", bus, dev, fun, off, val, size );

            dwBytesWritten = IrpSp->Parameters.Read.Length;
            Status = STATUS_SUCCESS;
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
            WritePCICfg( bus, dev, fun, off, size, val );

            Status = STATUS_SUCCESS;
            break;
          }
        case IOCTL_READ_PHYSMEM:
          {
            UINT32 len = 0;
            PVOID virt_addr;
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
            PVOID virt_addr = 0;
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
                ((UINT32*)pInBuf) += 3;

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

                break;
              }
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
            UINT64 va = 0x0;
            pInBuf  = Irp->AssociatedIrp.SystemBuffer;
            pOutBuf = Irp->AssociatedIrp.SystemBuffer;

            DbgPrint( "[chipsec] > IOCTL_FREE_PHYSMEM\n" );
            if( !Irp->AssociatedIrp.SystemBuffer ||
                IrpSp->Parameters.DeviceIoControl.InputBufferLength != sizeof(UINT64))
            {
               DbgPrint( "[chipsec] ERROR: STATUS_INVALID_PARAMETER\n" );
               Status = STATUS_INVALID_PARAMETER;
               break;
            }

            RtlCopyBytes( &va, (BYTE*)Irp->AssociatedIrp.SystemBuffer, sizeof(UINT64) );
            DbgPrint( "[chipsec][IOCTL_FREE_PHYSMEM] Virtual address of the memory being freed: 0x%I64X\n", va );
            MmFreeContiguousMemory( (PVOID)va );

            IrpSp->Parameters.Read.Length = 0;
            dwBytesWritten = IrpSp->Parameters.Read.Length;
            Status = STATUS_SUCCESS;
            break;
          }

        case IOCTL_GET_PHYSADDR:
          {
            UINT64 va = 0x0;
            PHYSICAL_ADDRESS pa = { 0x0, 0x0 };

            pInBuf  = Irp->AssociatedIrp.SystemBuffer;
            pOutBuf = Irp->AssociatedIrp.SystemBuffer;

            DbgPrint( "[chipsec] > IOCTL_GET_PHYSADDR\n" );
            if( !Irp->AssociatedIrp.SystemBuffer ||
                IrpSp->Parameters.DeviceIoControl.InputBufferLength != sizeof(UINT64))
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

            RtlCopyBytes( &va, (BYTE*)Irp->AssociatedIrp.SystemBuffer, sizeof(UINT64) );
            pa = MmGetPhysicalAddress( (PVOID)va );

            DbgPrint( "[chipsec][IOCTL_GET_PHYSADDR] Traslated virtual address 0x%I64X to physical: 0x%I64X\n", va, pa.QuadPart, pa.LowPart);
            RtlCopyBytes( Irp->AssociatedIrp.SystemBuffer, (void*)&pa, sizeof(UINT64) );
            IrpSp->Parameters.Read.Length = sizeof(UINT64);
            dwBytesWritten = IrpSp->Parameters.Read.Length;
            Status = STATUS_SUCCESS;
            break;
          }

        case IOCTL_LOAD_UCODE_PATCH:
          {
            PVOID ucode_buf = NULL;
            UINT64 ucode_start = 0;
            UINT16 ucode_size = 0;
            UINT32 _eax = 0, _edx = 0;
            int CPUInfo[4] = {-1};

            DbgPrint("[chipsec] > IOCTL_LOAD_UCODE_UPDATE\n" );

            if( !Irp->AssociatedIrp.SystemBuffer ||
                IrpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(BYTE) + sizeof(UINT16) )
            {
               DbgPrint( "[chipsec] ERROR: STATUS_INVALID_PARAMETER (input buffer size < 3)\n" );
               Status = STATUS_INVALID_PARAMETER;
               break;
            }

            RtlCopyBytes( &new_cpu_thread_id, (BYTE*)Irp->AssociatedIrp.SystemBuffer, sizeof(BYTE) );
            if( new_cpu_thread_id >= _num_active_cpus ) new_cpu_thread_id = 0;
            KeSetSystemAffinityThread( (KAFFINITY)(1 << new_cpu_thread_id) );
            DbgPrint( "[chipsec][IOCTL_LOAD_UCODE_UPDATE] Changed CPU thread to %d\n", KeGetCurrentProcessorNumber() );

            RtlCopyBytes( &ucode_size, (BYTE*)Irp->AssociatedIrp.SystemBuffer + sizeof(BYTE), sizeof(UINT16) );
            DbgPrint( "[chipsec][IOCTL_LOAD_UCODE_UPDATE] Ucode update size = 0x%X\n", ucode_size );

            if( IrpSp->Parameters.DeviceIoControl.InputBufferLength < ucode_size + sizeof(BYTE) + sizeof(UINT16) )
              {
                DbgPrint( "[chipsec] ERROR: STATUS_INVALID_PARAMETER (input buffer size < ucode_size + 3)\n" );
                Status = STATUS_INVALID_PARAMETER;
                break;
              }

            ucode_buf = ExAllocatePoolWithTag( NonPagedPool, ucode_size, 0x3184 );
            if( !ucode_buf )
              {
                DbgPrint( "[chipsec] ERROR: couldn't allocate pool for ucode binary\n" );
                break;
              }           
            RtlCopyBytes( ucode_buf, (BYTE*)Irp->AssociatedIrp.SystemBuffer + sizeof(BYTE) + sizeof(UINT16), ucode_size );
            ucode_start = (UINT64)ucode_buf;
            DbgPrint( "[chipsec][IOCTL_LOAD_UCODE_UPDATE] ucode update address = 0x%p (eax = 0x%08X, edx = 0x%08X)\n", ucode_start, (UINT32)(ucode_start & 0xFFFFFFFF), (UINT32)((ucode_start >> 32) & 0xFFFFFFFF) );
            DbgPrint( "[chipsec][IOCTL_LOAD_UCODE_UPDATE] ucode update contents:\n" );
            _dump_buffer( (unsigned char *)ucode_buf, min(ucode_size,0x100) );

            // --
            // -- trigger CPU ucode patch update
            // -- pInBuf points to the beginning of ucode update binary
            // --
            _wrmsr( MSR_IA32_BIOS_UPDT_TRIG, (UINT32)((ucode_start >> 32) & 0xFFFFFFFF), (UINT32)(ucode_start & 0xFFFFFFFF) );

            ExFreePoolWithTag( ucode_buf, 0x3184 );

            // --
            // -- check if patch was loaded
            // --
            // -- need to clear IA32_BIOS_SIGN_ID MSR first
            // -- CPUID will deposit an update ID value in 64-bit MSR at address MSR_IA32_BIOS_SIGN_ID
            // -- read IA32_BIOS_SIGN_ID MSR to check patch ID != 0
            // --
            DbgPrint( "[chipsec][IOCTL_LOAD_UCODE_UPDATE] checking ucode update was loaded..\n" );
            DbgPrint( "[chipsec][IOCTL_LOAD_UCODE_UPDATE] clear IA32_BIOS_SIGN_ID, CPUID EAX=1, read back IA32_BIOS_SIGN_ID\n" );
            _wrmsr( MSR_IA32_BIOS_SIGN_ID, 0, 0 );
            __cpuid(CPUInfo, 1);
            _rdmsr( MSR_IA32_BIOS_SIGN_ID, &_eax, &_edx );
            DbgPrint( "[chipsec][IOCTL_LOAD_UCODE_UPDATE] RDMSR( IA32_BIOS_SIGN_ID=0x8b ) = 0x%08x%08x\n", _edx, _eax );
            if( 0 != _edx ) DbgPrint( "[chipsec][IOCTL_LOAD_UCODE_UPDATE] Microcode update loaded (ID != 0)\n" );
            else            DbgPrint( "[chipsec] ERROR: Microcode update failed\n" );

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
            if( IrpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(BYTE) + 3*sizeof(UINT32) )
              {
                DbgPrint( "[chipsec][IOCTL_WRMSR] ERROR: STATUS_INVALID_PARAMETER (input buffer size < sizeof(BYTE) + 3*sizeof(UINT32))\n" );
                Status = STATUS_INVALID_PARAMETER;
                break;
              }

            RtlCopyBytes( &new_cpu_thread_id, (BYTE*)Irp->AssociatedIrp.SystemBuffer, sizeof(BYTE) );
            if( new_cpu_thread_id >= _num_active_cpus ) new_cpu_thread_id = 0;
            KeSetSystemAffinityThread( (KAFFINITY)(1 << new_cpu_thread_id) );
            DbgPrint( "[chipsec][IOCTL_WRMSR] Changed CPU thread to %d\n", KeGetCurrentProcessorNumber() );

            RtlCopyBytes( msrData, (BYTE*)Irp->AssociatedIrp.SystemBuffer + sizeof(BYTE), 3 * sizeof(UINT32) );
            _msr_addr = msrData[0];
            _eax      = msrData[1];
            _edx      = msrData[2];
            DbgPrint( "[chipsec][IOCTL_WRMSR] WRMSR( 0x%x ) <-- 0x%08x%08x\n", _msr_addr, _edx, _eax );

            // --
            // -- write MSR
            // --
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

            // --
            // -- read MSR to check if it was written
            // --
//            _rdmsr( _msr_addr, &_eax, &_edx );
//            DbgPrint( "[chipsec][IOCTL_WRMSR] RDMSR( 0x%x ) --> 0x%08x%08x\n", _msr_addr, _edx, _eax );

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
            if( IrpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(BYTE) + sizeof(UINT32) )
              {
                DbgPrint( "[chipsec] ERROR: STATUS_INVALID_PARAMETER - input buffer size < sizeof(BYTE) + sizeof(UINT32)\n" );
                Status = STATUS_INVALID_PARAMETER;
                break;
              }

            RtlCopyBytes( &new_cpu_thread_id, (BYTE*)Irp->AssociatedIrp.SystemBuffer, sizeof(BYTE) );
            if( new_cpu_thread_id >= _num_active_cpus ) new_cpu_thread_id = 0;
            KeSetSystemAffinityThread( (KAFFINITY)(1 << new_cpu_thread_id) );
            DbgPrint( "[chipsec][IOCTL_RDMSR] Changed CPU thread to %d\n", KeGetCurrentProcessorNumber() );

            RtlCopyBytes( msrData, (BYTE*)Irp->AssociatedIrp.SystemBuffer + sizeof(BYTE), sizeof(UINT32) );
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

            RtlCopyBytes( &new_cpu_thread_id, (BYTE*)Irp->AssociatedIrp.SystemBuffer, sizeof(BYTE) );
            if( new_cpu_thread_id >= _num_active_cpus ) new_cpu_thread_id = 0;
            KeSetSystemAffinityThread( (KAFFINITY)(1 << new_cpu_thread_id) );
            DbgPrint( "[chipsec][GET_CPU_DESCRIPTOR_TABLE] Changed CPU thread to %d\n", KeGetCurrentProcessorNumber() );
            RtlCopyBytes( &dt_code, (BYTE*)Irp->AssociatedIrp.SystemBuffer + sizeof(BYTE), sizeof(BYTE) );
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
            CPU_REG_TYPE gprs[6] = {0};
            CPU_REG_TYPE _rax = 0, _rbx = 0, _rcx = 0, _rdx = 0, _rsi = 0, _rdi = 0;
            unsigned int _smi_code_data = 0;

            DbgPrint("[chipsec] > IOCTL_SWSMI\n");
            pInBuf = Irp->AssociatedIrp.SystemBuffer;
            if( !pInBuf )
              {
	        DbgPrint( "[chipsec] ERROR: NO data provided\n" );
                Status = STATUS_INVALID_PARAMETER;
                break;
              }
            if( IrpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(UINT16) + sizeof(gprs) )
              {
                DbgPrint( "[chipsec] ERROR: STATUS_INVALID_PARAMETER (input buffer size < sizeof(UINT16) + sizeof(gprs))\n" );
                Status = STATUS_INVALID_PARAMETER;
                break;
              }
            RtlCopyBytes( &_smi_code_data, (BYTE*)Irp->AssociatedIrp.SystemBuffer, sizeof(UINT16) );
            RtlCopyBytes( gprs, (BYTE*)Irp->AssociatedIrp.SystemBuffer + sizeof(UINT16), sizeof(gprs) );
            _rax = gprs[ 0 ];
            _rbx = gprs[ 1 ];
            _rcx = gprs[ 2 ];
            _rdx = gprs[ 3 ];
            _rsi = gprs[ 4 ];
            _rdi = gprs[ 5 ];
            DbgPrint( "[chipsec][IOCTL_SWSMI] SW SMI to ports 0x%X-0x%X <- 0x%04X\n", 0xB2, 0xB3, _smi_code_data );
            DbgPrint( "                       RAX = 0x%I64x\n", _rax );
            DbgPrint( "                       RBX = 0x%I64x\n", _rbx );
            DbgPrint( "                       RCX = 0x%I64x\n", _rcx );
            DbgPrint( "                       RDX = 0x%I64x\n", _rdx );
            DbgPrint( "                       RSI = 0x%I64x\n", _rsi );
            DbgPrint( "                       RDI = 0x%I64x\n", _rdi );
            // --
            // -- send SMI using port 0xB2
            // --
            __try
              {
                _swsmi( _smi_code_data, _rax, _rbx, _rcx, _rdx, _rsi, _rdi );
              }
            __except( EXCEPTION_EXECUTE_HANDLER )
              {
                Status = GetExceptionCode();
                break;
              }
            Status = STATUS_SUCCESS;
            break;
          }
        case IOCTL_CPUID:
          {
            DWORD CPUInfo[4] = {-1};
            DWORD gprs[2] = {0};
            DWORD _rax = 0, _rcx = 0;
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
                DbgPrint( "[chipsec] ERROR: STATUS_INVALID_PARAMETER (input buffer size < %d)\n", sizeof(gprs) );
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

            if( IrpSp->Parameters.DeviceIoControl.InputBufferLength < (sizeof(cr_reg) + sizeof(val64) + sizeof(BYTE)))
            {
                 Status = STATUS_INVALID_PARAMETER;
                 break;
            }

            RtlCopyBytes( &cr_reg, (BYTE*)Irp->AssociatedIrp.SystemBuffer, sizeof(cr_reg) );
            RtlCopyBytes( &val64, (BYTE*)Irp->AssociatedIrp.SystemBuffer + sizeof(cr_reg), sizeof(val64) );
            new_cpu_thread_id = *((BYTE*)Irp->AssociatedIrp.SystemBuffer + sizeof(cr_reg) + sizeof(val64));
            if( new_cpu_thread_id >= _num_active_cpus )
            {
            //    new_cpu_thread_id = 0;
                 Status = STATUS_INVALID_PARAMETER;
                 break;
            }

            KeSetSystemAffinityThread( (KAFFINITY)(1 << new_cpu_thread_id) );
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

            if( IrpSp->Parameters.DeviceIoControl.InputBufferLength < (sizeof(cr_reg)+sizeof(BYTE))
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
            //    new_cpu_thread_id = 0;
                 Status = STATUS_INVALID_PARAMETER;
                 break;
            }

            KeSetSystemAffinityThread( (KAFFINITY)(1 << new_cpu_thread_id) );

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
        default:
            DbgPrint( "[chipsec] ERROR: invalid IOCTL\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

      } // -- switch

    // -- restore current KAFFINITY
    KeSetSystemAffinityThread( _kaffinity );
    DbgPrint( "[chipsec] Restored active CPU mask (KAFFINITY): 0x%08X\n", KeQueryActiveProcessors() );
    DbgPrint( "[chipsec] Current CPU thread                  : %d\n", KeGetCurrentProcessorNumber() );

    // --
    // -- Complete the I/O request, Record the status of the I/O action.
    // --
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = dwBytesWritten;

    DbgPrint( "[chipsec] Irp->IoStatus.Status = 0x%x, Irp->IoStatus.Information = 0x%x\n", Irp->IoStatus.Status, Irp->IoStatus.Information );
    DbgPrint( "[chipsec]\n" );

    IoCompleteRequest( Irp, IO_NO_INCREMENT );
    return Status;

}

#pragma code_seg()

