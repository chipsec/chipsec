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

#include <wdm.h>
#include "filter.h"
#include "flt_dbg.h"

NTSTATUS DriverEntry(IN PDRIVER_OBJECT dro, IN PUNICODE_STRING RegistryPath);

NTSTATUS PCIFltAddDevice(IN PDRIVER_OBJECT dro, IN PDEVICE_OBJECT pdo);
NTSTATUS PCIFltPnp(IN PDEVICE_OBJECT fido, IN PIRP irp);
NTSTATUS PCIFltPower(IN PDEVICE_OBJECT fido, IN PIRP irp);
VOID PCIFltUnload(IN PDRIVER_OBJECT dro);

NTSTATUS PCIFltCreate(IN PDEVICE_OBJECT fido, IN PIRP irp);
NTSTATUS PCIFltClose(IN PDEVICE_OBJECT fido, IN PIRP irp);
NTSTATUS PCIFltDevCtl(IN PDEVICE_OBJECT fido, IN PIRP irp);

NTSTATUS PassIRP(IN PDEVICE_OBJECT fido, IN PIRP irp);
NTSTATUS StartCompletion(IN PDEVICE_OBJECT fido, IN PIRP irp, IN PVOID Context);
NTSTATUS DevUsgNotifyCompletion(IN PDEVICE_OBJECT fido, IN PIRP irp, IN PVOID Context);

#pragma alloc_text(INIT, DriverEntry)

NTSTATUS DriverEntry(IN PDRIVER_OBJECT dro, IN PUNICODE_STRING RegistryPath)
{
    ULONG i;

    UNREFERENCED_PARAMETER(RegistryPath);

    DebugPrintInit("PCIFilter");

    //initialize all functions to PCIFltPass
    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
        dro->MajorFunction[i] = PassIRP;

    //we should handle PNP, POWER, AddDevice, Unload
    dro->MajorFunction[IRP_MJ_PNP] = PCIFltPnp;
    dro->MajorFunction[IRP_MJ_POWER] = PCIFltPower;
    dro->MajorFunction[IRP_MJ_DEVICE_CONTROL] = PCIFltDevCtl;
    dro->DriverExtension->AddDevice = PCIFltAddDevice;
    dro->DriverUnload = PCIFltUnload;

    //we should handle CREATE, CLOSE because pci bus
    //driver didn't implement these, without doing so
    //will prevent other driver to reference this device
    dro->MajorFunction[IRP_MJ_CREATE] = PCIFltCreate;
    dro->MajorFunction[IRP_MJ_CLOSE] = PCIFltClose;

    return STATUS_SUCCESS;
}

NTSTATUS PCIFltAddDevice(IN PDRIVER_OBJECT dro, IN PDEVICE_OBJECT pdo)
{
    NTSTATUS ntStatus = STATUS_SUCCESS;
    PDEVICE_OBJECT fido = NULL;
    PDEVICE_EXTENSION dx;
    UNICODE_STRING devNameU;

    PAGED_CODE();

    DebugPrintMsg("AddDevice started");

    RtlInitUnicodeString(&devNameU, L"\\Device\\ChipsecPCIFilter");

    //create a filter device object.
    ntStatus = IoCreateDevice(dro,
        sizeof(DEVICE_EXTENSION),
        &devNameU,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &fido);

    if (!NT_SUCCESS(ntStatus))
    {
        //Returning failure here prevents the entire stack from functioning,
        //but most likely the rest of the stack will not be able to create
        //device objects either, so it is still OK.
        return ntStatus;
    }

    dx = (PDEVICE_EXTENSION)fido->DeviceExtension;

    //initialize remove lock
    IoInitializeRemoveLock(&dx->rmLock, 'PBF', 1, 5);

    //attach to pci bus driver
    dx->lowerdo = IoAttachDeviceToDeviceStack(fido, pdo);
    if (dx->lowerdo == NULL)
    {
        //Failure for attachment is an indication of a broken plug & play system.
        IoDeleteDevice(fido);
        return STATUS_UNSUCCESSFUL;
    }

    //flags needs inherit from lower device object(pci bus driver)
    fido->Flags |= (dx->lowerdo->Flags & (DO_BUFFERED_IO | DO_DIRECT_IO | DO_POWER_PAGABLE));

    //update device type
    fido->DeviceType = dx->lowerdo->DeviceType;

    //update device characteristics
    fido->Characteristics = dx->lowerdo->Characteristics;

    //save physical device object
    dx->pdo = pdo;

    //set the initial state of the Filter DO
    INITIALIZE_PNP_STATE(dx);

    DebugPrintMsg("AddDevice succeeded");
    DebugPrint("PCI pdo=0x%x, fdo=0x%x, fido=0x%x", pdo, dx->lowerdo, fido);

    fido->Flags &= ~DO_DEVICE_INITIALIZING;

    return STATUS_SUCCESS;
}

//skip irp, just pass down
NTSTATUS PassIRP(IN PDEVICE_OBJECT fido, IN PIRP irp)
{
    PDEVICE_EXTENSION dx;
    NTSTATUS ntStatus;

    dx = (PDEVICE_EXTENSION)fido->DeviceExtension;

    //acquire remove lock
    ntStatus = IoAcquireRemoveLock(&dx->rmLock, irp);
    if (!NT_SUCCESS(ntStatus))
    {
        //complete irp if cannot acquire remove lock
        irp->IoStatus.Status = ntStatus;
        irp->IoStatus.Information = 0;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return ntStatus;
    }

    //just pass irp down, we never need it
    IoSkipCurrentIrpStackLocation(irp);
    ntStatus = IoCallDriver(dx->lowerdo, irp);

    //release remove lock
    IoReleaseRemoveLock(&dx->rmLock, irp);

    return ntStatus;
}

//pnp handler
NTSTATUS PCIFltPnp(IN PDEVICE_OBJECT fido, IN PIRP irp)
{
    PDEVICE_EXTENSION dx;
    PIO_STACK_LOCATION irpStack;
    NTSTATUS ntStatus;

    PAGED_CODE();

    dx = (PDEVICE_EXTENSION)fido->DeviceExtension;
    irpStack = IoGetCurrentIrpStackLocation(irp);

    //acquire remove lock
    ntStatus = IoAcquireRemoveLock(&dx->rmLock, irp);
    if (!NT_SUCCESS(ntStatus))
    {
        //complete irp if cannot acquire remove lock
        irp->IoStatus.Status = ntStatus;
        irp->IoStatus.Information = 0;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return ntStatus;
    }

    //default to success
    ntStatus = STATUS_SUCCESS;

    switch (irpStack->MinorFunction)
    {
    case IRP_MN_START_DEVICE:
        //The device is starting.
        //We cannot touch the device (send it any non pnp irps) until a
        //start device has been passed down to the lower drivers.
        IoCopyCurrentIrpStackLocationToNext(irp);
        IoSetCompletionRoutine(irp,
            (PIO_COMPLETION_ROUTINE)StartCompletion,
            NULL,
            TRUE,
            TRUE,
            TRUE);

        return IoCallDriver(dx->lowerdo, irp);

    case IRP_MN_REMOVE_DEVICE:

        IoSkipCurrentIrpStackLocation(irp);
        ntStatus = IoCallDriver(dx->lowerdo, irp);

        //release remove lock, wait until all acquisitions has been released
        IoReleaseRemoveLockAndWait(&dx->rmLock, irp);

        SET_NEW_PNP_STATE(dx, Deleted);

        IoDetachDevice(dx->lowerdo);
        IoDeleteDevice(fido);

        return ntStatus;

    case IRP_MN_QUERY_STOP_DEVICE:

        SET_NEW_PNP_STATE(dx, StopPending);

        break;

    case IRP_MN_CANCEL_STOP_DEVICE:
        //Check to see whether you have received cancel-stop
        //without first receiving a query-stop. This could happen if someone
        //above us fails a query-stop and passes down the subsequent
        //cancel-stop.
        if (dx->DevicePnPState == StopPending)
        {
            //We did receive a query-stop, so restore.
            RESTORE_PREVIOUS_PNP_STATE(dx);
        }
        //We must not fail this IRP.

        break;

    case IRP_MN_STOP_DEVICE:

        SET_NEW_PNP_STATE(dx, Stopped);

        break;

    case IRP_MN_QUERY_REMOVE_DEVICE:

        SET_NEW_PNP_STATE(dx, RemovePending);

        break;

    case IRP_MN_SURPRISE_REMOVAL:

        SET_NEW_PNP_STATE(dx, SurpriseRemovePending);

        break;

    case IRP_MN_CANCEL_REMOVE_DEVICE:
        //Check to see whether you have received cancel-remove
        //without first receiving a query-remove. This could happen if
        //someone above us fails a query-remove and passes down the
        //subsequent cancel-remove.
        if (dx->DevicePnPState == RemovePending)
        {
            //We did receive a query-remove, so restore.
            RESTORE_PREVIOUS_PNP_STATE(dx);
        }
        //We must not fail this IRP.

        break;

    case IRP_MN_DEVICE_USAGE_NOTIFICATION:
        //On the way down, pagable might become set. Mimic the driver
        //above us. If no one is above us, just set pagable.
        if ((fido->AttachedDevice == NULL) ||
            (fido->AttachedDevice->Flags & DO_POWER_PAGABLE))
        {
            fido->Flags |= DO_POWER_PAGABLE;
        }

        IoCopyCurrentIrpStackLocationToNext(irp);
        IoSetCompletionRoutine(irp,
            DevUsgNotifyCompletion,
            NULL,
            TRUE,
            TRUE,
            TRUE);

        return IoCallDriver(dx->lowerdo, irp);

    default:

        break;
    }

    //Pass irp down and forget it.
    IoSkipCurrentIrpStackLocation(irp);
    ntStatus = IoCallDriver(dx->lowerdo, irp);

    //release remove lock
    IoReleaseRemoveLock(&dx->rmLock, irp);

    return ntStatus;
}

//PNP START DEVICE irp completion routine
NTSTATUS StartCompletion(IN PDEVICE_OBJECT fido, IN PIRP irp, IN PVOID Context)
{
    PDEVICE_EXTENSION dx;

    UNREFERENCED_PARAMETER(Context);

    dx = (PDEVICE_EXTENSION)fido->DeviceExtension;

    //must do this if we don't return STATUS_MORE_PROCESSING_REQUIRED !
    if (irp->PendingReturned)
        IoMarkIrpPending(irp);

    if (NT_SUCCESS(irp->IoStatus.Status))
    {
        //As we are successfully now back, we will
        //first set our state to Started.
        SET_NEW_PNP_STATE(dx, Started);

        //On the way up inherit FILE_REMOVABLE_MEDIA during Start.
        //This characteristic is available only after the driver stack is started!.
        if (dx->lowerdo->Characteristics & FILE_REMOVABLE_MEDIA)
        {
            fido->Characteristics |= FILE_REMOVABLE_MEDIA;
        }
    }

    //release remove lock
    IoReleaseRemoveLock(&dx->rmLock, irp);

    return STATUS_SUCCESS;
}

//PNP DEVICE USAGE NOTIFICATION irp completion routine
NTSTATUS DevUsgNotifyCompletion(IN PDEVICE_OBJECT fido, IN PIRP	irp, IN PVOID Context)
{
    PDEVICE_EXTENSION dx;

    UNREFERENCED_PARAMETER(Context);

    dx = (PDEVICE_EXTENSION)fido->DeviceExtension;

    //must do this if we don't return STATUS_MORE_PROCESSING_REQUIRED !
    if (irp->PendingReturned)
    {
        IoMarkIrpPending(irp);
    }

    //On the way up, pagable might become clear. Mimic the driver below us.
    if (!(dx->lowerdo->Flags & DO_POWER_PAGABLE))
    {
        fido->Flags &= ~DO_POWER_PAGABLE;
    }

    //release remove lock
    IoReleaseRemoveLock(&dx->rmLock, irp);

    return STATUS_SUCCESS;
}

//power pnp
NTSTATUS PCIFltPower(IN PDEVICE_OBJECT fido, IN PIRP irp)
{
    PDEVICE_EXTENSION dx;
    NTSTATUS ntStatus;

    dx = (PDEVICE_EXTENSION)fido->DeviceExtension;

    PoStartNextPowerIrp(irp);

    //acquire remove lock
    ntStatus = IoAcquireRemoveLock(&dx->rmLock, irp);
    if (!NT_SUCCESS(ntStatus))
    {
        //complete irp if cannot acquire remove lock
        irp->IoStatus.Status = ntStatus;
        irp->IoStatus.Information = 0;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return ntStatus;
    }

    IoSkipCurrentIrpStackLocation(irp);
    ntStatus = PoCallDriver(dx->lowerdo, irp);

    //release remove lock
    IoReleaseRemoveLock(&dx->rmLock, irp);

    return ntStatus;
}

NTSTATUS PCIFltCreate(IN PDEVICE_OBJECT fido, IN PIRP irp)
{
    UNREFERENCED_PARAMETER(fido);

    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;

    IoCompleteRequest(irp, IO_NO_INCREMENT);

    DebugPrintMsg("IRP_MJ_CREATE");

    return STATUS_SUCCESS;
}

NTSTATUS PCIFltClose(IN PDEVICE_OBJECT fido, IN PIRP irp)
{
    UNREFERENCED_PARAMETER(fido);

    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;

    IoCompleteRequest(irp, IO_NO_INCREMENT);

    DebugPrintMsg("IRP_MJ_CLOSE");

    return STATUS_SUCCESS;
}

NTSTATUS PCIFltDevCtl(IN PDEVICE_OBJECT fido, IN PIRP irp)
{
    return PassIRP(fido, irp);
}

VOID PCIFltUnload(IN PDRIVER_OBJECT dro)
{
    PAGED_CODE();

    //The device object(s) should be NULL now
    //since we unload, all the devices objects associated with this
    //driver must be deleted.
    ASSERT(dro->DeviceObject == NULL);

    //We should not be unloaded until all the devices we control
    //have been removed from our queue.

    DebugPrintClose();

    return;
}
