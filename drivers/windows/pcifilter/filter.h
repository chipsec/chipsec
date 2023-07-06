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

#ifndef _FILT_H
#define _FILT_H


typedef enum tagDEVICE_PNP_STATE
{
    NotStarted = 0,           // Not started yet
    Started,                // Device has received the START_DEVICE IRP
    StopPending,            // Device has received the QUERY_STOP IRP
    Stopped,                // Device has received the STOP_DEVICE IRP
    RemovePending,          // Device has received the QUERY_REMOVE IRP
    SurpriseRemovePending,  // Device has received the SURPRISE_REMOVE IRP
    Deleted                 // Device has received the REMOVE_DEVICE IRP
} DEVICE_PNP_STATE;

#define INITIALIZE_PNP_STATE(_Data_)	\
    (_Data_)->DevicePnPState=NotStarted;\
    (_Data_)->PreviousPnPState=NotStarted;

#define SET_NEW_PNP_STATE(_Data_, _state_)	\
    (_Data_)->PreviousPnPState=(_Data_)->DevicePnPState;	\
    (_Data_)->DevicePnPState=(_state_);

#define RESTORE_PREVIOUS_PNP_STATE(_Data_)	\
    (_Data_)->DevicePnPState=(_Data_)->PreviousPnPState;

typedef struct tagDEVICE_EXTENSION
{
    //physical device object
    PDEVICE_OBJECT pdo;

    //the device object we attached to
    PDEVICE_OBJECT lowerdo;

    //current pnp state
    DEVICE_PNP_STATE DevicePnPState;

    //previous pnp state
    DEVICE_PNP_STATE PreviousPnPState;

    //Remove Lock
    IO_REMOVE_LOCK rmLock;

} DEVICE_EXTENSION, * PDEVICE_EXTENSION;
#endif  //_FILT_H


