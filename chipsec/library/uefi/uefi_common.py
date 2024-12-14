# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2021, Intel Corporation
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; Version 2.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
# Contact information:
# chipsec@intel.com
#


"""
Common UEFI/EFI functionality including UEFI variables, Firmware Volumes, Secure Boot variables, S3 boot-script, UEFI tables, etc.
"""

import struct
from collections import namedtuple
from typing import Dict, List, Any
from uuid import UUID

from chipsec.library.defines import bytestostring

# from chipsec.helper.oshelper import helper


################################################################################################
#
# Misc Defines
#
################################################################################################

#
# Status codes
# edk2: MdePkg/Include/Base.h
#

# @TODO
# define ENCODE_ERROR(StatusCode)     ((RETURN_STATUS)(MAX_BIT | (StatusCode)))
# define ENCODE_WARNING(a)            (a)

class StatusCode:
    EFI_SUCCESS = 0
    EFI_LOAD_ERROR = 1
    EFI_INVALID_PARAMETER = 2
    EFI_UNSUPPORTED = 3
    EFI_BAD_BUFFER_SIZE = 4
    EFI_BUFFER_TOO_SMALL = 5
    EFI_NOT_READY = 6
    EFI_DEVICE_ERROR = 7
    EFI_WRITE_PROTECTED = 8
    EFI_OUT_OF_RESOURCES = 9
    EFI_VOLUME_CORRUPTED = 10
    EFI_VOLUME_FULL = 11
    EFI_NO_MEDIA = 12
    EFI_MEDIA_CHANGED = 13
    EFI_NOT_FOUND = 14
    EFI_ACCESS_DENIED = 15
    EFI_NO_RESPONSE = 16
    EFI_NO_MAPPING = 17
    EFI_TIMEOUT = 18
    EFI_NOT_STARTED = 19
    EFI_ALREADY_STARTED = 20
    EFI_ABORTED = 21
    EFI_ICMP_ERROR = 22
    EFI_TFTP_ERROR = 23
    EFI_PROTOCOL_ERROR = 24
    EFI_INCOMPATIBLE_VERSION = 25
    EFI_SECURITY_VIOLATION = 26
    EFI_CRC_ERROR = 27
    EFI_END_OF_MEDIA = 28
    EFI_END_OF_FILE = 31
    EFI_INVALID_LANGUAGE = 32
    EFI_COMPROMISED_DATA = 33
    EFI_HTTP_ERROR = 35
    '''
  EFI_WARN_UNKNOWN_GLYPH    = 1
  EFI_WARN_DELETE_FAILURE   = 2
  EFI_WARN_WRITE_FAILURE    = 3
  EFI_WARN_BUFFER_TOO_SMALL = 4
  EFI_WARN_STALE_DATA       = 5
  EFI_WARN_FILE_SYSTEM      = 6
  '''


EFI_STATUS_DICT: Dict[int, str] = {
    StatusCode.EFI_SUCCESS: "EFI_SUCCESS",
    StatusCode.EFI_LOAD_ERROR: "EFI_LOAD_ERROR",
    StatusCode.EFI_INVALID_PARAMETER: "EFI_INVALID_PARAMETER",
    StatusCode.EFI_UNSUPPORTED: "EFI_UNSUPPORTED",
    StatusCode.EFI_BAD_BUFFER_SIZE: "EFI_BAD_BUFFER_SIZE",
    StatusCode.EFI_BUFFER_TOO_SMALL: "EFI_BUFFER_TOO_SMALL",
    StatusCode.EFI_NOT_READY: "EFI_NOT_READY",
    StatusCode.EFI_DEVICE_ERROR: "EFI_DEVICE_ERROR",
    StatusCode.EFI_WRITE_PROTECTED: "EFI_WRITE_PROTECTED",
    StatusCode.EFI_OUT_OF_RESOURCES: "EFI_OUT_OF_RESOURCES",
    StatusCode.EFI_VOLUME_CORRUPTED: "EFI_VOLUME_CORRUPTED",
    StatusCode.EFI_VOLUME_FULL: "EFI_VOLUME_FULL",
    StatusCode.EFI_NO_MEDIA: "EFI_NO_MEDIA",
    StatusCode.EFI_MEDIA_CHANGED: "EFI_MEDIA_CHANGED",
    StatusCode.EFI_NOT_FOUND: "EFI_NOT_FOUND",
    StatusCode.EFI_ACCESS_DENIED: "EFI_ACCESS_DENIED",
    StatusCode.EFI_NO_RESPONSE: "EFI_NO_RESPONSE",
    StatusCode.EFI_NO_MAPPING: "EFI_NO_MAPPING",
    StatusCode.EFI_TIMEOUT: "EFI_TIMEOUT",
    StatusCode.EFI_NOT_STARTED: "EFI_NOT_STARTED",
    StatusCode.EFI_ALREADY_STARTED: "EFI_ALREADY_STARTED",
    StatusCode.EFI_ABORTED: "EFI_ABORTED",
    StatusCode.EFI_ICMP_ERROR: "EFI_ICMP_ERROR",
    StatusCode.EFI_TFTP_ERROR: "EFI_TFTP_ERROR",
    StatusCode.EFI_PROTOCOL_ERROR: "EFI_PROTOCOL_ERROR",
    StatusCode.EFI_INCOMPATIBLE_VERSION: "EFI_INCOMPATIBLE_VERSION",
    StatusCode.EFI_SECURITY_VIOLATION: "EFI_SECURITY_VIOLATION",
    StatusCode.EFI_CRC_ERROR: "EFI_CRC_ERROR",
    StatusCode.EFI_END_OF_MEDIA: "EFI_END_OF_MEDIA",
    StatusCode.EFI_END_OF_FILE: "EFI_END_OF_FILE",
    StatusCode.EFI_INVALID_LANGUAGE: "EFI_INVALID_LANGUAGE",
    StatusCode.EFI_COMPROMISED_DATA: "EFI_COMPROMISED_DATA",
    StatusCode.EFI_HTTP_ERROR: "EFI_HTTP_ERROR"
}

EFI_MAX_BIT = 0x8000000000000000


def EFI_ERROR_STR(error: int) -> str:
    """
    Translates an EFI_STATUS value into its corresponding textual representation.
    """
    error &= ~EFI_MAX_BIT
    try:
        return EFI_STATUS_DICT[error]
    except KeyError:
        return "UNKNOWN"


EFI_GUID_FMT = "16s"
EFI_GUID_SIZE = struct.calcsize(EFI_GUID_FMT)


def EFI_GUID_STR(guid: bytes) -> str:
    guid_str = UUID(bytes_le=guid)
    return str(guid_str).upper()


def align(of:int, size: int) -> int:
    of = (((of + size - 1) // size) * size)
    return of


def bit_set(value: int, mask: int, polarity: bool = False) -> bool:
    if polarity:
        value = ~value
    return ((value & mask) == mask)


def get_3b_size(s_data: bytes) -> int:
    s_str = bytestostring(s_data)
    return (ord(s_str[0]) + (ord(s_str[1]) << 8) + (ord(s_str[2]) << 16))




# #################################################################################################
#
# UEFI Table Parsing Functionality
#
# #################################################################################################
MAX_EFI_TABLE_SIZE = 0x1000

# typedef struct {
#   UINT64  Signature;
#   UINT32  Revision;
#   UINT32  HeaderSize;
#   UINT32  CRC32;
#   UINT32  Reserved;
# } EFI_TABLE_HEADER;

EFI_TABLE_HEADER_FMT = '=8sIIII'
EFI_TABLE_HEADER_SIZE = 0x18


class EFI_TABLE_HEADER(namedtuple('EFI_TABLE_HEADER', 'Signature Revision HeaderSize CRC32 Reserved')):
    __slots__ = ()

    def __str__(self) -> str:
        return f"""Header:
  Signature     : {bytestostring(self.Signature)}
  Revision      : {EFI_SYSTEM_TABLE_REVISION(self.Revision)}
  HeaderSize    : 0x{self.HeaderSize:08X}
  CRC32         : 0x{self.CRC32:08X}
  Reserved      : 0x{self.Reserved:08X}"""


# #################################################################################################
# EFI System Table
# #################################################################################################
#
# \MdePkg\Include\Uefi\UefiSpec.h

EFI_SYSTEM_TABLE_SIGNATURE = 'IBI SYST'

EFI_2_80_SYSTEM_TABLE_REVISION = ((2 << 16) | (80))
EFI_2_70_SYSTEM_TABLE_REVISION = ((2 << 16) | (70))
EFI_2_60_SYSTEM_TABLE_REVISION = ((2 << 16) | (60))
EFI_2_50_SYSTEM_TABLE_REVISION = ((2 << 16) | (50))
EFI_2_40_SYSTEM_TABLE_REVISION = ((2 << 16) | (40))
EFI_2_31_SYSTEM_TABLE_REVISION = ((2 << 16) | (31))
EFI_2_30_SYSTEM_TABLE_REVISION = ((2 << 16) | (30))
EFI_2_20_SYSTEM_TABLE_REVISION = ((2 << 16) | (20))
EFI_2_10_SYSTEM_TABLE_REVISION = ((2 << 16) | (10))
EFI_2_00_SYSTEM_TABLE_REVISION = ((2 << 16) | (00))
EFI_1_10_SYSTEM_TABLE_REVISION = ((1 << 16) | (10))
EFI_1_02_SYSTEM_TABLE_REVISION = ((1 << 16) | (0o2))
EFI_REVISIONS: List[int] = [
    EFI_2_80_SYSTEM_TABLE_REVISION,
    EFI_2_70_SYSTEM_TABLE_REVISION, 
    EFI_2_60_SYSTEM_TABLE_REVISION, 
    EFI_2_50_SYSTEM_TABLE_REVISION, 
    EFI_2_40_SYSTEM_TABLE_REVISION, 
    EFI_2_31_SYSTEM_TABLE_REVISION,
    EFI_2_30_SYSTEM_TABLE_REVISION, 
    EFI_2_20_SYSTEM_TABLE_REVISION, 
    EFI_2_10_SYSTEM_TABLE_REVISION, 
    EFI_2_00_SYSTEM_TABLE_REVISION, 
    EFI_1_10_SYSTEM_TABLE_REVISION, 
    EFI_1_02_SYSTEM_TABLE_REVISION
    ]


def EFI_SYSTEM_TABLE_REVISION(revision: int) -> str:
    return f'{revision >> 16:d}.{revision & 0xFFFF:d}'


EFI_SYSTEM_TABLE_FMT = '=12Q'


class EFI_SYSTEM_TABLE(namedtuple('EFI_SYSTEM_TABLE', 'FirmwareVendor FirmwareRevision ConsoleInHandle ConIn ConsoleOutHandle ConOut StandardErrorHandle StdErr RuntimeServices BootServices NumberOfTableEntries ConfigurationTable')):
    __slots__ = ()

    def __str__(self) -> str:
        return f"""EFI System Table:
  FirmwareVendor      : 0x{self.FirmwareVendor:016X}
  FirmwareRevision    : 0x{self.FirmwareRevision:016X}
  ConsoleInHandle     : 0x{self.ConsoleInHandle:016X}
  ConIn               : 0x{self.ConIn:016X}
  ConsoleOutHandle    : 0x{self.ConsoleOutHandle:016X}
  ConOut              : 0x{self.ConOut:016X}
  StandardErrorHandle : 0x{self.StandardErrorHandle:016X}
  StdErr              : 0x{self.StdErr:016X}
  RuntimeServices     : 0x{self.RuntimeServices:016X}
  BootServices        : 0x{self.BootServices:016X}
  NumberOfTableEntries: 0x{self.NumberOfTableEntries:016X}
  ConfigurationTable  : 0x{self.ConfigurationTable:016X}
"""


# #################################################################################################
# EFI Runtime Services Table
# #################################################################################################
#
# \MdePkg\Include\Uefi\UefiSpec.h

EFI_RUNTIME_SERVICES_SIGNATURE = 'RUNTSERV'
EFI_RUNTIME_SERVICES_REVISION = EFI_2_31_SYSTEM_TABLE_REVISION

EFI_RUNTIME_SERVICES_TABLE_FMT = '=14Q'


class EFI_RUNTIME_SERVICES_TABLE(namedtuple('EFI_RUNTIME_SERVICES_TABLE', 'GetTime SetTime GetWakeupTime SetWakeupTime SetVirtualAddressMap ConvertPointer GetVariable GetNextVariableName SetVariable GetNextHighMonotonicCount ResetSystem UpdateCapsule QueryCapsuleCapabilities QueryVariableInfo')):
    __slots__ = ()

    def __str__(self) -> str:
        return f"""Runtime Services:
  GetTime                  : 0x{self.GetTime:016X}
  SetTime                  : 0x{self.SetTime:016X}
  GetWakeupTime            : 0x{self.GetWakeupTime:016X}
  SetWakeupTime            : 0x{self.SetWakeupTime:016X}
  SetVirtualAddressMap     : 0x{self.SetVirtualAddressMap:016X}
  ConvertPointer           : 0x{self.ConvertPointer:016X}
  GetVariable              : 0x{self.GetVariable:016X}
  GetNextVariableName      : 0x{self.GetNextVariableName:016X}
  SetVariable              : 0x{self.SetVariable:016X}
  GetNextHighMonotonicCount: 0x{self.GetNextHighMonotonicCount:016X}
  ResetSystem              : 0x{self.ResetSystem:016X}
  UpdateCapsule            : 0x{self.UpdateCapsule:016X}
  QueryCapsuleCapabilities : 0x{self.QueryCapsuleCapabilities:016X}
  QueryVariableInfo        : 0x{self.QueryVariableInfo:016X}
"""


# #################################################################################################
# EFI Boot Services Table
# #################################################################################################
#
# \MdePkg\Include\Uefi\UefiSpec.h

EFI_BOOT_SERVICES_SIGNATURE = 'BOOTSERV'
EFI_BOOT_SERVICES_REVISION = EFI_2_31_SYSTEM_TABLE_REVISION

EFI_BOOT_SERVICES_TABLE_FMT = '=44Q'


class EFI_BOOT_SERVICES_TABLE(namedtuple('EFI_BOOT_SERVICES_TABLE', 'RaiseTPL RestoreTPL AllocatePages FreePages GetMemoryMap AllocatePool FreePool CreateEvent SetTimer WaitForEvent SignalEvent CloseEvent CheckEvent InstallProtocolInterface ReinstallProtocolInterface UninstallProtocolInterface HandleProtocol Reserved RegisterProtocolNotify LocateHandle LocateDevicePath InstallConfigurationTable LoadImage StartImage Exit UnloadImage ExitBootServices GetNextMonotonicCount Stall SetWatchdogTimer ConnectController DisconnectController OpenProtocol CloseProtocol OpenProtocolInformation ProtocolsPerHandle LocateHandleBuffer LocateProtocol InstallMultipleProtocolInterfaces UninstallMultipleProtocolInterfaces CalculateCrc32 CopyMem SetMem CreateEventEx')):
    __slots__ = ()

    def __str__(self) -> str:
        return f"""Boot Services:
  RaiseTPL                           : 0x{self.RaiseTPL:016X}
  RestoreTPL                         : 0x{self.RestoreTPL:016X}
  AllocatePages                      : 0x{self.AllocatePages:016X}
  FreePages                          : 0x{self.FreePages:016X}
  GetMemoryMap                       : 0x{self.GetMemoryMap:016X}
  AllocatePool                       : 0x{self.AllocatePool:016X}
  FreePool                           : 0x{self.FreePool:016X}
  CreateEvent                        : 0x{self.CreateEvent:016X}
  SetTimer                           : 0x{self.SetTimer:016X}
  WaitForEvent                       : 0x{self.WaitForEvent:016X}
  SignalEvent                        : 0x{self.SignalEvent:016X}
  CloseEvent                         : 0x{self.CloseEvent:016X}
  CheckEvent                         : 0x{self.CheckEvent:016X}
  InstallProtocolInterface           : 0x{self.InstallProtocolInterface:016X}
  ReinstallProtocolInterface         : 0x{self.ReinstallProtocolInterface:016X}
  UninstallProtocolInterface         : 0x{self.UninstallProtocolInterface:016X}
  HandleProtocol                     : 0x{self.HandleProtocol:016X}
  Reserved                           : 0x{self.Reserved:016X}
  RegisterProtocolNotify             : 0x{self.RegisterProtocolNotify:016X}
  LocateHandle                       : 0x{self.LocateHandle:016X}
  LocateDevicePath                   : 0x{self.LocateDevicePath:016X}
  InstallConfigurationTable          : 0x{self.InstallConfigurationTable:016X}
  LoadImage                          : 0x{self.LoadImage:016X}
  StartImage                         : 0x{self.StartImage:016X}
  Exit                               : 0x{self.Exit:016X}
  UnloadImage                        : 0x{self.UnloadImage:016X}
  ExitBootServices                   : 0x{self.ExitBootServices:016X}
  GetNextMonotonicCount              : 0x{self.GetNextMonotonicCount:016X}
  Stall                              : 0x{self.Stall:016X}
  SetWatchdogTimer                   : 0x{self.SetWatchdogTimer:016X}
  ConnectController                  : 0x{self.ConnectController:016X}
  DisconnectController               : 0x{self.DisconnectController:016X}
  OpenProtocol                       : 0x{self.OpenProtocol:016X}
  CloseProtocol                      : 0x{self.CloseProtocol:016X}
  OpenProtocolInformation            : 0x{self.OpenProtocolInformation:016X}
  ProtocolsPerHandle                 : 0x{self.ProtocolsPerHandle:016X}
  LocateHandleBuffer                 : 0x{self.LocateHandleBuffer:016X}
  LocateProtocol                     : 0x{self.LocateProtocol:016X}
  InstallMultipleProtocolInterfaces  : 0x{self.InstallMultipleProtocolInterfaces:016X}
  UninstallMultipleProtocolInterfaces: 0x{self.UninstallMultipleProtocolInterfaces:016X}
  CalculateCrc32                     : 0x{self.CalculateCrc32:016X}
  CopyMem                            : 0x{self.CopyMem:016X}
  SetMem                             : 0x{self.SetMem:016X}
  CreateEventEx                      : 0x{self.CreateEventEx:016X}
"""


# #################################################################################################
# EFI System Configuration Table
# #################################################################################################
#
# \MdePkg\Include\Uefi\UefiSpec.h
# -------------------------------

EFI_VENDOR_TABLE_FORMAT = '<' + EFI_GUID_FMT + 'Q'
EFI_VENDOR_TABLE_SIZE = struct.calcsize(EFI_VENDOR_TABLE_FORMAT)


class EFI_VENDOR_TABLE(namedtuple('EFI_VENDOR_TABLE', 'VendorGuidData VendorTable')):
    __slots__ = ()

    def VendorGuid(self) -> str:
        return EFI_GUID_STR(self.VendorGuidData)


class EFI_CONFIGURATION_TABLE:
    def __init__(self):
        self.VendorTables = {}

    def __str__(self) -> str:
        vendor_table_str = ''.join([f'{{{vt}}} : 0x{self.VendorTables[vt]:016X}\n' for vt in self.VendorTables])
        return f'Vendor Tables:\n{vendor_table_str}'


# #################################################################################################
# EFI DXE Services Table
# #################################################################################################
#
# \MdePkg\Include\Pi\PiDxeCis.h
# -----------------------------
#
EFI_DXE_SERVICES_TABLE_SIGNATURE = 'DXE_SERV'  # 0x565245535f455844
EFI_DXE_SERVICES_TABLE_FMT = '=17Q'


class EFI_DXE_SERVICES_TABLE(namedtuple('EFI_DXE_SERVICES_TABLE', 'AddMemorySpace AllocateMemorySpace FreeMemorySpace RemoveMemorySpace GetMemorySpaceDescriptor SetMemorySpaceAttributes GetMemorySpaceMap AddIoSpace AllocateIoSpace FreeIoSpace RemoveIoSpace GetIoSpaceDescriptor GetIoSpaceMap Dispatch Schedule Trust ProcessFirmwareVolume')):
    __slots__ = ()

    def __str__(self) -> str:
        return f"""DXE Services:
  AddMemorySpace          : 0x{self.AddMemorySpace:016X}
  AllocateMemorySpace     : 0x{self.AllocateMemorySpace:016X}
  FreeMemorySpace         : 0x{self.FreeMemorySpace:016X}
  RemoveMemorySpace       : 0x{self.RemoveMemorySpace:016X}
  GetMemorySpaceDescriptor: 0x{self.GetMemorySpaceDescriptor:016X}
  SetMemorySpaceAttributes: 0x{self.SetMemorySpaceAttributes:016X}
  GetMemorySpaceMap       : 0x{self.GetMemorySpaceMap:016X}
  AddIoSpace              : 0x{self.AddIoSpace:016X}
  AllocateIoSpace         : 0x{self.AllocateIoSpace:016X}
  FreeIoSpace             : 0x{self.FreeIoSpace:016X}
  RemoveIoSpace           : 0x{self.RemoveIoSpace:016X}
  GetIoSpaceDescriptor    : 0x{self.GetIoSpaceDescriptor:016X}
  GetIoSpaceMap           : 0x{self.GetIoSpaceMap:016X}
  Dispatch                : 0x{self.Dispatch:016X}
  Schedule                : 0x{self.Schedule:016X}
  Trust                   : 0x{self.Trust:016X}
  ProcessFirmwareVolume   : 0x{self.ProcessFirmwareVolume:016X}
"""


# #################################################################################################
# EFI PEI Services Table
# #################################################################################################
EFI_FRAMEWORK_PEI_SERVICES_TABLE_SIGNATURE = 0x5652455320494550
FRAMEWORK_PEI_SPECIFICATION_MAJOR_REVISION = 0
FRAMEWORK_PEI_SPECIFICATION_MINOR_REVISION = 91
FRAMEWORK_PEI_SERVICES_REVISION = ((FRAMEWORK_PEI_SPECIFICATION_MAJOR_REVISION << 16) | (FRAMEWORK_PEI_SPECIFICATION_MINOR_REVISION))

# #################################################################################################
# EFI System Management System Table
# #################################################################################################

EFI_SMM_SYSTEM_TABLE_SIGNATURE = 'SMST'
EFI_SMM_SYSTEM_TABLE_REVISION = (0 << 16) | (0x09)


EFI_TABLES: Dict[str, Dict[str, Any]] = {
    EFI_SYSTEM_TABLE_SIGNATURE: {'name': 'EFI System Table', 'struct': EFI_SYSTEM_TABLE, 'fmt': EFI_SYSTEM_TABLE_FMT},
    EFI_RUNTIME_SERVICES_SIGNATURE: {'name': 'EFI Runtime Services Table', 'struct': EFI_RUNTIME_SERVICES_TABLE, 'fmt': EFI_RUNTIME_SERVICES_TABLE_FMT},
    EFI_BOOT_SERVICES_SIGNATURE: {'name': 'EFI Boot Services Table', 'struct': EFI_BOOT_SERVICES_TABLE, 'fmt': EFI_BOOT_SERVICES_TABLE_FMT},
    EFI_DXE_SERVICES_TABLE_SIGNATURE: {'name': 'EFI DXE Services Table', 'struct': EFI_DXE_SERVICES_TABLE, 'fmt': EFI_DXE_SERVICES_TABLE_FMT}
    # EFI_FRAMEWORK_PEI_SERVICES_TABLE_SIGNATURE : {'name' : 'EFI Framework PEI Services Table', 'struct' : EFI_FRAMEWORK_PEI_SERVICES_TABLE, 'fmt' : EFI_FRAMEWORK_PEI_SERVICES_TABLE_FMT },
    # EFI_SMM_SYSTEM_TABLE_SIGNATURE             : {'name' : 'EFI SMM System Table',             'struct' : EFI_SMM_SYSTEM_TABLE,             'fmt' : EFI_SMM_SYSTEM_TABLE_FMT             },
    # EFI_CONFIG_TABLE_SIGNATURE                 : {'name' : 'EFI Configuration Table',          'struct' : EFI_CONFIG_TABLE,                 'fmt' : EFI_CONFIG_TABLE_FMT                 }
}
