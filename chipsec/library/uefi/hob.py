# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2026, Intel Corporation
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
EFI Platform Initialization (PI) Hand-Off Block (HOB) list parsing.

Reference: UEFI PI Specification, MdePkg/Include/Pi/PiHob.h
"""

import struct
from collections import namedtuple
from typing import Dict, List, Optional

from chipsec.library.uefi.common import EFI_GUID_STR
from chipsec.library.logger import logger

# GUID that identifies the HOB list pointer in the EFI Configuration Table (gEfiHobListGuid)
EFI_HOB_LIST_GUID = '7739F24C-93D7-11D4-9A3A-0090273FC14D'

# Upper bound sanity limit when reading a HOB list from memory (16 MB)
MAX_HOB_LIST_SIZE = 0x1000000

# HOB types (EFI_HOB_TYPE_*)
EFI_HOB_TYPE_HANDOFF = 0x0001
EFI_HOB_TYPE_MEMORY_ALLOCATION = 0x0002
EFI_HOB_TYPE_RESOURCE_DESCRIPTOR = 0x0003
EFI_HOB_TYPE_GUID_EXTENSION = 0x0004
EFI_HOB_TYPE_FV = 0x0005
EFI_HOB_TYPE_CPU = 0x0006
EFI_HOB_TYPE_MEMORY_POOL = 0x0007
EFI_HOB_TYPE_FV2 = 0x0008
EFI_HOB_TYPE_LOAD_PEIM_UNUSED = 0x0009
EFI_HOB_TYPE_UEFI_CAPSULE = 0x000A
EFI_HOB_TYPE_FV3 = 0x000B
EFI_HOB_TYPE_UNUSED = 0xFFFE
EFI_HOB_TYPE_END_OF_HOB_LIST = 0xFFFF

HOB_TYPE_NAMES = {
    EFI_HOB_TYPE_HANDOFF: 'EFI_HOB_TYPE_HANDOFF',
    EFI_HOB_TYPE_MEMORY_ALLOCATION: 'EFI_HOB_TYPE_MEMORY_ALLOCATION',
    EFI_HOB_TYPE_RESOURCE_DESCRIPTOR: 'EFI_HOB_TYPE_RESOURCE_DESCRIPTOR',
    EFI_HOB_TYPE_GUID_EXTENSION: 'EFI_HOB_TYPE_GUID_EXTENSION',
    EFI_HOB_TYPE_FV: 'EFI_HOB_TYPE_FV',
    EFI_HOB_TYPE_CPU: 'EFI_HOB_TYPE_CPU',
    EFI_HOB_TYPE_MEMORY_POOL: 'EFI_HOB_TYPE_MEMORY_POOL',
    EFI_HOB_TYPE_FV2: 'EFI_HOB_TYPE_FV2',
    EFI_HOB_TYPE_LOAD_PEIM_UNUSED: 'EFI_HOB_TYPE_LOAD_PEIM_UNUSED',
    EFI_HOB_TYPE_UEFI_CAPSULE: 'EFI_HOB_TYPE_UEFI_CAPSULE',
    EFI_HOB_TYPE_FV3: 'EFI_HOB_TYPE_FV3',
    EFI_HOB_TYPE_UNUSED: 'EFI_HOB_TYPE_UNUSED',
    EFI_HOB_TYPE_END_OF_HOB_LIST: 'EFI_HOB_TYPE_END_OF_HOB_LIST',
}

# PI boot modes (EFI_BOOT_MODE)
BOOT_MODES = {
    0x00: 'BOOT_WITH_FULL_CONFIGURATION',
    0x01: 'BOOT_WITH_MINIMAL_CONFIGURATION',
    0x02: 'BOOT_ASSUMING_NO_CONFIGURATION_CHANGES',
    0x03: 'BOOT_WITH_FULL_CONFIGURATION_PLUS_DIAGNOSTICS',
    0x04: 'BOOT_WITH_DEFAULT_SETTINGS',
    0x05: 'BOOT_ON_S4_RESUME',
    0x06: 'BOOT_ON_S5_RESUME',
    0x10: 'BOOT_ON_S3_RESUME',
    0x11: 'BOOT_ON_FLASH_UPDATE',
    0x20: 'BOOT_IN_RECOVERY_MODE',
}

# Resource descriptor types (EFI_RESOURCE_TYPE)
RESOURCE_TYPES = {
    0x00000000: 'SYSTEM_MEMORY',
    0x00000001: 'MEMORY_MAPPED_IO',
    0x00000002: 'IO',
    0x00000003: 'FIRMWARE_DEVICE',
    0x00000004: 'MEMORY_MAPPED_IO_PORT',
    0x00000005: 'MEMORY_RESERVED',
    0x00000006: 'IO_RESERVED',
    0x00000007: 'MEMORY_UNACCEPTED',
}

# Memory types (EFI_MEMORY_TYPE)
MEMORY_TYPES = {
    0: 'EfiReservedMemoryType',
    1: 'EfiLoaderCode',
    2: 'EfiLoaderData',
    3: 'EfiBootServicesCode',
    4: 'EfiBootServicesData',
    5: 'EfiRuntimeServicesCode',
    6: 'EfiRuntimeServicesData',
    7: 'EfiConventionalMemory',
    8: 'EfiUnusableMemory',
    9: 'EfiACPIReclaimMemory',
    10: 'EfiACPIMemoryNVS',
    11: 'EfiMemoryMappedIO',
    12: 'EfiMemoryMappedIOPortSpace',
    13: 'EfiPalCode',
    14: 'EfiPersistentMemory',
}

# EFI_HOB_GENERIC_HEADER: UINT16 HobType; UINT16 HobLength; UINT32 Reserved;
EFI_HOB_GENERIC_HEADER_FMT = '<HHI'
EFI_HOB_GENERIC_HEADER_SIZE = struct.calcsize(EFI_HOB_GENERIC_HEADER_FMT)

# EFI_HOB_HANDOFF_INFO_TABLE (PHIT) body, following the generic header
EFI_HOB_HANDOFF_INFO_TABLE_FMT = '<IIQQQQQ'
EFI_HOB_HANDOFF_INFO_TABLE_SIZE = EFI_HOB_GENERIC_HEADER_SIZE + struct.calcsize(EFI_HOB_HANDOFF_INFO_TABLE_FMT)


class EFI_HOB_HANDOFF_INFO_TABLE(namedtuple('EFI_HOB_HANDOFF_INFO_TABLE',
                                            'Version BootMode EfiMemoryTop EfiMemoryBottom '
                                            'EfiFreeMemoryTop EfiFreeMemoryBottom EfiEndOfHobList')):
    __slots__ = ()

    def __str__(self) -> str:
        boot = BOOT_MODES.get(self.BootMode, 'UNKNOWN')
        return (f'PHIT (Hand-Off Info Table):\n'
                f'  Version             : 0x{self.Version:08X}\n'
                f'  BootMode            : 0x{self.BootMode:X} {boot}\n'
                f'  EfiMemoryTop        : 0x{self.EfiMemoryTop:016X}\n'
                f'  EfiMemoryBottom     : 0x{self.EfiMemoryBottom:016X}\n'
                f'  EfiFreeMemoryTop    : 0x{self.EfiFreeMemoryTop:016X}\n'
                f'  EfiFreeMemoryBottom : 0x{self.EfiFreeMemoryBottom:016X}\n'
                f'  EfiEndOfHobList     : 0x{self.EfiEndOfHobList:016X}')


class Hob:
    """A single parsed Hand-Off Block."""

    def __init__(self, hob_type: int, hob_length: int, address: int, raw: bytes) -> None:
        self.HobType = hob_type
        self.HobLength = hob_length
        self.address = address                      # physical address of this HOB
        self.raw = raw                              # raw bytes of the whole HOB
        self.name = HOB_TYPE_NAMES.get(hob_type, f'UNKNOWN(0x{hob_type:04X})')
        self.fields: Dict[str, object] = {}         # decoded, type-specific fields

    def __str__(self) -> str:
        line = f'[0x{self.address:016X}] type=0x{self.HobType:04X} len=0x{self.HobLength:04X}  {self.name}'
        for key, value in self.fields.items():
            if isinstance(value, int):
                line += f'\n        {key} = 0x{value:X}'
            else:
                line += f'\n        {key} = {value}'
        return line


def _decode_hob(hob: Hob) -> None:
    """Populate hob.fields with type-specific decoded values."""
    body = hob.raw
    body_off = EFI_HOB_GENERIC_HEADER_SIZE
    try:
        if hob.HobType == EFI_HOB_TYPE_HANDOFF and len(body) >= EFI_HOB_HANDOFF_INFO_TABLE_SIZE:
            phit = EFI_HOB_HANDOFF_INFO_TABLE(*struct.unpack_from(EFI_HOB_HANDOFF_INFO_TABLE_FMT, body, body_off))
            hob.fields['Version'] = phit.Version
            hob.fields['BootMode'] = BOOT_MODES.get(phit.BootMode, f'0x{phit.BootMode:X}')
            hob.fields['EfiMemoryTop'] = phit.EfiMemoryTop
            hob.fields['EfiMemoryBottom'] = phit.EfiMemoryBottom
            hob.fields['EfiFreeMemoryTop'] = phit.EfiFreeMemoryTop
            hob.fields['EfiFreeMemoryBottom'] = phit.EfiFreeMemoryBottom
            hob.fields['EfiEndOfHobList'] = phit.EfiEndOfHobList
        elif hob.HobType == EFI_HOB_TYPE_MEMORY_ALLOCATION and len(body) >= body_off + 0x24:
            name, base, length, mem_type = struct.unpack_from('<16sQQI', body, body_off)
            hob.fields['Name'] = EFI_GUID_STR(name)
            hob.fields['MemoryBaseAddress'] = base
            hob.fields['MemoryLength'] = length
            hob.fields['MemoryType'] = MEMORY_TYPES.get(mem_type, f'0x{mem_type:X}')
        elif hob.HobType == EFI_HOB_TYPE_RESOURCE_DESCRIPTOR and len(body) >= body_off + 0x28:
            owner, res_type, res_attr, start, length = struct.unpack_from('<16sIIQQ', body, body_off)
            hob.fields['Owner'] = EFI_GUID_STR(owner)
            hob.fields['ResourceType'] = RESOURCE_TYPES.get(res_type, f'0x{res_type:X}')
            hob.fields['ResourceAttribute'] = res_attr
            hob.fields['PhysicalStart'] = start
            hob.fields['ResourceLength'] = length
        elif hob.HobType == EFI_HOB_TYPE_GUID_EXTENSION and len(body) >= body_off + 16:
            name = struct.unpack_from('<16s', body, body_off)[0]
            hob.fields['Name'] = EFI_GUID_STR(name)
            hob.fields['DataLength'] = hob.HobLength - body_off - 16
        elif hob.HobType == EFI_HOB_TYPE_FV and len(body) >= body_off + 16:
            base, length = struct.unpack_from('<QQ', body, body_off)
            hob.fields['BaseAddress'] = base
            hob.fields['Length'] = length
        elif hob.HobType == EFI_HOB_TYPE_FV2 and len(body) >= body_off + 48:
            base, length, fv_name, file_name = struct.unpack_from('<QQ16s16s', body, body_off)
            hob.fields['BaseAddress'] = base
            hob.fields['Length'] = length
            hob.fields['FvName'] = EFI_GUID_STR(fv_name)
            hob.fields['FileName'] = EFI_GUID_STR(file_name)
        elif hob.HobType == EFI_HOB_TYPE_FV3 and len(body) >= body_off + 53:
            base, length, auth, extracted, fv_name, file_name = struct.unpack_from('<QQIB16s16s', body, body_off)
            hob.fields['BaseAddress'] = base
            hob.fields['Length'] = length
            hob.fields['AuthenticationStatus'] = auth
            hob.fields['ExtractedFv'] = bool(extracted)
            hob.fields['FvName'] = EFI_GUID_STR(fv_name)
            hob.fields['FileName'] = EFI_GUID_STR(file_name)
        elif hob.HobType == EFI_HOB_TYPE_CPU and len(body) >= body_off + 2:
            mem_bits, io_bits = struct.unpack_from('<BB', body, body_off)
            hob.fields['SizeOfMemorySpace'] = mem_bits
            hob.fields['SizeOfIoSpace'] = io_bits
        elif hob.HobType == EFI_HOB_TYPE_UEFI_CAPSULE and len(body) >= body_off + 16:
            base, length = struct.unpack_from('<QQ', body, body_off)
            hob.fields['BaseAddress'] = base
            hob.fields['Length'] = length
    except struct.error as err:
        logger().log_hal(f'[hob] Unable to decode HOB type 0x{hob.HobType:04X} at 0x{hob.address:016X}: {err}')


def parse_phit(buffer: bytes) -> Optional[EFI_HOB_HANDOFF_INFO_TABLE]:
    """Parse the PHIT (first HOB) from a buffer. Returns None if not a valid PHIT."""
    if len(buffer) < EFI_HOB_HANDOFF_INFO_TABLE_SIZE:
        return None
    hob_type, hob_length, _ = struct.unpack_from(EFI_HOB_GENERIC_HEADER_FMT, buffer, 0)
    if hob_type != EFI_HOB_TYPE_HANDOFF or hob_length != EFI_HOB_HANDOFF_INFO_TABLE_SIZE:
        return None
    return EFI_HOB_HANDOFF_INFO_TABLE(*struct.unpack_from(EFI_HOB_HANDOFF_INFO_TABLE_FMT, buffer, EFI_HOB_GENERIC_HEADER_SIZE))


def parse_hob_list(buffer: bytes, base_address: int = 0) -> List[Hob]:
    """
    Walk a HOB list buffer and return the parsed HOBs.

    Args:
        buffer: Raw bytes of the HOB list, starting at the PHIT.
        base_address: Physical address the buffer was read from (for absolute HOB addresses).

    Returns:
        List of Hob objects. Parsing stops at EFI_HOB_TYPE_END_OF_HOB_LIST, at the end of
        the buffer, or when an invalid HOB length is encountered.
    """
    hobs, _, _ = walk_hob_list(buffer, base_address)
    return hobs


def walk_hob_list(buffer: bytes, base_address: int = 0):
    """
    Walk a HOB list buffer, returning parsed HOBs and walk status.

    Unlike a naive walk, this only accepts HOBs that are fully contained in the
    buffer, so a partial trailing HOB (from a chunked read) is not included and is
    reported via the ``consumed`` count so the caller can read more data.

    Args:
        buffer: Raw bytes of the HOB list, starting at the PHIT.
        base_address: Physical address the buffer was read from (for absolute HOB addresses).

    Returns:
        Tuple of (hobs, complete, consumed) where:
          - hobs: list of fully-parsed Hob objects
          - complete: True if an END_OF_HOB_LIST HOB was reached
          - consumed: number of bytes consumed by fully-parsed HOBs
    """
    hobs: List[Hob] = []
    offset = 0
    total = len(buffer)
    complete = False
    while offset + EFI_HOB_GENERIC_HEADER_SIZE <= total:
        hob_type, hob_length, _ = struct.unpack_from(EFI_HOB_GENERIC_HEADER_FMT, buffer, offset)
        if hob_length < EFI_HOB_GENERIC_HEADER_SIZE:
            logger().log_hal(f'[hob] Invalid HOB length 0x{hob_length:X} at offset 0x{offset:X}; stopping')
            break
        if offset + hob_length > total:
            # HOB spills past the end of the available buffer (needs more data).
            break
        raw = buffer[offset:offset + hob_length]
        hob = Hob(hob_type, hob_length, base_address + offset, raw)
        _decode_hob(hob)
        hobs.append(hob)
        offset += hob_length
        if hob_type == EFI_HOB_TYPE_END_OF_HOB_LIST:
            complete = True
            break
    return hobs, complete, offset


def is_hob_list_complete(hobs: List[Hob]) -> bool:
    """Return True if the parsed HOB list is terminated by an END_OF_HOB_LIST HOB."""
    return bool(hobs) and hobs[-1].HobType == EFI_HOB_TYPE_END_OF_HOB_LIST
