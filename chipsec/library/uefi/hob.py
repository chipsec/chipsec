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
from typing import Dict, List, Optional, Tuple, Type

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


# Registry of HOB type -> Hob subclass, populated by Hob.__init_subclass__
HOB_CLASSES: Dict[int, Type['Hob']] = {}


class Hob:
    """
    A single parsed Hand-Off Block.

    Subclasses decode the type-specific body that follows the generic header. A
    subclass declares the HOB type it handles with HOB_TYPE and the layout of the
    body it needs with BODY_FMT, then fills self.fields in decode_fields().
    """

    HOB_TYPE: Optional[int] = None      # EFI_HOB_TYPE_* handled by this class
    BODY_FMT: str = ''                  # struct format of the body (after the generic header)
    register = None                     # register view of the payload, when a definition is known

    def __init_subclass__(cls, **kwargs) -> None:
        super().__init_subclass__(**kwargs)
        if cls.HOB_TYPE is not None:
            HOB_CLASSES[cls.HOB_TYPE] = cls

    def __init__(self, hob_type: int, hob_length: int, address: int, raw: bytes, definitions=None) -> None:
        self.HobType = hob_type
        self.HobLength = hob_length
        self.address = address                      # physical address of this HOB
        self.raw = raw                              # raw bytes of the whole HOB
        self.type_name = HOB_TYPE_NAMES.get(hob_type, f'UNKNOWN(0x{hob_type:04X})')
        self.fields: Dict[str, object] = {}         # decoded, type-specific fields
        self.definitions = definitions              # optional definition lookup (see walk_hob_list)
        self.decode()

    def decode(self) -> None:
        """Unpack the type-specific body and populate self.fields."""
        if not self.BODY_FMT:
            return
        body_size = struct.calcsize(self.BODY_FMT)
        if len(self.raw) < EFI_HOB_GENERIC_HEADER_SIZE + body_size:
            logger().log_hal(f'[hob] HOB type 0x{self.HobType:04X} at 0x{self.address:016X} is too short to decode '
                             f'(0x{len(self.raw):X} bytes)')
            return
        try:
            values = struct.unpack_from(self.BODY_FMT, self.raw, EFI_HOB_GENERIC_HEADER_SIZE)
        except struct.error as err:
            logger().log_hal(f'[hob] Unable to decode HOB type 0x{self.HobType:04X} at 0x{self.address:016X}: {err}')
            return
        self.decode_fields(values)

    def decode_fields(self, values: Tuple) -> None:
        """Populate self.fields from the values unpacked using BODY_FMT."""
        pass

    def __str__(self) -> str:
        line = f'[0x{self.address:016X}] type=0x{self.HobType:04X} len=0x{self.HobLength:04X}  {self.type_name}'
        for key, value in self.fields.items():
            if isinstance(value, int):
                line += f'\n        {key} = 0x{value:X}'
            else:
                line += f'\n        {key} = {value}'
        if self.register is not None:
            for reg_line in str(self.register).splitlines():
                line += f'\n        {reg_line}'
        return line

    def __repr__(self) -> str:
        return self.__str__()


class HandoffInfoTableHob(Hob):
    """EFI_HOB_HANDOFF_INFO_TABLE (PHIT)."""

    HOB_TYPE = EFI_HOB_TYPE_HANDOFF
    BODY_FMT = EFI_HOB_HANDOFF_INFO_TABLE_FMT
    phit: Optional[EFI_HOB_HANDOFF_INFO_TABLE] = None

    def decode_fields(self, values: Tuple) -> None:
        phit = EFI_HOB_HANDOFF_INFO_TABLE(*values)
        self.phit = phit
        self.fields['Version'] = phit.Version
        self.fields['BootMode'] = BOOT_MODES.get(phit.BootMode, f'0x{phit.BootMode:X}')
        self.fields['EfiMemoryTop'] = phit.EfiMemoryTop
        self.fields['EfiMemoryBottom'] = phit.EfiMemoryBottom
        self.fields['EfiFreeMemoryTop'] = phit.EfiFreeMemoryTop
        self.fields['EfiFreeMemoryBottom'] = phit.EfiFreeMemoryBottom
        self.fields['EfiEndOfHobList'] = phit.EfiEndOfHobList


class MemoryAllocationHob(Hob):
    """EFI_HOB_MEMORY_ALLOCATION."""

    HOB_TYPE = EFI_HOB_TYPE_MEMORY_ALLOCATION
    BODY_FMT = '<16sQQI'

    def decode_fields(self, values: Tuple) -> None:
        name, base, length, mem_type = values
        self.fields['GUID'] = EFI_GUID_STR(name)
        self.fields['MemoryBaseAddress'] = base
        self.fields['MemoryLength'] = length
        self.fields['MemoryType'] = MEMORY_TYPES.get(mem_type, f'0x{mem_type:X}')


class ResourceDescriptorHob(Hob):
    """EFI_HOB_RESOURCE_DESCRIPTOR."""

    HOB_TYPE = EFI_HOB_TYPE_RESOURCE_DESCRIPTOR
    BODY_FMT = '<16sIIQQ'

    def decode_fields(self, values: Tuple) -> None:
        owner, res_type, res_attr, start, length = values
        self.fields['Owner_GUID'] = EFI_GUID_STR(owner)
        self.fields['ResourceType'] = RESOURCE_TYPES.get(res_type, f'0x{res_type:X}')
        self.fields['ResourceAttribute'] = res_attr
        self.fields['PhysicalStart'] = start
        self.fields['ResourceLength'] = length


class GuidExtensionHob(Hob):
    """EFI_HOB_GUID_TYPE."""

    HOB_TYPE = EFI_HOB_TYPE_GUID_EXTENSION
    BODY_FMT = '<16s'
    data: bytes = b''       # GUID-specific data following the Name GUID

    def decode_fields(self, values: Tuple) -> None:
        data_off = EFI_HOB_GENERIC_HEADER_SIZE + struct.calcsize(self.BODY_FMT)
        self.data = self.raw[data_off:self.HobLength]
        self.fields['GUID'] = EFI_GUID_STR(values[0])
        self.fields['DataLength'] = self.HobLength - data_off
        self.fields['Data'] = self.data
        self.decode_payload()

    def decode_payload(self) -> None:
        """Build the register view of the payload if a matching definition was supplied."""
        if self.definitions is None:
            return
        hob_def = self.definitions.get_by_guid(str(self.fields['GUID']))
        if hob_def is None:
            return
        if len(self.data) < hob_def.size:
            logger().log_hal(f'[hob] {hob_def.name} at 0x{self.address:016X} payload is 0x{len(self.data):X} bytes, '
                             f'declaration needs 0x{hob_def.size:X}')
            return
        self.register = hob_def.create_register(self.data, address=self.address)

    def get_formatted_data(self, struct_str: str, field_names: List[str]) -> Optional[Dict[str, object]]:
        """
        Unpack the GUID extension data using a struct format string and return a dict of field names to values.

        Args:
            struct_str: struct format string for the data (e.g., '<IIQQ')
            field_names: list of field names corresponding to the unpacked values

        Returns:
            A dictionary mapping field names to unpacked values, or None if the data
            length does not match the size of the format string.
        """
        expected_size = struct.calcsize(struct_str)
        if len(self.data) != expected_size:
            logger().log_hal(f'[hob] GUID extension HOB data length mismatch: expected {expected_size} bytes, '
                             f'got {len(self.data)} bytes')
            return None
        values = struct.unpack(struct_str, self.data)
        return dict(zip(field_names, values))

class FirmwareVolumeHob(Hob):
    """EFI_HOB_FIRMWARE_VOLUME."""

    HOB_TYPE = EFI_HOB_TYPE_FV
    BODY_FMT = '<QQ'

    def decode_fields(self, values: Tuple) -> None:
        base, length = values
        self.fields['BaseAddress'] = base
        self.fields['Length'] = length


class FirmwareVolume2Hob(Hob):
    """EFI_HOB_FIRMWARE_VOLUME2."""

    HOB_TYPE = EFI_HOB_TYPE_FV2
    BODY_FMT = '<QQ16s16s'

    def decode_fields(self, values: Tuple) -> None:
        base, length, fv_name, file_name = values
        self.fields['BaseAddress'] = base
        self.fields['Length'] = length
        self.fields['FvName_GUID'] = EFI_GUID_STR(fv_name)
        self.fields['FileName_GUID'] = EFI_GUID_STR(file_name)


class FirmwareVolume3Hob(Hob):
    """EFI_HOB_FIRMWARE_VOLUME3."""

    HOB_TYPE = EFI_HOB_TYPE_FV3
    BODY_FMT = '<QQIB16s16s'

    def decode_fields(self, values: Tuple) -> None:
        base, length, auth, extracted, fv_name, file_name = values
        self.fields['BaseAddress'] = base
        self.fields['Length'] = length
        self.fields['AuthenticationStatus'] = auth
        self.fields['ExtractedFv'] = bool(extracted)
        self.fields['FvName_GUID'] = EFI_GUID_STR(fv_name)
        self.fields['FileName_GUID'] = EFI_GUID_STR(file_name)


class CpuHob(Hob):
    """EFI_HOB_CPU."""

    HOB_TYPE = EFI_HOB_TYPE_CPU
    BODY_FMT = '<BB'

    def decode_fields(self, values: Tuple) -> None:
        mem_bits, io_bits = values
        self.fields['SizeOfMemorySpace'] = mem_bits
        self.fields['SizeOfIoSpace'] = io_bits


class UefiCapsuleHob(Hob):
    """EFI_HOB_UEFI_CAPSULE."""

    HOB_TYPE = EFI_HOB_TYPE_UEFI_CAPSULE
    BODY_FMT = '<QQ'

    def decode_fields(self, values: Tuple) -> None:
        base, length = values
        self.fields['BaseAddress'] = base
        self.fields['Length'] = length


def create_hob(hob_type: int, hob_length: int, address: int, raw: bytes, definitions=None) -> Hob:
    """
    Factory returning the Hob subclass that handles hob_type.

    HOB types without a dedicated class (e.g. MEMORY_POOL, UNUSED, END_OF_HOB_LIST)
    fall back to the generic Hob, which exposes only the generic header and raw bytes.
    """
    hob_class = HOB_CLASSES.get(hob_type, Hob)
    return hob_class(hob_type, hob_length, address, raw, definitions)


def parse_phit(buffer: bytes) -> Optional[EFI_HOB_HANDOFF_INFO_TABLE]:
    """Parse the PHIT (first HOB) from a buffer. Returns None if not a valid PHIT."""
    if len(buffer) < EFI_HOB_HANDOFF_INFO_TABLE_SIZE:
        return None
    hob_type, hob_length, _ = struct.unpack_from(EFI_HOB_GENERIC_HEADER_FMT, buffer, 0)
    if hob_type != EFI_HOB_TYPE_HANDOFF or hob_length != EFI_HOB_HANDOFF_INFO_TABLE_SIZE:
        return None
    return EFI_HOB_HANDOFF_INFO_TABLE(*struct.unpack_from(EFI_HOB_HANDOFF_INFO_TABLE_FMT, buffer, EFI_HOB_GENERIC_HEADER_SIZE))


def parse_hob_list(buffer: bytes, base_address: int = 0, definitions=None) -> List[Hob]:
    """
    Walk a HOB list buffer and return the parsed HOBs.

    Args:
        buffer: Raw bytes of the HOB list, starting at the PHIT.
        base_address: Physical address the buffer was read from (for absolute HOB addresses).
        definitions: Optional HOB definition lookup (see walk_hob_list).

    Returns:
        List of Hob objects. Parsing stops at EFI_HOB_TYPE_END_OF_HOB_LIST, at the end of
        the buffer, or when an invalid HOB length is encountered.
    """
    hobs, _, _ = walk_hob_list(buffer, base_address, definitions)
    return hobs


def walk_hob_list(buffer: bytes, base_address: int = 0, definitions=None):
    """
    Walk a HOB list buffer, returning parsed HOBs and walk status.

    Unlike a naive walk, this only accepts HOBs that are fully contained in the
    buffer, so a partial trailing HOB (from a chunked read) is not included and is
    reported via the ``consumed`` count so the caller can read more data.

    Args:
        buffer: Raw bytes of the HOB list, starting at the PHIT.
        base_address: Physical address the buffer was read from (for absolute HOB addresses).
        definitions: Optional HOB definition lookup used to decode GUID extension HOB
            payloads while walking. Any object providing get_by_guid(guid) that returns
            a definition with size and create_register(data, address) works; in practice
            this is a HOBCommands built from the XML <structure> declarations.

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
        hobs.append(create_hob(hob_type, hob_length, base_address + offset, raw, definitions))
        offset += hob_length
        if hob_type == EFI_HOB_TYPE_END_OF_HOB_LIST:
            complete = True
            break
    return hobs, complete, offset


def is_hob_list_complete(hobs: List[Hob]) -> bool:
    """Return True if the parsed HOB list is terminated by an END_OF_HOB_LIST HOB."""
    return bool(hobs) and hobs[-1].HobType == EFI_HOB_TYPE_END_OF_HOB_LIST
