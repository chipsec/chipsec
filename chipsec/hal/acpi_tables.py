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
# Authors:
#  Sarah Van Sickle, INTEL DCG RED team
#


"""
HAL component decoding various ACPI tables
"""

__version__ = '0.1'

import struct
from collections import namedtuple
from uuid import UUID
from typing import List, Optional, Tuple
from chipsec.library.logger import logger, dump_buffer_bytes
from chipsec.hal.uefi_common import EFI_GUID_FMT, EFI_GUID_STR


class ACPI_TABLE:

    def parse(self, table_content: bytes) -> None:
        return

    def __str__(self) -> str:
        return """------------------------------------------------------------------
  Table Content
------------------------------------------------------------------
"""

########################################################################################################
#
# RSDP
#
########################################################################################################


# RSDP Format
ACPI_RSDP_FORMAT = '<8sB6sBI'
ACPI_RSDP_EXT_FORMAT = 'IQB3s'
ACPI_RSDP_SIZE = struct.calcsize(ACPI_RSDP_FORMAT)
ACPI_RSDP_EXT_SIZE = struct.calcsize(ACPI_RSDP_FORMAT + ACPI_RSDP_EXT_FORMAT)
assert ACPI_RSDP_EXT_SIZE == 36


class RSDP(ACPI_TABLE):
    def parse(self, table_content: bytes) -> None:
        if len(table_content) == ACPI_RSDP_SIZE:
            (self.Signature, self.Checksum, self.OEMID,
             self.Revision, self.RsdtAddress) = struct.unpack(ACPI_RSDP_FORMAT, table_content)
        else:
            (self.Signature, self.Checksum, self.OEMID,
             self.Revision, self.RsdtAddress, self.Length,
             self.XsdtAddress, self.ExtChecksum, self.Reserved) = struct.unpack(ACPI_RSDP_FORMAT + ACPI_RSDP_EXT_FORMAT, table_content)

    def __str__(self) -> str:
        default = ("==================================================================\n"
                   "  Root System Description Pointer (RSDP)\n"
                   "==================================================================\n"
                   f"  Signature        : {self.Signature}\n"
                   f"  Checksum         : 0x{self.Checksum:02X}\n"
                   f"  OEM ID           : {self.OEMID}\n"
                   f"  Revision         : 0x{self.Revision:02X}\n"
                   f"  RSDT Address     : 0x{self.RsdtAddress:08X}\n")
        if hasattr(self, "Length"):
            default += (f"  Length           : 0x{self.Length:08X}\n"
                        f"  XSDT Address     : 0x{self.XsdtAddress:016X}\n"
                        f"  Extended Checksum: 0x{self.ExtChecksum:02X}\n"
                        f"  Reserved         : {self.Reserved.hex()}\n"
                        )
        return default

    # some sanity checking on RSDP
    def is_RSDP_valid(self) -> bool:
        return 0 != self.Checksum and (0x0 == self.Revision or 0x2 == self.Revision)


########################################################################################################
#
# DMAR Table
#
########################################################################################################


ACPI_TABLE_FORMAT_DMAR = '=BB10s'
ACPI_TABLE_SIZE_DMAR = struct.calcsize(ACPI_TABLE_FORMAT_DMAR)


class DMAR (ACPI_TABLE):
    def __init__(self):
        self.dmar_structures = []
        self.DMAR_TABLE_FORMAT = {
            'DeviceScope_FORMAT': '=BBBBBB',
            'DRHD_FORMAT': '=HHBBHQ',
            'RMRR_FORMAT': '=HHHHQQ',
            'ATSR_FORMAT': '=HHBBH',
            'RHSA_FORMAT': '=HHIQI',
            'ANDD_FORMAT': 'HH3sB',
            'SATC_FORMAT': 'HHBBH',
            'SIDP_FORMAT': 'HHHH'
        }

    def parse(self, table_content: bytes) -> None:
        off = ACPI_TABLE_SIZE_DMAR
        struct_fmt = '=HH'
        while off < len(table_content) - 1:
            (_type, length) = struct.unpack(struct_fmt, table_content[off: off + struct.calcsize(struct_fmt)])
            if 0 == length:
                break
            self.dmar_structures.append(self._get_structure_DMAR(_type, table_content[off: off + length]))
            off += length
        (self.HostAddrWidth, self.Flags, self.Reserved) = struct.unpack_from(ACPI_TABLE_FORMAT_DMAR, table_content)
        return

    def __str__(self) -> str:
        _str = f"""------------------------------------------------------------------
  DMAR Table Contents
------------------------------------------------------------------
  Host Address Width  : {self.HostAddrWidth:d}
  Flags               : 0x{self.Flags:02X}
  Reserved            : {self.Reserved.hex()}
"""
        _str += "\n  Remapping Structures:\n"
        for st in self.dmar_structures:
            _str += str(st)
        return _str

    def _get_structure_DMAR(self, _type: int, DataStructure: bytes) -> str:
        if 0x00 == _type:
            ret = self._get_DMAR_structure_DRHD(DataStructure)
        elif 0x01 == _type:
            ret = self._get_DMAR_structure_RMRR(DataStructure)
        elif 0x02 == _type:
            ret = self._get_DMAR_structure_ATSR(DataStructure)
        elif 0x03 == _type:
            ret = self._get_DMAR_structure_RHSA(DataStructure)
        elif 0x04 == _type:
            ret = self._get_DMAR_structure_ANDD(DataStructure)
        elif 0x05 == _type:
            return self._get_DMAR_structure_SATC(DataStructure)
        elif 0x06 == _type:
            return self._get_DMAR_structure_SIDP(DataStructure)
        else:
            ret = (f"\n  Unknown DMAR structure 0x{_type:02X}\n")
        return str(ret)

    def _get_DMAR_structure_DRHD(self, structure: bytes) -> 'ACPI_TABLE_DMAR_DRHD':
        off = struct.calcsize(self.DMAR_TABLE_FORMAT["DRHD_FORMAT"])
        device_scope = self._get_DMAR_Device_Scope_list(structure[off:])
        return ACPI_TABLE_DMAR_DRHD(*struct.unpack_from(self.DMAR_TABLE_FORMAT["DRHD_FORMAT"], structure), DeviceScope=device_scope)

    def _get_DMAR_structure_RMRR(self, structure: bytes) -> 'ACPI_TABLE_DMAR_RMRR':
        off = struct.calcsize(self.DMAR_TABLE_FORMAT["RMRR_FORMAT"])
        device_scope = self._get_DMAR_Device_Scope_list(structure[off:])
        return ACPI_TABLE_DMAR_RMRR(*struct.unpack_from(self.DMAR_TABLE_FORMAT["RMRR_FORMAT"], structure), DeviceScope=device_scope)

    def _get_DMAR_structure_ATSR(self, structure: bytes) -> 'ACPI_TABLE_DMAR_ATSR':
        off = struct.calcsize(self.DMAR_TABLE_FORMAT["ATSR_FORMAT"])
        device_scope = self._get_DMAR_Device_Scope_list(structure[off:])
        return ACPI_TABLE_DMAR_ATSR(*struct.unpack_from(self.DMAR_TABLE_FORMAT["ATSR_FORMAT"], structure), DeviceScope=device_scope)

    def _get_DMAR_structure_RHSA(self, structure: bytes) -> 'ACPI_TABLE_DMAR_RHSA':
        return ACPI_TABLE_DMAR_RHSA(*struct.unpack_from(self.DMAR_TABLE_FORMAT["RHSA_FORMAT"], structure))

    def _get_DMAR_structure_ANDD(self, structure: bytes) -> 'ACPI_TABLE_DMAR_ANDD':
        sz = struct.calcsize('=H')
        length = struct.unpack('=H', structure[sz:sz + sz])[0]
        dmr_len = length - struct.calcsize(self.DMAR_TABLE_FORMAT["ANDD_FORMAT"])
        f = self.DMAR_TABLE_FORMAT["ANDD_FORMAT"] + (f'{dmr_len:d}s')
        return ACPI_TABLE_DMAR_ANDD(*struct.unpack_from(f, structure))

    def _get_DMAR_structure_SATC(self, structure: bytes) -> 'ACPI_TABLE_DMAR_SATC':
        off = struct.calcsize(self.DMAR_TABLE_FORMAT["SATC_FORMAT"])
        device_scope = self._get_DMAR_Device_Scope_list(structure[off:])
        return ACPI_TABLE_DMAR_SATC(*struct.unpack_from(self.DMAR_TABLE_FORMAT["SATC_FORMAT"], structure), DeviceScope=device_scope)

    def _get_DMAR_structure_SIDP(self, structure: bytes) -> 'ACPI_TABLE_DMAR_SIDP':
        off = struct.calcsize(self.DMAR_TABLE_FORMAT["SIDP_FORMAT"])
        device_scope = self._get_DMAR_Device_Scope_list(structure[off:])
        return ACPI_TABLE_DMAR_SIDP(*struct.unpack_from(self.DMAR_TABLE_FORMAT["SIDP_FORMAT"], structure), DeviceScope=device_scope)

    def _get_DMAR_Device_Scope_list(self, structure: bytes) -> List['ACPI_TABLE_DMAR_DeviceScope']:
        device_scope = []
        fmt = '=BB'
        step = struct.calcsize(fmt)
        off = 0
        while off < len(structure) - 1:
            (_type, length) = struct.unpack(fmt, structure[off:off + step])
            if 0 == length:
                break
            path_sz = length - struct.calcsize(self.DMAR_TABLE_FORMAT["DeviceScope_FORMAT"])
            f = self.DMAR_TABLE_FORMAT["DeviceScope_FORMAT"] + ('{:d}s'.format(path_sz))
            device_scope.append(ACPI_TABLE_DMAR_DeviceScope(*struct.unpack_from(f, structure[off:off + length])))
            off += length
        return device_scope

#
# DMAR Device Scope
#


DMAR_DS_TYPE_PCI_ENDPOINT = 0x1
DMAR_DS_TYPE_PCIPCI_BRIDGE = 0x2
DMAR_DS_TYPE_IOAPIC = 0x3
DMAR_DS_TYPE_MSI_CAPABLE_HPET = 0x4
DMAR_DS_TYPE_ACPI_NAMESPACE = 0x5
DMAR_DS_TYPE = {
    DMAR_DS_TYPE_PCI_ENDPOINT: 'PCI Endpoint Device',
    DMAR_DS_TYPE_PCIPCI_BRIDGE: 'PCI-PCI Bridge',
    DMAR_DS_TYPE_IOAPIC: 'I/O APIC Device',
    DMAR_DS_TYPE_MSI_CAPABLE_HPET: 'MSI Capable HPET',
    DMAR_DS_TYPE_ACPI_NAMESPACE: 'ACPI Namespace Device'
}


class ACPI_TABLE_DMAR_DeviceScope(namedtuple('ACPI_TABLE_DMAR_DeviceScope', 'Type Length Flags Reserved EnumerationID StartBusNum Path')):
    __slots__ = ()

    def __str__(self) -> str:
        return f"""      {DMAR_DS_TYPE[self.Type]} ({self.Type:02X}): Len: 0x{self.Length:02X}, Flags: 0x{self.Flags:02X}, Rsvd: 0x{self.Reserved:02X}, Enum ID: 0x{self.EnumerationID:02X}, Start Bus#: 0x{self.StartBusNum:02X}, Path: {self.Path.hex()}\n"""

#
# DMAR DMA Remapping Hardware Unit Definition (DRHD) Structure
#


class ACPI_TABLE_DMAR_DRHD(namedtuple('ACPI_TABLE_DMAR_DRHD', 'Type Length Flags Reserved SegmentNumber RegisterBaseAddr DeviceScope')):
    __slots__ = ()

    def __str__(self) -> str:
        _str = f"""
  DMA Remapping Hardware Unit Definition (0x{self.Type:04X}):
    Length                : 0x{self.Length:04X}
    Flags                 : 0x{self.Flags:02X}
    Reserved              : 0x{self.Reserved:02X}
    Segment Number        : 0x{self.SegmentNumber:04X}
    Register Base Address : 0x{self.RegisterBaseAddr:016X}
"""
        _str += '    Device Scope          :\n'
        for ds in self.DeviceScope:
            _str += str(ds)
        return _str

#
# DMAR Reserved Memory Range Reporting (RMRR) Structure
#


class ACPI_TABLE_DMAR_RMRR(namedtuple('ACPI_TABLE_DMAR_RMRR', 'Type Length Reserved SegmentNumber RMRBaseAddr RMRLimitAddr DeviceScope')):
    __slots__ = ()

    def __str__(self) -> str:
        _str = f"""
  Reserved Memory Range (0x{self.Type:04X}):
    Length                : 0x{self.Length:04X}
    Reserved              : 0x{self.Reserved:04X}
    Segment Number        : 0x{self.SegmentNumber:04X}
    Reserved Memory Base  : 0x{self.RMRBaseAddr:016X}
    Reserved Memory Limit : 0x{self.RMRLimitAddr:016X}
"""
        _str += '    Device Scope          :\n'
        for ds in self.DeviceScope:
            _str += str(ds)
        return _str
#
# DMAR Root Port ATS Capability Reporting (ATSR) Structure
#


class ACPI_TABLE_DMAR_ATSR(namedtuple('ACPI_TABLE_DMAR_ATSR', 'Type Length Flags Reserved SegmentNumber DeviceScope')):
    __slots__ = ()

    def __str__(self) -> str:
        _str = f"""
  Root Port ATS Capability (0x{self.Type:04X}):
    Length                : 0x{self.Length:04X}
    Flags                 : 0x{self.Flags:02X}
    Reserved (0)          : 0x{self.Reserved:02X}
    Segment Number        : 0x{self.SegmentNumber:04X}
"""
        _str += '    Device Scope          :\n'
        for ds in self.DeviceScope:
            _str += str(ds)
        return _str

#
# DMAR Remapping Hardware Status Affinity (RHSA) Structure
#


class ACPI_TABLE_DMAR_RHSA(namedtuple('ACPI_TABLE_DMAR_RHSA', 'Type Length Reserved RegisterBaseAddr ProximityDomain')):
    __slots__ = ()

    def __str__(self) -> str:
        return f"""
  Remapping Hardware Status Affinity (0x{self.Type:04X}):
    Length                : 0x{self.Length:04X}
    Reserved (0)          : 0x{self.Reserved:08X}
    Register Base Address : 0x{self.RegisterBaseAddr:016X}
    Proximity Domain      : 0x{self.ProximityDomain:08X}
"""


#
# DMAR ACPI Name-space Device Declaration (ANDD) Structure
#
ACPI_TABLE_DMAR_ANDD_FORMAT = '=HH3sB'
ACPI_TABLE_DMAR_ANDD_SIZE = struct.calcsize(ACPI_TABLE_DMAR_ANDD_FORMAT)
assert 8 == ACPI_TABLE_DMAR_ANDD_SIZE


class ACPI_TABLE_DMAR_ANDD(namedtuple('ACPI_TABLE_DMAR_ANDD', 'Type Length Reserved ACPIDevNum ACPIObjectName')):
    __slots__ = ()

    def __str__(self) -> str:
        return f"""
  Remapping Hardware Status Affinity (0x{self.Type:04X}):
    Length                : 0x{self.Length:04X}
    Reserved (0)          : {self.Reserved.hex()}
    ACPI Device Number    : 0x{self.ACPIDevNum:02X}
    ACPI Object Name      : {self.ACPIObjectName}
"""


#
# DMAR SoC Integrated Address Translation Cache Reporting (SATC) Structure
#
class ACPI_TABLE_DMAR_SATC(namedtuple('ACPI_TABLE_DMAR_SATC', 'Type Length Flags Reserved SegmentNumber DeviceScope')):
    __slots__ = ()

    def __str__(self):
        _str = f"""
  SoC Integrated Address Translation Cache (0x{self.Type:04X}):
    Length                : 0x{self.Length:04X}
    Flags                 : 0x{self.Flags:02X}
    Reserved (0)          : 0x{self.Reserved:02X}
    Segment Number        : 0x{self.SegmentNumber:016X}
"""
        _str += '    Device Scope          :\n'
        for ds in self.DeviceScope:
            _str += str(ds)
        return _str


#
# DMAR SoC Integrated Address Translation Cache Reporting (SIDP) Structure
#
class ACPI_TABLE_DMAR_SIDP(namedtuple('ACPI_TABLE_DMAR_SIDP', 'Type Length Reserved SegmentNumber DeviceScope')):
    __slots__ = ()

    def __str__(self):
        _str = f"""
  SoC Integrated Address Translation Cache Reporting Structure (0x{self.Type:04X}):
    Length                : 0x{self.Length:04X}
    Reserved (0)          : 0x{self.Reserved:02X}
    Segment Number        : 0x{self.SegmentNumber:016X}
"""
        _str += '    Device Scope          :\n'
        for ds in self.DeviceScope:
            _str += str(ds)
        return _str

########################################################################################################
#
# APIC Table
#
########################################################################################################


ACPI_TABLE_FORMAT_APIC = '=II'
ACPI_TABLE_SIZE_APIC = struct.calcsize(ACPI_TABLE_FORMAT_APIC)


class APIC (ACPI_TABLE):
    def __init__(self):
        self.apic_structs = []
        self.ACPI_TABLE_FORMAT = {}

        # APIC Table Structures
        self.APIC_TABLE_FORMAT = {
            "PROCESSOR_LAPIC": '<BBBBI',
            "IOAPIC": '<BBBBII',
            "INTERRUPT_SOURSE_OVERRIDE": '<BBBBIH',
            "NMI_SOURCE": '<BBHI',
            "LAPIC_NMI": '<BBBHB',
            "LAPIC_ADDRESS_OVERRIDE": '<BBHQ',
            "IOSAPIC": '<BBBBIQ',
            "PROCESSOR_LSAPIC": '<BBBBBHII',
            "PLATFORM_INTERRUPT_SOURCES": '<BBHBBBII',
            "PROCESSOR_Lx2APIC": '<BBHIII',
            "Lx2APIC_NMI": '<BBHIB3s',
            "GICC_CPU": '<BBHIIIIIQQQQIQQ',
            "GIC_DISTRIBUTOR": '<BBHIQII',
            "GIC_MSI": '<BBHIQIHH',
            "GIC_REDISTRIBUTOR": '<BBHQI'
        }

    def parse(self, table_content: bytes) -> None:
        (self.LAPICBase, self.Flags) = struct.unpack('=II', table_content[0: 8])
        cont = 8
        while cont < len(table_content) - 1:
            (value, length) = struct.unpack('=BB', table_content[cont: cont + 2])
            if 0 == length:
                break
            self.apic_structs.append(self.get_structure_APIC(value, table_content[cont: cont + length]))
            cont += length
        return

    def __str__(self) -> str:
        apic_str = f"""------------------------------------------------------------------
  APIC Table Contents
------------------------------------------------------------------
  Local APIC Base  : 0x{self.LAPICBase:016X}
  Flags            : 0x{self.Flags:08X}
"""
        apic_str += "\n  Interrupt Controller Structures:\n"
        for st in self.apic_structs:
            apic_str += str(st)
        return apic_str

    def get_structure_APIC(self, value: int, DataStructure: bytes) -> str:
        if 0x00 == value:
            ret = ACPI_TABLE_APIC_PROCESSOR_LAPIC(*struct.unpack_from(self.APIC_TABLE_FORMAT["PROCESSOR_LAPIC"], DataStructure))
        elif 0x01 == value:
            ret = ACPI_TABLE_APIC_IOAPIC(*struct.unpack_from(self.APIC_TABLE_FORMAT["IOAPIC"], DataStructure))
        elif 0x02 == value:
            ret = ACPI_TABLE_APIC_INTERRUPT_SOURSE_OVERRIDE(*struct.unpack_from(self.APIC_TABLE_FORMAT["INTERRUPT_SOURSE_OVERRIDE"], DataStructure))
        elif 0x03 == value:
            ret = ACPI_TABLE_APIC_NMI_SOURCE(*struct.unpack_from(self.APIC_TABLE_FORMAT["NMI_SOURCE"], DataStructure))
        elif 0x04 == value:
            ret = ACPI_TABLE_APIC_LAPIC_NMI(*struct.unpack_from(self.APIC_TABLE_FORMAT["LAPIC_NMI"], DataStructure))
        elif 0x05 == value:
            ret = ACPI_TABLE_APIC_LAPIC_ADDRESS_OVERRIDE(*struct.unpack_from(self.APIC_TABLE_FORMAT["LAPIC_ADDRESS_OVERRIDE"], DataStructure))
        elif 0x06 == value:
            ret = ACPI_TABLE_APIC_IOSAPIC(*struct.unpack_from(self.APIC_TABLE_FORMAT["IOSAPIC"], DataStructure))
        elif 0x07 == value:
            ret = ACPI_TABLE_APIC_PROCESSOR_LSAPIC(*struct.unpack_from(f'{self.APIC_TABLE_FORMAT["PROCESSOR_LSAPIC"]}{str(len(DataStructure) - 16)}s', DataStructure))
        elif 0x08 == value:
            ret = ACPI_TABLE_APIC_PLATFORM_INTERRUPT_SOURCES(*struct.unpack_from(self.APIC_TABLE_FORMAT["PLATFORM_INTERRUPT_SOURCES"], DataStructure))
        elif 0x09 == value:
            ret = ACPI_TABLE_APIC_PROCESSOR_Lx2APIC(*struct.unpack_from(self.APIC_TABLE_FORMAT["PROCESSOR_Lx2APIC"], DataStructure))
        elif 0x0A == value:
            ret = ACPI_TABLE_APIC_Lx2APIC_NMI(*struct.unpack_from(self.APIC_TABLE_FORMAT["Lx2APIC_NMI"], DataStructure))
        elif 0x0B == value:
            ret = ACPI_TABLE_APIC_GICC_CPU(*struct.unpack_from(self.APIC_TABLE_FORMAT["GICC_CPU"], DataStructure))
        elif 0x0C == value:
            ret = ACPI_TABLE_APIC_GIC_DISTRIBUTOR(*struct.unpack_from(self.APIC_TABLE_FORMAT["GIC_DISTRIBUTOR"], DataStructure))
        elif 0x0D == value:
            ret = ACPI_TABLE_APIC_GIC_MSI(*struct.unpack_from(self.APIC_TABLE_FORMAT["GIC_MSI"], DataStructure))
        elif 0x0E == value:
            ret = ACPI_TABLE_APIC_GIC_REDISTRIBUTOR(*struct.unpack_from(self.APIC_TABLE_FORMAT["GIC_REDISTRIBUTOR"], DataStructure))
        else:
            DataStructure_str = dump_buffer_bytes(DataStructure, length=16)
            ret = f"""
Reserved ....................................{value}"
{DataStructure_str}"
"""
        return str(ret)


class ACPI_TABLE_APIC_PROCESSOR_LAPIC(namedtuple('ACPI_TABLE_APIC_PROCESSOR_LAPIC', 'Type Length ACPIProcID APICID Flags')):
    __slots__ = ()

    def __str__(self) -> str:
        return f"""
  Processor Local APIC (0x00)
    Type         : 0x{self.Type:02X}
    Length       : 0x{self.Length:02X}
    ACPI Proc ID : 0x{self.ACPIProcID:02X}
    APIC ID      : 0x{self.APICID:02X}
    Flags        : 0x{self.Flags:02X}
"""


class ACPI_TABLE_APIC_IOAPIC(namedtuple('ACPI_TABLE_APIC_IOAPIC', 'Type Length IOAPICID Reserved IOAPICAddr GlobalSysIntBase')):
    __slots__ = ()

    def __str__(self) -> str:
        return f"""
  I/O APIC (0x01)
    Type                : 0x{self.Type:02X}
    Length              : 0x{self.Length:02X}
    Reserved            : 0x{self.IOAPICID:02X}
    I/O APIC ID         : 0x{self.Reserved:02X}
    I/O APIC Base       : 0x{self.IOAPICAddr:02X}
    Global Sys Int Base : 0x{self.GlobalSysIntBase:02X}
"""


class ACPI_TABLE_APIC_INTERRUPT_SOURSE_OVERRIDE(namedtuple('ACPI_TABLE_APIC_INTERRUPT_SOURSE_OVERRIDE', 'Type Length Bus Source GlobalSysIntBase Flags')):
    __slots__ = ()

    def __str__(self) -> str:
        return f"""
  Interrupt Source Override (0x02)
    Type                : 0x{self.Type:02X}
    Length              : 0x{self.Length:02X}
    Bus                 : 0x{self.Bus:02X}
    Source              : 0x{self.Source:02X}
    Global Sys Int Base : 0x{self.GlobalSysIntBase:02X}
    Flags               : 0x{self.Flags:02X}
"""


class ACPI_TABLE_APIC_NMI_SOURCE(namedtuple('ACPI_TABLE_APIC_NMI_SOURCE', 'Type Length Flags GlobalSysIntBase')):
    __slots__ = ()

    def __str__(self) -> str:
        return f"""
  Non-maskable Interrupt (NMI) Source (0x03)
    Type                : 0x{self.Type:02X}
    Length              : 0x{self.Length:02X}
    Flags               : 0x{self.Flags:02X}
    Global Sys Int Base : 0x{self.GlobalSysIntBase:02X}
"""


class ACPI_TABLE_APIC_LAPIC_NMI(namedtuple('ACPI_TABLE_APIC_LAPIC_NMI', 'Type Length ACPIProcessorID Flags LocalAPICLINT')):
    __slots__ = ()

    def __str__(self) -> str:
        return f"""
  Local APIC NMI (0x04)
    Type              : 0x{self.Type:02X}
    Length            : 0x{self.Length:02X}
    ACPI Processor ID : 0x{self.ACPIProcessorID:02X}
    Flags             : 0x{self.Flags:02X}
    Local APIC LINT   : 0x{self.LocalAPICLINT:02X}
"""


class ACPI_TABLE_APIC_LAPIC_ADDRESS_OVERRIDE(namedtuple('ACPI_TABLE_APIC_LAPIC_ADDRESS_OVERRIDE', 'Type Length Reserved LocalAPICAddress')):
    __slots__ = ()

    def __str__(self) -> str:
        return f"""
  Local APIC Address Override (0x05)
    Type               : 0x{self.Type:02X}
    Length             : 0x{self.Length:02X}
    Reserved           : 0x{self.Reserved:02X}
    Local APIC Address : 0x{self.LocalAPICAddress:02X}
"""


class ACPI_TABLE_APIC_IOSAPIC(namedtuple('ACPI_TABLE_APIC_IOSAPIC', 'Type Length IOAPICID Reserved GlobalSysIntBase IOSAPICAddress')):
    __slots__ = ()

    def __str__(self) -> str:
        return f"""
  I/O SAPIC (0x06)
    Type                : 0x{self.Type:02X}
    Length              : 0x{self.Length:02X}
    IO APIC ID          : 0x{self.IOAPICID:02X}
    Reserved            : 0x{self.Reserved:02X}
    Global Sys Int Base : 0x{self.GlobalSysIntBase:02X}
    IO SAPIC Address    : 0x{self.IOSAPICAddress:02X}
"""


class ACPI_TABLE_APIC_PROCESSOR_LSAPIC(namedtuple('ACPI_TABLE_APIC_PROCESSOR_LSAPIC', 'Type Length ACPIProcID LocalSAPICID LocalSAPICEID Reserved Flags ACPIProcUIDValue ACPIProcUIDString'), ):
    __slots__ = ()

    def __str__(self) -> str:
        return f"""
  Local SAPIC (0x07)
    Type                 : 0x{self.Type:02X}
    Length               : 0x{self.Length:02X}
    ACPI Proc ID         : 0x{self.ACPIProcID:02X}
    Local SAPIC ID       : 0x{self.LocalSAPICID:02X}
    Local SAPIC EID      : 0x{self.LocalSAPICEID:02X}
    Reserved             : 0x{self.Reserved:02X}
    Flags                : 0x{self.Flags:02X}
    ACPI Proc UID Value  : 0x{self.ACPIProcUIDValue:02X}
    ACPI Proc UID String : 0x{self.ACPIProcUIDString:02X}
"""


class ACPI_TABLE_APIC_PLATFORM_INTERRUPT_SOURCES(namedtuple('ACPI_TABLE_APIC_PLATFORM_INTERRUPT_SOURCES', 'Type Length Flags InterruptType ProcID ProcEID IOSAPICVector GlobalSystemInterrupt PlatIntSourceFlags')):
    __slots__ = ()

    def __str__(self) -> str:
        return f"""
  Platform Interrupt Sources (0x08)
    Type                    : 0x{self.Type:02X}
    Length                  : 0x{self.Length:02X}
    Flags                   : 0x{self.Flags:02X}
    Interrupt Type          : 0x{self.InterruptType:02X}
    Proc ID                 : 0x{self.ProcID:02X}
    Proc EID                : 0x{self.ProcEID:02X}
    I/O SAPIC Vector        : 0x{self.IOSAPICVector:02X}
    Global System Interrupt : 0x{self.GlobalSystemInterrupt:02X}
    Plat Int Source Flags   : 0x{self.PlatIntSourceFlags:02X}
"""


class ACPI_TABLE_APIC_PROCESSOR_Lx2APIC(namedtuple('ACPI_TABLE_APIC_PROCESSOR_Lx2APIC', 'Type Length Reserved x2APICID Flags ACPIProcUID')):
    __slots__ = ()

    def __str__(self) -> str:
        return f"""
  Processor Local x2APIC (0x09)
    Type          : 0x{self.Type:02X}
    Length        : 0x{self.Length:02X}
    Reserved      : 0x{self.Reserved:02X}
    x2APIC ID     : 0x{self.x2APICID:02X}
    Flags         : 0x{self.Flags:02X}
    ACPI Proc UID : 0x{self.ACPIProcUID:02X}
"""


class ACPI_TABLE_APIC_Lx2APIC_NMI(namedtuple('ACPI_TABLE_APIC_Lx2APIC_NMI', 'Type Length Flags ACPIProcUID Localx2APICLINT Reserved')):
    __slots__ = ()

    def __str__(self) -> str:
        return f"""
  Local x2APIC NMI (0x0A)
    Type              : 0x{self.Type:02X}
    Length            : 0x{self.Length:02X}
    Flags             : 0x{self.Flags:02X}
    ACPI Proc UID     : 0x{self.ACPIProcUID:02X}
    Local x2APIC LINT : 0x{self.Localx2APICLINT:02X}
    Reserved          : 0x{self.Reserved:}
"""


class ACPI_TABLE_APIC_GICC_CPU(namedtuple('ACPI_TABLE_APIC_GICC_CPU', 'Type Length Reserved CPUIntNumber ACPIProcUID Flags ParkingProtocolVersion PerformanceInterruptGSIV ParkedAddress PhysicalAddress GICV GICH VGICMaintenanceINterrupt GICRBaseAddress MPIDR')):
    __slots__ = ()

    def __str__(self) -> str:
        return f"""
  GICC CPU Interface Structure (0x0B)
    Type                       : 0x{self.Type:02X}
    Length                     : 0x{self.Length:02X}
    Reserved                   : 0x{self.Reserved:02X}
    CPU Int Number             : 0x{self.CPUIntNumber:02X}
    ACPI Proc UID              : 0x{self.ACPIProcUID:02X}
    Flags                      : 0x{self.Flags:02X}
    Parking Protocol Version   : 0x{self.ParkingProtocolVersion:02X}
    Performance Interrupt GSIV : 0x{self.PerformanceInterruptGSIV:02X}
    Parked Address             : 0x{self.ParkedAddress:02X}
    Physical Address           : 0x{self.PhysicalAddress:02X}
    GICV                       : 0x{self.GICV:02X}
    GICH                       : 0x{self.GICH:02X}
    VGIC Maintenance INterrupt : 0x{self.VGICMaintenanceINterrupt:02X}
    GICR Base Address          : 0x{self.GICRBaseAddress:02X}
    MPIDR                      : 0x{self.MPIDR:02X}
"""


class ACPI_TABLE_APIC_GIC_DISTRIBUTOR(namedtuple('ACPI_TABLE_APIC_GIC_DISTRIBUTOR', 'Type Length Reserved GICID PhysicalBaseAddress SystemVectorBase Reserved2 ')):
    __slots__ = ()

    def __str__(self) -> str:
        return f"""
  GICD GIC Distributor Structure (0x0C)
    Type                  : 0x{self.Type:02X}
    Length                : 0x{self.Length:02X}
    Reserved              : 0x{self.Reserved:02X}
    GICID                 : 0x{self.GICID:02X}
    Physical Base Address : 0x{self.PhysicalBaseAddress:02X}
    System Vector Base    : 0x{self.SystemVectorBase:02X}
    Reserved              : 0x{self.Reserved2:02X}
"""


class ACPI_TABLE_APIC_GIC_MSI(namedtuple('ACPI_TABLE_APIC_GIC_MSI', 'Type Length Reserved GICMSIFrameID PhysicalBaseAddress Flags SPICount SPIBase')):
    __slots__ = ()

    def __str__(self) -> str:
        return f"""
  GICv2m MSI Frame (0x0D)
    Type                  : 0x{self.Type:02X}
    Length                : 0x{self.Length:02X}
    Reserved              : 0x{self.Reserved:02X}
    GIC MSI Frame ID      : 0x{self.GICMSIFrameID:02X}
    Physical Base Address : 0x{self.PhysicalBaseAddress:02X}
    Flags                 : 0x{self.Flags:02X}
    SPI Count             : 0x{self.SPICount:02X}
    SPI Base              : 0x{self.SPIBase:02X}
"""


class ACPI_TABLE_APIC_GIC_REDISTRIBUTOR(namedtuple('ACPI_TABLE_APIC_GIC_REDISTRIBUTOR', 'Type Length Reserved DiscoverRangeBaseAdd DiscoverRangeLength')):
    __slots__ = ()

    def __str__(self) -> str:
        return f"""
  GICR Redistributor Structure (0x0E)
    Type                  : 0x{self.Type:02X}
    Length                : 0x{self.Length:02X}
    Reserved              : 0x{self.Reserved:02X}
    Discover Range Base   : 0x{self.DiscoverRangeBaseAdd:02X}
    Discover Range Length : 0x{self.DiscoverRangeLength:02X}
"""

########################################################################################################
#
# XSDT Table
#
########################################################################################################


class XSDT (ACPI_TABLE):
    def __init__(self):
        self.Entries = []

    def parse(self, table_content: bytes) -> None:
        num_of_tables = len(table_content) // 8
        self.Entries = struct.unpack(f'={num_of_tables:d}Q', table_content)
        return

    def __str__(self) -> str:
        entries_str = ''.join([f'0x{addr:016X}\n' for addr in self.Entries])
        return f"""==================================================================
  Extended System Description Table (XSDT)
==================================================================
ACPI Table Entries:
{entries_str}
"""

########################################################################################################
#
# RSDT Table
#
########################################################################################################


class RSDT (ACPI_TABLE):
    def __init__(self):
        self.Entries = []

    def parse(self, table_content: bytes) -> None:
        num_of_tables = len(table_content) // 4
        self.Entries = struct.unpack(f'={num_of_tables:d}I', table_content)
        return

    def __str__(self) -> str:
        entries_str = ''.join([f'0x{addr:016X}\n' for addr in self.Entries])
        return f"""==================================================================
  Root System Description Table (RSDT)
==================================================================
ACPI Table Entries:
{entries_str}
"""

########################################################################################################
#
# FADT Table
#
########################################################################################################


class FADT (ACPI_TABLE):
    def __init__(self):
        self.dsdt = None
        self.x_dsdt = None
        self.smi = None
        self.acpi_enable = None
        self.acpi_disable = None

    def parse(self, table_content: bytes) -> None:
        self.dsdt = struct.unpack('<I', table_content[4:8])[0]
        self.smi = struct.unpack('<I', table_content[12:16])[0]
        self.acpi_enable = struct.unpack('B', table_content[16:17])[0]
        self.acpi_disable = struct.unpack('B', table_content[17:18])[0]
        if len(table_content) >= 112:
            self.x_dsdt = struct.unpack('<Q', table_content[104:112])[0]
        else:
            if logger().HAL:
                logger().log('[acpi] Cannot find X_DSDT entry in FADT.')

    def get_DSDT_address_to_use(self) -> Optional[int]:
        dsdt_address_to_use = None
        if self.x_dsdt is None:
            if self.dsdt != 0:
                dsdt_address_to_use = self.dsdt
        else:
            if self.x_dsdt != 0 and self.dsdt == 0:
                dsdt_address_to_use = self.x_dsdt
            elif self.x_dsdt == 0 and self.dsdt != 0:
                dsdt_address_to_use = self.dsdt
            elif self.x_dsdt != 0 and self.x_dsdt == self.dsdt:
                dsdt_address_to_use = self.x_dsdt
        return dsdt_address_to_use

    def __str__(self) -> str:
        dsdt_str = f'0x{self.x_dsdt:016X}' if self.x_dsdt is not None else 'Not found'
        return f"""------------------------------------------------------------------
  Fixed ACPI Description Table (FADT) Contents
------------------------------------------------------------------
  DSDT    : 0x{self.dsdt:08X}
  X_DSDT  : {dsdt_str}
  SMI_CMD : 0x{self.smi:04X}
  ACPI_EN : 0x{self.acpi_enable:01X}
  ACPI_DIS: 0x{self.acpi_disable:01X}
"""

########################################################################################################
#
# BGRT Table
#
########################################################################################################


class BGRT (ACPI_TABLE):
    def __init__(self):
        return

    def parse(self, table_content: bytes) -> None:
        self.Version = struct.unpack('<H', table_content[0:2])[0]
        self.Status = struct.unpack('<b', table_content[2:3])[0]
        self.ImageType = struct.unpack('<b', table_content[3:4])[0]
        self.ImageAddress = struct.unpack('<Q', table_content[4:12])[0]
        self.ImageOffsetX = struct.unpack('<I', table_content[12:16])[0]
        self.ImageOffsetY = struct.unpack('<I', table_content[16:20])[0]
        if self.Status == 0:
            self.OrientationOffset = '0 degrees'
        elif self.Status == 1:
            self.OrientationOffset = '90 degrees'
        elif self.Status == 2:
            self.OrientationOffset = '180 degrees'
        elif self.Status == 3:
            self.OrientationOffset = '270 degrees'
        else:
            self.OrientationOffset = 'Reserved bits are used'
        if self.ImageType == 0:
            self.ImageTypeStr = ' - Bitmap'
        else:
            self.ImageTypeStr = 'Reserved'

    def __str__(self) -> str:
        return f"""
------------------------------------------------------------------
  Version                       : {self.Version:d}
  Status                        : {self.Status:d}
   Clockwise Orientation Offset : {self.OrientationOffset}
  Image Type                    : {self.ImageType:d} {self.ImageTypeStr}
  Image Address                 : 0x{self.ImageAddress:016X}
  Image Offset X                : 0x{self.ImageOffsetX:08X}
  Image Offset Y                : 0x{self.ImageOffsetY:08X}
"""

########################################################################################################
#
# BERT Table
#
########################################################################################################


class BERT (ACPI_TABLE):
    def __init__(self, bootRegion: bytes) -> None:
        self.bootRegion = bootRegion
        return

    def parseSectionType(self, table_content: bytes) -> str:
        # Processor Generic: {0x9876CCAD, 0x47B4, 0x4bdb, {0xB6, 0x5E, 0x16, 0xF1, 0x93, 0xC4, 0xF3, 0xDB}}
        # Processor Specific: IA32/X64:{0xDC3EA0B0, 0xA144, 0x4797, {0xB9, 0x5B, 0x53, 0xFA, 0x24, 0x2B, 0x6E, 0x1D}}
        # Processor Specific: IPF: {0xe429faf1, 0x3cb7, 0x11d4, {0xb, 0xca, 0x7, 0x00, 0x80,0xc7, 0x3c, 0x88, 0x81}}
        # Processor Specific: ARM: { 0xE19E3D16, 0xBC11,0x11E4,{0x9C, 0xAA, 0xC2, 0x05,0x1D, 0x5D, 0x46, 0xB0}}
        # Platform Memory: {0xA5BC1114, 0x6F64, 0x4EDE, {0xB8, 0x63, 0x3E, 0x83, 0xED, 0x7C, 0x83, 0xB1}}
        # PCIe: {0xD995E954, 0xBBC1, 0x430F, {0xAD, 0x91, 0xB4, 0x4D, 0xCB,0x3C, 0x6F, 0x35}}
        # Firmware Error Record Reference: {0x81212A96, 0x09ED, 0x4996, {0x94, 0x71, 0x8D, 0x72, 0x9C,0x8E, 0x69, 0xED}}
        # PCI/PCI-X Bus: {0xC5753963, 0x3B84, 0x4095, {0xBF, 0x78, 0xED, 0xDA, 0xD3,0xF9, 0xC9, 0xDD}}
        # PCI Component/Device: {0xEB5E4685, 0xCA66, 0x4769, {0xB6, 0xA2, 0x26, 0x06, 0x8B,0x00, 0x13, 0x26}}
        # DMAr Generic: {0x5B51FEF7, 0xC79D, 0x4434, {0x8F, 0x1B, 0xAA, 0x62, 0xDE, 0x3E, 0x2C, 0x64}}
        # Intel VT for Directed I/O Specific DMAr Section:  {0x71761D37, 0x32B2, 0x45cd, {0xA7, 0xD0, 0xB0, 0xFE 0xDD, 0x93, 0xE8, 0xCF}}
        # IOMMU Specific DMAr Section: {0x036F84E1, 0x7F37, 0x428c, {0xA7, 0x9E, 0x57, 0x5F, 0xDF, 0xAA, 0x84, 0xEC}}
        val1 = struct.unpack('<L', table_content[0:4])[0]
        val2 = struct.unpack('<L', table_content[4:8])[0]
        val3 = struct.unpack('<L', table_content[8:12])[0]
        val4 = struct.unpack('<L', table_content[12:16])[0]
        results = f'''0x{val1:08X} 0x{val2:08X} 0x{val3:08X} 0x{val4:08X} - '''
        """if val1 == 0x9876CCAD and val2 == 0x47B4 and val3 == 0x4bdb and val4 in [0xB6, 0x5E, 0x16, 0xF1, 0x93, 0xC4, 0xF3, 0xDB]:
            return results + '''Generic Processor'''
        elif val1 == 0xDC3EA0B0 and val2 == 0xA144 and val3 == 0x4797 and val4 in [0xB9, 0x5B, 0x53, 0xFA, 0x24, 0x2B, 0x6E, 0x1D]:
            return results + '''Processor Specific: IA32/X64'''
        elif val1 == 0xe429faf1 and val2 == 0x3cb7 and val3 == 0x11d4 and val4 in [0xb, 0xca, 0x7, 0x00, 0x80,0xc7, 0x3c, 0x88, 0x81]:
            return results + '''Processor Specific: IPF'''
        elif val1 == 0xE19E3D16 and val2 == 0xBC11 and val3 == 0x11E4 and val4 in [0x9C, 0xAA, 0xC2, 0x05,0x1D, 0x5D, 0x46, 0xB0]:
            return results + '''Processor Specific: ARM'''
        elif val1 == 0xA5BC1114 and val2 == 0x6F64 and val3 == 0x4EDE and val4 in [0xB8, 0x63, 0x3E, 0x83, 0xED, 0x7C, 0x83, 0xB1]:
            return results + '''Platform Memory'''
        elif val1 == 0xD995E954 and val2 == 0xBBC1 and val3 == 0x430F and val4 in [0xAD, 0x91, 0xB4, 0x4D, 0xCB,0x3C, 0x6F, 0x35]:
            return results + '''PCIe'''
        elif val1 == 0x81212A96 and val2 == 0x09ED and val3 == 0x4996 and val4 in [0x94, 0x71, 0x8D, 0x72, 0x9C, 0x8E, 0x69, 0xED]:
            return results + '''Firmware Error Record Reference'''
        elif val1 == 0xC5753963 and val2 == 0x3B84 and val3 == 0x4095 and val4 in [0xBF, 0x78, 0xED, 0xDA, 0xD3, 0xF9, 0xC9, 0xDD]:
            return results + '''PCI/PCI-X Bus'''
        elif val1 == 0xEB5E4685 and val2 == 0xCA66 and val3 == 0x4769 and val4 in [0xB6, 0xA2, 0x26, 0x06, 0x8B, 0x00, 0x13, 0x26]:
            return results + '''PCI Component/Device'''
        elif val1 == 0x5B51FEF7 and val2 == 0xC79D and val3 == 0x4434 and val4 in [0x8F, 0x1B, 0xAA, 0x62, 0xDE, 0x3E, 0x2C, 0x64]:
            return results + '''DMAr Generic'''
        elif val1 == 0x71761D37 and val2 == 0x32B2 and val3 == 0x45cd and val4 in [0xA7, 0xD0, 0xB0, 0xFE, 0xDD, 0x93, 0xE8, 0xCF]:
            return results + '''Intel VT for Directed I/O Specific DMAr Section'''
        elif val1 == 0x036F84E1 and val2 == 0x7F37 and val3 == 0x428c and val4 in [0xA7, 0x9E, 0x57, 0x5F, 0xDF, 0xAA, 0x84, 0xEC]:
            return results + '''IOMMU Specific DMAr Section'''"""
        return results + '''Unknown'''

    def parseTime(self, table_content: bytes) -> str:
        seconds = struct.unpack('<B', table_content[0:1])[0]
        minutes = struct.unpack('<B', table_content[1:2])[0]
        hours = struct.unpack('<B', table_content[2:3])[0]
        percision = struct.unpack('<B', table_content[3:4])[0]
        day = struct.unpack('<B', table_content[4:5])[0]
        month = struct.unpack('<B', table_content[5:6])[0]
        year = struct.unpack('<B', table_content[6:7])[0]
        century = struct.unpack('<B', table_content[7:8])[0]
        precision_str = ''
        if percision > 0:
            precision_str = '(time is percise and correlates to time of event)'
        return f''' {hours:d}:{minutes:d}:{seconds:d} {month:d}/{day:d}/{century:d}{year:d} [m/d/y] {precision_str}'''

    def parseGenErrorEntries(self, table_content: bytes) -> str:
        errorSeverities = ['Recoverable', 'Fatal', 'Corrected', 'None', 'Unknown severity entry']
        sectionType = self.parseSectionType(table_content[0:16])
        errorSeverity = struct.unpack('<L', table_content[16:20])[0]
        revision = struct.unpack('<H', table_content[20:22])[0]
        validationBits = struct.unpack('<B', table_content[22:23])[0]
        flags = struct.unpack('<B', table_content[23:24])[0]
        errDataLen = struct.unpack('<L', table_content[24:28])[0]
        FRU_Id1 = struct.unpack('<L', table_content[28:32])[0]
        FRU_Id2 = struct.unpack('<L', table_content[32:36])[0]
        FRU_Id3 = struct.unpack('<L', table_content[36:40])[0]
        FRU_Id4 = struct.unpack('<L', table_content[40:44])[0]
        FRU_Text = struct.unpack('<20s', table_content[44:64])[0]
        timestamp = struct.unpack('<Q', table_content[64:72])[0]
        timestamp_str = self.parseTime(table_content[64:72])
        if errDataLen > 0:
            data = str(struct.unpack('<P', table_content[72:errDataLen + 72])[0])
        else:
            data = 'None'
        errorSeverity_str = errorSeverities[4]
        if errorSeverity < 4:
            errorSeverity_str = errorSeverities[errorSeverity]
        revision_str = ''
        if revision != 3:
            revision_str = ' - Should be 0x003'
        FRU_Id_str = ''
        if FRU_Id1 == 0 and FRU_Id2 == 0 and FRU_Id3 == 0 and FRU_Id4 == 0:
            FRU_Id_str = ' - Default value, invalid FRU ID'
        return f'''
      Section Type                                  : {sectionType}
      Error Severity                                : {errorSeverity} - {errorSeverity_str}
      Revision                                      : 0x{revision:04X}{revision_str}
      Validation Bits                               : 0x{validationBits:02X}
      Flags                                         : 0x{flags:02X}
        Primary                                     : 0x{flags & 1:02X}
        Containment Warning                         : 0x{flags & 2:02X}
        Reset                                       : 0x{flags & 4:02X}
        Error Threshold Exceeded                    : 0x{flags & 8:02X}
        Resource Not Accessible                     : 0x{flags & 16:02X}
        Latent Error                                : 0x{flags & 32:02X}
        Propagated                                  : 0x{flags & 64:02X}
        Overflow                                    : 0x{flags & 128:02X}
        Reserved                                    : 0x{flags & 256:02X}
      Error Data Length                             : 0x{errDataLen:08X} ( {errDataLen:d} )
      FRU Id                                        : {FRU_Id1} {FRU_Id2} {FRU_Id3} {FRU_Id4}{FRU_Id_str}
      FRU Text                                      : {FRU_Text}
      Timestamp                                     : {timestamp:d} - {timestamp_str}
      Data                                          : {data}'''

    def parseErrorBlock(self, table_content: bytes) -> None:
        errorSeverities = ['Recoverable', 'Fatal', 'Corrected', 'None', 'Unknown severity entry']
        blockStatus = struct.unpack('<L', table_content[0:4])[0]
        rawDataOffset = struct.unpack('<L', table_content[4:8])[0]
        rawDataLen = struct.unpack('<L', table_content[8:12])[0]
        dataLen = struct.unpack('<L', table_content[12:16])[0]
        errorSeverity = struct.unpack('<L', table_content[16:20])[0]
        genErrorDataEntries = self.parseGenErrorEntries(table_content[20:])
        errorSeverity_str = errorSeverities[4]
        if errorSeverity < 4:
            errorSeverity_str = errorSeverities[errorSeverity]
        self.BootRegion = f'''
Generic Error Status Block
    Block Status                                    : 0x{blockStatus:08X}
      Correctable Error Valid                       : 0x{blockStatus & 1:08X}
      Uncorrectable Error Valid                     : 0x{blockStatus & 2:08X}
      Multiple Uncorrectable Errors                 : 0x{blockStatus & 4:08X}
      Multiple Correctable Errors                   : 0x{blockStatus & 8:08X}
      Error Data Entry Count                        : 0x{blockStatus & 1023:08X}
      Reserved                                      : 0x{blockStatus & 262143:08X}
    Raw Data Offset                                 : 0x{rawDataOffset:08X} ( {rawDataOffset:d} )
    Raw Data Length                                 : 0x{rawDataLen:08X} ( {rawDataLen:d} )
    Data Length                                     : 0x{dataLen:08X} ( {dataLen:d} )
    Error Severity                                  : 0x{errorSeverity:08X} - {errorSeverity_str}
    Generic Error Data Entries{genErrorDataEntries}
'''

    def parse(self, table_content: bytes) -> None:
        self.BootRegionLen = struct.unpack('<L', table_content[0:4])[0]
        self.BootRegionAddr = struct.unpack('<Q', table_content[4:12])[0]
        self.parseErrorBlock(self.bootRegion)

    def __str__(self) -> str:
        return f"""
------------------------------------------------------------------
  Boot Region Length                                : {self.BootRegionLen:d}
  Boot Region Address	                            : 0x{self.BootRegionAddr:016X}
  Boot Region - {self.BootRegion}
"""

########################################################################################################
#
# EINJ Table
#
########################################################################################################


class EINJ (ACPI_TABLE):
    def __init__(self):
        return

    def parseAddress(self, table_content: bytes) -> str:
        return str(GAS(table_content))

    def parseInjection(self, table_content: bytes) -> None:
        errorInjectActions = ['BEGIN_INJECTION_OPERATION', 'GET_TRIGGER_ERROR_ACTION', 'SET_ERROR_TYPE', 'GET_ERROR_TYPE', 'END_OPERATION', 'EXECUTE_OPERATION',
                              'CHECK_BUSY_STATUS', 'GET_COMMAND_STATUS', 'SET_ERROR_TYPE_WITH_ADDRESS', 'GET_EXECUTE_OPERATION_TIMING', 'not recognized as valid aciton']
        injectionInstructions = ['READ_REGISTER', 'READ_REGISTER_VALUE', 'WRITE_REGISTER', 'WRITE_REGISTER_VALUE', 'NOOP', 'not recognized as valid instruction']
        injectionAction = struct.unpack('<B', table_content[0:1])[0]
        instruction = struct.unpack('<B', table_content[1:2])[0]
        flags = struct.unpack('<B', table_content[2:3])[0]
        reserved = struct.unpack('<B', table_content[3:4])[0]
        injectionHeaderSz = struct.unpack('<L', table_content[0:4])[0]
        registerRegion = self.parseAddress(table_content[4:16])
        value = struct.unpack('<Q', table_content[16:24])[0]
        mask = struct.unpack('<Q', table_content[24:32])[0]
        if injectionAction < 10:
            injectionAction_str = errorInjectActions[injectionAction]
        elif injectionAction == 255:
            injectionAction_str = 'TRIGGER_ERROR'
        else:
            injectionAction_str = errorInjectActions[10]
        if instruction < 5:
            instruction_str = injectionInstructions[instruction]
        else:
            instruction_str = injectionInstructions[5]
        if flags == 1 and (instruction == 2 or instruction == 3):
            flags_str = ' - PRESERVE_REGISTER'
        elif flags == 0:
            flags_str = ' - Ignore'
        else:
            flags_str = ''
        if reserved != 0:
            reserved_str = ' - Error, must be 0'
        else:
            reserved_str = ''
        self.results_str += f"""
  Injection Instruction Entry
    Injection Action                                : 0x{injectionAction:02X} ( {injectionAction:d} ) - {injectionAction_str}
    Instruction                                     : 0x{instruction:02X} ( {instruction:d} ) - {instruction_str}
    Flags                                           : 0x{flags:02X} ( {flags:d} ){flags_str}
    Reserved                                        : 0x{reserved:02X} ( {reserved:d} ){reserved_str}
    Register Region - {registerRegion}
    Value                                           : 0x{value:016X} ( {value:d} )
    Mask                                            : 0x{mask:016X} ( {mask:d} )
    """

    def parseInjectionActionTable(self, table_contents: bytes, numInjections: int) -> None:
        curInjection = 0
        while curInjection < numInjections:
            self.parseInjection(table_contents[curInjection * 32:(curInjection + 1) * 32])
            curInjection += 1

    def parse(self, table_content: bytes) -> None:
        injectionHeaderSz = struct.unpack('<L', table_content[0:4])[0]
        injectionFlags = struct.unpack('<B', table_content[4:5])[0]
        reserved1 = struct.unpack('<B', table_content[5:6])[0]
        reserved2 = struct.unpack('<B', table_content[6:7])[0]
        reserved3 = struct.unpack('<B', table_content[7:8])[0]
        reserved3 = reserved3 << 16
        reserved2 = reserved2 << 8
        reserved = reserved3 | reserved2 | reserved1
        injectionEntryCount = struct.unpack('<L', table_content[8:12])[0]
        injection_str = ''
        reserved_str = ''
        if injectionFlags != 0:
            injection_str = ' - Error, this feild should be 0'
        if reserved != 0:
            reserved_str = ' - Error, this field should be 0'
        self.results_str = f"""
------------------------------------------------------------------
  Injection Header Size                             : 0x{injectionHeaderSz:016X} ( {injectionHeaderSz:d} )
  Injection Flags                                   : 0x{injectionFlags:02X}{injection_str}
  Reserved                                          : 0x{reserved:06X}{reserved_str}
  Injection Entry Count                             : 0x{injectionEntryCount:08X} ( {injectionEntryCount:d} )
  Injection Instruction Entries
"""

    def __str__(self) -> str:
        return self.results_str

########################################################################################################
#
# ERST Table
#
########################################################################################################


class ERST (ACPI_TABLE):
    def __init__(self):
        return

    def parseAddress(self, table_content: bytes) -> str:
        return str(GAS(table_content))

    def parseActionTable(self, table_content: bytes, instrCountEntry: int) -> None:
        curInstruction = 0
        while curInstruction < instrCountEntry:
            self.parseInstructionEntry(table_content[32 * curInstruction:])
            curInstruction += 1

    def parseInstructionEntry(self, table_content: bytes) -> None:
        serializationInstr_str = ''
        serializationAction = struct.unpack('<B', table_content[0:1])[0]
        instruction = struct.unpack('<B', table_content[1:2])[0]
        flags = struct.unpack('<B', table_content[2:3])[0]
        reserved = struct.unpack('<B', table_content[3:4])[0]
        registerRegion = self.parseAddress(table_content[4:16])
        value = struct.unpack('<Q', table_content[16:24])[0]
        mask = struct.unpack('<Q', table_content[24:32])[0]
        serializationActions = ['BEGIN_WRITE_OPERATION', 'BEGIN_READ_OPERATION', 'BEGIN_CLEAR_OPERATION', 'END_OPERATION', 'SET_RECORD_OFFESET', 'EXECUTE_OPERATION', 'CHECK_BUSY_STATUS',
                                'GET_COMMAND_STATUS', 'GET_RECORD_IDENTIFIER', 'SET_RECORD_IDENTIFIER', 'GET_RECORD_COUNT', 'BEGIN_DUMMY_WRITE_OPERATION', 'RESERVED', 'GET_ERROR_LOG_ADDRESS_RANGE',
                                'GET_ERROR_LOG_ADDRESS_RANGE_LENGTH', 'GET_ERROR_LOG_ADDRESS_RANGE_ATTEIBUTES', 'GET_EXECUTE_OPERATION_TIMINGS']
        serializationInstructions = ['READ_REGISTER', 'READ_REGISTER_VALUE', 'WRITE_REGISTER', 'WRITE_REGISTER_VALUE', 'NOOP', 'LOAD_VAR1', 'LOAD_VAR2', 'STORE_VAR1', 'ADD', 'SUBTRACT',
                                     'ADD_VALUE', 'SUBTRACT_VALUE', 'STALL', 'STALL_WHILE_TRUE', 'SKIP_NEXT_INSTRUCTION_IF_TRUE', 'GOTO', 'SET_SCR_ADDRESS_BASE', 'SET_DST_ADDRESS_BASE', 'MOVE_DATA']
        if serializationAction < 17:
            serializationAction_str = serializationActions[serializationAction]
        else:
            serializationAction_str = 'Unknown'
        if instruction < 17:
            serializationInstr_str = serializationInstructions[instruction]
        else:
            serializationAction_str = 'Unknown'
        if reserved != 0:
            reserved_str = ' - Error, this should be 0'
        else:
            reserved_str = ''
        if flags == 1:
            flags_str = ' - PRESERVE_REGISTER'
        else:
            flags_str = ''

        self.results_str += f'''
    Serialization Intruction Entry
      Serialized Action                             : 0x{serializationAction:02X} - {serializationAction_str}
      Instruction                                   : 0x{instruction:02X} - {serializationInstr_str}
      Flags                                         : 0x{flags:02X}{flags_str}
      Reserved                                      : 0x{reserved:02X}{reserved_str}
      Register Region - {registerRegion}
      Value                                         : 0x{value:016X}
      Mask                                          : 0x{mask:016X}
    '''

    def parse(self, table_content: bytes) -> None:
        headerSz = struct.unpack('<L', table_content[0:4])[0]
        reserved = struct.unpack('<L', table_content[4:8])[0]
        instrCountEntry = struct.unpack('<L', table_content[8:12])[0]
        if reserved != 0:
            reserved_str = ' - Error, this should be 0'
        else:
            reserved_str = ''
        self.results_str = f"""
------------------------------------------------------------------
  Serialization Header Size                       : 0x{headerSz:08X} ( {headerSz:d} )
  Reserved                                        : 0x{reserved:08X}{reserved_str}
  Instruction Count Entry                         : 0x{instrCountEntry:08X} ( {instrCountEntry:d} )
  Serialization Action Table
"""
        self.parseActionTable(table_content[12:], instrCountEntry)

    def __str__(self) -> str:
        return self.results_str

########################################################################################################
#
# HEST Table
#
########################################################################################################


class HEST (ACPI_TABLE):
    def __init__(self):
        return

    def parseErrEntry(self, table_content: bytes) -> Optional[int]:
        _type = struct.unpack('<H', table_content[0:2])[0]
        if _type == 0:  # Arch Machine Check Execption Structure
            return self.parseAMCES(table_content)
        elif _type == 1:  # Arch Corrected Mach Check Structure or ArchitectureDeferred machine Check Structure
            return self.parseAMCS(table_content, _type)
        elif _type == 2:  # NMI Error Structure
            return self.parseNMIStructure(table_content)
        elif _type == 6 or _type == 7 or _type == 8:  # PCIe Root Port AER Structure or PCIe Device AER Structure or PCIe Bridge AER Structure
            return self.parsePCIe(table_content, _type)
        elif _type == 9 or _type == 10:  # Generic hardware Error Source Structure or Generic Hardware Error Source version 2
            return self.parseGHESS(table_content, _type)
        return

    def parseNotify(self, table_content: bytes) -> str:
        types = ['Polled', 'External Interrupt', 'Local Interrupt', 'SCI', 'NMI', 'CMCI', 'MCE', 'GPI-Signal',
                 'ARMv8 SEA', 'ARMv8 SEI', 'External Interrupt - GSIV', 'Software Delicated Exception', 'Reserved']
        errorType = struct.unpack('<B', table_content[0:1])[0]
        length = struct.unpack('<B', table_content[1:2])[0]
        configWrEn = struct.unpack('<H', table_content[2:4])[0]
        pollInterval = struct.unpack('<L', table_content[4:8])[0]
        vector = struct.unpack('<L', table_content[8:12])[0]
        switchPollingThreshVal = struct.unpack('<L', table_content[12:16])[0]
        switchPollThresWind = struct.unpack('<L', table_content[16:20])[0]
        errThreshVal = struct.unpack('<L', table_content[20:24])[0]
        errThreshWind = struct.unpack('<L', table_content[24:28])[0]

        if errorType <= 12:
            typeStr = types[errorType]
        else:
            typeStr = types[12]

        vector_str = ''
        if errorType == 10:
            vector_str = 'Specifies the GSIV triggerd by error source'

        return f"""Hardware Error Notification Structure
      Type                                        : {errorType:d} - {typeStr}
      Length                                      : 0x{length:02X}
      Configuration Write Enable                  : 0x{configWrEn:04X}
        Type                                      : {configWrEn & 1:d}
        Poll Interval                             : {configWrEn & 2:d}
        Switch To Polling Threshold Value         : {configWrEn & 4:d}
        Switch To Polling Threshold Window        : {configWrEn & 8:d}
        Error Threshold Value                     : {configWrEn & 16:d}
        Error Threshold Window                    : {configWrEn & 32:d}
      Poll Interval                               : {pollInterval:d} milliseconds
      Vector                                      : {vector:d}{vector_str}
      Switch To Polling Threshold Value           : 0x{switchPollingThreshVal:08X}
      Switch To Polling Threshold Window          : {errThreshVal:d} milliseconds
      Error Threshold Value                       : 0x{errThreshVal:08X}
      Error Threshold Window                      : {errThreshWind:d} milliseconds
      """

    def machineBankParser(self, table_content: bytes) -> None:
        bankNum = struct.unpack('<B', table_content[0:1])[0]
        clearStatus = struct.unpack('<B', table_content[1:2])[0]
        statusDataFormat = struct.unpack('<B', table_content[2:3])[0]
        reserved1 = struct.unpack('<L', table_content[3:4])[0]
        controlRegMsrAddr = struct.unpack('<L', table_content[4:8])[0]
        controlInitData = struct.unpack('<L', table_content[8:16])[0]
        statusRegMSRAddr = struct.unpack('<L', table_content[16:20])[0]
        addrRegMSRAddr = struct.unpack('<L', table_content[20:24])[0]
        miscRegMSTAddr = struct.unpack('<L', table_content[24:28])[0]

        if clearStatus == 0:
            clearStatus_str = 'Clear'
        else:
            clearStatus_str = "Don't Clear"

        statusDataFormatStrList = ['IA-32 MCA', 'Intel 64 MCA', 'AMD64MCA', 'Reserved']
        if statusDataFormat < 3:
            statusDataFormat_str = statusDataFormatStrList[statusDataFormat]
        else:
            statusDataFormat_str = statusDataFormatStrList[3]

        if controlRegMsrAddr != 0:
            controlRegMsrAddr_str = ''
        else:
            controlRegMsrAddr_str = ' - Ignore'

        if statusRegMSRAddr != 0:
            statusRegMSRAddr_str = ''
        else:
            statusRegMSRAddr_str = ' - Ignore'

        if addrRegMSRAddr != 0:
            addrRegMSRAddr_str = ''
        else:
            addrRegMSRAddr_str = ' - Ignore'

        if miscRegMSTAddr != 0:
            miscRegMSTAddr_str = ''
        else:
            miscRegMSTAddr_str = ' - Ignore'

        self.resultsStr += f"""Machine Check Error Bank Structure
      Bank Number                                 : 0x{bankNum:04X}
      Clear Status On Initialization              : 0x{clearStatus:04X} - {clearStatus_str}
      Status Data Format                          : 0x{statusDataFormat:04X} - {statusDataFormat_str}
      Reserved                                    : 0x{reserved1:04X}
      Control Register MSR Address                : 0x{controlRegMsrAddr:04X}{controlRegMsrAddr_str}
      Control Init Data                           : 0x{controlInitData:04X}
      Status Register MSR Address                 : 0x{statusRegMSRAddr:04X}{statusRegMSRAddr_str}
      Address Register MSR Address                : 0x{addrRegMSRAddr:04X}{addrRegMSRAddr_str}
      Misc Register MSR Address                   : 0x{miscRegMSTAddr:04X}{miscRegMSTAddr_str}"""

    def parseAddress(self, table_content: bytes) -> str:
        return str(GAS(table_content))

    def parseAMCES(self, table_content: bytes) -> int:
        sourceID = struct.unpack('<H', table_content[2:4])[0]
        reserved1 = struct.unpack('<H', table_content[4:6])[0]
        flags = struct.unpack('<B', table_content[6:7])[0]
        enabled = struct.unpack('<B', table_content[7:8])[0]
        recordsToPreAllocate = struct.unpack('<L', table_content[8:12])[0]
        maxSectorsPerRecord = struct.unpack('<L', table_content[12:16])[0]
        globalCapabilityInitData = struct.unpack('<Q', table_content[16:24])[0]
        globalControlInitData = struct.unpack('<Q', table_content[24:32])[0]
        numHardwareBanks = struct.unpack('<B', table_content[32:33])[0]
        reserved2_1 = struct.unpack('<B', table_content[33:34])[0]
        reserved2_2 = struct.unpack('<B', table_content[34:35])[0]
        reserved2_3 = struct.unpack('<B', table_content[35:36])[0]
        reserved2_4 = struct.unpack('<B', table_content[36:37])[0]
        reserved2_5 = struct.unpack('<B', table_content[37:38])[0]
        reserved2_6 = struct.unpack('<B', table_content[38:39])[0]
        reserved2_7 = struct.unpack('<B', table_content[39:40])[0]

        if (flags & 1) == 1:
            firmware_first = 1
            firmware_first_str = 'System firmware handles errors from the source first'
        else:
            firmware_first = 0
            firmware_first_str = 'System firmware does not handle errors from the source first'

        if (flags & 4) == 4:
            ghes_assist = 1
            ghes_assist_str = 'Additional information given'
        else:
            ghes_assist = 0
            ghes_assist_str = 'Additional information not given'

        if firmware_first == 0:
            ghes_assist_str = 'Bit is reserved'

        self.resultsStr += f"""
  Architecture Machine Check Exception Structure
    Source ID                                     : 0x{sourceID:04X}
    Reserved                                      : 0x{reserved1:04X}
    Flags                                         : 0x{flags:02X}
    FIRMWARE_FIRST                                : {firmware_first} - {firmware_first_str}
    GHES_ASSIST                                   : {ghes_assist} - {ghes_assist_str}
    Enabled                                       : 0x{enabled:02X}
    Number of Records to Pre-allocate             : 0x{recordsToPreAllocate:08X}
    Max Sections Per Record                       : 0x{maxSectorsPerRecord:08X}
    Global Capability Init Data                   : 0x{globalCapabilityInitData:016X}
    Number of Hardware Banks                      : 0x{numHardwareBanks:02X}
    Reserved                                      : 0x{reserved2_1:02X} 0x{reserved2_2:02X} 0x{reserved2_3:02X} 0x{reserved2_4:02X} 0x{reserved2_5:02X} 0x{reserved2_6:02X} 0x{reserved2_7:02X}
    """
        curBankNum = 0
        while curBankNum < numHardwareBanks:
            self.machineBankParser(table_content[40 + curBankNum * 28:40 + (curBankNum + 1) * 28])
            curBankNum += 1
        return 40 + numHardwareBanks * 28

    def parseAMCS(self, table_content: bytes, _type: int) -> int:
        sourceID = struct.unpack('<H', table_content[2:4])[0]
        reserved1 = struct.unpack('<H', table_content[4:6])[0]
        flags = struct.unpack('<B', table_content[6:7])[0]
        enabled = struct.unpack('<B', table_content[7:8])[0]
        recordsToPreAllocate = struct.unpack('<L', table_content[8:12])[0]
        maxSectorsPerRecord = struct.unpack('<L', table_content[12:16])[0]
        notificationStructure = self.parseNotify(table_content[16:44])
        numHardwareBanks = struct.unpack('<B', table_content[44:45])[0]
        reserved2_1 = struct.unpack('<B', table_content[45:46])[0]
        reserved2_2 = struct.unpack('<B', table_content[46:47])[0]
        reserved2_3 = struct.unpack('<B', table_content[47:48])[0]

        if (flags & 1) == 1:
            firmware_first = 1
            firmware_first_str = 'System firmware handles errors from the source first'
        else:
            firmware_first = 0
            firmware_first_str = 'System firmware does not handle errors from the source first'

        if (flags & 4) == 4:
            ghes_assist = 1
            ghes_assist_str = 'Additional information given'
        else:
            ghes_assist = 0
            ghes_assist_str = 'Additional information not given'

        flags_str = ''
        if flags != 1 and flags != 4 and flags != 5:
            flags_str = ' - Error, Reserved Bits are not 0'

        if firmware_first == 0:
            ghes_assist_str = 'Bit is reserved'

        if _type == 1:
            title = 'Architecture Corrected Machine Check Structure'
        else:
            title = 'Architecture Deferred Machine Check Structure'

        self.resultsStr += f"""
    {title}
    Source ID         				  : 0x{sourceID:04X}
    Reserved                                      : 0x{reserved1:04X}
    Flags                                         : 0x{flags:02X}{flags_str}
      FIRMWARE_FIRST                              : {firmware_first} - {firmware_first_str}
      GHES_ASSIST                                 : {ghes_assist} - {ghes_assist_str}
    Enabled                                       : 0x{enabled:02X}
    Number of Records to Pre-allocate             : 0x{recordsToPreAllocate:08X}
    Max Sections Per Record                       : 0x{maxSectorsPerRecord:08X}
    {notificationStructure}
    Number of Hardware Banks                      : 0x{numHardwareBanks:02X}
    Reserved                                      : 0x{reserved2_1:02X} 0x{reserved2_2:02X} 0x{reserved2_3:02X}

    """
        currBank = 0
        while currBank < numHardwareBanks:
            self.machineBankParser(table_content[48 + currBank * 28:48 + (currBank + 1) * 28])
            currBank += 1
        return 48 + numHardwareBanks * 28

    def parseNMIStructure(self, table_content: bytes) -> int:
        sourceID = struct.unpack('<H', table_content[2:4])[0]
        reserved = struct.unpack('<L', table_content[4:8])[0]
        numRecordsToPreAllocate = struct.unpack('<L', table_content[8:12])[0]
        maxSectorsPerRecord = struct.unpack('<L', table_content[12:16])[0]
        maxRawDataLength = struct.unpack('<L', table_content[16:20])[0]

        if reserved == 0:
            reserved_str = ''
        else:
            reserved_str = ' - Error, not 0'

        self.resultsStr += f"""
  Architecture NMI Error Structure
    Source ID                                     : 0x{sourceID:04X}
    Reserved                                      : 0x{reserved:08X}{reserved_str}
    Number of Records to Pre-Allocate             : 0x{numRecordsToPreAllocate:08X}
    Max Sections Per Record                       : 0x{maxSectorsPerRecord:08X}
    Max Raw Data Length                           : 0x{maxRawDataLength:08X}
    """
        return 20

    def parsePCIe(self, table_content: bytes, _type: int) -> int:
        sourceID = struct.unpack('<H', table_content[2:4])[0]
        reserved1 = struct.unpack('<H', table_content[4:6])[0]
        flags = struct.unpack('<B', table_content[6:7])[0]
        enabled = struct.unpack('<B', table_content[7:8])[0]
        numRecordsToPreAllocate = struct.unpack('<L', table_content[8:12])[0]
        maxSectorsPerRecord = struct.unpack('<L', table_content[12:16])[0]
        bus = struct.unpack('<L', table_content[16:20])[0]
        device = struct.unpack('<H', table_content[20:22])[0]
        function = struct.unpack('<H', table_content[22:24])[0]
        deviceControl = struct.unpack('<H', table_content[24:26])[0]
        reserved2 = struct.unpack('<H', table_content[26:28])[0]
        uncorrectableErrorMask = struct.unpack('<L', table_content[28:32])[0]
        uncorrectableErrorServerity = struct.unpack('<L', table_content[32:36])[0]
        correctableErrorMask = struct.unpack('<L', table_content[36:40])[0]
        advancedErrorCapabilitiesAndControl = struct.unpack('<L', table_content[40:44])[0]
        if _type == 6:
            title = 'PCI Express Root Port AER Structure'
            rootErrCommand = struct.unpack('<L', table_content[44:48])[0]
            extra_str = f'''
    Root Error Command                            : 0x{rootErrCommand:08X}'''
            size = 48
        elif _type == 8:
            title = 'PCI Express Bridge AER Structure'
            secondaryUncorrErrMask = struct.unpack('<L', table_content[44:48])[0]
            secondaryUncorrErrServ = struct.unpack('<L', table_content[48:52])[0]
            secondaryAdvCapabAndControl = struct.unpack('<L', table_content[52:56])[0]
            extra_str = f'''
    Secondary Uncorrectable Error Mask            : 0x{secondaryUncorrErrMask:08X}
    Secondary Uncorrectable Error Severity        : 0x{secondaryUncorrErrServ:08X}
    Secondary Advanced Capabilities and Control   : 0x{secondaryAdvCapabAndControl:08X}'''
            size = 56
        else:
            title = 'PCI Express Device AER Structure'
            extra_str = ''
            size = 44

        if (flags & 1) == 1:
            firmware_first = 1
            firmware_first_str = 'System firmware handles errors from the source first'
        else:
            firmware_first = 0
            firmware_first_str = 'System firmware does not handle errors from the source first'

        if (flags & 2) == 2:
            global_flag = 1
            global_flag_str = 'Settings in table are for all PCIe Devices'
        else:
            global_flag = 0
            global_flag_str = 'Settings in table are not for all PCIe Devices'
        flags_str = ''
        reserved2_str = ''
        isGlobal_str = ''
        isFirmware_str = ''

        if flags >= 4:
            flags_str = 'Error, reserved bits are not 0'
        if reserved2 != 0:
            reserved2_str = ' - Error, reserved bits should be 0'
        if global_flag != 0:
            isGlobal_str = ' - This field should be ignored since Global is set'
        if firmware_first != 0:
            isFirmware_str = ' - This field should be ignored since FIRMWARE_FIRST is set'

        self.resultsStr += f"""
  {title}
    Source ID                                     : 0x{sourceID:04X}
    Reserved                                      : 0x{reserved1:08X}
    Flags                                         : 0x{flags:02X}{flags_str}
      FIRMWARE_FIRST                              : {firmware_first} - {firmware_first_str} {isFirmware_str}
      GLOBAL                                      : {global_flag} - {global_flag_str}
    Enabled                                       : 0x{enabled:08X}
    Number of Records to Pre-Allocate             : 0x{numRecordsToPreAllocate:08X}
    Max Sections Per Record                       : 0x{maxSectorsPerRecord:08X}
    Bus                                           : 0x{bus:08X}
    Device                                        : 0x{device:04X}{isGlobal_str}
    Function                                      : 0x{function:04X}{isGlobal_str}
    Device Control                                : 0x{deviceControl:04X}
    Reserved                                      : 0x{reserved2:04X}{reserved2_str}
    Uncorrectable Error Mask                      : 0x{uncorrectableErrorMask:08X}
    Uncorrected Error Severity                    : 0x{uncorrectableErrorServerity:08X}
    Corrected Error Mask                          : 0x{correctableErrorMask:08X}
    Advanced Error Capabilities and Control       : 0x{advancedErrorCapabilitiesAndControl:08X}{extra_str}
    """
        return size

    def parseGHESS(self, table_content: bytes, _type: int) -> int:
        sourceID = struct.unpack('<H', table_content[2:4])[0]
        relatedSourceID = struct.unpack('<H', table_content[4:6])[0]
        flags = struct.unpack('<B', table_content[6:7])[0]
        enabled = struct.unpack('<B', table_content[7:8])[0]
        numRecordsToPreAllocate = struct.unpack('<L', table_content[8:12])[0]
        maxSectorsPerRecord = struct.unpack('<L', table_content[12:16])[0]
        maxRawDataLength = struct.unpack('<L', table_content[16:20])[0]
        address_str = self.parseAddress(table_content[20:32])
        notification_str = self.parseNotify(table_content[32:60])
        errStatusBlockLen = struct.unpack('<L', table_content[60:64])[0]
        if _type == 9:
            title = 'Generic Hardware Error Source Structure'
            extra_str = ''
        else:
            title = 'Generic Hardware Error Source Version 2'
            readAckReg_str = self.parseAddress(table_content[64:76])
            readAckPresv = struct.unpack('<Q', table_content[76:84])[0]
            readAckWr = struct.unpack('<Q', table_content[84:88])[0]
            extra_str = f'''
    Read Ack Register - {readAckReg_str}
    Read Ack Preserve                             : 0x{readAckPresv:016X}
    Read Ack Write                                : 0x{readAckWr:016X}'''
        if relatedSourceID == 65535:
            relatedSourceID_str = 'Does not represent an alternate souce'
        else:
            relatedSourceID_str = ''

        self.resultsStr += f"""
  {title}
    Source ID                                     : 0x{sourceID:04X}
    Related Source Id                             : 0x{relatedSourceID:08X}{relatedSourceID_str}
    Flags                                         : 0x{flags:02X} - Reserved
    Enabled                                       : 0x{enabled:02X}
    Number of Records to Pre-Allocate             : 0x{numRecordsToPreAllocate:08X}
    Max Sections Per Record                       : 0x{maxSectorsPerRecord:08X}
    Max Raw Data Length                           : 0x{maxRawDataLength:08X}
    Error Status Address - {address_str}
    {notification_str}
    Error Status Block Length                     : 0x{errStatusBlockLen:08X}{extra_str}
    """
        return 64

    def parse(self, table_content: bytes) -> None:
        self.ErrorSourceCount = struct.unpack('<L', table_content[0:4])[0]
        self.resultsStr = f"""
------------------------------------------------------------------
  Error Source Count                              : {self.ErrorSourceCount}
"""
        nextTable = 4
        currErrSource = 0
        while currErrSource < self.ErrorSourceCount:
            table_entry = self.parseErrEntry(table_content[nextTable:])
            if table_entry is not None:
                nextTable += table_entry
            currErrSource += 1

    def __str__(self) -> str:
        return self.resultsStr


########################################################################################################
#
# SPMI Table
#
########################################################################################################

class SPMI (ACPI_TABLE):
    def __init__(self):
        return

    def parseAddress(self, table_content: bytes) -> str:
        return str(GAS(table_content))

    def parseNonUID(self, table_content: bytes) -> str:
        pciSegGrpNum = struct.unpack('<B', table_content[0:1])[0]
        pciBusNum = struct.unpack('<B', table_content[1:2])[0]
        pciDevNum = struct.unpack('<B', table_content[2:3])[0]
        pciFuncNum = struct.unpack('<B', table_content[3:4])[0]
        return f'''  PCI Segment GroupNumber                                 : 0x{pciSegGrpNum:02X}
  PCI Bus Number                                          : 0x{pciBusNum:02X}
  PCI Device Number                                       : 0x{pciDevNum:02X}
  PCI Function Number                                     : 0x{pciFuncNum:02X}'''

    def parseUID(self, table_content: bytes) -> str:
        uid = struct.unpack('<L', table_content[0:4])[0]
        return f'''  UID                                                     : 0x{uid:02X}'''

    def parse(self, table_content: bytes) -> None:
        interfaceType = struct.unpack('<B', table_content[0:1])[0]
        reserved1 = struct.unpack('<B', table_content[1:2])[0]
        specRev = struct.unpack('<B', table_content[2:3])[0]
        interruptType = struct.unpack('<H', table_content[3:5])[0]
        gpe = struct.unpack('<B', table_content[5:6])[0]
        reserved2 = struct.unpack('<B', table_content[6:7])[0]
        pciDeviceFlag = struct.unpack('<B', table_content[7:8])[0]
        globalSysInter = struct.unpack('<L', table_content[8:12])[0]
        baseAdder = self.parseAddress(table_content[12:24])
        reserved3 = struct.unpack('<B', table_content[28:29])[0]
        if interfaceType == 1:
            intTypeStr = "Keyboard Controller Style (KCS)"
        elif interfaceType == 2:
            intTypeStr = "Server Management Interface Chip (SMIC)"
        elif interfaceType == 3:
            intTypeStr = "Block Transfer (BT)"
        elif interfaceType == 4:
            intTypeStr = "SMBus System Interface (SSIF)"
        else:
            intTypeStr = "Reserved"
        specRevStr = (f'0x{specRev:02X}')
        intType_0 = interruptType & 1
        intType_1 = interruptType & 2 >> 1
        intType_other = interruptType ^ 3 >> 2
        if intType_0 == 1:
            intTypeSCIGPE = "supported"
        else:
            intTypeSCIGPE = "not supported"
        if intType_1 == 1:
            intTypeIO = "supported"
        else:
            intTypeIO = "not supported"
        GPE_str = ''
        if (interruptType & 1) != 1:
            GPE_str = " - should be set to 00h"
        pciDeviceFlag_0 = pciDeviceFlag & 1
        if pciDeviceFlag_0 == 1:
            pci_str = 'For PCi IPMI devices'
            otherStr = self.parseNonUID(table_content[25:28])
        else:
            pci_str = 'non-PCI device'
            otherStr = self.parseUID(table_content[25:28])
        pciDeviceFlag_reserved = 1 ^ pciDeviceFlag_0
        globalSysInt_str = ''
        if intType_1 != 1:
            globalSysInt_str = ' - this field should be 0'
        self.results = f'''==================================================================
  Service Processor Management Interface Description Table ( SPMI )
==================================================================
  Interface Type                                          : 0x{interfaceType:02X} - {intTypeStr}
  Reserved                                                : 0x{reserved1:02X} - Must always be 01h to be compatible with any software implementing previous versions of the spec
  Specification Revision (version)                        : {specRevStr}
  Interrupt Type                                          : 0x{interruptType:04X}
    SCI triggered through GPE                             : 0x{intType_0:02X} - {intTypeSCIGPE}
    I/0 APIC/SAPIC interrupt (Global System Interrupt)    : 0x{intType_1:02X} - {intTypeIO}
    Reserved                                              : 0x{intType_other:02X} - Must be 0
  GPE                                                     : 0x{gpe:02X}{GPE_str}
  Reserved                                                : 0x{reserved2:02X} - should be 00h
  PCI Device Flag                                         : 0x{pciDeviceFlag:02X}
    PCI Device Flag                                       : {pciDeviceFlag_0:d} {pci_str}
    Reserved                                              : {pciDeviceFlag_reserved:d} - must be 0
  Global System Interrupt                                 : 0x{globalSysInter:08X}{globalSysInt_str}
  Base Address - {baseAdder}
{otherStr}
  Reserved                                                : 0x{reserved3:02X}

'''

    def __str__(self) -> str:
        return self.results


########################################################################################################
#
# RASF Table
#
########################################################################################################

class RASF (ACPI_TABLE):
    def __init__(self):
        return

    def parse(self, table_content: bytes) -> None:
        rpcci1 = struct.unpack('<B', table_content[0:1])[0]
        rpcci2 = struct.unpack('<B', table_content[1:2])[0]
        rpcci3 = struct.unpack('<B', table_content[2:3])[0]
        rpcci4 = struct.unpack('<B', table_content[3:4])[0]
        rpcci5 = struct.unpack('<B', table_content[4:5])[0]
        rpcci6 = struct.unpack('<B', table_content[5:6])[0]
        rpcci7 = struct.unpack('<B', table_content[6:7])[0]
        rpcci8 = struct.unpack('<B', table_content[7:8])[0]
        rpcci9 = struct.unpack('<B', table_content[8:9])[0]
        rpcci10 = struct.unpack('<B', table_content[9:10])[0]
        rpcci11 = struct.unpack('<B', table_content[10:11])[0]
        rpcci12 = struct.unpack('<B', table_content[11:12])[0]
        self.results = f'''==================================================================
  ACPI RAS Feature Table ( RASF )
==================================================================
  RASF Platform Communication Channel Identifier          : 0x{rpcci1:02X} 0x{rpcci2:02X} 0x{rpcci3:02X} 0x{rpcci4:02X} 0x{rpcci5:02X} 0x{rpcci6:02X} 0x{rpcci7:02X} 0x{rpcci8:02X} 0x{rpcci9:02X} 0x{rpcci10:02X} 0x{rpcci11:02X} 0x{rpcci12:02X}

'''

    def __str__(self) -> str:
        return self.results


########################################################################################################
#
# MSCT Table
#
########################################################################################################

class MSCT (ACPI_TABLE):
    def __init__(self):
        return

    def parseProx(self, table_content: bytes, val: int) -> str:
        rev = struct.unpack('<B', table_content[0:1])[0]
        length = struct.unpack('<B', table_content[1:2])[0]
        maxDomRangeL = struct.unpack('<L', table_content[2:6])[0]
        maxDomRangeH = struct.unpack('<L', table_content[6:10])[0]
        maxProcCap = struct.unpack('<L', table_content[10:14])[0]
        maxMemCap = struct.unpack('<Q', table_content[14:22])[0]
        maxProcCap_str = ''
        maxMemCap_str = ''
        if maxProcCap == 0:
            maxProcCap_str = ' - Proximity domains do not contain a processor'
        if maxMemCap == 0:
            maxMemCap_str = '- Proximity domains do not contain memory'
        return f'''
    Maximum Proximity Domain Informaiton Structure[{val:d}]
      Revision                                              : 0x{rev:02X} ( {rev:d} )
      Length                                                : 0x{length:02X} ( {length:d} )
      Proximity Domain Range (low)                          : 0x{maxDomRangeL:04X}
      Proximity Domain Range (high)                         : 0x{maxDomRangeH:04X}
      Maximum Processor Capacity                            : 0x{maxProcCap:04X} ( {maxProcCap:d} ){maxProcCap_str}
      Maximum Memory Capacity                               : 0x{maxMemCap:016X} ( {maxMemCap:d} ) bytes {maxMemCap_str}

'''

    def parseProxDomInfoStruct(self, table_contents: bytes, num: int) -> str:
        val = 0
        result = ''
        while val < num:
            result += self.parseProx(table_contents[22 * val: 22 * (val + 1)], val)
            val = val + 1
        return result

    def parse(self, table_content: bytes) -> None:
        offsetProxDomInfo = struct.unpack('<L', table_content[0:4])[0]
        maxNumProxDoms = struct.unpack('<L', table_content[4:8])[0]
        maxNumClockDoms = struct.unpack('<L', table_content[8:12])[0]
        maxPhysAddr = struct.unpack('<Q', table_content[12:20])[0]
        proxDomInfoStructStr = self.parseProxDomInfoStruct(table_content[20:], maxNumProxDoms)
        self.results = f'''==================================================================
  Maximum System Characteristics Table ( MSCT )
==================================================================
  Offset to Proximity Domain Information Structure        : 0x{offsetProxDomInfo:08X}
  Maximum Number of Proximity Domains                     : 0x{maxNumProxDoms:08X} ( {maxNumProxDoms:d} )
  Maximum Number of Clock Domains                         : 0x{maxNumClockDoms:08X} ( {maxNumClockDoms:d} )
  Maximum Physical Address                                : 0x{maxPhysAddr:016X}
  Proximity Domain  Information Structure{proxDomInfoStructStr}

'''

    def __str__(self) -> str:
        return self.results


########################################################################################################
#
# NFIT Table
#
########################################################################################################

class NFIT (ACPI_TABLE):
    def __init__(self, header):
        length = struct.unpack('<L', header[4:8])[0]
        self.total_length = length
        return

    def platCapStruct(self, tableLen: int, table_content: bytes) -> str:
        highestValidCap = struct.unpack('<B', table_content[4:5])[0]
        reserved1_1 = struct.unpack('<B', table_content[5:6])[0]
        reserved1_2 = struct.unpack('<B', table_content[6:7])[0]
        reserved1_3 = struct.unpack('<B', table_content[7:8])[0]
        capabilities = struct.unpack('<L', table_content[8:12])[0]
        cap1 = capabilities & 1
        cap2 = capabilities & 2
        cap3 = capabilities & 4
        capRes = capabilities & ~(7)
        reserved2 = struct.unpack('<L', table_content[12:16])[0]
        if cap1 == 1:
            cap1_str = 'Platform ensures the entire CPU store data path is flushed to persistent memory on system power loss'
        else:
            cap1_str = 'Platform does not ensure the entire CPU store data path is flushed to persistent memory on system power loss'
        if cap2 == 2:
            cap2_str = 'Platform provides mehanisms to automatically flush outstanding write data from the memory controller to persistent memory in the event of power loss'
        else:
            if cap1 == 1:
                cap2_str = 'Platform does not provides mehanisms to automatically flush outstanding write data from the memory controller to persistent memory in the event of power loss'
            else:
                cap2_str = 'This should be set to 1 - Platform does not support'
        if cap3 == 4:
            cap3_str = 'Platform supports mirroring multiple byte addressable persistent memory regions together'
        else:
            cap3_str = 'Platform does not support mirroring multiple byte addressable persistent memory regions together'
        return f'''
    Platform Capabilities Structure [Type 7]
      Length                                                      : 0x{tableLen:04X} ( {tableLen:d} bytes )
      Highest Valid Capability                                    : 0x{highestValidCap:02X}
      Reserved                                                    : 0x{reserved1_1:02X} 0x{reserved1_2:02X} 0x{reserved1_3:02X}
      Capabilities                                                : 0x{capabilities:08X}
        CPU Cache Flush to NVDIMM Durability on Power Loss        : 0x{cap1:08X} - {cap1_str}
        Mem Controller Flush to NVDIMM Durability on Power Loss   : 0x{cap2:08X} - {cap2_str}
        Byte Addressible Persistent Mem Hw Mirroring Capable      : 0x{cap3:08X} - {cap3_str}
        Reserved                                                  : 0x{capRes:08X}
      Reserved                                                    : 0x{reserved2:08X}
'''

    def flushHintAddrStruct(self, tableLen: int, table_content: bytes) -> Tuple[int, str]:
        nfitDevHandle = struct.unpack('<L', table_content[4:8])[0]
        numFlushHintAddr = struct.unpack('<L', table_content[4:8])[0]
        reserved = struct.unpack('<L', table_content[4:8])[0]
        curLine = 0
        lines = ''
        while curLine < numFlushHintAddr:
            lineInfo = struct.unpack('<Q', table_content[curLine * 8 + 8:curLine * 8 + 16])[0]
            lines += f'''
        Flush Hint Address {curLine + 1:d}                                     : 0x{lineInfo:016X} '''
            curLine += 1
        return (curLine - 1) * 8 + 16, f'''
    Flush Hint Address Structure [Type 6]
      Length                                                      : 0x{tableLen:04X} ( {tableLen:d} bytes )
      NFIT Device Handle                                          : 0x{nfitDevHandle:08X}
      Number of Flush Hint Addresses in this Structure            : 0x{numFlushHintAddr:08X} ( {numFlushHintAddr:d} )
      Reserved                                                    : 0x{reserved:08X}
      Flush Hint Addresses{lines}
'''

    def nvdimmBlockDataWindowsRegionStruct(self, tableLen: int, table_content: bytes) -> str:
        nvdimmControlRegionStructureIndex = struct.unpack('<H', table_content[4:6])[0]
        numBlockDataWindows = struct.unpack('<H', table_content[6:8])[0]
        blockDataWindowsStartOffset = struct.unpack('<Q', table_content[8:16])[0]
        szBlckDataWindow = struct.unpack('<Q', table_content[16:24])[0]
        blckAccMemCap = struct.unpack('<Q', table_content[24:32])[0]
        begAddr = struct.unpack('<Q', table_content[32:40])[0]
        return f'''
    NVDIMM Block Data Region Structure [Type 5]
      Length                                                      : 0x{tableLen:04X} ( {tableLen:d} bytes )
      NVDIMM Control Region Structure Index                       : 0x{nvdimmControlRegionStructureIndex:04X} - Should not be 0
      Number of Block Data Windows                                : 0x{numBlockDataWindows:04X} ( {numBlockDataWindows:d} )
      Block Data Window Start Offest                              : 0x{blockDataWindowsStartOffset:016X} ( {blockDataWindowsStartOffset:d} bytes )
      Size of Block Data Window                                   : 0x{szBlckDataWindow:016X} ( {szBlckDataWindow:d} bytes )
      Block Accessible Memory Capacity                            : 0x{blckAccMemCap:016X} ( {blckAccMemCap:d} bytes )
      Start Addr for 1st Block in Block Accessible Mem            : 0x{begAddr:016X} ( {begAddr:d} bytes )
'''

    def nvdimmControlRegionStructMark(self, tableLen: int, table_content: bytes) -> str:
        nvdimmControlRegionStructureIndex = struct.unpack('<H', table_content[4:6])[0]
        vendorID = struct.unpack('<H', table_content[6:8])[0]
        deviceID = struct.unpack('<H', table_content[8:10])[0]
        revID = struct.unpack('<H', table_content[10:12])[0]
        subsystemVendorID = struct.unpack('<H', table_content[12:14])[0]
        subsysDevID = struct.unpack('<H', table_content[14:16])[0]
        subsysRevID = struct.unpack('<H', table_content[16:18])[0]
        validFields = struct.unpack('<B', table_content[18:19])[0]
        manLocation = struct.unpack('<B', table_content[19:20])[0]
        manDate = struct.unpack('<H', table_content[20:22])[0]
        # need more parsing of the date
        reserved = struct.unpack('<H', table_content[22:24])[0]
        serialNum = struct.unpack('<L', table_content[24:28])[0]
        regionFormatInterfaceCode = struct.unpack('<H', table_content[28:30])[0]
        rfic1 = struct.unpack('<B', table_content[28:29])[0]
        rfic2 = struct.unpack('<B', table_content[29:30])[0]
        rfic_r1 = rfic1 & 224
        rfic_fif = rfic1 & 31
        rfic_r2 = rfic2 & 224
        rfic_fcf = rfic2 & 31
        numBlockControlWindows = struct.unpack('<H', table_content[30:32])[0]
        cont_str = 'ERROR - Table is shorter than expected.'
        if numBlockControlWindows != 0:
            szBlckControlWindow = struct.unpack('<Q', table_content[32:40])[0]
            commandRegOffset = struct.unpack('<Q', table_content[40:48])[0]
            szCommandReg = struct.unpack('<Q', table_content[48:56])[0]
            statusRegOffset = struct.unpack('<Q', table_content[56:64])[0]
            szStatus = struct.unpack('<Q', table_content[64:72])[0]
            nvdimmControlRegionFl = struct.unpack('<H', table_content[72:74])[0]
            reserved2_1 = struct.unpack('<B', table_content[74:75])[0]
            reserved2_2 = struct.unpack('<B', table_content[75:76])[0]
            reserved2_3 = struct.unpack('<B', table_content[76:77])[0]
            reserved2_4 = struct.unpack('<B', table_content[77:78])[0]
            reserved2_5 = struct.unpack('<B', table_content[78:79])[0]
            reserved2_6 = struct.unpack('<B', table_content[79:80])[0]
            cont_str = f'''      Size of Block Control Windows                               : 0x{szBlckControlWindow:016X} ({szBlckControlWindow:d} bytes)
      Command Reg Offset in Block Control Windows                 : 0x{commandRegOffset:016X}
      Size of Command Register in Block Control Windows           : 0x{szCommandReg:016X}
      Status Register Offset in Block Control Windows             : 0x{statusRegOffset:016X}
      Size of Status Register in Block Control Windows            : 0x{szStatus:016X}
      NVDIMM Control Region Flag                                  : 0x{nvdimmControlRegionFl:04X}
      Reserved                                                    : 0x{reserved2_1:02X} 0x{reserved2_2:02X} 0x{reserved2_3:02X} 0x{reserved2_4:02X} 0x{reserved2_5:02X} 0x{reserved2_6:02X}
      {cont_str}'''
        valid_0 = validFields & 1
        valid_str = ''
        valid_man_str = ''
        if valid_0 == 0:
            valid_str = 'System is compliant with ACPI 6.0 - Manufacturing Location & Date fields are invalid and should be ignored'
            valid_man_str = 'Value is invalid and should be ignored'
        return f'''
    NVDIMM Control Region Structure [Type 4]
      Length                                                      : 0x{tableLen:04X} ( {tableLen:d} bytes )
      NVDIMM Control Region Structure Index                       : 0x{nvdimmControlRegionStructureIndex:04X}
      Vendor ID                                                   : 0x{vendorID:04X}
      Device ID                                                   : 0x{deviceID:04X}
      Revision ID                                                 : 0x{revID:04X}
      Subsystem Vendor ID                                         : 0x{subsystemVendorID:04X}
      Subsystem Device ID                                         : 0x{subsysDevID:04X}
      Subsystem Revision ID                                       : 0x{subsysRevID:04X}
      Valid Fields                                                : 0x{validFields:02X}
        Bit[0]                                                    : {valid_0}{valid_str}
      Manufacturing Location                                      : 0x{manLocation:02X}{valid_man_str}
      Manufacturing Date                                          : 0x{manDate:04X}{valid_man_str}
      Reserved                                                    : 0x{reserved:04X}
      Serial Number                                               : 0x{serialNum:08X}
      Region Format Interface Code                                : 0x{regionFormatInterfaceCode:04X}
        Reserved                                                  : 0x{rfic_r1:02X}
        Function Interface Field                                  : 0x{rfic_fif:02X}
        Reserved                                                  : 0x{rfic_r2:02X}
        Function Class Field                                      : 0x{rfic_fcf:02X}
      Number of Block Control Windows                             : 0x{numBlockControlWindows:08X}
'''

    def smbiosManagementInfo(self, tableLen: int, table_content: bytes) -> str:
        smbios_tables = ['BIOS Information', 'System Information', 'Baseboard (or Module) Information', 'System Enclosure or Chassis', 'Processor Information', 'Memory Controller Information, obsolete', 'Memory Module Information, obsolete', 'Cache Information', 'Port Connector Information', 'System Slots', 'On Board Devices Information, obsolete', 'OEM Strings', 'System Confirguration Options', 'BIOS Language Information', 'Group Associations', 'System Event Log', 'Physical Memory Array', 'Memory Device', '32-Bit Memory Error Information', 'Memory Array Mapped Address', 'Memory Device Mapped Address',
                         'Built-in Pointing Device', 'Portable Battery', 'System Reset', 'Hardware Security', 'System Power Controls', 'Voltage Probe', 'Cooling Device', 'Temperature Probe', 'Electrical Current Probe', 'Out-of-Band Remote Address', 'Boot Integrity Services (BIS) Entry Point', 'System Boot Information', '64-Bit Mmemory Error Information', 'Management Device', 'Management Device Component', 'Management Device Threshold Data', 'Memory Channel', 'IPMI Device Information', 'System Power Supply', 'Additional Information', 'Onboard Devices Extended Information', 'Mangement Controller Host Interface']
        reserved = struct.unpack('<L', table_content[4:8])[0]
        curPos = 8
        dataStr = ''
        return f'''
    SMBIOS Management Information Structure [Type 3]
      Length                                                      : 0x{tableLen:04X} ( {tableLen:d} bytes )
      Reserved                                                    : 0x{reserved:08X}
      ----Unable to further at this time.----
'''  # TODO

    def interleave(self, tableLen: int, table_content: bytes) -> Tuple[int, str]:
        interleaveStructureIndex = struct.unpack('<H', table_content[4:6])[0]
        reserved = struct.unpack('<H', table_content[6:8])[0]
        numLinesDescribed = struct.unpack('<L', table_content[8:12])[0]
        lineSz = struct.unpack('<L', table_content[12:16])[0]
        curLine = 0
        lines = ''
        while curLine < numLinesDescribed:
            lineInfo = struct.unpack('<L', table_content[curLine * 4 + 16:curLine * 4 + 20])[0]
            lines += f'''
        Line {curLine + 1:d} Offset                                            : 0x{lineInfo:08X} ( {lineInfo:d} bytes )'''
            curLine += 1
        return (curLine - 1) * 4 + 20, f'''
    Interleave Structure [Type 2]
      Length                                                      : 0x{tableLen:04X} ( {tableLen:d} bytes )
      Reserved                                                    : 0x{reserved:04X}
      Number of Lines Described                                   : 0x{numLinesDescribed:08X} ( {numLinesDescribed:d} )
      Line Size                                                   : 0x{lineSz:08X} ( {lineSz:d} bytes )
      Lines {lines}
'''

    def parseMAP(self, tableLen: int, table_content: bytes) -> str:
        nfitDeviceHandle = struct.unpack('<L', table_content[4:8])[0]
        nvdimmPhysID = struct.unpack('<H', table_content[8:10])[0]
        nvdimmRegionID = struct.unpack('<H', table_content[10:12])[0]
        spaRangeStructureIndex = struct.unpack('<H', table_content[12:14])[0]
        nvdimmControlRegionSz = struct.unpack('<H', table_content[14:16])[0]
        nvdimmRegionSz = struct.unpack('<Q', table_content[16:24])[0]
        regionOffset = struct.unpack('<Q', table_content[24:32])[0]
        nvdimmPhysicalAddressRegionBase = struct.unpack('<Q', table_content[32:40])[0]
        interleaveStructIndex = struct.unpack('<H', table_content[40:42])[0]
        interleaveWays = struct.unpack('<H', table_content[42:44])[0]
        nvdimmStateFlags = struct.unpack('<H', table_content[44:46])[0]
        reserve = struct.unpack('<H', table_content[46:48])[0]
        return f'''
    NVDIMM Region Mapping Structure [Type 1]
      Length                                                      : 0x{tableLen:04X} ( {tableLen:d} bytes )
      NFIT Device Handle                                          : 0x{nfitDeviceHandle:08X}
      NVDIMM Physical ID                                          : 0x{nvdimmPhysID:04X}
      NVDIMM Region ID                                            : 0x{nvdimmRegionID:04X}
      SPA Range Structure Index                                   : 0x{spaRangeStructureIndex:04X}
      NVDIMM Control Region Structure Index                       : 0x{nvdimmControlRegionSz:016X}
      NVDIMM Region Size                                          : 0x{nvdimmRegionSz:016X}
      Region Offset                                               : 0x{regionOffset:016X}
      NVDIMM Physical Address Region Base                         : 0x{nvdimmPhysicalAddressRegionBase:016X}
      Interleave Structure Index                                  : 0x{interleaveStructIndex:04X}
      Interleave Ways                                             : 0x{interleaveWays:04X}
      NVDIMM State Flags                                          : 0x{nvdimmStateFlags:04X}
      Reserved                                                    : 0x{reserve:04X}
'''

    def parseSPA(self, tableLen: int, table_content: bytes) -> str:
        volitileMemGUID = [0x7305944f, 0xfdda, 0x44e3, 0xb1, 0x6c, 0x3f, 0x22, 0xd2, 0x52, 0xe5, 0xd0]
        byteAddrPMGUID = [0x66f0d379, 0xb4f3, 0x4074, 0xac, 0x43, 0x0d, 0x33, 0x18, 0xb7, 0x8c, 0xdb]
        nvdimmControlRegionGUID = [0x92f701f6, 0x13b4, 0x405d, 0x91, 0x0b, 0x29, 0x93, 0x67, 0xe8, 0x23, 0x4c]
        nvdimmBlckDataWindowRegionGUID = [0x91af0530, 0x5d86, 0x470e, 0xa6, 0xb0, 0x0a, 0x2d, 0xb9, 0x40, 0x82, 0x49]
        ramDiskVirtualDiskVolGUID = [0x77ab535a, 0x45fc, 0x624b, 0x55, 0x60, 0xf7, 0xb2, 0x81, 0xd1, 0xf9, 0x6e]
        ramDiskVirtualCDVolGUID = [0x3d5abd30, 0x4175, 0x87ce, 0x6d, 0x64, 0xd2, 0xad, 0xe5, 0x23, 0xc4, 0xbb]
        ramDiskVirtualDiskPersisGUID = [0x5cea02c9, 0x4d07, 0x69d3, 0x26, 0x9f, 0x44, 0x96, 0xfb, 0xe0, 0x96, 0xf9]
        ramDiskVirtualCDPersisGUID = [0x08018188, 0x42cd, 0xbb48, 0x10, 0x0f, 0x53, 0x87, 0xd5, 0x3d, 0xed, 0x3d]
        spaRangeStructure = struct.unpack('<H', table_content[4:6])[0]
        flags = struct.unpack('<H', table_content[6:8])[0]
        flag1 = flags & 1
        flag2 = flags & 2
        flag3 = flags >> 2
        reserved = struct.unpack('<L', table_content[8:12])[0]
        proximityDomain = struct.unpack('<L', table_content[12:16])[0]
        addressRangeTypeGUID_1 = struct.unpack('<L', table_content[16:20])[0]
        addressRangeTypeGUID_2 = struct.unpack('<H', table_content[20:22])[0]
        addressRangeTypeGUID_3 = struct.unpack('<H', table_content[22:24])[0]
        addressRangeTypeGUID_4 = struct.unpack('<B', table_content[24:25])[0]
        addressRangeTypeGUID_5 = struct.unpack('<B', table_content[25:26])[0]
        addressRangeTypeGUID_6 = struct.unpack('<B', table_content[26:27])[0]
        addressRangeTypeGUID_7 = struct.unpack('<B', table_content[27:28])[0]
        addressRangeTypeGUID_8 = struct.unpack('<B', table_content[28:29])[0]
        addressRangeTypeGUID_9 = struct.unpack('<B', table_content[29:30])[0]
        addressRangeTypeGUID_10 = struct.unpack('<B', table_content[30:31])[0]
        addressRangeTypeGUID_11 = struct.unpack('<B', table_content[31:32])[0]
        systemPARangeBase = struct.unpack('<Q', table_content[32:40])[0]
        SPARLen = struct.unpack('<Q', table_content[40:48])[0]
        addrRangeMemMapAttr = struct.unpack('<Q', table_content[48:56])[0]
        spaRangeStructure_str = ''
        if spaRangeStructure == 0:
            spaRangeStructure_str = ' - Value of 0 is reserved and shall not be used as an index'
        if flag1 == 1:
            flag1_str = ' - Control region only for hot add/online operation'
        else:
            flag1_str = ' - Control region not only for hot add/online operation'
        if flag2 != 1:
            flag2_str = ' - Data in proximity region is not valid'
        else:
            if (addrRangeMemMapAttr & 1) == 1:
                flag2_str = 'EFI_MEMORY_UC'
            elif (addrRangeMemMapAttr & 2) == 2:
                flag2_str = 'EFI_MEMORY_WC'
            elif (addrRangeMemMapAttr & 4) == 4:
                flag2_str = 'EFI_MEMORY_WT'
            elif (addrRangeMemMapAttr & 8) == 8:
                flag2_str = 'EFI_MEMORY_WB'
            elif (addrRangeMemMapAttr & 16) == 16:
                flag2_str = 'EFI_MEMORY_UCE'
            elif (addrRangeMemMapAttr & 4096) == 4096:
                flag2_str = 'EFI_MEMORY_WP'
            elif (addrRangeMemMapAttr & 8192) == 8192:
                flag2_str = 'EFI_MEMORY_RP'
            elif (addrRangeMemMapAttr & 16384) == 16384:
                flag2_str = 'EFI_MEMORY_XP'
            elif (addrRangeMemMapAttr & 32768) == 32768:
                flag2_str = 'EFI_MEMORY_NV'
            elif (addrRangeMemMapAttr & 65536) == 65536:
                flag2_str = 'EFI_MEMORY_MORE_RELIABLE'
            else:
                flag2_str = 'undefined'
        addressRangeTypeGUID = [addressRangeTypeGUID_1, addressRangeTypeGUID_2, addressRangeTypeGUID_3, addressRangeTypeGUID_4, addressRangeTypeGUID_5,
                                addressRangeTypeGUID_6, addressRangeTypeGUID_7, addressRangeTypeGUID_8, addressRangeTypeGUID_9, addressRangeTypeGUID_10, addressRangeTypeGUID_11]
        if addressRangeTypeGUID == volitileMemGUID:
            artg_str = 'Volitile Memory Region'
        elif addressRangeTypeGUID == byteAddrPMGUID:
            artg_str = 'Byte Addressable Persistent Memory (PM) Region'
        elif addressRangeTypeGUID == nvdimmControlRegionGUID:
            artg_str = 'NVDIMM Control Region'
        elif addressRangeTypeGUID == nvdimmBlckDataWindowRegionGUID:
            artg_str = 'NVDIMM Block Data Window Region'
        elif addressRangeTypeGUID == ramDiskVirtualDiskVolGUID:
            artg_str = 'RAM Disk supporting a Virtual Disk Region - Volitile (volitile memory region containing raw disk format)'
        elif addressRangeTypeGUID == ramDiskVirtualCDVolGUID:
            artg_str = 'RAM Disk supporting a Virtual CD Region - Volitile (volitile memory region containing an ISO image)'
        elif addressRangeTypeGUID == ramDiskVirtualDiskPersisGUID:
            artg_str = 'RAM Disk supporting Virtual Disk Region - Persistent (persistent memroy region containing raw disk format)'
        elif addressRangeTypeGUID == ramDiskVirtualCDPersisGUID:
            artg_str = 'RAM Disk supporting a Virtual CD Region - Persistent (persistent memory region containing an ISO image)'
        else:
            artg_str = 'Not in specification, could be a vendor defined GUID'
        return f'''
    System Physical Address (SPA) Range Structure [Type 1]
      Length                                                      : 0x{tableLen:04X} ( {tableLen:d} bytes )
      SPA Range Structure Index                                   : 0x{spaRangeStructure:04X}{spaRangeStructure_str}
      Flags                                                       : 0x{flags:04X}
        Bit[0] (Add/Online Operation Only)                        : 0x{flag1:04X}{flag1_str}
        Bit[1] (Proximity Domain Validity)                        : 0x{flag2:04X}{flag2_str}
        Bits[15:2]                                                : 0x{flag3:04X} - Reserved
      Reserved                                                    : 0x{reserved:08X}
      Proximity Domain                                            : 0x{proximityDomain:08X} - must match value in SRAT table
      Address Range Type GUID                                     : 0x{addressRangeTypeGUID_1:08X} 0x{addressRangeTypeGUID_2:04X} 0x{addressRangeTypeGUID_3:04X} 0x{addressRangeTypeGUID_4:02X} 0x{addressRangeTypeGUID_5:02X} 0x{addressRangeTypeGUID_6:02X} 0x{addressRangeTypeGUID_7:02X} 0x{addressRangeTypeGUID_8:02X} 0x{addressRangeTypeGUID_9:02X} 0x{addressRangeTypeGUID_10:02X} 0x{addressRangeTypeGUID_11:02X} - {artg_str}
      System Physical Address Range Base                          : 0x{systemPARangeBase:016X}
      System Physical Address Range Length                        : 0x{SPARLen:016X} ({SPARLen:d} bytes)
      Address Range Memory Mapping Attribute                      : 0x{addrRangeMemMapAttr:016X}
'''

    def parseStructures(self, table_content: bytes) -> str:
        notFinished = True
        curPos = 0
        result = ''
        while notFinished:
            tableType = struct.unpack('<H', table_content[curPos:curPos + 2])[0]
            tableLen = struct.unpack('<H', table_content[curPos + 2:curPos + 4])[0]
            result += f''' Length:                    {self.total_length:d}'''
            if tableType == 0:
                result += self.parseSPA(tableLen, table_content[curPos:])
                curPos = curPos + tableLen
            elif tableType == 1:
                result += self.parseMAP(tableLen, table_content[curPos:])
                curPos = curPos + tableLen
            elif tableType == 2:
                sz, result_str = self.interleave(tableLen, table_content[curPos:])
                result += result_str
                curPos = curPos + tableLen
            elif tableType == 3:
                result += self.smbiosManagementInfo(tableLen, table_content[curPos:])
                curPos = curPos + tableLen
            elif tableType == 4:
                result += self.nvdimmControlRegionStructMark(tableLen, table_content[curPos:])
                curPos += tableLen
            elif tableType == 5:
                result += self.nvdimmBlockDataWindowsRegionStruct(tableLen, table_content[curPos:])
                curPos = curPos + tableLen
            elif tableType == 6:
                sz, result_str = self.flushHintAddrStruct(tableLen, table_content[curPos:])
                result += result_str
                curPos = curPos + tableLen
            elif tableType == 7:
                result += self.platCapStruct(tableLen, table_content[curPos:])
                curPos = curPos + tableLen
            else:
                pass
            if curPos >= self.total_length:
                notFinished = False
        return result

    def parse(self, table_content: bytes) -> None:
        reserved = struct.unpack('<L', table_content[0:4])[0]
        NFITstructures = self.parseStructures(table_content[4:])
        self.results = f'''==================================================================
  NVDIMM Firmware Interface Table ( NFIT )
==================================================================
  Reserved                                                      : {reserved:08X}
  NFIT Structures{NFITstructures}

'''

    def __str__(self) -> str:
        return self.results


########################################################################################################
#
# UEFI Table
#
########################################################################################################
SMM_COMM_TABLE = str(UUID('c68ed8e29dc64cbd9d94db65acc5c332')).upper()


class UEFI_TABLE (ACPI_TABLE):
    def __init__(self):
        self.buf_addr = 0
        self.smi = 0
        self.invoc_reg = None
        return

    def parse(self, table_content: bytes) -> None:
        self.results = '''==================================================================
  Table Content
=================================================================='''
        # Ensure can get identifier and dataOffset fields
        if len(table_content) < 18:
            return
        # Get Guid and Data Offset
        guid = struct.unpack(EFI_GUID_FMT, table_content[:16])[0]
        identifier = EFI_GUID_STR(guid)
        offset = struct.unpack('H', table_content[16:18])[0]
        self.results += f"""
  identifier                 : {identifier}
  Data Offset                : {offset:d}"""
        # check if SMM Communication ACPI Table
        if not (SMM_COMM_TABLE == identifier):
            return
        content_offset = offset - 36
        # check to see if there is enough data to get SW SMI Number and Buffer Ptr Address
        if content_offset < 0 or content_offset + 12 > len(table_content):
            return
        self.smi = struct.unpack('I', table_content[content_offset:content_offset + 4])[0]
        content_offset += 4
        self.buf_addr = struct.unpack('Q', table_content[content_offset:content_offset + 8])[0]
        content_offset += 8
        self.results += f"""
  SW SMI NUM                 : {self.smi}
  Buffer Ptr Address         : {self.buf_addr:X}"""
        # Check to see if there is enough data for Invocation Register
        if content_offset + 12 <= len(table_content):
            self.invoc_reg = GAS(table_content[content_offset:content_offset + 12])
            self.results += f"\n  Invocation Register        :\n{str(self.invoc_reg)}"
        else:
            self.results += "\n  Invocation Register        : None\n"

    def __str__(self) -> str:
        return self.results

    CommBuffInfo = Tuple[int, int, Optional['GAS']]

    def get_commbuf_info(self) -> CommBuffInfo:
        return (self.smi, self.buf_addr, self.invoc_reg)

########################################################################################################
#
# WSMT Table
#
########################################################################################################


class WSMT (ACPI_TABLE):

    FIXED_COMM_BUFFERS = 1
    COMM_BUFFER_NESTED_PTR_PROTECTION = 2
    SYSTEM_RESOURCE_PROTECTION = 4

    def __init__(self):
        self.fixed_comm_buffers = False
        self.comm_buffer_nested_ptr_protection = False
        self.system_resource_protection = False

    def parse(self, table_content: bytes) -> None:
        if len(table_content) < 4:
            return

        mitigations = struct.unpack("<L", table_content)[0]

        self.fixed_comm_buffers = bool(mitigations & WSMT.FIXED_COMM_BUFFERS)
        self.comm_buffer_nested_ptr_protection = bool(mitigations & WSMT.COMM_BUFFER_NESTED_PTR_PROTECTION)
        self.system_resource_protection = bool(mitigations & WSMT.SYSTEM_RESOURCE_PROTECTION)

    def __str__(self) -> str:
        return f"""------------------------------------------------------------------
Windows SMM Mitigations Table (WSMT) Contents
------------------------------------------------------------------
FIXED_COMM_BUFFERS                  : {self.fixed_comm_buffers}
COMM_BUFFER_NESTED_PTR_PROTECTION   : {self.comm_buffer_nested_ptr_protection}
SYSTEM_RESOURCE_PROTECTION          : {self.system_resource_protection}
    """



########################################################################################################
#
# Generic Address Structure
#
########################################################################################################


class GAS:
    def __init__(self, table_content: bytes):
        self.addrSpaceID = struct.unpack('<B', table_content[0:1])[0]
        self.regBitWidth = struct.unpack('<B', table_content[1:2])[0]
        self.regBitOffset = struct.unpack('<B', table_content[2:3])[0]
        self.accessSize = struct.unpack('<B', table_content[3:4])[0]
        self.addr = struct.unpack('<Q', table_content[4:12])[0]
        if self.addrSpaceID == 0:
            self.addrSpaceID_str = 'System Memory Space'
        elif self.addrSpaceID == 1:
            self.addrSpaceID_str = 'System I/O Space'
        elif self.addrSpaceID == 2:
            self.addrSpaceID_str = 'PCI Configuration Space'
        elif self.addrSpaceID == 3:
            self.addrSpaceID_str = 'Embedded Controller'
        elif self.addrSpaceID == 4:
            self.addrSpaceID_str = 'SMBus'
        elif self.addrSpaceID == 0x0A:
            self.addrSpaceID_str = 'Platform Communications Channel (PCC)'
        elif self.addrSpaceID == 0x7F:
            self.addrSpaceID_str = 'Functional Fixed Hardware'
        elif self.addrSpaceID >= 0xC0 and self.addrSpaceID <= 0xFF:
            self.addrSpaceID_str = 'OEM Defined'
        else:
            self.addrSpaceID_str = 'Reserved'
        accessSizeList = ['Undefined (legacy reasons)', 'Byte Access', 'Word Access', 'Dword Access', 'QWord Access', 'Not a defined value, check if defined by Address Space ID']
        if self.accessSize < 6:
            self.accessSize_str = accessSizeList[self.accessSize]
        else:
            self.accessSize_str = accessSizeList[5]

    def __str__(self) -> str:
        return f"""  Generic Address Structure
    Address Space ID                            : {self.addrSpaceID:02X} - {self.accessSize_str}
    Register Bit Width                          : {self.regBitWidth:02X}
    Register Bit Offset                         : {self.regBitOffset:02X}
    Access Size                                 : {self.accessSize:02X} - {self.accessSize_str}
    Address                                     : {self.addr:16X}
    """

    def get_info(self) -> Tuple[int, int, int, int, int]:
        return (self.addrSpaceID, self.regBitWidth, self.regBitOffset, self.accessSize, self.addr)
