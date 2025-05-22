# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2022, Intel Corporation
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
Values for PCI/PCIe and static functions
TODO: Add more info here...
"""

import struct
from collections import namedtuple
from typing import List, Tuple, Optional
from chipsec.library.logger import logger
from chipsec.library.pcidb import VENDORS, DEVICES
from chipsec.library.bits import get_bits


#
# PCI configuration header registers
#
class PCI():
    # Common (type 0/1) registers
    PCI_HDR_VID_OFF = 0x0
    PCI_HDR_DID_OFF = 0x2
    PCI_HDR_CMD_OFF = 0x4
    PCI_HDR_STS_OFF = 0x6
    PCI_HDR_RID_OFF = 0x8
    PCI_HDR_CLSCODE_OFF = 0x9
    PCI_HDR_PI_OFF = 0x9
    PCI_HDR_SUB_CLS_OFF = 0xA
    PCI_HDR_CLS_OFF = 0xB
    PCI_HDR_CLSIZE_OFF = 0xC
    PCI_HDR_MLT_OFF = 0xD
    PCI_HDR_TYPE_OFF = 0xE
    PCI_HDR_BIST_OFF = 0xF
    PCI_HDR_CAP_OFF = 0x34
    PCI_HDR_INTRLN_OFF = 0x3C
    PCI_HDR_INTRPIN_OFF = 0x3D
    PCI_HDR_BAR0_LO_OFF = 0x10
    PCI_HDR_BAR0_HI_OFF = 0x14

    # PCIe BAR register fields
    PCI_HDR_BAR_CFGBITS_MASK = 0xF

    PCI_HDR_BAR_IOMMIO_MASK = 0x1
    PCI_HDR_BAR_IOMMIO_MMIO = 0
    PCI_HDR_BAR_IOMMIO_IO = 1

    PCI_HDR_BAR_TYPE_MASK = (0x3 << 1)
    PCI_HDR_BAR_TYPE_SHIFT = 1
    PCI_HDR_BAR_TYPE_64B = 2
    PCI_HDR_BAR_TYPE_1MB = 1
    PCI_HDR_BAR_TYPE_32B = 0

    PCI_HDR_BAR_BASE_MASK_MMIO64 = 0xFFFFFFFFFFFFFFF0
    PCI_HDR_BAR_BASE_MASK_MMIO = 0xFFFFFFF0
    PCI_HDR_BAR_BASE_MASK_IO = 0xFFFC

    # Type 0 specific registers
    PCI_HDR_TYPE0_BAR1_LO_OFF = 0x18
    PCI_HDR_TYPE0_BAR1_HI_OFF = 0x1C
    PCI_HDR_TYPE0_BAR2_LO_OFF = 0x20
    PCI_HDR_TYPE0_BAR2_HI_OFF = 0x24
    PCI_HDR_TYPE0_XROM_BAR_OFF = 0x30

    # Type 1 specific registers
    PCI_HDR_TYPE1_XROM_BAR_OFF = 0x38

    # Field defines

    PCI_HDR_CMD_MS_MASK = 0x2

    PCI_HDR_TYPE_TYPE_MASK = 0x7F
    PCI_HDR_TYPE_MF_MASK = 0x80

    PCI_TYPE0 = 0x0
    PCI_TYPE1 = 0x1

    PCI_HDR_XROM_BAR_EN_MASK = 0x00000001
    PCI_HDR_XROM_BAR_BASE_MASK = 0xFFFFF000

    PCI_HDR_BAR_STEP = 0x4

    #
    # Generic/standard PCI Expansion (Option) ROM
    #

    XROM_SIGNATURE = 0xAA55
    PCI_XROM_HEADER_FMT = '<H22sH'
    PCI_XROM_HEADER_SIZE = struct.calcsize(PCI_XROM_HEADER_FMT)

    class PCI_XROM_HEADER(namedtuple('PCI_XROM_HEADER', 'Signature ArchSpecific PCIROffset')):
        __slots__ = ()

        def __str__(self) -> str:
            return f"""
    PCI XROM
    -----------------------------------
    Signature       : 0x{self.Signature:04X} (= 0xAA55)
    ArchSpecific    : {self.ArchSpecific.encode('hex').upper()}
    PCIR Offset     : 0x{self.PCIROffset:04X}
    """

    # @TBD: PCI Data Structure

    #
    # EFI specific PCI Expansion (Option) ROM
    #

    EFI_XROM_SIGNATURE = 0x0EF1
    EFI_XROM_HEADER_FMT = '<HHIHHHBHH'
    EFI_XROM_HEADER_SIZE = struct.calcsize(EFI_XROM_HEADER_FMT)

    class EFI_XROM_HEADER(namedtuple('EFI_XROM_HEADER', 'Signature InitSize EfiSignature EfiSubsystem EfiMachineType CompressType Reserved EfiImageHeaderOffset PCIROffset')):
        __slots__ = ()

        def __str__(self) -> str:
            return f"""
    EFI PCI XROM
    ---------------------------------------
    Signature           : 0x{self.Signature:04X} (= 0xAA55)
    Init Size           : 0x{self.InitSize:04X} (x 512 B)
    EFI Signature       : 0x{self.EfiSignature:08X} (= 0x0EF1)
    EFI Subsystem       : 0x{self.EfiSubsystem:04X}
    EFI Machine Type    : 0x{self.EfiMachineType:04X}
    Compression Type    : 0x{self.CompressType:04X}
    Reserved            : 0x{self.Reserved:02X}
    EFI Image Hdr Offset: 0x{self.EfiImageHeaderOffset:04X}
    PCIR Offset         : 0x{self.PCIROffset:04X}
    """

    #
    # Legacy PCI Expansion (Option) ROM
    #

    XROM_HEADER_FMT = '<HBI17sH'
    XROM_HEADER_SIZE = struct.calcsize(XROM_HEADER_FMT)

    class XROM_HEADER(namedtuple('XROM_HEADER', 'Signature InitSize InitEP Reserved PCIROffset')):
        __slots__ = ()

        def __str__(self) -> str:
            return f"""
    XROM
    --------------------------------------
    Signature           : 0x{self.Signature:04X}
    Init Size           : 0x{self.InitSize:02X} (x 512 B)
    Init Entry-point    : 0x{self.InitEP:08X}
    Reserved            : {self.Reserved.encode('hex').upper()}
    PCIR Offset         : 0x{self.PCIROffset:04X}
    """

    class XROM:
        def __init__(self, bus, dev, fun, en, base, size):
            self.bus: int = bus
            self.dev: int = dev
            self.fun: int = fun
            self.vid: int = 0xFFFF
            self.did: int = 0xFFFF
            self.en: int = en
            self.base: int = base
            self.size: int = size
            self.header: Optional[PCI.PCI_XROM_HEADER] = None

    def get_vendor_name_by_vid(vid: int) -> str:
        if vid in VENDORS:
            return VENDORS[vid]
        return ''

    def get_device_name_by_didvid(vid: int, did: int) -> str:
        if vid in DEVICES:
            if did in DEVICES[vid]:
                return DEVICES[vid][did]
        return ''

    def print_pci_devices(_devices: List[Tuple[int, int, int, int, int, int]]) -> None:
        logger().log("BDF     | VID:DID   | Vendor                       | Device")
        logger().log("-------------------------------------------------------------------------")
        for (b, d, f, vid, did, _) in _devices:
            vendor_name = PCI.get_vendor_name_by_vid(vid)
            device_name = PCI.get_device_name_by_didvid(vid, did)
            logger().log(f'{b:02X}:{d:02X}.{f:X} | {vid:04X}:{did:04X} | {vendor_name:28} | {device_name}')

    def print_pci_XROMs(_xroms: List[XROM]) -> None:
        if len(_xroms) == 0:
            return None
        logger().log("BDF     | VID:DID   | XROM base | XROM size | en ")
        logger().log("-------------------------------------------------")
        for xrom in _xroms:
            logger().log(f'{xrom.bus:02X}:{xrom.dev:02X}.{xrom.fun:X} | {xrom.vid:04X}:{xrom.did:04X} | {xrom.base:08X}  | {xrom.size:08X}  | {xrom.en:d}')


# pci extended capability IDs
ecIDs = {
    0x0: 'Null Capability',
    0x1: 'Advanced Error Reporting (AER)',
    0x2: 'Virtual Channel (VC)',
    0x3: 'Device Serial Number',
    0x4: 'Power Budgeting',
    0x5: 'Root Complex Link Declaration',
    0x6: 'Root Complex Internal Link Control',
    0x7: 'Root Complex Event Collector Endpoint Association',
    0x8: 'Multi-Function Virtual Channel (MFVC)',
    0x9: 'Virtual Channel (VC)',
    0xA: 'Root Complex Register Block (RCRB) Header',
    0xB: 'Vendor-Specific Extended Capability (VSEC)',
    0xC: 'Configuration Access Correlation (CAC)',
    0xD: 'Access Control Services (ACS)',
    0xE: 'Alternative Routing-ID Interpretation (ARI)',
    0xF: 'Address Translation Services (ATS)',
    0x10: 'Single Root I/O Virtualizaiton (SR-IOV)',
    0x11: 'Multi-Root I/O Virtualization (MR-IOV)',
    0x12: 'Multicast',
    0x13: 'Page Request Interface (PRI)',
    0x14: 'Reserved for AMD',
    0x15: 'Resizable BAR',
    0x16: 'Dynamic Power Allocation (DPA)',
    0x17: 'TPH Requester',
    0x18: 'Latency Tolerance Reporting (LTR)',
    0x19: 'Secondary PCI Express',
    0x1A: 'Protocol Multiplexing (PMUX)',
    0x1B: 'Process Address Space ID (PASID)',
    0x1C: 'LN Requester (LNR)',
    0x1D: 'Downstream Port Containment (DPC)',
    0x1E: 'L1 PM Substates',
    0x1F: 'Precision Time Measurement (PTM)',
    0x20: 'PCI Express over M-PHY (M-PCIe)',
    0x21: 'FRS Queueing',
    0x22: 'Readiness Time Reporting',
    0x23: 'Designanated Vendor-Specific Extended Capability',
    0x24: 'VF Resizable BAR',
    0x25: 'Data Link Feature',
    0x26: 'Physical Layer 16.0 GT/s',
    0x27: 'Lane Margining at the Receiver',
    0x28: 'Hiearchy ID',
    0x29: 'Native PCIe Enclosure Management (NPEM)',
    0x2A: 'Physical Layer 32.0 GT/s',
    0x2B: 'Alternative Protocol',
    0x2C: 'System Firmware Intermediary (SFI)',
    0x2D: 'Shadow Functions',
    0x2E: 'Data Object Exchange'
}


class ECEntry:
    def __init__(self, bus, dev, fun, off, value):
        self.bus = bus
        self.dev = dev
        self.fun = fun
        self.off = off
        self.next = get_bits(value, 20, 12)
        self.ver = get_bits(value, 16, 4)
        self.id = get_bits(value, 0, 16)


class VSECEntry:
    def __init__(self, value):
        self.size = get_bits(value, 20, 12)
        self.rev = get_bits(value, 16, 4)
        self.id = get_bits(value, 0, 16)


def print_pci_extended_capability(ecentries: List[ECEntry]) -> None:
    currentbdf = (None, None, None)
    for ecentry in ecentries:
        if currentbdf != (ecentry.bus, ecentry.dev, ecentry.fun):
            currentbdf = (ecentry.bus, ecentry.dev, ecentry.fun)
            logger().log(f'Extended Capbilities for 0x{ecentry.bus:02X}:{ecentry.dev:02X}.{ecentry.fun:X}:')
        logger().log(f'\tNext Capability Offset: {ecentry.next:03X}')
        logger().log(f'\tCapability Version: {ecentry.ver:01X}')
        logger().log(f'\tCapability ID: {ecentry.id:04X} - {ecIDs.get(ecentry.id, "Reserved")}')
