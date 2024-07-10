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
Access to of PCI/PCIe device hierarchy
- enumerating PCI/PCIe devices
- read/write access to PCI configuration headers/registers
- enumerating PCI expansion (option) ROMs
- identifying PCI/PCIe devices MMIO and I/O ranges (BARs)

usage:
    >>> self.cs.pci.read_byte( 0, 0, 0, 0x88 )
    >>> self.cs.pci.write_byte( 0, 0, 0, 0x88, 0x1A )
    >>> self.cs.pci.enumerate_devices()
    >>> self.cs.pci.enumerate_xroms()
    >>> self.cs.pci.find_XROM( 2, 0, 0, True, True, 0xFED00000 )
    >>> self.cs.pci.get_device_bars( 2, 0, 0 )
    >>> self.cs.pci.get_DIDVID( 2, 0, 0 )
    >>> self.cs.pci.is_enabled( 2, 0, 0 )
"""

import struct
from collections import namedtuple
import itertools
from typing import List, Tuple, Optional
from chipsec.library.logger import logger, pretty_print_hex_buffer
from chipsec.library.file import write_file
from chipsec.hal.pcidb import VENDORS, DEVICES
from chipsec.library.exceptions import OsHelperError
from chipsec.library.defines import is_all_ones, MASK_16b, MASK_32b, MASK_64b, BOUNDARY_4KB

#
# PCI configuration header registers
#

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
        self.header: Optional[PCI_XROM_HEADER] = None


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
        vendor_name = get_vendor_name_by_vid(vid)
        device_name = get_device_name_by_didvid(vid, did)
        logger().log(f'{b:02X}:{d:02X}.{f:X} | {vid:04X}:{did:04X} | {vendor_name:28} | {device_name}')


def print_pci_XROMs(_xroms: List[XROM]) -> None:
    if len(_xroms) == 0:
        return None
    logger().log("BDF     | VID:DID   | XROM base | XROM size | en ")
    logger().log("-------------------------------------------------")
    for xrom in _xroms:
        logger().log(f'{xrom.bus:02X}:{xrom.dev:02X}.{xrom.fun:X} | {xrom.vid:04X}:{xrom.did:04X} | {xrom.base:08X}  | {xrom.size:08X}  | {xrom.en:d}')


class Pci:

    def __init__(self, cs):
        self.cs = cs
        self.helper = cs.helper
        self.hal_log_every_read = True

    #
    # Access to PCI configuration registers
    #

    def read_dword(self, bus: int, device: int, function: int, address: int) -> int:
        value = self.helper.read_pci_reg(bus, device, function, address, 4)
        if self.hal_log_every_read or value != 0xFFFFFFFF:
            logger().log_hal(f'[pci] reading B/D/F: {bus:d}/{device:d}/{function:d}, offset: 0x{address:02X}, value: 0x{value:08X}')
        return value

    def read_word(self, bus: int, device: int, function: int, address: int) -> int:
        word_value = self.helper.read_pci_reg(bus, device, function, address, 2)
        if self.hal_log_every_read or word_value != 0xFFFF:
            logger().log_hal(f'[pci] reading B/D/F: {bus:d}/{device:d}/{function:d}, offset: 0x{address:02X}, value: 0x{word_value:04X}')
        return word_value

    def read_byte(self, bus: int, device: int, function: int, address: int) -> int:
        byte_value = self.helper.read_pci_reg(bus, device, function, address, 1)
        if self.hal_log_every_read or byte_value != 0xFF:
            logger().log_hal(f'[pci] reading B/D/F: {bus:d}/{device:d}/{function:d}, offset: 0x{address:02X}, value: 0x{byte_value:02X}')
        return byte_value

    def write_byte(self, bus: int, device: int, function: int, address: int, byte_value: int) -> None:
        self.helper.write_pci_reg(bus, device, function, address, byte_value, 1)
        logger().log_hal(f'[pci] writing B/D/F: {bus:d}/{device:d}/{function:d}, offset: 0x{address:02X}, value: 0x{byte_value:02X}')
        return None

    def write_word(self, bus: int, device: int, function: int, address: int, word_value: int) -> None:
        self.helper.write_pci_reg(bus, device, function, address, word_value, 2)
        logger().log_hal(f'[pci] writing B/D/F: {bus:d}/{device:d}/{function:d}, offset: 0x{address:02X}, value: 0x{word_value:04X}')
        return None

    def write_dword(self, bus: int, device: int, function: int, address: int, dword_value: int) -> None:
        self.helper.write_pci_reg(bus, device, function, address, dword_value, 4)
        logger().log_hal(f'[pci] writing B/D/F: {bus:d}/{device:d}/{function:d}, offset: 0x{address:02X}, value: 0x{dword_value:08X}')
        return None

    #
    # Enumerating PCI devices and dumping configuration space
    #

    def enumerate_devices(self, bus: Optional[int] = None, device: Optional[int] = None, function: Optional[int] = None, spec: Optional[bool] = True) -> List[Tuple[int, int, int, int, int, int]]:
        devices = []
        self.hal_log_every_read = False
        if bus is not None:
            bus_range = [bus]
        else:
            bus_range = range(256)
        if device is not None:
            dev_range = [device]
        else:
            dev_range = range(32)
        if function is not None:
            func_range = [function]
        else:
            func_range = range(8)

        for b, d in itertools.product(bus_range, dev_range):
            for f in func_range:
                try:
                    did_vid = self.read_dword(b, d, f, 0x0)
                    if 0xFFFFFFFF != did_vid:
                        vid = did_vid & 0xFFFF
                        did = (did_vid >> 16) & 0xFFFF
                        rid = self.read_byte(b, d, f, 0x8)
                        devices.append((b, d, f, vid, did, rid))
                    elif f == 0 and spec:
                        break
                except OsHelperError:
                    logger().log_hal(f"[pci] unable to access B/D/F: {b:d}/{d:d}/{f:d}")
        self.hal_log_every_read = True
        return devices

    def dump_pci_config(self, bus: int, device: int, function: int) -> List[int]:
        cfg = []
        for off in range(0, 0x100, 4):
            tmp_val = self.read_dword(bus, device, function, off)
            for shift in range(0, 32, 8):
                cfg.append((tmp_val >> shift) & 0xFF)
        return cfg

    def print_pci_config_all(self) -> None:
        logger().log("[pci] enumerating available PCI devices...")
        pci_devices = self.enumerate_devices()
        for (b, d, f, vid, did, rid) in pci_devices:
            cfg_buf = self.dump_pci_config(b, d, f)
            logger().log(f"\n[pci] PCI device {b:02X}:{d:02X}.{f:02X} configuration:")
            pretty_print_hex_buffer(cfg_buf)

    #
    # PCI Expansion ROM functions
    #

    def parse_XROM(self, xrom: XROM, xrom_dump: bool = False) -> Optional[PCI_XROM_HEADER]:
        xrom_sig = self.cs.mem.read_physical_mem_word(xrom.base)
        if xrom_sig != XROM_SIGNATURE:
            return None
        xrom_hdr_buf = self.cs.mem.read_physical_mem(xrom.base, PCI_XROM_HEADER_SIZE)
        xrom_hdr = PCI_XROM_HEADER(*struct.unpack_from(PCI_XROM_HEADER_FMT, xrom_hdr_buf))
        if xrom_dump:
            xrom_fname = f'xrom_{xrom.bus:X}-{xrom.dev:X}-{xrom.fun:X}_{xrom.vid:X}{xrom.did:X}.bin'
            xrom_buf = self.cs.mem.read_physical_mem(xrom.base, xrom.size)  # use xrom_hdr.InitSize ?
            write_file(xrom_fname, xrom_buf)
        return xrom_hdr

    def find_XROM(self, bus: int, dev: int, fun: int, try_init: bool = False, xrom_dump: bool = False, xrom_addr: Optional[int] = None) -> Tuple[bool, Optional[XROM]]:
        # return results
        xrom_found, xrom = False, None

        logger().log_hal(f'[pci] checking XROM in {bus:02X}:{dev:02X}.{fun:02X}')

        cmd = self.read_word(bus, dev, fun, PCI_HDR_CMD_OFF)
        ms = (cmd & PCI_HDR_CMD_MS_MASK) == PCI_HDR_CMD_MS_MASK
        logger().log_hal(f'[pci]   PCI CMD (memory space = {ms:d}): 0x{cmd:04X}')

        hdr_type = self.read_byte(bus, dev, fun, PCI_HDR_TYPE_OFF)
        _mf = hdr_type & PCI_HDR_TYPE_MF_MASK
        _type = hdr_type & PCI_HDR_TYPE_TYPE_MASK
        xrom_bar_off = PCI_HDR_TYPE1_XROM_BAR_OFF if _type == PCI_TYPE1 else PCI_HDR_TYPE0_XROM_BAR_OFF

        xrom_bar = self.read_dword(bus, dev, fun, xrom_bar_off)
        xrom_exists = (xrom_bar != 0)

        if xrom_exists:
            logger().log_hal(f'[pci]   device programmed XROM BAR: 0x{xrom_bar:08X}')
        else:
            logger().log_hal(f'[pci]   device did not program XROM BAR: 0x{xrom_bar:08X}')
            if try_init:
                self.write_dword(bus, dev, fun, xrom_bar_off, PCI_HDR_XROM_BAR_BASE_MASK)
                xrom_bar = self.read_dword(bus, dev, fun, xrom_bar_off)
                xrom_exists = (xrom_bar != 0)
                logger().log_hal(f'[pci]   returned 0x{xrom_bar:08X} after writing {PCI_HDR_XROM_BAR_BASE_MASK:08X}')
                if xrom_exists and (xrom_addr is not None):
                    # device indicates XROM may exist. Initialize its base with supplied MMIO address
                    size_align = ~(xrom_bar & PCI_HDR_XROM_BAR_BASE_MASK)  # actual XROM alignment
                    if (xrom_addr & size_align) != 0:
                        logger().log_warning(f'XROM address 0x{xrom_addr:08X} must be aligned at 0x{size_align:08X}')
                        return False, None
                    self.write_dword(bus, dev, fun, xrom_bar_off, (xrom_addr | PCI_HDR_XROM_BAR_EN_MASK))
                    xrom_bar = self.read_dword(bus, dev, fun, xrom_bar_off)
                    logger().log_hal(f'[pci]   programmed XROM BAR with 0x{xrom_bar:08X}')

        #
        # At this point, a device indicates that XROM exists. Let's check if XROM is really there
        #
        xrom_en = (xrom_bar & PCI_HDR_XROM_BAR_EN_MASK) == 0x1
        xrom_base = xrom_bar & PCI_HDR_XROM_BAR_BASE_MASK
        xrom_size = ~xrom_base + 1

        if xrom_exists:
            logger().log_hal(f'[pci]   XROM: BAR = 0x{xrom_bar:08X}, base = 0x{xrom_base:08X}, size = 0x{xrom_size:X}, en = {xrom_en:d}')
            xrom = XROM(bus, dev, fun, xrom_en, xrom_base, xrom_size)
            if xrom_en and (xrom_base != PCI_HDR_XROM_BAR_BASE_MASK):
                xrom.header = self.parse_XROM(xrom, xrom_dump)
                xrom_found = (xrom is not None) and (xrom.header is not None)
                if xrom_found:
                    logger().log_hal(f"[pci]   XROM found at 0x{xrom_base:08X}")
                    logger().log_hal(str(xrom.header))

        if not xrom_found:
            logger().log_hal('[pci]   XROM was not found')

        return xrom_found, xrom

    def enumerate_xroms(self, try_init: bool = False, xrom_dump: bool = False, xrom_addr: Optional[int] = None) -> List[Optional[XROM]]:
        pci_xroms = []
        logger().log("[pci] enumerating available PCI devices...")
        pci_devices = self.enumerate_devices()
        for (b, d, f, vid, did, rid) in pci_devices:
            exists, xrom = self.find_XROM(b, d, f, try_init, xrom_dump, xrom_addr)
            if exists and (xrom is not None):
                xrom.vid = vid
                xrom.did = did
                pci_xroms.append(xrom)
        return pci_xroms

    def get_header_type(self, bus, dev, fun):
        res = self.read_byte(bus, dev, fun, PCI_HDR_TYPE_OFF)
        return res & PCI_HDR_TYPE_TYPE_MASK

    #
    # Calculates actual size of MMIO BAR range
    def calc_bar_size(self, bus: int, dev: int, fun: int, off: int, is64: bool, isMMIO: bool) -> int:
        logger().log_hal(f'calc_bar_size {bus}:{dev}.{fun} offset{off}')
        # Read the original value of the register
        orig_regL = self.read_dword(bus, dev, fun, off)
        logger().log_hal(f'orig_regL: {orig_regL:X}')
        if is64:
            orig_regH = self.read_dword(bus, dev, fun, off + PCI_HDR_BAR_STEP)
            logger().log_hal(f'orig_regH: {orig_regH:X}')
        # Write all 1's to the register
        self.write_dword(bus, dev, fun, off + PCI_HDR_BAR_STEP, MASK_32b)
        if is64:
            self.write_dword(bus, dev, fun, off, MASK_32b)
        # Read the register back
        regL = self.read_dword(bus, dev, fun, off)
        logger().log_hal(f'regL: {regL:X}')
        if is64:
            regH = self.read_dword(bus, dev, fun, off + PCI_HDR_BAR_STEP)
            logger().log_hal(f'regH: {regH:X}')
        # Write original value back to register
        self.write_dword(bus, dev, fun, off, orig_regL)
        if is64:
            self.write_dword(bus, dev, fun, off + PCI_HDR_BAR_STEP, orig_regH)
        # Calculate Sizing
        if isMMIO and is64:
            reg = regL | (regH << 32)
            orig_reg = orig_regL | (orig_regH << 32)
            if orig_reg == reg:
                size = BOUNDARY_4KB
            else:
                size = (~(reg & PCI_HDR_BAR_BASE_MASK_MMIO64) & MASK_64b) + 1
        elif isMMIO:
            if regL == orig_regL:
                size = BOUNDARY_4KB
            else:
                size = (~(regL & PCI_HDR_BAR_BASE_MASK_MMIO) & MASK_32b) + 1
        else:
            if regL == orig_regL:
                size = 0x100
            else:
                size = (~(regL & PCI_HDR_BAR_BASE_MASK_IO) & MASK_16b) + 1
        return size

    # Returns all I/O and MMIO BARs defined in the PCIe header of the device
    # Returns array of elements in format (BAR_address, isMMIO, is64bit, BAR_reg_offset, BAR_reg_value)
    def get_device_bars(self, bus: int, dev: int, fun: int, bCalcSize: bool = False) -> List[Tuple[int, bool, bool, int, int, int]]:
        _bars = []
        hdr_type = self.get_header_type(bus, dev, fun)
        if hdr_type == 0:
            bounds = PCI_HDR_TYPE0_BAR2_HI_OFF
        elif hdr_type == 1:
            bounds = PCI_HDR_TYPE0_BAR1_LO_OFF
        else:
            bounds = PCI_HDR_BAR0_LO_OFF

        off = PCI_HDR_BAR0_LO_OFF
        size = BOUNDARY_4KB
        while off <= bounds:
            reg = self.read_dword(bus, dev, fun, off)
            if reg and reg != MASK_32b:
                # BAR is initialized
                isMMIO = (PCI_HDR_BAR_IOMMIO_MMIO == (reg & PCI_HDR_BAR_IOMMIO_MASK))
                if isMMIO:
                    # MMIO BAR
                    mem_type = (reg & PCI_HDR_BAR_TYPE_MASK) >> PCI_HDR_BAR_TYPE_SHIFT
                    if PCI_HDR_BAR_TYPE_64B == mem_type:
                        # 64-bit MMIO BAR
                        if bCalcSize and hdr_type == 0:
                            size = self.calc_bar_size(bus, dev, fun, off, True, True)
                        off += PCI_HDR_BAR_STEP
                        reg_hi = self.read_dword(bus, dev, fun, off)
                        reg |= (reg_hi << 32)
                        base = (reg & PCI_HDR_BAR_BASE_MASK_MMIO64)
                        if base != 0:
                            _bars.append((base, isMMIO, True, off - PCI_HDR_BAR_STEP, reg, size))
                    elif PCI_HDR_BAR_TYPE_1MB == mem_type:
                        # MMIO BAR below 1MB - not supported
                        pass
                    elif PCI_HDR_BAR_TYPE_32B == mem_type:
                        # 32-bit only MMIO BAR
                        base = (reg & PCI_HDR_BAR_BASE_MASK_MMIO)
                        if base != 0:
                            if bCalcSize and hdr_type == 0:
                                size = self.calc_bar_size(bus, dev, fun, off, False, True)
                            _bars.append((base, isMMIO, False, off, reg, size))
                else:
                    # I/O BAR
                    base = (reg & PCI_HDR_BAR_BASE_MASK_IO)
                    if base != 0:
                        if bCalcSize and hdr_type == 0:
                            size = self.calc_bar_size(bus, dev, fun, off, False, False)
                        else:
                            size = 0x100
                        _bars.append((base, isMMIO, False, off, reg, size))
            off += PCI_HDR_BAR_STEP
        return _bars

    def get_DIDVID(self, bus: int, dev: int, fun: int) -> Tuple[int, int]:
        didvid = self.read_dword(bus, dev, fun, 0x0)
        vid = didvid & 0xFFFF
        did = (didvid >> 16) & 0xFFFF
        return (did, vid)

    def is_enabled(self, bus: int, dev: int, fun: int) -> bool:
        (did, vid) = self.get_DIDVID(bus, dev, fun)
        if (is_all_ones(vid, 2)) or (is_all_ones(did, 2)):
            return False
        return True
