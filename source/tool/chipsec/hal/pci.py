#!/usr/local/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2016, Intel Corporation
# 
#This program is free software; you can redistribute it and/or
#modify it under the terms of the GNU General Public License
#as published by the Free Software Foundation; Version 2.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with this program; if not, write to the Free Software
#Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
#Contact information:
#chipsec@intel.com
#



# -------------------------------------------------------------------------------
#
# CHIPSEC: Platform Hardware Security Assessment Framework
# (c) 2010-2012 Intel Corporation
#
# -------------------------------------------------------------------------------

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

__version__ = '1.0'

import struct
import sys
import os.path
from collections import namedtuple

from chipsec.logger import logger, pretty_print_hex_buffer
from chipsec.file import write_file
from chipsec.cfg.common import *
from chipsec.hal.pcidb import *


class PciRuntimeError (RuntimeError):
    pass
class PciDeviceNotFoundError (RuntimeError):
    pass

#
# PCI configuration header registers
#

# Common (type 0/1) registers
PCI_HDR_VID_OFF            = 0x0
PCI_HDR_DID_OFF            = 0x2
PCI_HDR_CMD_OFF            = 0x4
PCI_HDR_STS_OFF            = 0x6
PCI_HDR_RID_OFF            = 0x8
PCI_HDR_CLSCODE_OFF        = 0x9
PCI_HDR_CLSIZE_OFF         = 0xC
PCI_HDR_MLT_OFF            = 0xD
PCI_HDR_TYPE_OFF           = 0xE
PCI_HDR_BIST_OFF           = 0xF
PCI_HDR_CAP_OFF            = 0x34
PCI_HDR_INTRLN_OFF         = 0x3C
PCI_HDR_INTRPIN_OFF        = 0x3D
PCI_HDR_BAR0_LO_OFF        = 0x10
PCI_HDR_BAR0_HI_OFF        = 0x14

# Type 0 specific registers
PCI_HDR_TYPE0_BAR1_LO_OFF  = 0x18
PCI_HDR_TYPE0_BAR1_HI_OFF  = 0x1C
PCI_HDR_TYPE0_BAR2_LO_OFF  = 0x20
PCI_HDR_TYPE0_BAR2_HI_OFF  = 0x24
PCI_HDR_TYPE0_XROM_BAR_OFF = 0x30

# Type 1 specific registers
PCI_HDR_TYPE1_XROM_BAR_OFF = 0x38

# Field defines

PCI_HDR_CMD_MS_MASK        = 0x2

PCI_HDR_TYPE_TYPE_MASK     = 0x7F
PCI_HDR_TYPE_MF_MASK       = 0x80

PCI_TYPE0                  = 0x0
PCI_TYPE1                  = 0x1

PCI_HDR_XROM_BAR_EN_MASK   = 0x00000001
PCI_HDR_XROM_BAR_BASE_MASK = 0xFFFFF000


#
# Generic/standard PCI Expansion (Option) ROM
#

XROM_SIGNATURE       = 0xAA55
PCI_XROM_HEADER_FMT  = '<H22sH'
PCI_XROM_HEADER_SIZE = struct.calcsize( PCI_XROM_HEADER_FMT )
class PCI_XROM_HEADER( namedtuple('PCI_XROM_HEADER', 'Signature ArchSpecific PCIROffset') ):
    __slots__ = ()
    def __str__(self):
        return """
PCI XROM
-----------------------------------
Signature       : 0x%04X (= 0xAA55)
ArchSpecific    : %s
PCIR Offset     : 0x%04X
""" % ( self.Signature, self.ArchSpecific.encode('hex').upper(), self.PCIROffset )

# @TBD: PCI Data Structure

#
# EFI specific PCI Expansion (Option) ROM
#

EFI_XROM_SIGNATURE   = 0x0EF1
EFI_XROM_HEADER_FMT  = '<HHIHHHBHH'
EFI_XROM_HEADER_SIZE = struct.calcsize( EFI_XROM_HEADER_FMT )
class EFI_XROM_HEADER( namedtuple('EFI_XROM_HEADER', 'Signature InitSize EfiSignature EfiSubsystem EfiMachineType CompressType Reserved EfiImageHeaderOffset PCIROffset') ):
    __slots__ = ()
    def __str__(self):
        return """
EFI PCI XROM
---------------------------------------
Signature           : 0x%04X (= 0xAA55)
Init Size           : 0x%04X (x 512 B)
EFI Signature       : 0x%08X (= 0x0EF1)
EFI Subsystem       : 0x%04X
EFI Machine Type    : 0x%04X
Compression Type    : 0x%04X
Reserved            : 0x%02X
EFI Image Hdr Offset: 0x%04X
PCIR Offset         : 0x%04X
""" % ( self.Signature, self.InitSize, self.EfiSignature, self.EfiSubsystem, self.EfiMachineType, self.CompressType, self.Reserved, self.EfiImageHeaderOffset, self.PCIROffset )

#
# Legacy PCI Expansion (Option) ROM
#

XROM_HEADER_FMT  = '<HBI17sH'
XROM_HEADER_SIZE = struct.calcsize( XROM_HEADER_FMT )
class XROM_HEADER( namedtuple('XROM_HEADER', 'Signature InitSize InitEP Reserved PCIROffset') ):
    __slots__ = ()
    def __str__(self):
        return """
XROM
--------------------------------------
Signature           : 0x%04X
Init Size           : 0x%02X (x 512 B)
Init Entry-point    : 0x%08X
Reserved            : %s
PCIR Offset         : 0x%04X
""" % ( self.Signature, self.InitSize, self.InitEP, self.Reserved.encode('hex').upper(), self.PCIROffset )


class XROM(object):
    def __init__(self, bus, dev, fun, en, base, size):
        self.bus    = bus
        self.dev    = dev
        self.fun    = fun
        self.vid    = 0xFFFF
        self.did    = 0xFFFF
        self.en     = en
        self.base   = base
        self.size   = size
        self.header = None


def get_vendor_name_by_vid( vid ):
    if vid in VENDORS:
        return VENDORS[vid]
    return ''

def get_device_name_by_didvid( vid, did ):
    if vid in VENDORS:
        if did in DEVICES[vid]:
            return DEVICES[vid][did]
    return ''

def print_pci_devices( _devices ):
    logger().log( "BDF     | VID:DID   | Vendor                                   | Device" )
    logger().log( "-------------------------------------------------------------------------------------" )
    for (b, d, f, vid, did) in _devices:
        vendor_name = get_vendor_name_by_vid( vid )
        device_name = get_device_name_by_didvid( vid, did )
        logger().log( "%02X:%02X.%X | %04X:%04X | %-40s | %s" % (b, d, f, vid, did, vendor_name, device_name) )

def print_pci_XROMs( _xroms ):
    if len(_xroms) == 0: return
    logger().log( "BDF     | VID:DID   | XROM base | XROM size | en " )
    logger().log( "-------------------------------------------------" )
    for xrom in _xroms:
        logger().log( "%02X:%02X.%X | %04X:%04X | %08X  | %08X  | %d" % (xrom.bus,xrom.dev,xrom.fun,xrom.vid,xrom.did,xrom.base,xrom.size,xrom.en) )


class Pci:

    def __init__( self, cs ):
        self.cs     = cs
        self.helper = cs.helper

    #
    # Access to PCI configuration registers
    #

    def read_dword(self, bus, device, function, address ):
        value = self.helper.read_pci_reg( bus, device, function, address, 4 )
        if logger().VERBOSE:
            logger().log( "[pci] reading B/D/F: %d/%d/%d, offset: 0x%02X, value: 0x%08X" % (bus, device, function, address, value) )
        return value

    def read_word(self, bus, device, function, address ):
        word_value = self.helper.read_pci_reg( bus, device, function, address, 2 )
        if logger().VERBOSE:
            logger().log( "[pci] reading B/D/F: %d/%d/%d, offset: 0x%02X, value: 0x%04X" % (bus, device, function, address, word_value) )
        return word_value

    def read_byte(self, bus, device, function, address ):
        byte_value = self.helper.read_pci_reg( bus, device, function, address, 1 )
        if logger().VERBOSE:
            logger().log( "[pci] reading B/D/F: %d/%d/%d, offset: 0x%02X, value: 0x%02X" % (bus, device, function, address, byte_value) )
        return byte_value

    def write_byte(self, bus, device, function, address, byte_value ):
        self.helper.write_pci_reg( bus, device, function, address, byte_value, 1 )
        if logger().VERBOSE:
            logger().log( "[pci] writing B/D/F: %d/%d/%d, offset: 0x%02X, value: 0x%02X" % (bus, device, function, address, byte_value) )
        return

    def write_word(self, bus, device, function, address, word_value ):
        self.helper.write_pci_reg( bus, device, function, address, word_value, 2 )
        if logger().VERBOSE:
            logger().log( "[pci] writing B/D/F: %d/%d/%d, offset: 0x%02X, value: 0x%04X" % (bus, device, function, address, word_value) )
        return

    def write_dword( self, bus, device, function, address, dword_value ):
        self.helper.write_pci_reg( bus, device, function, address, dword_value, 4 )
        if logger().VERBOSE:
            logger().log( "[pci] writing B/D/F: %d/%d/%d, offset: 0x%02X, value: 0x%08X" % (bus, device, function, address, dword_value) )
        return


    #
    # Enumerating PCI devices and dumping configuration space
    #

    def enumerate_devices( self ):
        devices = []
        for b in range(256):
            for d in range(32):
                for f in range(8):
                    did_vid = self.read_dword( b, d, f, 0x0 )
                    #didvid = read_mmcfg_reg( cs, b, d, f, 0x0 )
                    if 0xFFFFFFFF != did_vid:
                        vid = did_vid&0xFFFF
                        did = (did_vid >> 16)&0xFFFF
                        devices.append( (b, d, f, vid, did) )
        return devices

    def dump_pci_config( self, bus, device, function ):
        cfg = [0xFF]*0x100
        for off in xrange(0x100):
            cfg[off] = self.read_byte( bus, device, function, off )
        return cfg

    def print_pci_config_all( self ):
        logger().log( "[pci] enumerating available PCI devices..." )
       	pci_devices = self.enumerate_devices()
        for (b, d, f, vid, did) in pci_devices:
            cfg_buf = self.dump_pci_config( b, d, f )
            logger().log( "\n[pci] PCI device %02X:%02X.%02X configuration:" % (b,d,f) )
            pretty_print_hex_buffer( cfg_buf )


    #
    # PCI Expansion ROM functions
    #

    def parse_XROM( self, xrom_base, xrom_dump=False ):
        xrom_sig = self.cs.mem.read_physical_mem_word( xrom_base )
        if xrom_sig != XROM_SIGNATURE: return None
        xrom_hdr_buf = self.cs.mem.read_physical_mem( xrom_base, PCI_XROM_HEADER_SIZE )
        xrom_hdr = PCI_XROM_HEADER( *struct.unpack_from( PCI_XROM_HEADER_FMT, xrom_hdr_buf ) )
        if xrom_dump:
            xrom_fname = 'xrom_%x-%x-%x_%x%x.bin' % (bus, dev, fun, vid, did)
            xrom_buf = self.cs.mem.read_physical_mem( xrom_base, xrom_size ) # use xrom_hdr.InitSize ?
            write_file( xrom_fname, xrom_buf )
        return xrom_hdr

    def find_XROM( self, bus, dev, fun, try_init=False, xrom_dump=False, xrom_addr=None ):
        # return results
        xrom_found,xrom = False,None

        logger().log( "[pci] checking XROM in %02X:%02X.%02X" % (bus,dev,fun) )

        cmd = self.read_word(bus, dev, fun, PCI_HDR_CMD_OFF)
        ms = ((cmd & PCI_HDR_CMD_MS_MASK) == PCI_HDR_CMD_MS_MASK)
        if logger().HAL: logger().log( "[pci]   PCI CMD (memory space = %d): 0x%04X" % (ms,cmd) )

        hdr_type = self.read_byte(bus, dev, fun, PCI_HDR_TYPE_OFF)
        _mf   = hdr_type & PCI_HDR_TYPE_MF_MASK
        _type = hdr_type & PCI_HDR_TYPE_TYPE_MASK
        xrom_bar_off = PCI_HDR_TYPE1_XROM_BAR_OFF if _type == PCI_TYPE1 else PCI_HDR_TYPE0_XROM_BAR_OFF

        xrom_bar = self.read_dword( bus, dev, fun, xrom_bar_off )
        orig_xrom_bar = xrom_bar
        xrom_exists = (xrom_bar != 0)

        if xrom_exists:
            if logger().HAL: logger().log( "[pci]   device programmed XROM BAR: 0x%08X" % xrom_bar )
        else:
            if logger().HAL: logger().log( "[pci]   device didn't program XROM BAR: 0x%08X" % xrom_bar )
            if try_init:
                self.write_dword( bus, dev, fun, xrom_bar_off, PCI_HDR_XROM_BAR_BASE_MASK )
                xrom_bar = self.read_dword( bus, dev, fun, xrom_bar_off )
                xrom_exists = (xrom_bar != 0)
                if logger().HAL: logger().log( "[pci]   returned 0x%08X after writing %08X" % (xrom_bar,PCI_HDR_XROM_BAR_BASE_MASK) )
                if xrom_exists and (xrom_addr is not None):
                    # device indicates XROM may exist. Initialize its base with supplied MMIO address
                    size_align = ~(xrom_bar & PCI_HDR_XROM_BAR_BASE_MASK) # actual XROM alignment
                    if (xrom_addr & size_align) != 0:
                        logger().warn( "XROM address 0x%08X must be aligned at 0x%08X" % (xrom_addr,size_align) )
                        return False,None
                    self.write_dword( bus, dev, fun, xrom_bar_off, (xrom_addr|PCI_HDR_XROM_BAR_EN_MASK) )
                    xrom_bar = self.read_dword( bus, dev, fun, xrom_bar_off )
                    if logger().HAL: logger().log( "[pci]   programmed XROM BAR with 0x%08X" % xrom_bar )

                # restore original value of XROM BAR
                #if orig_xrom_bar != xrom_bar:
                #    self.write_dword( bus, dev, fun, xrom_bar_off, orig_xrom_bar )
 
        #
        # At this point, a device indicates that XROM exists. Let's check if XROM is really there
        #
        xrom_en   = ((xrom_bar & PCI_HDR_XROM_BAR_EN_MASK) == 0x1)
        xrom_base = (xrom_bar & PCI_HDR_XROM_BAR_BASE_MASK)
        xrom_size = ~xrom_base + 1

        if xrom_exists:
            if logger().HAL: logger().log( "[pci]   XROM: BAR = 0x%08X, base = 0x%08X, size = 0x%X, en = %d" % (xrom_bar,xrom_base,xrom_size,xrom_en) )
            xrom = XROM(bus, dev, fun, xrom_en, xrom_base, xrom_size)
            if xrom_en and (xrom_base != PCI_HDR_XROM_BAR_BASE_MASK):
                xrom.header = self.parse_XROM( xrom_base, xrom_dump )
                xrom_found  = (xrom.header is not None)
                if xrom_found:
                    if logger().HAL:
                        logger().log( "[pci]   XROM found at 0x%08X" % xrom_base )
                        logger().log( xrom.header )

        if not xrom_found:
            if logger().HAL: logger().log( "[pci]   XROM was not found" )

        return xrom_found,xrom

    def enumerate_xroms( self, try_init=False, xrom_dump=False, xrom_addr=None ):
        pci_xroms = []
        logger().log( "[pci] enumerating available PCI devices..." )
       	pci_devices = self.enumerate_devices()
        for (b, d, f, vid, did) in pci_devices:
            exists,xrom = self.find_XROM( b, d, f, try_init, xrom_dump, xrom_addr )
            if exists:
                xrom.vid = vid
                xrom.did = did
                pci_xroms.append( xrom )
        return pci_xroms

    #
    # Enumerating PCI device MMIO and I/O ranges (BARs)
    #

    #
    # Returns all I/O and MMIO BARs defined in the PCIe header of the device
    # Returns array of elements in format (BAR_address, isMMIO, is64bit, BAR_reg_offset, BAR_reg_value)
    # @TODO: need to account for Type 0 vs Type 1 headers
    def get_device_bars( self, bus, dev, fun ):
        _bars = []
        off = 0x10
        while (off < 0x28):
            reg = self.read_dword( bus, dev, fun, off )
            if reg:
                # BAR is initialized
                isMMIO = (0 == (reg & 0x1))
                if isMMIO:
                    # MMIO BAR
                    is64bit = ( (reg>>1) & 0x3 )
                    if 0x2 == is64bit:
                        # 64-bit MMIO BAR
                        off += 4
                        reg_hi = self.read_dword( bus, dev, fun, off )
                        reg |= (reg_hi << 32)
                        base = (reg & 0xFFFFFFFFFFFFFFF0)
                        #base = ((base_hi << 32) | (base_lo & 0xFFFFFFF0))
                        _bars.append( (base, isMMIO, True, off-4, reg) )
                    elif 1 == is64bit:
                        # MMIO BAR below 1MB - not supported
                        pass
                    elif 0 == is64bit:
                        # 32-bit only MMIO BAR
                        base = (reg & 0xFFFFFFF0)
                        _bars.append( (base, isMMIO, False, off, reg) )
                else:
                    # I/O BAR
                    base = (reg & 0xFFFFFFFE)
                    _bars.append( ( base, isMMIO, False, off, reg) )
            off += 4
        return _bars

    def get_DIDVID( self, bus, dev, fun ):
        didvid = self.read_dword( bus, dev, fun, 0x0 )
        vid = didvid & 0xFFFF
        did = (didvid >> 16) & 0xFFFF
        return (did, vid)

    def is_enabled( self, bus, dev, fun ):
        (did, vid) = self.get_DIDVID( bus, dev, fun )
        if (0xFFFF == vid) or (0xFFFF == did):
            return False
        return True


'''
    ##################################################################################
    # PCIEXBAR - technically not MMIO but Memory-mapped CFG space (MMCFG)
    # but defined by BAR similarly to MMIO BARs
    ##################################################################################

    def get_PCIEXBAR_base_address( self ):
        base_lo = self.read_dword( 0, 0, 0, Cfg.PCI_PCIEXBAR_REG_OFF )
        base_hi = self.read_dword( 0, 0, 0, Cfg.PCI_PCIEXBAR_REG_OFF + 4 )
        if (0 == base_lo & 0x1):
           logger().warn('PCIEXBAR is disabled')

        base_lo &= Cfg.PCI_PCIEXBAR_REG_ADMSK256
        if (Cfg.PCI_PCIEXBAR_REG_LENGTH_128MB == (base_lo & Cfg.PCI_PCIEXBAR_REG_LENGTH_MASK) >> 1):
           base_lo |= Cfg.PCI_PCIEXBAR_REG_ADMSK128
        elif (Cfg.PCI_PCIEXBAR_REG_LENGTH_64MB == (base_lo & Cfg.PCI_PCIEXBAR_REG_LENGTH_MASK) >> 1):
           base_lo |= (Cfg.PCI_PCIEXBAR_REG_ADMSK128|Cfg.PCI_PCIEXBAR_REG_ADMSK64)
        base = (base_hi << 32) | base_lo
        if logger().VERBOSE:
           logger().log( '[mmio] PCIEXBAR (MMCFG): 0x%016X' % base )
        return base

    ##################################################################################
    # Read/write memory mapped PCIe configuration registers
    ##################################################################################

    def read_mmcfg_reg( self, bus, dev, fun, off, size ):
        pciexbar = self.get_PCIEXBAR_base_address()
        pciexbar_off = (bus * 32 * 8 + dev * 8 + fun) * 0x1000 + off
        #value = read_MMIO_reg( cs, pciexbar, pciexbar_off )
        value = self.helper.read_physical_mem_dword( pciexbar + pciexbar_off )
        if logger().VERBOSE:
           logger().log( "[mmcfg] reading B/D/F %d/%d/%d + %02X (PCIEXBAR + %08X): 0x%08X" % (bus, dev, fun, off, pciexbar_off, value) )
        if 1 == size:
           return (value & 0xFF)
        elif 2 == size:
           return (value & 0xFFFF)
        return value

    def write_mmcfg_reg( self, bus, dev, fun, off, size, value ):
        pciexbar = self.get_PCIEXBAR_base_address()
        pciexbar_off = (bus * 32 * 8 + dev * 8 + fun) * 0x1000 + off
        #write_MMIO_reg( cs, pciexbar, pciexbar_off, (value&0xFFFFFFFF) )
        self.helper.write_physical_mem_dword( pciexbar + pciexbar_off, value )
        if logger().VERBOSE:
           logger().log( "[mmcfg] writing B/D/F %d/%d/%d + %02X (PCIEXBAR + %08X): 0x%08X" % (bus, dev, fun, off, pciexbar_off, value) )
        return
'''
