#!/usr/local/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2014, Intel Corporation
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
## \addtogroup hal
# chipsec/hal/pci.py
# ===============================================
# Access to PCIe configuration spaces of I/O devices
# usage:
#     read_pci_dword( 0, 0, 0, 0x88 )
#     write_pci_dword( 0, 0, 0, 0x88, 0x1A )
#
#
__version__ = '1.0'

import struct
import sys
import os.path

from chipsec.logger import logger
from chipsec.cfg.common import *
from chipsec.hal.pcidb import *

#class PCI_BDF(Structure):
#    _fields_ = [("BUS",  c_ushort, 16),  # Bus
#                ("DEV",  c_ushort, 16),  # Device
#                ("FUNC", c_ushort, 16),  # Function
#                ("OFF",  c_ushort, 16)]  # Offset


class PciRuntimeError (RuntimeError):
    pass

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


class Pci:

    def __init__( self, helper ):
        self.helper = helper
        #self.devices = []

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

    #
    # Returns all I/O and MMIO BARs defined in the PCIe header of the device 
    # Returns array of elements in format (bar_address, isMMIO_BAR, is64bit_BAR, pcie_BAR_reg_offset)
    # @TODO: need to account for Type 0 vs Type 1 headers
    def get_device_bars( self, bus, dev, fun ):
        _bars = []
        off = 0x10
        while (off < 0x28):
            base_lo = self.read_dword( bus, dev, fun, off )
            if base_lo:
               # BAR is initialized
               if (0 == (base_lo & 0x1)):
                  # MMIO BAR
                  is64bit = ( (base_lo>>1) & 0x3 )
                  if 0x2 == is64bit:
                     # 64-bit MMIO BAR
                     off += 4
                     base_hi = self.read_dword( bus, dev, fun, off )
                     base = ((base_hi << 32) | (base_lo & 0xFFFFFFF0))
                     _bars.append( (base, True, True, off-4) )
                  elif 1 == is64bit:
                     # MMIO BAR below 1MB
                     pass
                  elif 0 == is64bit:
                     # 32-bit only MMIO BAR
                     _bars.append( (base_lo, True, False, off) )
               else:
                  # I/O BAR
                  _bars.append( (base_lo&0xFFFFFFFE, False, False, off) )
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


"""
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
"""
