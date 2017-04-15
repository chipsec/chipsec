#!/usr/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2015, Intel Corporation
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
Access to MMIO (Memory Mapped IO) BARs and Memory-Mapped PCI Configuration Space (MMCFG)

usage:
    >>> read_MMIO_reg(cs, bar_base, 0x0, 4 )
    >>> write_MMIO_reg(cs, bar_base, 0x0, 0xFFFFFFFF, 4 )
    >>> read_MMIO( cs, bar_base, 0x1000 )
    >>> dump_MMIO( cs, bar_base, 0x1000 )

    Access MMIO by BAR name:

    >>> read_MMIO_BAR_reg( cs, 'MCHBAR', 0x0, 4 )
    >>> write_MMIO_BAR_reg( cs, 'MCHBAR', 0x0, 0xFFFFFFFF, 4 )
    >>> get_MMIO_BAR_base_address( cs, 'MCHBAR' )
    >>> is_MMIO_BAR_enabled( cs, 'MCHBAR' )
    >>> is_MMIO_BAR_programmed( cs, 'MCHBAR' )
    >>> dump_MMIO_BAR( cs, 'MCHBAR' )
    >>> list_MMIO_BARs( cs )

    Access Memory Mapped Config Space:

    >>> get_MMCFG_base_address(cs)
    >>> read_mmcfg_reg( cs, 0, 0, 0, 0x10, 4 )
    >>> read_mmcfg_reg( cs, 0, 0, 0, 0x10, 4, 0xFFFFFFFF )

    DEPRECATED: Access MMIO by BAR id:

    >>> read_MMIOBAR_reg( cs, mmio.MMIO_BAR_MCHBAR, 0x0 )
    >>> write_MMIOBAR_reg( cs, mmio.MMIO_BAR_MCHBAR, 0xFFFFFFFF )
    >>> get_MMIO_base_address( cs, mmio.MMIO_BAR_MCHBAR )
"""

import struct
import sys

from chipsec.hal import hal_base
from chipsec.logger import logger

from chipsec.cfg.common import *

# CPU
# Device 0
MMIO_BAR_MCHBAR      = 1   # MCHBAR
MMIO_BAR_DMIBAR      = 2   # DMIBAR
MMIO_BAR_PCIEXBAR    = 3   # PCIEXBAR
# Device 1
# @TODO
# Device 2
MMIO_BAR_GTTMMADR    = 10  # GFx MMIO
MMIO_BAR_GMADR       = 11  # GFx Aperture
# Device 3 (Device 27)
MMIO_BAR_HDABAR      = 20  # HD Audio MMIO BAR
# PCH
# @TODO
# Device 31
MMIO_BAR_LPCRCBA     = 100 # ICH LPC Interface Root Complex (RCBA)
MMIO_BAR_LPCRCBA_SPI = 101 # RCBA SPIBASE

MMIO_BAR_name = {
    MMIO_BAR_MCHBAR      : "MCHBAR",
    MMIO_BAR_DMIBAR      : "DMIBAR",
    MMIO_BAR_PCIEXBAR    : "PCIEXBAR",
    MMIO_BAR_GMADR       : "GMADR",
    MMIO_BAR_GTTMMADR    : "GTTMMADR",
    MMIO_BAR_HDABAR      : "HDABAR",
    MMIO_BAR_LPCRCBA     : "RCBA"
}

DEFAULT_MMIO_BAR_SIZE = 0x1000

class MMIO(hal_base.HALBase):

    def __init__(self, cs):
        super(MMIO, self).__init__(cs)
        self.MMIO_BAR_base = {
            MMIO_BAR_MCHBAR      : self.get_MCHBAR_base_address,
            MMIO_BAR_DMIBAR      : self.get_DMIBAR_base_address,
            MMIO_BAR_PCIEXBAR    : self.get_PCIEXBAR_base_address,
            MMIO_BAR_GMADR       : self.get_GMADR_base_address,
            MMIO_BAR_GTTMMADR    : self.get_GTTMMADR_base_address,
            MMIO_BAR_HDABAR      : self.get_HDAudioBAR_base_address,
            MMIO_BAR_LPCRCBA     : self.get_LPC_RCBA_base_address
        }

    ###########################################################################
    # Access to MMIO BAR defined by configuration files (chipsec/cfg/*.py)
    ###########################################################################
    #
    # To add your own MMIO bar:
    #   1. Add new MMIO BAR id (any)
    #   2. Write a function get_yourBAR_base_address() with no args that
    #      returns base addres of new bar
    #   3. Add a pointer to this function to MMIO_BAR_base map
    #   4. Don't touch read/write_MMIO_reg functions ;)
    #
    ###########################################################################


    #
    # Dev0 BARs: MCHBAR, DMIBAR
    #
    def get_MCHBAR_base_address(self):
        base = self.cs.pci.read_dword(0, 0, 0, Cfg.PCI_MCHBAR_REG_OFF)
        if (0 == base & 0x1):
            logger().warn('MCHBAR is disabled')
        base = base & 0xFFFFF000
        if logger().VERBOSE:
            logger().log('[mmio] MCHBAR: 0x%016X' % base)
        return base

    def get_DMIBAR_base_address(self):
        base_lo = self.cs.pci.read_dword(0, 0, 0, Cfg.PCI_DMIBAR_REG_OFF)
        base_hi = self.cs.pci.read_dword(0, 0, 0, Cfg.PCI_DMIBAR_REG_OFF + 4)
        if (0 == base_lo & 0x1):
            logger().warn('DMIBAR is disabled')
        base = (base_hi << 32) | (base_lo & 0xFFFFF000)
        if logger().VERBOSE:
            logger().log( '[mmio] DMIBAR: 0x%016X' % base )
        return base

    #
    # PCH LPC Interface Root Complex base address (RCBA)
    #
    def get_LPC_RCBA_base_address(self):
        reg_value = self.cs.pci.read_dword(0, 31, 0, Cfg.LPC_RCBA_REG_OFFSET)
        #RcbaReg = LPC_RCBA_REG( (reg_value>>14)&0x3FFFF, (reg_value>>1)&0x1FFF, reg_value&0x1 )
        #rcba_base = RcbaReg.BaseAddr << Cfg.RCBA_BASE_ADDR_SHIFT
        rcba_base = (reg_value >> Cfg.RCBA_BASE_ADDR_SHIFT) << Cfg.RCBA_BASE_ADDR_SHIFT
        if logger().VERBOSE:
            logger().log( "[mmio] LPC RCBA: 0x%08X" % rcba_base )
        return rcba_base

    #
    # GFx MMIO: GMADR/GTTMMADR
    #
    def get_GFx_base_address(self, dev2_offset):
        #bar = PCI_BDF(0, 2, 0, dev2_offset)
        base_lo = self.cs.pci.read_dword(0, 2, 0, dev2_offset)
        base_hi = self.cs.pci.read_dword(0, 2, 0, dev2_offset + 4)
        base = base_hi | (base_lo & 0xFF000000)
        return base

    def get_GMADR_base_address(self):
        base = self.get_GFx_base_address(Cfg.PCI_GMADR_REG_OFF)
        if logger().VERBOSE:
            logger().log( '[mmio] GMADR: 0x%016X' % base )
        return base

    def get_GTTMMADR_base_address(self):
        base = self.get_GFx_base_address(Cfg.PCI_GTTMMADR_REG_OFF)
        if logger().VERBOSE:
            logger().log( '[mmio] GTTMMADR: 0x%016X' % base )
        return base

    #
    # HD Audio MMIO
    #
    def get_HDAudioBAR_base_address(self):
        base = self.cs.pci.read_dword( 0, Cfg.PCI_HDA_DEV, 0, Cfg.PCI_HDAUDIOBAR_REG_OFF )
        base = base & (0xFFFFFFFF << 14)
        if logger().VERBOSE:
            logger().log( '[mmio] HD Audio MMIO: 0x%08X' % base )
        return base

    #
    # PCIEXBAR - technically not MMIO but Memory-mapped CFG space (MMCFG)
    # but defined by BAR similarly to MMIO BARs
    #
    def get_PCIEXBAR_base_address(self):
        base_lo = self.cs.pci.read_dword( 0, 0, 0, Cfg.PCI_PCIEXBAR_REG_OFF )
        base_hi = self.cs.pci.read_dword( 0, 0, 0, Cfg.PCI_PCIEXBAR_REG_OFF + 4 )
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

    #
    # Get base address of MMIO range by MMIO_BAR_* id
    #
    def get_MMIO_base_address(self, bar_id):
        return self.MMIO_BAR_base[bar_id]

    #
    # Read MMIO register in MMIO BAR defined by MMIO_BAR_* id
    #
    def read_MMIOBAR_reg(self, bar_id, offset ):
        bar_base  = self.MMIO_BAR_base[ bar_id ]
        reg_addr  = bar_base + offset
        reg_value = self.cs.helper.read_mmio_reg( reg_addr, 4 )
        if logger().VERBOSE:
            logger().log( '[mmio] %s + 0x%08X (0x%08X) = 0x%08X' % (MMIO_BAR_name[bar_id], offset, reg_addr, reg_value) )
        return reg_value

    #
    # Write MMIO register in MMIO BAR defined by MMIO_BAR_* id
    #
    def write_MMIOBAR_reg(self, bar_id, offset, dword_value):
        bar_base  = self.MMIO_BAR_base[bar_id]
        reg_addr  = bar_base + offset
        if logger().VERBOSE:
            logger().log('[mmio] write %s + 0x%08X (0x%08X) = 0x%08X' % (self.MMIO_BAR_name[bar_id], offset, reg_addr, dword_value) )
        self.cs.helper.write_mmio_reg(reg_addr, 4, dword_value)


    #
    # Read MMIO register as an offset off of MMIO range base address
    #
    def read_MMIO_reg(self, bar_base, offset, size=4 ):
        reg_value = self.cs.helper.read_mmio_reg( bar_base + offset, size )
        if logger().VERBOSE: logger().log( '[mmio] 0x%08X + 0x%08X = 0x%08X' % (bar_base, offset, reg_value) )
        return reg_value

    def read_MMIO_reg_byte(self, bar_base, offset ):
        reg_value = self.cs.helper.read_mmio_reg( bar_base + offset, 1 )
        if logger().VERBOSE: logger().log( '[mmio] 0x%08X + 0x%08X = 0x%08X' % (bar_base, offset, reg_value) )
        return reg_value

    def read_MMIO_reg_word(self, bar_base, offset ):
        reg_value = self.cs.helper.read_mmio_reg( bar_base + offset, 2 )
        if logger().VERBOSE: logger().log( '[mmio] 0x%08X + 0x%08X = 0x%08X' % (bar_base, offset, reg_value) )
        return reg_value

    def read_MMIO_reg_dword(self, bar_base, offset ):
        reg_value = self.cs.helper.read_mmio_reg( bar_base + offset, 4 )
        if logger().VERBOSE: logger().log( '[mmio] 0x%08X + 0x%08X = 0x%08X' % (bar_base, offset, reg_value) )
        return reg_value

    #
    # Write MMIO register as an offset off of MMIO range base address
    #
    def write_MMIO_reg(self, bar_base, offset, value, size=4 ):
        if logger().VERBOSE: logger().log( '[mmio] write 0x%08X + 0x%08X = 0x%08X' % (bar_base, offset, value) )
        self.cs.helper.write_mmio_reg( bar_base + offset, size, value )

    def write_MMIO_reg_byte(self, bar_base, offset, value ):
        if logger().VERBOSE: logger().log( '[mmio] write 0x%08X + 0x%08X = 0x%08X' % (bar_base, offset, value) )
        self.cs.helper.write_mmio_reg( bar_base + offset, 1, value )

    def write_MMIO_reg_word(self, bar_base, offset, value ):
        if logger().VERBOSE: logger().log( '[mmio] write 0x%08X + 0x%08X = 0x%08X' % (bar_base, offset, value) )
        self.cs.helper.write_mmio_reg( bar_base + offset, 2, value )

    def write_MMIO_reg_dword(self, bar_base, offset, value ):
        if logger().VERBOSE: logger().log( '[mmio] write 0x%08X + 0x%08X = 0x%08X' % (bar_base, offset, value) )
        self.cs.helper.write_mmio_reg( bar_base + offset, 4, value )

    #
    # Read MMIO registers as offsets off of MMIO range base address
    #
    def read_MMIO(self, bar_base, size):
        regs = []
        size -= size % 4
        for offset in range(0, size, 4):
            regs.append(self.read_MMIO_reg(bar_base, offset))
        return regs

    #
    # Dump MMIO range
    #
    def dump_MMIO(self, bar_base, size ):
        logger().log("[mmio] MMIO register range [0x%016X:0x%016X+%08X]:" % (bar_base, bar_base, size))
        size -= size % 4
        for offset in range(0, size, 4):
            logger().log( '+%08X: %08X' % (offset, self.read_MMIO_reg(bar_base, offset)) )


    ###############################################################################
    # Access to MMIO BAR defined by XML configuration files (chipsec/cfg/*.xml)
    ###############################################################################

    #
    # Check if MMIO BAR with bar_name has been defined in XML config
    # Use this function to fall-back to hardcoded config in case XML config is not available
    #
    def is_MMIO_BAR_defined(self, bar_name):
        is_bar_defined = False
        try:
            _bar = self.cs.Cfg.MMIO_BARS[ bar_name ]
            if _bar is not None:
                if 'register' in _bar:
                    is_bar_defined = self.cs.is_register_defined(_bar['register'])
                elif ('bus' in _bar) and ('dev' in _bar) and ('fun' in _bar) and ('reg' in _bar):
                    # old definition
                    is_bar_defined = True
        except KeyError:
            pass

        if not is_bar_defined:
            if logger().VERBOSE: logger().warn( "'%s' MMIO BAR definition not found/correct in XML config" % bar_name )
        return is_bar_defined

    #
    # Get base address of MMIO range by MMIO BAR name
    #
    def get_MMIO_BAR_base_address(self, bar_name):
        bar = self.cs.Cfg.MMIO_BARS[ bar_name ]
        if bar is None or bar == {}: return -1,-1

        if 'register' in bar:
            bar_reg   = bar['register']
            if 'base_field' in bar:
                base_field = bar['base_field']
                base = self.cs.read_register_field(bar_reg, base_field, preserve_field_position=True)
            else:
                base = self.cs.read_register(bar_reg)
        else:
            # this method is not preferred (less flexible)
            b = int(bar['bus'],16)
            d = int(bar['dev'],16)
            f = int(bar['fun'],16)
            r = int(bar['reg'],16)
            width = int(bar['width'],16)
            if 8 == width:
                base_lo = self.cs.pci.read_dword( b, d, f, r )
                base_hi = self.cs.pci.read_dword( b, d, f, r + 4 )
                base = (base_hi << 32) | base_lo
            else:
                base = self.cs.pci.read_dword( b, d, f, r )

        if 'mask' in bar: base &= int(bar['mask'],16)
        if 'offset' in bar: base = base + int(bar['offset'],16)
        size = int(bar['size'],16) if ('size' in bar) else DEFAULT_MMIO_BAR_SIZE

        if logger().VERBOSE: logger().log( '[mmio] %s: 0x%016X (size = 0x%X)' % (bar_name,base,size) )
        return base, size

    #
    # Check if MMIO range is enabled by MMIO BAR name
    #
    def is_MMIO_BAR_enabled(self, bar_name):
        bar = self.cs.Cfg.MMIO_BARS[ bar_name ]
        is_enabled = True
        if 'register' in bar:
            bar_reg   = bar['register']
            if 'enable_field' in bar:
                bar_en_field = bar['enable_field']
                is_enabled = (1 == self.cs.read_register_field(bar_reg, bar_en_field))
        else:
            # this method is not preferred (less flexible)
            b = int(bar['bus'],16)
            d = int(bar['dev'],16)
            f = int(bar['fun'],16)
            r = int(bar['reg'],16)
            width = int(bar['width'],16)
            if 8 == width:
                base_lo = self.cs.pci.read_dword( b, d, f, r )
                base_hi = self.cs.pci.read_dword( b, d, f, r + 4 )
                base = (base_hi << 32) | base_lo
            else:
                base = self.cs.pci.read_dword( b, d, f, r )

            if 'enable_bit' in bar:
                en_mask = 1 << int(bar['enable_bit'])
                is_enabled = (0 != base & en_mask)

        return is_enabled

    #
    # Check if MMIO range is programmed by MMIO BAR name
    #
    def is_MMIO_BAR_programmed(self, bar_name):
        bar = self.cs.Cfg.MMIO_BARS[bar_name]

        if 'register' in bar:
            bar_reg   = bar['register']
            if 'base_field' in bar:
                base_field = bar['base_field']
                base = self.cs.read_register_field(bar_reg, base_field, preserve_field_position=True)
            else:
                base = self.cs.read_register(bar_reg)
        else:
            # this method is not preferred (less flexible)
            b = int(bar['bus'],16)
            d = int(bar['dev'],16)
            f = int(bar['fun'],16)
            r = int(bar['reg'],16)
            width = int(bar['width'],16)
            if 8 == width:
                base_lo = self.cs.pci.read_dword( b, d, f, r )
                base_hi = self.cs.pci.read_dword( b, d, f, r + 4 )
                base = (base_hi << 32) | base_lo
            else:
                base = self.cs.pci.read_dword( b, d, f, r )

        #if 'mask' in bar: base &= int(bar['mask'],16)
        return (0 != base)

    #
    # Read MMIO register from MMIO range defined by MMIO BAR name
    #
    def read_MMIO_BAR_reg(self, bar_name, offset, size=4 ):
        (bar_base,bar_size) = self.get_MMIO_BAR_base_address(bar_name)
        # @TODO: check offset exceeds BAR size
        return self.read_MMIO_reg(bar_base, offset, size)

    #
    # Write MMIO register from MMIO range defined by MMIO BAR name
    #
    def write_MMIO_BAR_reg(self, bar_name, offset, value, size=4 ):
        (bar_base,bar_size) = self.get_MMIO_BAR_base_address(bar_name)
        # @TODO: check offset exceeds BAR size
        return self.write_MMIO_reg(bar_base, offset, value, size)

    def read_MMIO_BAR(self, bar_name):
        (bar_base,bar_size) = self.get_MMIO_BAR_base_address(bar_name)
        return self.read_MMIO(bar_base, bar_size)

    #
    # Dump MMIO range by MMIO BAR name
    #
    def dump_MMIO_BAR(self, bar_name):
        (bar_base,bar_size) = self.get_MMIO_BAR_base_address(bar_name)
        self.dump_MMIO(bar_base, bar_size)

    def list_MMIO_BARs(self):
        logger().log('')
        logger().log( '--------------------------------------------------------------------------------' )
        logger().log( ' MMIO Range   | BAR Register   | Base             | Size     | En? | Description' )
        logger().log( '--------------------------------------------------------------------------------' )
        for _bar_name in self.cs.Cfg.MMIO_BARS:
            if not self.is_MMIO_BAR_defined( _bar_name ): continue
            _bar = self.cs.Cfg.MMIO_BARS[_bar_name]
            (_base,_size) = self.get_MMIO_BAR_base_address(_bar_name)
            _en = self.is_MMIO_BAR_enabled( _bar_name)

            if 'register' in _bar:
                _s = _bar['register']
                if 'offset' in _bar: _s += (' + 0x%X' % int(_bar['offset'],16))
            else:
                _s = '%02X:%02X.%01X + %s' % ( int(_bar['bus'],16),int(_bar['dev'],16),int(_bar['fun'],16),_bar['reg'] )

            logger().log( ' %-12s | %-14s | %016X | %08X | %d   | %s' % (_bar_name, _s, _base, _size, _en, _bar['desc']) )


    ##################################################################################
    # Access to Memory Mapped PCIe Configuration Space
    ##################################################################################

    def get_MMCFG_base_address(self):
        (bar_base,bar_size)  = self.get_MMIO_BAR_base_address('MMCFG')
        # @TODO: temporary w/a
        #if (Cfg.PCI_PCIEXBAR_REG_LENGTH_256MB == (bar_base & Cfg.PCI_PCIEXBAR_REG_LENGTH_MASK) >> 1):
        #    bar_base &= ~(Cfg.PCI_PCIEXBAR_REG_ADMSK128|Cfg.PCI_PCIEXBAR_REG_ADMSK64)
        #elif (Cfg.PCI_PCIEXBAR_REG_LENGTH_128MB == (bar_base & Cfg.PCI_PCIEXBAR_REG_LENGTH_MASK) >> 1):
        #    bar_base &= ~Cfg.PCI_PCIEXBAR_REG_ADMSK64
        ##elif (Cfg.PCI_PCIEXBAR_REG_LENGTH_64MB == (bar_base & Cfg.PCI_PCIEXBAR_REG_LENGTH_MASK) >> 1):
        ##   pass
        if logger().HAL: logger().log( '[mmcfg] Memory Mapped CFG Base: 0x%016X' % bar_base )
        return bar_base

    def read_mmcfg_reg(self, bus, dev, fun, off, size):
        pciexbar = self.get_MMCFG_base_address()
        pciexbar_off = (bus * 32 * 8 + dev * 8 + fun) * 0x1000 + off
        value = self.read_MMIO_reg(pciexbar, pciexbar_off)
        if logger().VERBOSE: logger().log( "[mmcfg] reading %02d:%02d.%d + 0x%02X (MMCFG + 0x%08X): 0x%08X" % (bus, dev, fun, off, pciexbar_off, value) )
        if 1 == size:
            return (value & 0xFF)
        elif 2 == size:
            return (value & 0xFFFF)
        return value

    def write_mmcfg_reg(self, bus, dev, fun, off, size, value):
        pciexbar = self.get_MMCFG_base_address()
        pciexbar_off = (bus * 32 * 8 + dev * 8 + fun) * 0x1000 + off
        self.write_MMIO_reg(pciexbar, pciexbar_off, (value&0xFFFFFFFF))
        if logger().VERBOSE: logger().log( "[mmcfg] writing %02d:%02d.%d + 0x%02X (MMCFG + 0x%08X): 0x%08X" % (bus, dev, fun, off, pciexbar_off, value) )
        return True
