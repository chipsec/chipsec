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
# chipsec/hal/mmio.py
# =============================================
# Access to MMIO (Memory Mapped IO) BARs and Memory-Mapped PCI Configuration Space (MMCFG)
# ~~~
# #usage:
#     read_MMIOBAR_reg( cs, mmio.MMIO_BAR_MCHBAR, 0x0 )
#     write_MMIOBAR_reg( cs, mmio.MMIO_BAR_MCHBAR, 0xFFFFFFFF )
#     read_MMIO_reg( bar_base, 0x0 )
#     write_MMIO_reg( bar_base, 0x0, 0xFFFFFFFF )
#
#     get_MMIO_base_address( cs, mmio.MMIO_BAR_MCHBAR )
#     is_MMIOBAR_enabled( cs, mmio.MMIO_BAR_MCHBAR )
#     is_MMIOBAR_programmed( cs, mmio.MMIO_BAR_MCHBAR )
#
#     read_MMIOBAR( cs, mmio.MMIO_BAR_MCHBAR, 0x1000 )
#     read_MMIO( cs, bar_base, 0x1000 )
#     dump_MMIO( cs, bar_base, 0x1000 )
#
#     read_mmcfg_reg( cs, 0, 0, 0, 0x10, 4 ):
#     read_mmcfg_reg( cs, 0, 0, 0, 0x10, 4, 0xFFFFFFFF )
# ~~~
#
__version__ = '1.0'

import struct
import sys

from chipsec.logger import logger
#from chipsec.pci import PCI_BDF

from chipsec.cfg.common import *


##################################################################################
# Dev0 BARs: MCHBAR, DMIBAR
##################################################################################
def get_MCHBAR_base_address(cs):
    #bar = PCI_BDF( 0, 0, 0, Cfg.PCI_MCHBAR_REG_OFF )
    base = cs.pci.read_dword( 0, 0, 0, Cfg.PCI_MCHBAR_REG_OFF )
    if (0 == base & 0x1):
       logger().warn('MCHBAR is disabled')
    base = base & 0xFFFFF000
    if logger().VERBOSE:
       logger().log( '[mmio] MCHBAR: 0x%016X' % base )
    return base

def get_DMIBAR_base_address(cs):
    #bar = PCI_BDF( 0, 0, 0, Cfg.PCI_DMIBAR_REG_OFF )
    base_lo = cs.pci.read_dword( 0, 0, 0, Cfg.PCI_DMIBAR_REG_OFF )
    base_hi = cs.pci.read_dword( 0, 0, 0, Cfg.PCI_DMIBAR_REG_OFF + 4 )
    if (0 == base_lo & 0x1):
       logger().warn('DMIBAR is disabled')
    base = (base_hi << 32) | (base_lo & 0xFFFFF000)
    if logger().VERBOSE:
       logger().log( '[mmio] DMIBAR: 0x%016X' % base )
    return base


##################################################################################
# PCH LPC Interface Root Complex base address (RCBA)
##################################################################################

def get_LPC_RCBA_base_address(cs):
    reg_value = cs.pci.read_dword( 0, 31, 0, Cfg.LPC_RCBA_REG_OFFSET )
    #RcbaReg = LPC_RCBA_REG( (reg_value>>14)&0x3FFFF, (reg_value>>1)&0x1FFF, reg_value&0x1 )
    #rcba_base = RcbaReg.BaseAddr << Cfg.RCBA_BASE_ADDR_SHIFT
    rcba_base = (reg_value >> Cfg.RCBA_BASE_ADDR_SHIFT) << Cfg.RCBA_BASE_ADDR_SHIFT
    if logger().VERBOSE:
      logger().log( "[mmio] LPC RCBA: 0x%08X" % rcba_base )
    return rcba_base


##################################################################################
# Base of SPI Controller MMIO registers
##################################################################################

def get_PCH_RCBA_SPI_base(cs):
    rcba_spi_base = get_LPC_RCBA_base_address(cs) + Cfg.PCH_RCRB_SPI_BASE
    if logger().VERBOSE:
       logger().log( "[mmio] RCBA SPI base: 0x%08X (assuming below 4GB)" % rcba_spi_base )
    return rcba_spi_base


##################################################################################
# GFx MMIO: GMADR/GTTMMADR
##################################################################################

def get_GFx_base_address(cs, dev2_offset):
    #bar = PCI_BDF( 0, 2, 0, dev2_offset )
    base_lo = cs.pci.read_dword( 0, 2, 0, dev2_offset )
    base_hi = cs.pci.read_dword( 0, 2, 0, dev2_offset + 4 )
    base = base_hi | (base_lo & 0xFF000000)
    return base
def get_GMADR_base_address( cs ):
    base = get_GFx_base_address(cs, Cfg.PCI_GMADR_REG_OFF)
    if logger().VERBOSE:
       logger().log( '[mmio] GMADR: 0x%016X' % base )
    return base
def get_GTTMMADR_base_address( cs ):
    base = get_GFx_base_address(cs, Cfg.PCI_GTTMMADR_REG_OFF)
    if logger().VERBOSE:
       logger().log( '[mmio] GTTMMADR: 0x%016X' % base )
    return base

##################################################################################
# HD Audio MMIO
##################################################################################

def get_HDAudioBAR_base_address(cs):
    base = cs.pci.read_dword( 0, Cfg.PCI_HDA_DEV, 0, Cfg.PCI_HDAUDIOBAR_REG_OFF )
    base = base & (0xFFFFFFFF << 14)
    if logger().VERBOSE:
       logger().log( '[mmio] HD Audio MMIO: 0x%08X' % base )
    return base


##################################################################################
# PCIEXBAR - technically not MMIO but Memory-mapped CFG space (MMCFG)
# but defined by BAR similarly to MMIO BARs
##################################################################################

def get_PCIEXBAR_base_address(cs):
    base_lo = cs.pci.read_dword( 0, 0, 0, Cfg.PCI_PCIEXBAR_REG_OFF )
    base_hi = cs.pci.read_dword( 0, 0, 0, Cfg.PCI_PCIEXBAR_REG_OFF + 4 )
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
#
# To add your own MMIO bar:
#   1. Add new MMIO BAR id (any)
#   2. Write a function get_yourBAR_base_address() with no args that returns base addres of new bar
#   3. Add a pointer to this function to MMIO_BAR_base map
#   4. Don't touch read/write_MMIO_reg functions ;)
#
##################################################################################

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

MMIO_BAR_base = {
                  MMIO_BAR_MCHBAR      : get_MCHBAR_base_address,
                  MMIO_BAR_DMIBAR      : get_DMIBAR_base_address,
                  MMIO_BAR_PCIEXBAR    : get_PCIEXBAR_base_address,
                  MMIO_BAR_GMADR       : get_GMADR_base_address,
                  MMIO_BAR_GTTMMADR    : get_GTTMMADR_base_address,
                  MMIO_BAR_HDABAR      : get_HDAudioBAR_base_address,
                  MMIO_BAR_LPCRCBA     : get_LPC_RCBA_base_address,
                  MMIO_BAR_LPCRCBA_SPI : get_PCH_RCBA_SPI_base
                }
MMIO_BAR_name = {
                  MMIO_BAR_MCHBAR      : "MCHBAR",
                  MMIO_BAR_DMIBAR      : "DMIBAR",
                  MMIO_BAR_PCIEXBAR    : "PCIEXBAR",
                  MMIO_BAR_GMADR       : "GMADR",
                  MMIO_BAR_GTTMMADR    : "GTTMMADR",
                  MMIO_BAR_HDABAR      : "HDABAR",
                  MMIO_BAR_LPCRCBA     : "RCBA",
                  MMIO_BAR_LPCRCBA_SPI : "SPIBAR"
                }
#MMIO_BAR_name = dict( MMIO_BAR_base+[(e[1], e[0]) for e in MMIO_BAR_base] )


def get_MMIO_base_address( cs, bar_id ):
    return MMIO_BAR_base[ bar_id ](cs)

def is_MMIOBAR_enabled( cs, bar_id ):
    bar_base  = MMIO_BAR_base[ bar_id ](cs)
    return (0 != bar_base)


def is_MMIOBAR_programmed( cs, bar_id ):
    bar_base  = MMIO_BAR_base[ bar_id ](cs)
    return (0 != bar_base)

def read_MMIOBAR_reg(cs, bar_id, offset ):
    bar_base  = MMIO_BAR_base[ bar_id ](cs)
    reg_addr  = bar_base + offset 
    reg_value = cs.mem.read_physical_mem_dword( reg_addr )
    if logger().VERBOSE:
      logger().log( '[mmio] %s + 0x%08X (0x%08X) = 0x%08X' % (MMIO_BAR_name[bar_id], offset, reg_addr, reg_value) )
    return reg_value
def read_MMIO_reg(cs, bar_base, offset ):
    reg_value = cs.mem.read_physical_mem_dword( bar_base + offset )
    if logger().VERBOSE:
      logger().log( '[mmio] 0x%08X + 0x%08X = 0x%08X' % (bar_base, offset, reg_value) )
    return reg_value
    
def write_MMIOBAR_reg(cs, bar_id, offset, dword_value ):
    bar_base  = MMIO_BAR_base[ bar_id ]()
    reg_addr  = bar_base + offset
    if logger().VERBOSE:
       logger().log( '[mmio] write %s + 0x%08X (0x%08X) = 0x%08X' % (MMIO_BAR_name[bar_id], offset, reg_addr, dword_value) )
    cs.mem.write_physical_mem_dword( reg_addr, dword_value )
    return 1
def write_MMIO_reg(cs, bar_base, offset, dword_value ):
    if logger().VERBOSE:
       logger().log( '[mmio] write 0x%08X + 0x%08X = 0x%08X' % (bar_base, offset, dword_value) )
    cs.mem.write_physical_mem_dword( bar_base + offset, dword_value )
    return 1

def read_MMIOBAR( cs, bar_id, size ):
    regs = []
    size = size - size%4
    bar_base  = MMIO_BAR_base[ bar_id ]()
    for offset in range(0,size,4):
        regs.append( read_MMIO_reg( cs, bar_base, offset ) )
    return regs
def read_MMIO( cs, bar_base, size ):
    regs = []
    size = size - size%4
    for offset in range(0,size,4):
        regs.append( read_MMIO_reg( cs, bar_base, offset ) )
    return regs

def dump_MMIO( cs, bar_base, size ):
    regs = read_MMIO( cs, bar_base, size )
    off = 0
    for r in regs:
        logger().log( '0x%04x: %08x' % (off, r) )
        off = off + 4



##################################################################################
# Read/write memory mapped PCIe configuration registers
##################################################################################

def read_mmcfg_reg( cs, bus, dev, fun, off, size ):
    pciexbar = get_PCIEXBAR_base_address( cs )
    pciexbar_off = (bus * 32 * 8 + dev * 8 + fun) * 0x1000 + off
    value = read_MMIO_reg( cs, pciexbar, pciexbar_off )
    if logger().VERBOSE:
       logger().log( "[mmcfg] reading B/D/F %d/%d/%d + %02X (PCIEXBAR + %08X): 0x%08X" % (bus, dev, fun, off, pciexbar_off, value) )
    if 1 == size:
       return (value & 0xFF)
    elif 2 == size:
       return (value & 0xFFFF)
    return value

def write_mmcfg_reg( cs, bus, dev, fun, off, size, value ):
    pciexbar = get_PCIEXBAR_base_address( cs )
    pciexbar_off = (bus * 32 * 8 + dev * 8 + fun) * 0x1000 + off
    write_MMIO_reg( cs, pciexbar, pciexbar_off, (value&0xFFFFFFFF) )
    if logger().VERBOSE:
       logger().log( "[mmcfg] writing B/D/F %d/%d/%d + %02X (PCIEXBAR + %08X): 0x%08X" % (bus, dev, fun, off, pciexbar_off, value) )
    return True
