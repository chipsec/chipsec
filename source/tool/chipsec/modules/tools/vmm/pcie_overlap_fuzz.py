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



"""
PCIe device Memory-Mapped I/O (MMIO) ranges VMM emulation fuzzer which first overlaps MMIO BARs of all available PCIe devices
then fuzzes them by writing garbage if corresponding option is enabled

 Usage:
   ``chipsec_main.py -i -m tools.vmm.pcie_overlap_fuzz -l pcie_overlap_fuzz.log``
"""

from chipsec.module_common import *

from chipsec.hal.mmio import *
from chipsec.hal.physmem import *
import chipsec.hal.pci  as pci

import time
import random

logger = logger()
cs     = chipsec.chipset.cs()

#################################################################
# Fuzzing configuration
#################################################################
#
OVERLAP_MODE = 1
FUZZ_OVERLAP = 0
FUZZ_RANDOM = 0

#logger.VERBOSE = False

_EXCLUDE_MMIO_BAR1 = []

_EXCLUDE_MMIO_BAR2 = []

def get_mmio_range_size( bus, dev, fun, off ):
    size = 0
    base_lo = cs.pci.read_dword( bus, dev, fun, off )
    if base_lo:
        # BAR is initialized
        if (0 == (base_lo & 0x1)):
            # MMIO BAR
            # 32-bit only MMIO BAR
            cs.pci.write_dword( bus, dev, fun, off, 0xffffffff )
            new_lo = cs.pci.read_dword( bus, dev, fun, off )
            cs.pci.write_dword( bus, dev, fun, off,  base_lo)
            size = (~( new_lo & 0xFFFFF800 ) & 0xffffffff) + 1 & 0xFFFFF000
            return size
        else:
            return 0
    return size

def overlap_mmio_range(bus1, dev1, fun1, is64bit1, off1, bus2, dev2, fun2, is64bit2, off2, direction):
    base_lo1 = cs.pci.read_dword( bus1, dev1, fun1, off1 )
    base_lo2 = cs.pci.read_dword( bus2, dev2, fun2, off2 )
    if (0 == (base_lo1 & 0x1)) and (0 == (base_lo2 & 0x1)):
        if not is64bit1 and not is64bit2:
        # 32-bit MMIO BARs
        # MMIO BARs
            if direction:
                cs.pci.write_dword( bus2, dev2, fun2, off2,  base_lo1)
            else:
                cs.pci.write_dword( bus1, dev1, fun1, off1,  base_lo2)
        elif is64bit1 and is64bit2:
            # 64-bit MMIO BARs
            base_hi1 = cs.pci.read_dword( bus1, dev1, fun1, off1+4 )
            base_hi2 = cs.pci.read_dword( bus2, dev2, fun2, off2+4 )
            if direction:
                cs.pci.write_dword( bus2, dev2, fun2, off2,  base_lo1)
                cs.pci.write_dword( bus2, dev2, fun2, off2+4,  base_hi1)
            else:
                cs.pci.write_dword( bus1, dev1, fun1, off1,  base_lo2)
                cs.pci.write_dword( bus1, dev1, fun1, off1+4,  base_hi2)
        elif is64bit1 and not is64bit2:
            cs.pci.write_dword( bus1, dev1, fun1, off1,  base_lo2)
            cs.pci.write_dword( bus1, dev1, fun1, off1+4,  0)
        else:
            cs.pci.write_dword( bus2, dev2, fun2, off2,  base_lo1)
            cs.pci.write_dword( bus2, dev2, fun2, off2+4,  0)

def fuzz_offset(cs, bar, reg_off, reg_value, is64bit):
    write_MMIO_reg( cs, bar, reg_off, reg_value ) # same value
    write_MMIO_reg( cs, bar, reg_off, ~reg_value & 0xFFFFFFFF )
    write_MMIO_reg( cs, bar, reg_off, 0xFFFFFFFF )
    write_MMIO_reg( cs, bar, reg_off, 0x5A5A5A5A )
    write_MMIO_reg( cs, bar, reg_off, 0x00000000 )

def fuzz_unaligned(cs, bar, reg_off, is64bit):
    dummy = read_MMIO_reg( cs, bar, reg_off + 1 )
    # @TODO: crosses the reg boundary
    #write_MMIO_reg( cs, bar, reg_off + 1, 0xFFFFFFFF )
    cs.mem.write_physical_mem_word( bar + reg_off + 1, 0xFFFF )
    cs.mem.write_physical_mem_byte( bar + reg_off + 1, 0xFF )

def fuzz_mmio_bar( bar, is64bit, size=0x1000 ):
    logger.log( "[*] Fuzzing MMIO BAR 0x%016X, size = 0x%X.." % (bar,size) )
    reg_off = 0
    # Issue 32b MMIO requests with various values to all MMIO registers
    for reg_off in range(0,size,4):
        reg_value = read_MMIO_reg( cs, bar, reg_off )
        fuzz_offset( cs, bar, reg_off, reg_value, is64bit )
        fuzz_unaligned( cs, bar, reg_off, is64bit )
        # restore the original value
        write_MMIO_reg( cs, bar, reg_off, reg_value )

def fuzz_mmio_bar_random( bar, is64bit, size=0x1000 ):
    logger.log( "[*] Fuzzing MMIO BAR in random mode 0x%016X, size = 0x%X.." % (bar,size) )
    reg_off = 0
    while 1:
        rand = random.randint(0, size/4-1)
        fuzz_offset (cs, bar, rand*4, is64bit)
        fuzz_offset (cs, bar, rand*4+1, is64bit)
        fuzz_unaligned(cs, bar, rand*4, is64bit)

def fuzz_overlap_pcie_device(pcie_devices):
    for (b1, d1, f1, vid1, did1) in pcie_devices:
        logger.log( "[*] Overlapping MMIO bars .." )
        device_bars1 = cs.pci.get_device_bars( b1, d1, f1 )
        for (bar1, isMMIO1, is64bit1, bar_off1, bar_reg1) in device_bars1:
            if bar1 not in _EXCLUDE_MMIO_BAR1:
                if isMMIO1:
                    for (b2, d2, f2, vid2, did2) in pcie_devices:
                        device_bars2 = cs.pci.get_device_bars( b2, d2, f2 )
                        for (bar2, isMMIO2, is64bit2, bar_off2, bar_reg2) in device_bars2:
                            if bar2 not in _EXCLUDE_MMIO_BAR2:
                                if isMMIO2:
                                    if bar1 != bar2:
                                        logger.log( "[+] Overlap device %02X:%02X.%X offset %X bar: %08X and %02X:%02X.%X offset %X bar: %08X" % (b1, d1, f1, bar_off1, bar1, b2, d2, f2, bar_off2, bar2) )
                                        overlap_mmio_range(b1, d1, f1, is64bit1, bar_off1, b2, d2, f2, is64bit2, bar_off2, OVERLAP_MODE)
                                        if FUZZ_OVERLAP:
                                            if OVERLAP_MODE:
                                                size1 = get_mmio_range_size( b1, d1, f1, bar_off1 )
                                                logger.log( "[+] Fuzzing device %02X:%02X.%X offset %X bar" % (b1, d1, f1, bar_off1) )
                                                if FUZZ_RANDOM:
                                                    fuzz_mmio_bar_random( bar1, is64bit1, size1 )
                                                else:
                                                    fuzz_mmio_bar( bar1, is64bit1, size1 )
                                            else:
                                                size2 = get_mmio_range_size( b2, d2, f2, bar_off2 )
                                                logger.log( "[+] Fuzzing device %02X:%02X.%X offset %X bar" % (b2, d2, f2, bar_off2) )
                                                if FUZZ_RANDOM:
                                                    fuzz_mmio_bar_random( bar1, is64bit1, size1 )
                                                else:
                                                    fuzz_mmio_bar( bar2, is64bit2, size2 )
                                                                        

def run( module_argv ):
    logger.start_test( "Tool to overlap and fuzz MMIO spaces of available PCIe devices" )

    pcie_devices = []
    logger.log( "[*] Enumerating available PCIe devices.." )
    pcie_devices = cs.pci.enumerate_devices()

    logger.log( "[*] About to fuzz the following PCIe devices.." )
    pci.print_pci_devices( pcie_devices )
    fuzz_overlap_pcie_device( pcie_devices )

    return True
