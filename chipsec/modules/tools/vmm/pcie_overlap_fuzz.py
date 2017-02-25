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
   ``chipsec_main.py -i -m tools.vmm.pcie_overlap_fuzz -l log.txt``
"""

from chipsec.module_common import *
from chipsec.hal import pci

import time
import random

#################################################################
# Fuzzing configuration
#################################################################
#
OVERLAP_MODE = 1
FUZZ_OVERLAP = 0
FUZZ_RANDOM = 0

_EXCLUDE_MMIO_BAR1 = []
_EXCLUDE_MMIO_BAR2 = []

class pcie_overlap_fuzz(BaseModule):

    def overlap_mmio_range(self, bus1, dev1, fun1, is64bit1, off1, bus2, dev2, fun2, is64bit2, off2, direction):
        base_lo1 = self.cs.pci.read_dword( bus1, dev1, fun1, off1 )
        base_lo2 = self.cs.pci.read_dword( bus2, dev2, fun2, off2 )
        if (0 == (base_lo1 & 0x1)) and (0 == (base_lo2 & 0x1)):
            if not is64bit1 and not is64bit2:
            # 32-bit MMIO BARs
            # MMIO BARs
                if direction:
                    self.cs.pci.write_dword( bus2, dev2, fun2, off2,  base_lo1)
                else:
                    self.cs.pci.write_dword( bus1, dev1, fun1, off1,  base_lo2)
            elif is64bit1 and is64bit2:
                # 64-bit MMIO BARs
                base_hi1 = self.cs.pci.read_dword( bus1, dev1, fun1, off1+4 )
                base_hi2 = self.cs.pci.read_dword( bus2, dev2, fun2, off2+4 )
                if direction:
                    self.cs.pci.write_dword( bus2, dev2, fun2, off2,  base_lo1)
                    self.cs.pci.write_dword( bus2, dev2, fun2, off2+4,  base_hi1)
                else:
                    self.cs.pci.write_dword( bus1, dev1, fun1, off1,  base_lo2)
                    self.cs.pci.write_dword( bus1, dev1, fun1, off1+4,  base_hi2)
            elif is64bit1 and not is64bit2:
                self.cs.pci.write_dword( bus1, dev1, fun1, off1,  base_lo2)
                self.cs.pci.write_dword( bus1, dev1, fun1, off1+4,  0)
            else:
                self.cs.pci.write_dword( bus2, dev2, fun2, off2,  base_lo1)
                self.cs.pci.write_dword( bus2, dev2, fun2, off2+4,  0)

    def fuzz_offset(self, bar, reg_off, reg_value, is64bit):
        self.cs.mmio.write_MMIO_reg(bar, reg_off, reg_value ) # same value
        self.cs.mmio.write_MMIO_reg(bar, reg_off, ~reg_value & 0xFFFFFFFF )
        self.cs.mmio.write_MMIO_reg(bar, reg_off, 0xFFFFFFFF )
        self.cs.mmio.write_MMIO_reg(bar, reg_off, 0x5A5A5A5A )
        self.cs.mmio.write_MMIO_reg(bar, reg_off, 0x00000000 )

    def fuzz_unaligned(self, bar, reg_off, is64bit):
        dummy = self.cs.mmio.read_MMIO_reg(bar, reg_off + 1 )
        # @TODO: crosses the reg boundary
        #self.cs.mmio.write_MMIO_reg(bar, reg_off + 1, 0xFFFFFFFF )
        self.cs.mem.write_physical_mem_word( bar + reg_off + 1, 0xFFFF )
        self.cs.mem.write_physical_mem_byte( bar + reg_off + 1, 0xFF )

    def fuzz_mmio_bar(self, bar, is64bit, size=0x1000 ):
        self.logger.log( "[*] Fuzzing MMIO BAR 0x%016X, size = 0x%X.." % (bar,size) )
        reg_off = 0
        # Issue 32b MMIO requests with various values to all MMIO registers
        for reg_off in range(0,size,4):
            reg_value = self.cs.mmio.read_MMIO_reg(bar, reg_off )
            self.fuzz_offset(bar, reg_off, reg_value, is64bit )
            self.fuzz_unaligned(bar, reg_off, is64bit )
            # restore the original value
            self.cs.mmio.write_MMIO_reg(bar, reg_off, reg_value )

    def fuzz_mmio_bar_random(self, bar, is64bit, size=0x1000 ):
        self.logger.log( "[*] Fuzzing MMIO BAR in random mode 0x%016X, size = 0x%X.." % (bar,size) )
        reg_off = 0
        while 1:
            rand = random.randint(0, size/4-1)
            self.fuzz_offset (bar, rand*4, is64bit)
            self.fuzz_offset (bar, rand*4+1, is64bit)
            self.fuzz_unaligned(bar, rand*4, is64bit)

    def fuzz_overlap_pcie_device(self, pcie_devices):
        for (b1, d1, f1, vid1, did1) in pcie_devices:
            self.logger.log( "[*] overlapping MMIO bars..." )
            device_bars1 = self.cs.pci.get_device_bars( b1, d1, f1, bCalcSize=True )
            for (bar1, isMMIO1, is64bit1, bar_off1, bar_reg1, size1) in device_bars1:
                if bar1 not in _EXCLUDE_MMIO_BAR1:
                    if isMMIO1:
                        for (b2, d2, f2, vid2, did2) in pcie_devices:
                            device_bars2 = self.cs.pci.get_device_bars( b2, d2, f2, bCalcSize=True )
                            for (bar2, isMMIO2, is64bit2, bar_off2, bar_reg2, size2) in device_bars2:
                                if bar2 not in _EXCLUDE_MMIO_BAR2:
                                    if isMMIO2:
                                        if bar1 != bar2:
                                            self.logger.log( "[*] overlap device %02X:%02X.%X offset %X bar: %08X and %02X:%02X.%X offset %X bar: %08X" % (b1, d1, f1, bar_off1, bar1, b2, d2, f2, bar_off2, bar2) )
                                            self.overlap_mmio_range(b1, d1, f1, is64bit1, bar_off1, b2, d2, f2, is64bit2, bar_off2, OVERLAP_MODE)
                                            if FUZZ_OVERLAP:
                                                _bar     = bar1     if OVERLAP_MODE else bar2
                                                _is64bit = is64bit1 if OVERLAP_MODE else is64bit2
                                                _size    = size1    if OVERLAP_MODE else size2
                                                self.logger.log( "[*] fuzzing MMIO BAR 0x%X..." % _bar )
                                                if FUZZ_RANDOM:
                                                    self.fuzz_mmio_bar_random( _bar, _is64bit, _size )
                                                else:
                                                    self.fuzz_mmio_bar( _bar, _is64bit, _size )
                                                                            

    def run(self, module_argv):
        self.logger.start_test( "Tool to overlap and fuzz MMIO spaces of available PCIe devices" )

        pcie_devices = []
        self.logger.log( "[*] Enumerating available PCIe devices.." )
        pcie_devices = self.cs.pci.enumerate_devices()

        self.logger.log( "[*] About to fuzz the following PCIe devices.." )
        pci.print_pci_devices( pcie_devices )
        self.fuzz_overlap_pcie_device( pcie_devices )

        return ModuleResult.PASSED

