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
This module verifies memory map secure configuration,
i.e. that memory map registers are correctly configured and locked down.
"""

from chipsec.module_common import *

_MODULE_NAME = 'memconfig'

TAGS = [MTAG_HWCONFIG]


memmap_registers = {
  "PCI0.0.0_GGC"        : 'GGCLOCK',
  "PCI0.0.0_PAVPC"      : 'PAVPLCK',
  "PCI0.0.0_DPR"        : 'LOCK',
  "PCI0.0.0_MESEG_MASK" : 'MELCK',
  "PCI0.0.0_REMAPBASE"  : 'LOCK',
  "PCI0.0.0_REMAPLIMIT" : 'LOCK',
  "PCI0.0.0_TOM"        : 'LOCK',
  "PCI0.0.0_TOUUD"      : 'LOCK',
  "PCI0.0.0_BDSM"       : 'LOCK',
  "PCI0.0.0_BGSM"       : 'LOCK',
  "PCI0.0.0_TSEGMB"     : 'LOCK',
  "PCI0.0.0_TOLUD"      : 'LOCK'
}

memmap_registers_dev0bars = [
  "PCI0.0.0_PXPEPBAR",
  "PCI0.0.0_MCHBAR",
  "PCI0.0.0_PCIEXBAR",
  "PCI0.0.0_DMIBAR",
]


class memconfig(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)

    def is_supported(self):
        return self.cs.is_core()

    def check_memmap_locks(self):
        self.logger.start_test( "Host Bridge Memory Map Locks" )

        regs = memmap_registers.keys()
        regs.sort()
        all_locked = True

        for r in regs:
            d = chipsec.chipset.get_register_def( self.cs, r )
            v = chipsec.chipset.read_register( self.cs, r )
            locked = chipsec.chipset.get_register_field( self.cs, r, v, memmap_registers[r] )
            if locked == 1:
                self.logger.log_good( "%-20s = 0x%016X - LOCKED   - %s" % (r, v, d['desc']) )
            else:
                all_locked = False
                self.logger.log_bad(  "%-20s = 0x%016X - UNLOCKED - %s" % (r, v, d['desc']) )

        if all_locked:
            res = ModuleResult.PASSED
            self.logger.log_passed_check( "All memory map registers seem to be locked down" )
        else:
            res = ModuleResult.FAILED
            self.logger.log_failed_check( "Not all memory map registers are locked down" )

        return res

    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run( self, module_argv ):
        return self.check_memmap_locks()
