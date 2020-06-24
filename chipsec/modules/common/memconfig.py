#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2020, Intel Corporation
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

from chipsec.module_common import BaseModule, ModuleResult, MTAG_HWCONFIG

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
        if self.cs.is_core():
            return True
        self.res = ModuleResult.NOTAPPLICABLE
        return False

    def check_memmap_locks(self):
        self.logger.start_test( "Host Bridge Memory Map Locks" )

        # Determine if IA_UNTRUSTED can be used to lock the system.
        ia_untrusted = None
        if self.cs.is_register_defined('MSR_BIOS_DONE') and self.cs.register_has_field('MSR_BIOS_DONE', 'IA_UNTRUSTED'):
            ia_untrusted = self.cs.read_register_field('MSR_BIOS_DONE', 'IA_UNTRUSTED')

        regs = sorted(memmap_registers.keys())
        all_locked = True

        self.logger.log('[*]')
        if ia_untrusted is not None:
            self.logger.log('[*] Checking legacy register lock state:')
        else:
            self.logger.log('[*] Checking register lock state:')
        for r in regs:
            if not self.cs.is_register_defined(r) or not self.cs.register_has_field(r, memmap_registers[r]):
                self.logger.log_unknown('Skipping Validation: Register {} or field {} was not defined for this platform.'.format(r, memmap_registers[r]))
                continue
            d = self.cs.get_register_def( r )
            v = self.cs.read_register( r )
            locked = self.cs.get_register_field( r, v, memmap_registers[r] )
            if locked == 1:
                self.logger.log_good( "{:20} = 0x{:16X} - LOCKED   - {}".format(r, v, d['desc']) )
            else:
                all_locked = False
                self.logger.log_bad(  "{:20} = 0x{:16X} - UNLOCKED - {}".format(r, v, d['desc']) )

        if ia_untrusted is not None:
            self.logger.log('[*]')
            self.logger.log('[*] Checking if IA Untrusted mode is used to lock registers')
            if ia_untrusted == 1:
                self.logger.log_good('IA Untrusted mode set')
                all_locked = True
            else:
                self.logger.log_bad('IA Untrusted mode not set')

        self.logger.log('[*]')
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
        self.res = self.check_memmap_locks()
        return self.res
