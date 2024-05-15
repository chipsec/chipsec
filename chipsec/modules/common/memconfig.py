# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2020, Intel Corporation
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
This module verifies memory map secure configuration,
that memory map registers are correctly configured and locked down.

Usage:
  ``chipsec_main -m common.memconfig``

Example:
    >>> chipsec_main.py -m common.memconfig

.. note::
    - This module will only run on Core (client) platforms.
"""

from chipsec.module_common import BaseModule, MTAG_HWCONFIG
from chipsec.library.returncode import ModuleResult
from typing import List

_MODULE_NAME = 'memconfig'

TAGS = [MTAG_HWCONFIG]


class memconfig(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)
        self.memmap_registers = {
            "PCI0.0.0_GGC": 'GGCLOCK',
            "PCI0.0.0_PAVPC": 'PAVPLCK',
            "PCI0.0.0_DPR": 'LOCK',
            "PCI0.0.0_MESEG_MASK": 'MELCK',
            "PCI0.0.0_REMAPBASE": 'LOCK',
            "PCI0.0.0_REMAPLIMIT": 'LOCK',
            "PCI0.0.0_TOM": 'LOCK',
            "PCI0.0.0_TOUUD": 'LOCK',
            "PCI0.0.0_BDSM": 'LOCK',
            "PCI0.0.0_BGSM": 'LOCK',
            "PCI0.0.0_TSEGMB": 'LOCK',
            "PCI0.0.0_TOLUD": 'LOCK'
        }

    def is_supported(self) -> bool:
        if self.cs.is_intel():
            if self.cs.is_core():
                return True
            self.logger.log_important("Not a 'Core' (Desktop) platform.  Skipping test.")
        else:
            self.logger.log_important("Not an Intel platform.  Skipping test.")
        return False

    def check_memmap_locks(self) -> int:

        # Determine if IA_UNTRUSTED can be used to lock the system.
        ia_untrusted = None
        if self.cs.register.has_field('MSR_BIOS_DONE', 'IA_UNTRUSTED'):
            ia_untrusted = self.cs.register.read_field('MSR_BIOS_DONE', 'IA_UNTRUSTED')

        regs = sorted(self.memmap_registers.keys())
        all_locked = True

        self.logger.log('[*]')
        if ia_untrusted is not None:
            self.logger.log('[*] Checking legacy register lock state:')
        else:
            self.logger.log('[*] Checking register lock state:')
        for reg in regs:
            reg_field = self.memmap_registers[reg]
            if not self.cs.register.has_field(reg, reg_field):
                self.logger.log_important(f'Skipping Validation: Register {reg} or field {reg_field} was not defined for this platform.')
                continue
            reg_def = self.cs.register.get_def(reg)
            reg_value = self.cs.register.read(reg)
            reg_desc = reg_def['desc']
            locked = self.cs.register.get_field(reg, reg_value, reg_field)
            if locked == 1:
                self.logger.log_good(f"{reg:20} = 0x{reg_value:016X} - LOCKED   - {reg_desc}")
            else:
                all_locked = False
                self.logger.log_bad(f"{reg:20} = 0x{reg_value:016X} - UNLOCKED - {reg_desc}")

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
            self.logger.log_passed("All memory map registers seem to be locked down")
        else:
            res = ModuleResult.FAILED
            self.logger.log_failed("Not all memory map registers are locked down")
            self.result.setStatusBit(self.result.status.LOCKS)

        return res

    def run(self, module_argv: List[str]) -> int:
        self.logger.start_test("Host Bridge Memory Map Locks")
        self.res = self.check_memmap_locks()
        return self.result.getReturnCode(self.res)
