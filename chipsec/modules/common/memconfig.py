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

from chipsec.module_common import BaseModule, HWCONFIG
from chipsec.library.returncode import ModuleResult
from typing import List

_MODULE_NAME = 'memconfig'

TAGS = [HWCONFIG]
METADATA_TAGS = ['OPENSOURCE', 'IA', 'COMMON', 'MEMCONFIG']


class memconfig(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)
        self.memmap_registers = {
            "8086.HOSTCTL.GGC": 'GGCLOCK',
            "8086.HOSTCTL.PAVPC": 'PAVPLCK',
            "8086.HOSTCTL.DPR": 'LOCK',
            "8086.HOSTCTL.MESEG_MASK": 'MELCK',
            "8086.HOSTCTL.REMAPBASE": 'LOCK',
            "8086.HOSTCTL.REMAPLIMIT": 'LOCK',
            "8086.HOSTCTL.TOM": 'LOCK',
            "8086.HOSTCTL.TOUUD": 'LOCK',
            "8086.HOSTCTL.BDSM": 'LOCK',
            "8086.HOSTCTL.BGSM": 'LOCK',
            "8086.HOSTCTL.TSEGMB": 'LOCK',
            "8086.HOSTCTL.TOLUD": 'LOCK'
        }
        self.cs.set_scope({
            "MSR_BIOS_DONE": "8086.MSR",
        })

    def is_supported(self) -> bool:
        if self.cs.is_intel():
            if self.cs.is_core():
                return True
            self.logger.log_important("Not a 'Core' (Desktop) platform.  Skipping test.")
        else:
            self.logger.log_important('Not an Intel platform.  Skipping test.')
        return False

    def check_memmap_locks(self) -> int:

        ia_untrusted = None
        if self.cs.register.has_field('MSR_BIOS_DONE', 'IA_UNTRUSTED'):
            bios_done = self.cs.register.get_list_by_name('MSR_BIOS_DONE')
            ia_untrusted = bios_done.read_field('IA_UNTRUSTED')

        regs = sorted(self.memmap_registers.keys())
        all_locked = True

        self.logger.log('[*]')
        if ia_untrusted is not None:
            self.logger.log('[*] Checking legacy register lock state:')
        else:
            self.logger.log('[*] Checking register lock state:')
        for reg in regs:
            if not self.cs.register.has_field(reg, self.memmap_registers[reg]):
                self.logger.log_important(f'{reg}.{self.memmap_registers[reg]} not defined for platform.  Skipping register.')
                continue
            reglist = self.cs.register.get_list_by_name(reg)
            if not reglist:
                all_locked = False
                self.logger.log_important(f'{reg} register not found. Unable to verify lock state.')
                continue
            description = reglist[0].desc
            reglist.read_and_verbose_print()
            if reglist.is_all_field_value(1, self.memmap_registers[reg]):
                self.logger.log_good(f'{reg:20} - LOCKED   - {description}')
            else:
                all_locked = False
                self.logger.log_bad(f'{reg:20} - UNLOCKED - {description}')

        if ia_untrusted is not None:
            self.logger.log('[*]')
            self.logger.log('[*] Checking if IA Untrusted mode is used to lock registers')
            if all(data == 1 for data in ia_untrusted):
                self.logger.log_good('IA Untrusted mode set')
                all_locked = True
            else:
                self.logger.log_bad('IA Untrusted mode not set')

        self.logger.log('[*]')
        if all_locked:
            res = ModuleResult.PASSED
            self.logger.log_passed('All memory map registers seem to be locked down')
        else:
            res = ModuleResult.FAILED
            self.logger.log_failed('Not all memory map registers are locked down')
            self.result.setStatusBit(self.result.status.LOCKS)

        return res

    def run(self, module_argv: List[str]) -> int:
        self.logger.start_test('Host Bridge Memory Map Locks')
        self.res = self.check_memmap_locks()
        return self.result.getReturnCode(self.res)
