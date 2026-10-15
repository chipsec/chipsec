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
Checks for BIOS Interface Lock including Top Swap Mode

References:
    - `BIOS Boot Hijacking and VMware Vulnerabilities Digging <http://powerofcommunity.net/poc2007/sunbing.pdf>`_ by Bing Sun

Usage:
    ``chipsec_main -m common.bios_ts``

Examples:
    >>> chipsec_main.py -m common.bios_ts

Registers used:
    - BiosInterfaceLockDown (control)
    - TopSwapStatus (control)
    - TopSwap (control)

"""

from chipsec.library.exceptions import CSReadError
from chipsec.module_common import BaseModule, BIOS
from chipsec.library.returncode import ModuleResult
from typing import List

TAGS = [BIOS]
METADATA_TAGS = ['OPENSOURCE', 'IA', 'COMMON', 'BIOS_TS']


class bios_ts(BaseModule):
    def __init__(self):
        BaseModule.__init__(self)

    def is_supported(self) -> bool:
        if self.cs.control.is_defined('BiosInterfaceLockDown'):
            return True
        self.logger.log_important('BiosInterfaceLockDown control not defined for platform.  Skipping module.')
        return False

    def check_bios_iface_lock(self) -> int:
        bild = self.cs.control.get_list_by_name('BiosInterfaceLockDown')
        bild.read_and_print()
        lock_failed = bild.is_any_value(0)
        lock_unverified = False

        if self.cs.control.is_defined('TopSwapStatus'):
            top_swap_status = self.cs.control.get_list_by_name('TopSwapStatus')
            top_swap_status.read_and_print()

        if self.cs.control.is_defined('TopSwap'):
            top_swap = self.cs.control.get_list_by_name('TopSwap')
            top_swap.read_and_print()

        rtc_regs = self.cs.register.get_list_by_name('RC')
        rtc_bild_regs = rtc_regs.filter_with_field('BILD')
        if rtc_bild_regs:
            for reg in rtc_bild_regs:
                try:
                    reg.read()
                except Exception as err:
                    lock_unverified = True
                    self.logger.log_debug(
                        f'Unable to read RC.BILD register: {err}'
                    )
            invalid_values = lock_unverified or any(
                reg.value is None or reg.value == (1 << (reg.size * 8)) - 1
                for reg in rtc_bild_regs
            )
            if invalid_values:
                lock_unverified = True
                self.logger.log_warning(
                    'Unable to verify RTC BIOS Interface Lock-Down (RC.BILD)'
                )
                self.result.setStatusBit(self.result.status.VERIFY)
            elif not rtc_bild_regs.is_all_field_value(1, 'BILD'):
                lock_failed = True
                self.logger.log_bad(
                    'RTC BIOS Interface Lock-Down (RC.BILD) is not set'
                )

        if lock_failed:
            res = ModuleResult.FAILED
            self.result.setStatusBit(self.result.status.LOCKS)
            self.logger.log_failed('BIOS Interface is not locked (including Top Swap Mode)')
        elif lock_unverified:
            res = ModuleResult.WARNING
            self.logger.log_warning('BIOS Interface lock status could not be fully verified')
        else:
            res = ModuleResult.PASSED
            self.logger.log_passed('BIOS Interface is locked (including Top Swap Mode)')

        return self.result.getReturnCode(res)

    def run(self, module_argv: List[str]) -> int:
        self.logger.start_test('BIOS Interface Lock (including Top Swap Mode)')
        try:
            self.res = self.check_bios_iface_lock()
        except CSReadError as err:
            self.logger.log_warning(f'Unable to read register: {err}')
            self.result.setStatusBit(self.result.status.VERIFY)
            self.res = self.result.getReturnCode(ModuleResult.WARNING)
        return self.res
