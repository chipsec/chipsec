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

from chipsec.module_common import BaseModule, ModuleResult, MTAG_BIOS
from typing import List
TAGS = [MTAG_BIOS]


class bios_ts(BaseModule):
    def __init__(self):
        BaseModule.__init__(self)
        self.rc_res = ModuleResult(0x98e2db0, 'https://chipsec.github.io/modules/chipsec.modules.common.bios_ts.html')

    def is_supported(self) -> bool:
        if self.cs.is_control_defined('BiosInterfaceLockDown'):
            return True
        self.logger.log_important('BiosInterfaceLockDown control not defined for platform.  Skipping module.')
        self.rc_res.setStatusBit(self.rc_res.status.NOT_APPLICABLE)
        self.res = self.rc_res.getReturnCode(ModuleResult.NOTAPPLICABLE)
        return False

    def check_bios_iface_lock(self) -> int:
        bild = self.cs.get_control('BiosInterfaceLockDown')
        self.logger.log(f"[*] BiosInterfaceLockDown (BILD) control = {bild:d}")

        if self.cs.is_control_defined('TopSwapStatus'):
            if self.cs.is_control_all_ffs('TopSwapStatus'):
                self.logger.log("[*] BIOS Top Swap mode: can't determine status.")
                self.logger.log_verbose('TopSwapStatus read returned all 0xFs.')
            else:
                tss = self.cs.get_control('TopSwapStatus')
                self.logger.log(f"[*] BIOS Top Swap mode is {'enabled' if (1 == tss) else 'disabled'} (TSS = {tss:d})")

        if self.cs.is_control_defined('TopSwap'):
            if self.cs.is_control_all_ffs('TopSwap'):
                self.logger.log("[*] RTC Top Swap control (TS): can't determine status.")
                self.logger.log_verbose('TopSwap read returned all 0xFs.')
            else:
                ts = self.cs.get_control('TopSwap')
                self.logger.log(f"[*] RTC TopSwap control (TS) = {ts:x}")

        if bild == 0:
            res = ModuleResult.FAILED
            self.rc_res.setStatusBit(self.rc_res.status.LOCKS)
            self.logger.log_failed("BIOS Interface is not locked (including Top Swap Mode)")
        else:
            res = ModuleResult.PASSED
            self.logger.log_passed("BIOS Interface is locked (including Top Swap Mode)")
        
        return self.rc_res.getReturnCode(res)

    def run(self, module_argv: List[str]) -> int:
        self.logger.start_test("BIOS Interface Lock (including Top Swap Mode)")
        self.res = self.check_bios_iface_lock()
        return self.res
