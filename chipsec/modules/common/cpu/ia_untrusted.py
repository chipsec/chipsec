# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2018-2021, Intel Corporation
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
IA Untrusted checks

Usage:
    ``chipsec_main -m common.cpu.ia_untrusted``

Examples:
    >>> chipsec_main.py -m common.cpu.ia_untrusted

Registers used:
    - MSR_BIOS_DONE.IA_UNTRUSTED
    - MSR_BIOS_DONE.SoC_BIOS_DONE

"""

from chipsec.module_common import BaseModule, HWCONFIG
from chipsec.library.returncode import ModuleResult
from typing import List

TAGS = [HWCONFIG]
METADATA_TAGS = ['OPENSOURCE', 'IA', 'COMMON', 'CPU', 'IA_UNTRUSTED']


class ia_untrusted(BaseModule):
    def __init__(self):
        BaseModule.__init__(self)
        self.result.url = 'https://chipsec.github.io/modules/chipsec.modules.common.cpu.ia_untrusted.html'
        self.cs.set_scope({
            "MSR_BIOS_DONE": "8086.MSR",
        })

    def is_supported(self) -> bool:
        if self.cs.register.has_field('MSR_BIOS_DONE', 'IA_UNTRUSTED'):
            return True
        self.logger.log_important('MSR_BIOS_DONE.IA_UNTRUSTED is not defined for platform.  Skipping checks.')
        return False

    def check_untrusted(self) -> int:
        self.logger.log('[*] Check that untrusted mode has been set.')
        res = ModuleResult.PASSED
        msr_bios_done = self.cs.register.get_list_by_name('MSR_BIOS_DONE')
        if msr_bios_done:
            msr_bios_done.read()
            if self.cs.register.has_field('MSR_BIOS_DONE', 'SoC_BIOS_DONE'):
                soc = msr_bios_done[0].get_field('SoC_BIOS_DONE')
                if soc == 0:
                    res = ModuleResult.FAILED
                    self.result.setStatusBit(self.result.status.CONFIGURATION)
                    self.logger.log_bad('SoC_BIOS_DONE not set.')
                else:
                    self.logger.log_good('SoC_BIOS_DONE set.')
                self.logger.log('')

            for bd in msr_bios_done:
                self.logger.log_verbose(bd)
                ia_untrusted = bd.get_field('IA_UNTRUSTED')
                if ia_untrusted == 0:
                    res = ModuleResult.FAILED
                    self.result.setStatusBit(self.result.status.CONFIGURATION)
                    self.logger.log_bad(f'IA_UNTRUSTED not set on thread {bd.get_instance()}.')
                else:
                    self.logger.log_good(f'IA_UNTRUSTED set on thread {bd.get_instance()}.')
        return res

    def run(self, module_argv: List[str]) -> int:
        self.logger.start_test('IA_UNTRUSTED Check')
        self.res = self.check_untrusted()
        self.logger.log('')
        if self.res == ModuleResult.PASSED:
            self.logger.log_passed('IA_UNTRUSTED set on all threads')
        elif self.res == ModuleResult.FAILED:
            self.logger.log_failed('IA_UNTRUSTED not set on all threads')
        
        return self.result.getReturnCode(self.res)
