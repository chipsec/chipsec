# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2021, Intel Corporation
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
Check Memory Remapping Configuration

Reference:
    - `Preventing & Detecting Xen Hypervisor Subversions <http://www.invisiblethingslab.com/resources/bh08/part2-full.pdf>`_ by Joanna Rutkowska & Rafal Wojtczuk

Usage:
  ``chipsec_main -m common.remap``

Example:
    >>> chipsec_main.py -m common.remap

Registers used:
    - 8086.HOSTCTL.MCHBAR*.REMAPBASE
    - 8086.HOSTCTL.MCHBAR*.REMAPLIMIT
    - 8086.HOSTCTL.TOUUD
    - 8086.HOSTCTL.TOLUD
    - 8086.HOSTCTL.TSEGMB

.. note::
    - This module will only run on Core platforms.

"""

from typing import Tuple
from chipsec.library.register import ObjList
from chipsec.module_common import BaseModule, HWCONFIG, SMM
from chipsec.library.returncode import ModuleResult
from chipsec.library.defines import BIT32, ALIGNED_1MB

_MODULE_NAME = 'remap'

TAGS = [SMM, HWCONFIG]
METADATA_TAGS = ['OPENSOURCE', 'IA', 'COMMON', 'REMAP']

_REMAP_ADDR_MASK = 0x7FFFF00000
_TOLUD_MASK = 0xFFFFF000


class remap(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)
        self.cs.set_scope({
            None: "8086.HOSTCTL*",
            'MSR_BIOS_DONE': "8086.MSR",
            'IA_UNTRUSTED': "8086.MSR",
            'IBECC_ACTIVATE': "8086.HOSTCTL*",
            'REMAPBASE': "8086.HOSTCTL.MCHBAR*",
            'REMAPLIMIT': "8086.HOSTCTL.MCHBAR*"
        })

    def is_supported(self) -> bool:
        if self.cs.is_core():
            rbase_exist = self.cs.register.is_defined('REMAPBASE')
            rlimit_exist = self.cs.register.is_defined('REMAPLIMIT')
            touud_exist = self.cs.register.is_defined('TOUUD')
            tolud_exist = self.cs.register.is_defined('TOLUD')
            tseg_exist = self.cs.register.is_defined('TSEGMB')
            if rbase_exist and rlimit_exist and touud_exist and tolud_exist and tseg_exist:
                return True
            self.logger.log_important('Required register definitions not defined for platform.  Skipping module.')
        else:
            self.logger.log_important('Not a Core (client) platform.  Skipping module.')

        return False

    def is_ibecc_enabled(self) -> bool:
        if self.cs.register.is_defined('IBECC_ACTIVATE'):
            ibecc = self.cs.register.get_list_by_name('IBECC_ACTIVATE')
            ibecc.read() # TODO: Stopped here.
            if ibecc.is_all_field_value(1, 'IBECC_EN'):
                return True
            else:
                self.logger.log_verbose('IBECC is not enabled!')
        else:
            self.logger.log_verbose('IBECC is not defined!')
        return False

    def check_remap_config(self) -> int:
        is_warning = False
        self.logger.log('[*] Registers:')
        self.logger.log(f'[*]   4GB                : 0x{BIT32:016X}')
        remapbase_reg = self.cs.register.get_list_by_name('REMAPBASE')
        remaplimit_reg = self.cs.register.get_list_by_name('REMAPLIMIT')
        touud_reg = self.cs.register.get_list_by_name('TOUUD')
        tolud_reg = self.cs.register.get_list_by_name('TOLUD')
        tsegmb_reg = self.cs.register.get_list_by_name('TSEGMB')
        remapbase_reg.read_and_print()
        remaplimit_reg.read_and_print()
        touud_reg.read_and_print()
        tolud_reg.read_and_print()
        tsegmb_reg.read_and_print()

        if self.cs.register.has_field('MSR_BIOS_DONE', 'IA_UNTRUSTED'):
            ia_untrusted_reg = self.cs.register.get_list_by_name('MSR_BIOS_DONE')

        touud = touud_reg.get_field('TOUUD', preserve_field_position=True)[0]
        tolud = tolud_reg.get_field('TOLUD', preserve_field_position=True)[0]
        self.logger.log('')

        remap_ok = True

        self.logger.log('[*] Checking memory remap configuration..')

        is_warning, remap_ok = self.check_remap_base_and_limit(remapbase_reg, remaplimit_reg, touud, is_warning, remap_ok)
        ok = (0 == tolud & ALIGNED_1MB) and \
             (0 == touud & ALIGNED_1MB)
        remap_ok = remap_ok and ok
        if ok:
            self.logger.log_good('  All addresses are 1MB aligned')
        else:
            self.logger.log_bad('  Not all addresses are 1MB aligned')

        self.logger.log('[*] Checking if memory remap configuration is locked..')
        
        is_ia_untrusted_set = (ia_untrusted_reg.is_all_field_value(1, 'IA_UNTRUSTED'))
        remap_ok = remap_ok and is_ia_untrusted_set
        if is_ia_untrusted_set:
            self.logger.log_good('  IA_Untrusted is set')
        else:
            self.logger.log_bad('  IA_Untrusted is not set')

        ok = touud_reg.is_all_field_value(1, 'LOCK') or is_ia_untrusted_set
        remap_ok = remap_ok and ok
        if ok:
            self.logger.log_good('  TOUUD is locked')
        else:
            self.logger.log_bad('  TOUUD is not locked')

        ok = tolud_reg.is_all_field_value(1, 'LOCK') or is_ia_untrusted_set
        remap_ok = remap_ok and ok
        if ok:
            self.logger.log_good('  TOLUD is locked')
        else:
            self.logger.log_bad('  TOLUD is not locked')

        if remapbase_reg.all_has_field('LOCK') and remaplimit_reg.all_has_field('LOCK'):
            ok = (remapbase_reg.is_all_field_value(1, 'LOCK')) and (remaplimit_reg.is_all_field_value(1,'LOCK')) or is_ia_untrusted_set
            remap_ok = remap_ok and ok
            if ok:
                self.logger.log_good('  REMAPBASE and REMAPLIMIT are locked')
            else:
                self.logger.log_bad('  REMAPBASE and REMAPLIMIT are not locked')

        if remap_ok:
            if is_warning:
                self.logger.log_warning('Most Memory Remap registers are configured correctly and locked')
                self.logger.log('[!] Manual verification of REMAP BASE and LIMIT register values may be needed.')
                res = ModuleResult.WARNING
                self.result.setStatusBit(self.result.status.VERIFY)
            else:
                res = ModuleResult.PASSED
                self.result.setStatusBit(self.result.status.SUCCESS)
                self.logger.log_passed('Memory Remap is configured correctly and locked')
        else:
            res = ModuleResult.FAILED
            self.result.setStatusBit(self.result.status.CONFIGURATION)
            self.result.setStatusBit(self.result.status.LOCKS)
            self.logger.log_failed('Memory Remap is not properly configured/locked. Remap attack may be possible')

        return self.result.getReturnCode(res)

    def check_remap_base_and_limit(self, remapbase_regs: list, remaplimit_regs: list, touud: int, is_warning: bool, remap_ok: bool) -> Tuple[bool, bool]:
        bars = set([reg.bar for reg in remapbase_regs])
        
        for bar in bars:
            remapbase_reg = [reg for reg in remapbase_regs if reg.bar == bar]
            remaplimit_reg = [reg for reg in remaplimit_regs if reg.bar == bar]
        
            if len(remapbase_reg) == len(remaplimit_reg) == 1:
                remapbase_reg = remapbase_reg[0]
                remaplimit_reg = remaplimit_reg[0]
            
            remapbase = remapbase_reg.get_field('REMAPBASE')
            remaplimit = remaplimit_reg.get_field('REMAPLMT')
            
            if remapbase == remaplimit:
                self.logger.log('[!]   Memory Remap status is Unknown')
                is_warning = True
            elif remapbase > remaplimit:
                self.logger.log('[*]   Memory Remap is disabled')
            else:
                self.logger.log('[*]   Memory Remap is enabled')
                remaplimit_addr = (remaplimit | 0xFFFFF)
                if self.is_ibecc_enabled():
                    ok = (remaplimit_addr > touud) and (remapbase < touud)
                else:
                    ok = ((remaplimit_addr + 1) == touud)
                remap_ok = remap_ok and ok
                if ok:
                    self.logger.log_good('  Remap window configuration is correct: REMAPBASE <= REMAPLIMIT < TOUUD')
                else:
                    self.logger.log_bad('  Remap window configuration is not correct')
        return is_warning, remap_ok

    def run(self, _) -> int:
        self.logger.start_test('Memory Remapping Configuration')

        self.res = self.check_remap_config()
        return self.res
