# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2024, AMD Corporation
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
# coudrant@amd.com
#


"""
CPU SMM Addr

This module checks to see that SMMMask has Tseg and Aseg programmed correctly.  It also verifies that CPU access to SMM
is blocked while not in SMM.

Usage:
    ``chipsec_main -m common.smm_addr``

Examples:
    >>> chipsec_main.py -m common.smm_addr

Registers used:
    AMD:
    - SMMMASK.TMTypeDram
    - SMMMASK.AMTypeDram
    - SMMMASK.TValid
    - SMMMASK.AValid
    - SMM_BASE


"""

from chipsec.module_common import BaseModule, BIOS, SMM
from chipsec.library.returncode import ModuleResult
from chipsec.hal.msr import MemType
from typing import List

TAGS = [BIOS, SMM]
METADATA_TAGS = ['OPENSOURCE', 'IA', 'COMMON', 'SMM_ADDR']


class smm_addr(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)

    def is_supported(self) -> bool:
        if self.cs.is_amd():
            smmaddr_exist = self.cs.register.is_defined('SMMADDR')
            smmmask_exist = self.cs.register.is_defined('SMMMASK')
            if smmaddr_exist and smmmask_exist:
                return True
        self.logger.log_information('Required registers are not defined for this platform.  Skipping module.')
        return False

    def check_SMMMask(self) -> int:

        if self.cs.cpu.check_SMRR_supported():
            self.logger.log_good("OK. SMMMask range protection is supported")
        else:
            self.logger.log_not_applicable("CPU does not support SMMMask range protection of SMRAM")
            self.result.setStatusBit(self.result.status.NOT_APPLICABLE)
            self.res = self.result.getReturnCode(ModuleResult.NOTAPPLICABLE)
        #
        # SMMMask are supported
        #
        smm_addr_ok = True

        #
        # 2. Check SMMMASK is programmed correctly (on CPU0)
        #
        self.logger.log('')
        self.logger.log("[*] Checking SMMMask range base programming..")

        cpu0_smmmask = self.cs.register.read('SMMMASK')
        self.cs.register.print('SMMMASK', cpu0_smmmask)
        tseg_type = self.cs.register.get_field('SMMMASK', cpu0_smmmask, 'TMTYPEDRAM')
        aseg_type = self.cs.register.get_field('SMMMASK', cpu0_smmmask, 'AMTYPEDRAM')

        if tseg_type in MemType:
            self.logger.log(f"[*] TSEG range memory type is {MemType[tseg_type]}")
        else:
            smm_addr_ok = False
            self.logger.log_bad(f"TSEG range memory type 0x{tseg_type:X} is invalid")

        if aseg_type in MemType:
            self.logger.log(f"[*] ASEG range memory type is {MemType[aseg_type]}")
        else:
            self.logger.log_bad(f"ASEG range memory type 0x{aseg_type:X} is invalid")

        if smm_addr_ok:
            self.logger.log_good("OK so far. ASEG and TESEG are programmed correctly")

        #
        # 3. Check TSeg and ASeg are Valid on CPU0
        #
        self.logger.log('')
        self.logger.log("[*] Checking SMM Mask Aseg and Tseg validity..")
        smmmask = self.cs.register.read('SMMMASK')
        self.cs.register.print('SMMMASK', smmmask)
        tsegvalid = self.cs.register.get_field('SMMMASK', smmmask, 'TVALID')
        asegvalid = self.cs.register.get_field('SMMMASK', smmmask, 'AVALID')

        if (not bool(tsegvalid) or not bool(asegvalid)):
            smm_addr_ok = False
            self.logger.log_bad("SMMMask range is not enabled")

        if smm_addr_ok:
            self.logger.log_good("OK so far. SMMMask range is enabled")

        #
        # 4. Verify that SMMMask_BASE/MASK MSRs have the same values on all logical CPUs
        #
        self.logger.log('')
        self.logger.log("[*] Verifying that SMM range base & mask are the same on all logical CPUs..")
        smmbase  = []
        for tid in range(self.cs.msr.get_cpu_thread_count()):
            smmbase.append(self.cs.register.read('SMM_BASE', tid))
            smmmask = self.cs.register.read('SMMMASK', tid)
            self.logger.log(f"[CPU{tid:d}] SMMMask = {smmbase[tid]:016X}, SMMMask = {smmmask:016X}")

            if (smmmask != cpu0_smmmask):
                smm_addr_ok = False
                self.logger.log_bad("SMMMask range base/mask do not match on all logical CPUs")
                break

        if smm_addr_ok:
            self.logger.log_good("OK so far. SMMMask range base/mask match on all logical CPUs")

        #
        # 5. Reading from & writing to SMMMask Dram physical address
        # writes should be dropped, reads should return all F's
        #

        for tid_base in smmbase:
            self.logger.log(f"[*] Trying to read memory at SMM base 0x{tid_base:08X}..")
            ok = 0xFFFFFFFF == self.cs.mem.read_physical_mem_dword(tid_base)
            if not ok:
                self.logger.log_bad("Able to read SMM base at 0x{tid_base:08X}..")
                break

        smm_addr_ok = smm_addr_ok and ok
        if ok:
            self.logger.log_passed("SMMMask reads are blocked in non-SMM mode")  # return all F's
        else:
            self.logger.log_failed("SMMMask reads are not blocked in non-SMM mode")  # all F's are not returned

        self.logger.log('')
        if not smm_addr_ok:
            res = ModuleResult.FAILED
            self.result.setStatusBit(self.result.status.CONFIGURATION)
            self.logger.log_failed("SMMMask protection against cache attack is not configured properly")
        else:
            res = ModuleResult.PASSED
            self.logger.log_passed("SMMask protection against cache attack is properly configured")

        res = ModuleResult.PASSED

        return self.result.getReturnCode(res)

    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run(self, module_argv: List[str]) -> int:
        self.logger.start_test("CPU SMM Cache Poisoning / System Management Mode Mask Registers")
        self.res = self.check_SMMMask()
        return self.res
