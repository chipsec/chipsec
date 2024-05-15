# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2022, Intel Corporation
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
SMM TSEG Range Configuration Checks

This module examines the configuration and locking of SMRAM range configuration protecting from DMA attacks.
If it fails, then DMA protection may not be securely configured to protect SMRAM.

Just like SMRAM needs to be protected from software executing on the CPU,
it also needs to be protected from devices that have direct access to DRAM (DMA).
Protection from DMA is configured through proper programming of SMRAM memory range.
If BIOS does not correctly configure and lock the configuration,
then malware could reprogram configuration and open SMRAM area to DMA access,
allowing manipulation of memory that should have been protected.

References:
    - `System Management Mode Design and Security Issues <http://www.ssi.gouv.fr/uploads/IMG/pdf/IT_Defense_2010_final.pdf>`_
    - `Summary of Attack against BIOS and Secure Boot <https://www.defcon.org/images/defcon-22/dc-22-presentations/Bulygin-Bazhaniul-Furtak-Loucaides/DEFCON-22-Bulygin-Bazhaniul-Furtak-Loucaides-Summary-of-attacks-against-BIOS-UPDATED.pdf>`_

Usage:
    ``chipsec_main -m smm_dma``

Examples:
    >>> chipsec_main.py -m smm_dma

Registers used:
    - TSEGBaseLock (control)
    - TSEGLimitLock (control)
    - MSR_BIOS_DONE.IA_UNTRUSTED
    - PCI0.0.0_TSEGMB.TSEGMB
    - PCI0.0.0_BGSM.BGSM
    - IA32_SMRR_PHYSBASE.PhysBase
    - IA32_SMRR_PHYSMASK.PhysMask

Supported Platforms:
    - Core (client)

"""

from chipsec.module_common import BaseModule, MTAG_SMM, MTAG_HWCONFIG
from chipsec.library.returncode import ModuleResult
from typing import List

_MODULE_NAME = 'smm_dma'

TAGS = [MTAG_SMM, MTAG_HWCONFIG]


class smm_dma(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)

    def is_supported(self) -> bool:
        if self.cs.is_atom():
            self.logger.log_important('Module not supported on Atom platforms.  Skipping module.')
            return False
        elif self.cs.is_server():
            self.logger.log_important('Xeon (server) platform detected.  Skipping module.')
            return False
        elif not self.cs.control.is_defined('TSEGBaseLock') or not self.cs.control.is_defined('TSEGLimitLock'):
            self.logger.log_important('TSEGBaseLock and/or TSEGLimitLock control(s) not defined for platform.  Skipping module.')
            return False
        else:
            return True

    def check_tseg_locks(self) -> int:
        tseg_base_lock = self.cs.control.get('TSEGBaseLock')
        tseg_limit_lock = self.cs.control.get('TSEGLimitLock')
        ia_untrusted = 0
        if self.cs.register.has_field('MSR_BIOS_DONE', 'IA_UNTRUSTED'):
            ia_untrusted = self.cs.register.read_field('MSR_BIOS_DONE', 'IA_UNTRUSTED')

        if (tseg_base_lock and tseg_limit_lock) or (0 != ia_untrusted):
            self.logger.log_good("TSEG range is locked")
            return ModuleResult.PASSED
        else:
            self.logger.log_bad("TSEG range is not locked")
            self.result.setStatusBit(self.result.status.LOCKS)
            return ModuleResult.FAILED

    def check_tseg_config(self) -> int:
        res = ModuleResult.FAILED
        (tseg_base, tseg_limit, tseg_size) = self.cs.cpu.get_TSEG()
        self.logger.log(f"[*] TSEG      : 0x{tseg_base:016X} - 0x{tseg_limit:016X} (size = 0x{tseg_size:08X})")
        if self.cs.cpu.check_SMRR_supported():
            (smram_base, smram_limit, smram_size) = self.cs.cpu.get_SMRR_SMRAM()
            self.logger.log(f"[*] SMRR range: 0x{smram_base:016X} - 0x{smram_limit:016X} (size = 0x{smram_size:08X})\n")
        else:
            smram_base = 0
            smram_limit = 0
            self.logger.log("[*] SMRR is not supported\n")

        self.logger.log("[*] Checking TSEG range configuration..")
        if (0 == smram_base) and (0 == smram_limit):
            res = ModuleResult.WARNING
            self.logger.log_warning("TSEG is properly configured but can't determine if it covers entire SMRAM")
            self.result.setStatusBit(self.result.status.VERIFY)
        else:
            if (tseg_base <= smram_base) and (smram_limit <= tseg_limit):
                self.logger.log_good("TSEG range covers entire SMRAM")
                if self.check_tseg_locks() == ModuleResult.PASSED:
                    res = ModuleResult.PASSED
                    self.logger.log_passed("TSEG is properly configured. SMRAM is protected from DMA attacks")
                else:
                    self.logger.log_failed("TSEG is properly configured, but the configuration is not locked.")
                    self.result.setStatusBit(self.result.status.LOCKS)
            else:
                self.logger.log_bad("TSEG range doesn't cover entire SMRAM")
                self.logger.log_failed("TSEG is not properly configured. Portions of SMRAM may be vulnerable to DMA attacks")
                self.result.setStatusBit(self.result.status.POTENTIALLY_VULNERABLE)

        return self.result.getReturnCode(res)

    def run(self, module_argv: List[str]) -> int:
        self.logger.start_test("SMM TSEG Range Configuration Check")
        self.res = self.check_tseg_config()
        return self.res
