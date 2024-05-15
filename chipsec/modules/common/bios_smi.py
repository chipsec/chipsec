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
The module checks that SMI events configuration is locked down
- Global SMI Enable/SMI Lock
- TCO SMI Enable/TCO Lock

References:
    - `Setup for Failure: Defeating SecureBoot <http://syscan.org/index.php/download/get/6e597f6067493dd581eed737146f3afb/SyScan2014_CoreyKallenberg_SetupforFailureDefeatingSecureBoot.zip>`_ by Corey Kallenberg, Xeno Kovah, John Butterworth, Sam Cornwell
    - `Summary of Attacks Against BIOS and Secure Boot <https://www.defcon.org/images/defcon-22/dc-22-presentations/Bulygin-Bazhaniul-Furtak-Loucaides/DEFCON-22-Bulygin-Bazhaniul-Furtak-Loucaides-Summary-of-attacks-against-BIOS-UPDATED.pdf>`_

Usage:
    ``chipsec_main -m common.bios_smi``

Examples:
    >>> chipsec_main.py -m common.bios_smi

Registers used:
    - SmmBiosWriteProtection (Control)
    - TCOSMILock (Control)
    - SMILock (Control)
    - BiosWriteEnable (Control)

"""

from chipsec.module_common import BaseModule, MTAG_BIOS, MTAG_SMM
from chipsec.library.returncode import ModuleResult
from typing import List


TAGS = [MTAG_BIOS, MTAG_SMM]


class bios_smi(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)

    def is_supported(self) -> bool:
        if not self.cs.control.is_defined('SmmBiosWriteProtection') or \
           not self.cs.control.is_defined('TCOSMILock') or \
           not self.cs.control.is_defined('SMILock') or \
           not self.cs.control.is_defined('BiosWriteEnable'):
            self.logger.log_important('Required controls not defined for platform.  Skipping module.')
            return False
        return True

    def check_SMI_locks(self) -> int:

        #
        # Checking SMM_BWP first in BIOS control to warn if SMM write-protection of the BIOS is not enabled
        #
        smm_bwp = self.cs.control.get('SmmBiosWriteProtection')
        if 0 == smm_bwp:
            self.logger.log_bad("SMM BIOS region write protection has not been enabled (SMM_BWP is not used)\n")
        else:
            self.logger.log_good("SMM BIOS region write protection is enabled (SMM_BWP is used)\n")

        ok = True
        warn = False

        #
        # Checking if global SMI and TCO SMI are enabled (GBL_SMI_EN and TCO_EN bits in SMI_EN register)
        #
        if self.cs.control.is_defined('TCOSMIEnable') and self.cs.control.is_defined('GlobalSMIEnable'):
            self.logger.log("[*] Checking SMI enables..")
            tco_en = self.cs.control.get('TCOSMIEnable')
            gbl_smi_en = self.cs.control.get('GlobalSMIEnable')
            self.logger.log(f"    Global SMI enable: {gbl_smi_en:d}")
            self.logger.log(f"    TCO SMI enable   : {tco_en:d}")

            if gbl_smi_en != 1:
                ok = False
                self.logger.log_bad("Global SMI is not enabled")
            elif (tco_en != 1) and (smm_bwp != 1):
                warn = True
                self.logger.log_warning("TCO SMI is not enabled. BIOS may not be using it")
            elif (tco_en != 1) and (smm_bwp == 1):
                ok = False
                self.logger.log_bad("TCO SMI should be enabled if using SMM BIOS region protection")
            else:
                self.logger.log_good("All required SMI events are enabled")
            self.logger.log('')
            self.logger.log("[*] Checking SMI configuration locks..")

        #
        # Checking TCO_LOCK
        #
        tco_lock = self.cs.control.get('TCOSMILock')
        if tco_lock != 1:
            ok = False
            self.logger.log_bad("TCO SMI event configuration is not locked. TCO SMI events can be disabled")
        else:
            self.logger.log_good("TCO SMI configuration is locked (TCO SMI Lock)")

        #
        # Checking SMI_LOCK
        #
        smi_lock = self.cs.control.get('SMILock')
        if smi_lock != 1:
            ok = False
            self.logger.log_bad("SMI events global configuration is not locked. SMI events can be disabled")
        else:
            self.logger.log_good("SMI events global configuration is locked (SMI Lock)")
        self.logger.log('')

        if ok and not warn:
            res = ModuleResult.PASSED
            self.logger.log_passed("All required SMI sources seem to be enabled and locked")
        elif ok and warn:
            res = ModuleResult.WARNING
            self.result.setStatusBit(self.result.status.VERIFY)
            self.logger.log_warning("One or more warnings detected when checking SMI enable state")
        else:
            res = ModuleResult.FAILED
            self.result.setStatusBit(self.result.status.LOCKS)
            self.logger.log_failed("Not all required SMI sources are enabled and locked")
        
        return self.result.getReturnCode(res)

    def run(self, module_argv: List[str]) -> int:
        self.logger.start_test("SMI Events Configuration")
        self.res = self.check_SMI_locks()
        return self.res
