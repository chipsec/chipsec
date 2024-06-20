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
#
# Authors:
#  Yuriy Bulygin
#  Erik Bjorge
#


"""
SPI Flash Region Access Control

Checks SPI Flash Region Access Permissions programmed in the Flash Descriptor

Usage:
    ``chipsec_main -m common.spi_access``

Examples:
    >>> chipsec_main.py -m common.spi_access

Registers used:
    - HSFS.FDV
    - FRAP.BRWA

.. important::
    - Some platforms may use alternate means of protecting these regions.
      Consider this when assessing results.

"""

from chipsec.library.exceptions import CSReadError
from chipsec.module_common import BaseModule, MTAG_BIOS
from chipsec.library.returncode import ModuleResult
from chipsec.hal.spi import SPI, GBE, PLATFORM_DATA, ME, FLASH_DESCRIPTOR
from typing import List

TAGS = [MTAG_BIOS]


class spi_access(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)

    def is_supported(self) -> bool:
        if self.cs.register.has_field('HSFS', 'FDV') and self.cs.register.has_field('FRAP', 'BRWA'):
            return True
        self.logger.log_important('HSFS.FDV or FRAP.BRWA registers not defined for platform.  Skipping module.')
        return False

    ##
    # Displays the SPI Regions Access Permissions
    def check_flash_access_permissions(self) -> int:

        res = ModuleResult.PASSED
        fdv = self.cs.register.read_field('HSFS', 'FDV') == 1
        frap = self.cs.register.read('FRAP')
        brwa = self.cs.register.get_field('FRAP', frap, 'BRWA')

        # Informational
        # State of Flash Descriptor Valid bit
        if not fdv:
            self.logger.log("[*] Flash Descriptor Valid bit is not set")

        # CPU/Software access to Platform Data region (platform specific)
        if brwa & (1 << PLATFORM_DATA):
            self.logger.log("[*] Software has write access to Platform Data region in SPI flash (it's platform specific)")

        # Warnings
        # CPU/Software access to GBe region
        if brwa & (1 << GBE):
            res = ModuleResult.WARNING
            self.result.setStatusBit(self.result.status.ACCESS_RW)
            self.logger.log_warning("Software has write access to GBe region in SPI flash")

        # Failures
        # CPU/Software access to Flash Descriptor region (Read Only)
        if brwa & (1 << FLASH_DESCRIPTOR):
            res = ModuleResult.FAILED
            self.result.setStatusBit(self.result.status.ACCESS_RW)
            self.logger.log_bad("Software has write access to SPI flash descriptor")

        # CPU/Software access to Intel ME region (Read Only)
        if brwa & (1 << ME):
            res = ModuleResult.FAILED
            self.result.setStatusBit(self.result.status.ACCESS_RW)
            self.logger.log_bad("Software has write access to Management Engine (ME) region in SPI flash")

        if fdv:
            if ModuleResult.PASSED == res:
                self.logger.log_passed("SPI Flash Region Access Permissions in flash descriptor look ok")
            elif ModuleResult.FAILED == res:
                self.logger.log_failed("SPI Flash Region Access Permissions are not programmed securely in flash descriptor")
                self.logger.log_important('System may be using alternative protection by including descriptor region in SPI Protected Range Registers')
                self.logger.log_important('If using alternative protections, this can be considered a WARNING')
            elif ModuleResult.WARNING == res:
                self.logger.log_warning("Certain SPI flash regions are writeable by software")
        else:
            res = ModuleResult.WARNING
            self.result.setStatusBit(self.result.status.UNSUPPORTED_FEATURE)
            self.logger.log_warning("Either flash descriptor is not valid or not present on this system")

        return self.result.getReturnCode(res)

    def run(self, module_argv: List[str]) -> int:
        self.logger.start_test("SPI Flash Region Access Control")
        try:
            self.spi = SPI(self.cs)
            self.spi.display_SPI_Ranges_Access_Permissions()
            self.res = self.check_flash_access_permissions()
        except CSReadError as err:
            self.logger.log_warning(f"Unable to read register: {err}")
            self.result.setStatusBit(self.result.status.VERIFY)
            self.res = self.result.getReturnCode(ModuleResult.WARNING)
        return self.res
