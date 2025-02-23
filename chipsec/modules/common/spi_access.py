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
    - 8086.SPI.HSFS.FDV
    - 8086.SPI.FRAP.BRWA

.. important::
    - Some platforms may use alternate means of protecting these regions.
      Consider this when assessing results.

"""

from chipsec.library.exceptions import CSReadError
from chipsec.module_common import BaseModule, BIOS
from chipsec.library.returncode import ModuleResult
from chipsec.hal.intel.spi import SPI
from chipsec.library.intel.spi import GBE, PLATFORM_DATA, ME, FLASH_DESCRIPTOR
from typing import List

TAGS = [BIOS]
METADATA_TAGS = ['OPENSOURCE', 'IA', 'COMMON', 'SPI_ACCESS']


class spi_access(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)
        self.cs.set_scope({
            "HSFS": "8086.SPI",
            "FRAP": "8086.SPI",
        })

    def is_supported(self) -> bool:
        if self.cs.register.has_field('HSFS', 'FDV') and self.cs.register.has_field('FRAP', 'BRWA'):
            return True
        self.logger.log_important('HSFS.FDV or FRAP.BRWA registers not defined for platform.  Skipping module.')
        return False

    def check_flash_access_permissions(self) -> int:
        frap_objs = self.cs.register.get_list_by_name('FRAP')
        frap_objs.read()
        for frap in frap_objs:
            self.logger.log_verbose(frap)
            fdv_obj = self.cs.register.get_instance_by_name('HSFS', frap.get_instance())
            fdv = fdv_obj.read_field('FDV') == 1
            brwa = frap.get_field('BRWA')

            if not fdv:
                self.logger.log("[*] Flash Descriptor Valid bit is not set")
       
            if brwa & (1 << PLATFORM_DATA):
                self.logger.log("[*] Software has write access to Platform Data region in SPI flash (it's platform specific)")

            if brwa & (1 << GBE):
                self.update_res(ModuleResult.WARNING)
                self.result.setStatusBit(self.result.status.ACCESS_RW)
                self.logger.log_warning("Software has write access to GBe region in SPI flash")

            if brwa & (1 << FLASH_DESCRIPTOR):
                self.update_res(ModuleResult.FAILED)
                self.result.setStatusBit(self.result.status.ACCESS_RW)
                self.logger.log_bad("Software has write access to SPI flash descriptor")

            if brwa & (1 << ME):
                self.update_res(ModuleResult.FAILED)
                self.result.setStatusBit(self.result.status.ACCESS_RW)
                self.logger.log_bad("Software has write access to Management Engine (ME) region in SPI flash")

            if fdv:
                if ModuleResult.PASSED == self.res:
                    self.logger.log_good("SPI Flash Region Access Permissions in flash descriptor look ok")
                elif ModuleResult.FAILED == self.res:
                    self.logger.log_failed('SPI Flash Region Access Permissions are not programmed securely in flash descriptor')
                    self.logger.log_important('System may be using alternative protection by including descriptor region in SPI Protected Range Registers')
                    self.logger.log_important('If using alternative protections, this can be considered a WARNING')
                elif ModuleResult.WARNING == self.res:
                    self.logger.log_warning("Certain SPI flash regions are writeable by software")
            else:
                self.update_res(ModuleResult.WARNING)
                self.result.setStatusBit(self.result.status.UNSUPPORTED_FEATURE)
                self.logger.log_warning("Either flash descriptor is not valid or not present on this system")

        return self.result.getReturnCode(self.res)

    def run(self, module_argv: List[str]) -> int:
        self.logger.start_test('SPI Flash Region Access Control')
        try:
            self.spi = SPI(self.cs)
            self.spi.display_SPI_Ranges_Access_Permissions()
            self.res = self.check_flash_access_permissions()
        except CSReadError as err:
            self.logger.log_warning(f'Unable to read register: {err}')
            self.result.setStatusBit(self.result.status.VERIFY)
            self.res = self.result.getReturnCode(ModuleResult.WARNING)
        return self.res
