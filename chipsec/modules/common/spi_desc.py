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
The SPI Flash Descriptor indicates read/write permissions for devices to access regions of the flash memory. 
This module simply reads the Flash Descriptor and checks that software cannot modify the Flash Descriptor itself. 
If software can write to the Flash Descriptor, then software could bypass any protection defined by it. 
While often used for debugging, this should not be the case on production systems.

This module checks that software cannot write to the flash descriptor.

Usage:
    ``chipsec_main -m common.spi_desc``

Examples:
    >>> chipsec_main.py -m common.spi_desc

Registers used:
    - FRAP.BRRA
    - FRAP.BRWA

"""

from chipsec.module_common import BaseModule, ModuleResult, MTAG_BIOS
from chipsec.hal.spi import FLASH_DESCRIPTOR
from typing import List

TAGS = [MTAG_BIOS]


class spi_desc(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)
        self.rc_res = ModuleResult(0x63fa19c, 'https://chipsec.github.io/modules/chipsec.modules.common.spi_desc.html')

    def is_supported(self) -> bool:
        if self.cs.register_has_all_fields('FRAP', ['BRRA', 'BRWA']):
            return True
        self.logger.log_important('FRAP.BRWA or FRAP.BRRA registers not defined for platform.  Skipping module.')
        self.rc_res.setStatusBit(self.rc_res.status.NOT_APPLICABLE)
        self.res = self.rc_res.getReturnCode(ModuleResult.NOTAPPLICABLE)
        return False

    ##
    # Displays the SPI Regions Access Permissions
    def check_flash_access_permissions(self) -> int:

        res = ModuleResult.PASSED
        frap = self.cs.read_register('FRAP')
        self.cs.print_register('FRAP', frap)
        brra = self.cs.get_register_field('FRAP', frap, 'BRRA')
        brwa = self.cs.get_register_field('FRAP', frap, 'BRWA')

        self.logger.log(f"[*] Software access to SPI flash regions: read = 0x{brra:02X}, write = 0x{brwa:02X}")
        if brwa & (1 << FLASH_DESCRIPTOR):
            res = ModuleResult.FAILED
            self.rc_res.setStatusBit(self.rc_res.status.ACCESS_RW)
            self.logger.log_bad("Software has write access to SPI flash descriptor")

        self.logger.log('')
        if ModuleResult.PASSED == res:
            self.logger.log_passed("SPI flash permissions prevent SW from writing to flash descriptor")
        elif ModuleResult.FAILED == res:
            self.logger.log_failed("SPI flash permissions allow SW to write flash descriptor")
            self.logger.log_important('System may be using alternative protection by including descriptor region in SPI Protected Range Registers')
        
        return self.rc_res.getReturnCode(res)

    def run(self, module_argv: List[str]) -> int:
        self.logger.start_test("SPI Flash Region Access Control")
        self.res = self.check_flash_access_permissions()
        return self.res
