# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2026, Intel Corporation
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

"""
Displays firmware (BIOS/UEFI) information gathered from SMBIOS and OS interfaces.

Usage:
    ``chipsec_main -m common.firmware_info``

Examples:
    >>> chipsec_main.py -m common.firmware_info

"""

from typing import List

from chipsec.module_common import BaseModule
from chipsec.library.returncode import ModuleResult

TAGS = []
METADATA_TAGS = ['OPENSOURCE', 'IA', 'COMMON', 'FIRMWARE_INFO']


class firmware_info(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)

    def is_supported(self) -> bool:
        return True

    def get_firmware_info(self) -> int:
        vendor = self.cs.firmware_vendor()
        product = self.cs.firmware_product()
        version = self.cs.firmware_version()
        fw_type = self.cs.firmware_type()

        self.logger.log(f'[*] Firmware Information')
        self.logger.log(f'    Type   : {fw_type    or "Unknown"}')
        self.logger.log(f'    Vendor : {vendor     or "Unknown"}')
        self.logger.log(f'    Product: {product    or "Unknown"}')
        self.logger.log(f'    Version: {version    or "Unknown"}')

        self.logger.log_information('Firmware information collected')
        return self.result.getReturnCode(ModuleResult.INFORMATION)

    def run(self, module_argv: List[str]) -> int:
        self.logger.start_test('Firmware Information')
        return self.get_firmware_info()
