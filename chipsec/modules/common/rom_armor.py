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
# chipsec@amd.com
#


"""
This module verifies support for Rom Armor and SPI ROM protections.

Reference:


usage:
    ``chipsec_main -m common.rom_armor``

Examples:
    >>> chipsec_main.py -m common.rom_armor

"""

from chipsec.module_common import BaseModule, BIOS, SMM
from chipsec.library.returncode import ModuleResult
from typing import List

TAGS = [BIOS, SMM]
METADATA_TAGS = ['OPENSOURCE', 'IA', 'COMMON', 'ROM_ARMOR']

SMU_PSP_SMN_BASE = 0x3800000
SMU_PSP_MBOX_CMD_STATUS = 0x00010970


class rom_armor(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)

    def is_supported(self) -> bool:
        return self.cs.is_amd()

    def check_ROMAMOR(self) -> bool:
        reg_value = self.cs.psp.smu_read32(SMU_PSP_SMN_BASE + SMU_PSP_MBOX_CMD_STATUS)
        self.logger.log_information(f"PSP Mailbox Status 0x{reg_value:X}")
        reg_value = self.cs.psp.smu_read32(SMU_PSP_SMN_BASE + 0x109fc)
        self.logger.log_information(f"PSP Mailbox Features 0x{reg_value:X}")
        hsti = self.cs.psp.query_HSTI()
        self.logger.log_information(f"HSTI 0x{hsti:X}")
        return bool(hsti>>11)

    def check_RA_Fencing(self) -> int:
        # Confirm SPI Control Bass address is blocked
        spi_ctrl_bar = self.cs.pci.read_dword(0, 0x14, 3, 0xa0)

        if (spi_ctrl_bar == 0xFFFFFFFF):
            self.logger.log_good("SPI BAR access from host is blocked")
        else:
            self.logger.log_bad("Host is able to access SPI Bar")

        return ModuleResult.PASSED

    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run(self, module_argv: List[str]) -> int:
        self.logger.start_test("Rom Armor Verification")
        rom_armor_enabled = self.check_ROMAMOR()
        self.res = ModuleResult.FAILED
        if (not (rom_armor_enabled)):
            self.logger.log_failed("Rom Armor is not enabled.")
            return self.res
        else:
            self.logger.log_good("Rom Armor enabled.")
        self.res = self.check_RA_Fencing()

        return self.res
