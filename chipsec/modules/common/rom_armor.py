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
Compatible SMM memory (SMRAM) Protection check module
This CHIPSEC module simply reads SMRAMC and checks that D_LCK is set.

Reference:
In 2006, `Security Issues Related to Pentium System Management Mode <http://www.ssi.gouv.fr/archive/fr/sciences/fichiers/lti/cansecwest2006-duflot.pdf>`_ outlined a configuration issue where compatibility SMRAM was not locked on some platforms. This means that ring 0 software was able to modify System Management Mode (SMM) code and data that should have been protected.

In Compatability SMRAM (CSEG), access to memory is defined by the SMRAMC register. When SMRAMC[D_LCK] is not set by the BIOS, SMRAM can be accessed even when the CPU is not in SMM. Such attacks were also described in `Using CPU SMM to Circumvent OS Security Functions <http://fawlty.cs.usfca.edu/~cruse/cs630f06/duflot.pdf>`_ and `Using SMM for Other Purposes <http://phrack.org/issues/65/7.html>`_.

usage:
    ``chipsec_main -m common.smm``

Examples:
    >>> chipsec_main.py -m common.smm

This module will only run on client (core) platforms that have PCI0.0.0_SMRAMC defined.
"""

from chipsec.module_common import BaseModule, MTAG_BIOS, MTAG_SMM
from chipsec.library.returncode import ModuleResult
from typing import List
import pdb

TAGS = [MTAG_BIOS, MTAG_SMM]

SMU_PSP_SMN_BASE = 0x3800000
#SMU_PSP_MBOX_CMD_STATUS = 0x00010570
#SMU_PSP_MBOX_CMD_BUF_LO = 0x00010574
#SMU_PSP_MBOX_CMD_BUF_HI = 0x00010578
SMU_PSP_MBOX_CMD_STATUS = 0x00010970
SMU_PSP_MBOX_CMD_BUF_LO = 0x00010974
SMU_PSP_MBOX_CMD_BUF_HI = 0x00010978

#FCH_SDP_PROTECT_SPI_0 = 0x2DC6000
#FCH_SDP_PROTECT_SPI_1 = 0x2DC6004
#FCH_SDP_PROTECT_SPI_2 = 0x2DC6004
#FCH_SDP_PROTECT_SPI_3 = 0x2DC6008
#FCH_SDP_PROTECT_SPI_4 = 0x2DC6010
#FCH_SDP_PROTECT_SPI_5 = 0x2DC6014
#FCH_SDP_PROTECT_SPI_6 = 0x2DC6014
#FCH_SDP_PROTECT_SPI_7 = 0x2DC6018

#HSTI PSP Security Feature State
PSP_ROM_ARMOR_ENFORCED = 11

SMU_INDEX_ADDR = 0xb8
SMU_DATA_ADDR = 0xbc

PSP_MBOX_CMD_SMM_INFO = 0x02

class rom_armor(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)
        self.result.id = 0x666
        #self.result.url = 'https://chipsec.github.io/modules/chipsec.modules.common.smm.html'

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
        spi_ctrl_bar = self.cs.pci.read_dword(0,0x14,3,0xa0)

        if(spi_ctrl_bar == 0xFFFFFFFF):
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
        if(not(rom_armor_enabled)):
            self.logger.log_failed("Rom Armor is not enabled.")
            return self.res
        else:
            self.logger.log_good("Rom Armor enabled.")
        self.res = self.check_RA_Fencing()
        
        return self.res
