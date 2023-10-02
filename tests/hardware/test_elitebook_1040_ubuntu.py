# CHIPSEC: Platform Security Assessment Framework
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
#
from tests.hardware import test_ubuntu


class EliteBook1040UbuntuTest(test_ubuntu.GenericUbuntuTest):

    PRODUCT_NAME = 'HP EliteBook Folio 1040 G1'
    BIOS_VERSION = 'L83 Ver. 01.21'
    BOOT_MODE = test_ubuntu.GenericUbuntuTest.BOOT_MODE_LEGACY
    PASS = [
        "chipsec.modules.common.bios_smi",
        "chipsec.modules.common.bios_ts",
        "chipsec.modules.common.bios_wp",
        "chipsec.modules.common.smm",
        "chipsec.modules.common.smrr",
        "chipsec.modules.common.spi_desc",
        "chipsec.modules.common.spi_lock",
        "chipsec.modules.remap",
        "chipsec.modules.smm_dma",
    ]

    WARNING = [
        "chipsec.modules.common.secureboot.variables",
        "chipsec.modules.common.uefi.s3bootscript",
        "chipsec.modules.common.uefi.access_uefispec",
    ]

    def test_main(self):
        self._generic_main()
