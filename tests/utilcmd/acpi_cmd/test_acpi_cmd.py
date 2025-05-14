# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2023, Intel Corporation
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

""""
To execute: python[3] -m unittest tests.utilcmd.acpi_cmd.test_acpi_cmd
"""

import os
import struct
import unittest

from chipsec.library.file import get_main_dir
from tests.utilcmd.run_chipsec_util import setup_run_destroy_util
from chipsec.testcase import ExitCode
from tests.software import mock_helper, util


class TestAcpiUtilcmd(unittest.TestCase):
    def test_list(self) -> None:
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate.json")
        acpi_list_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "acpi_cmd", "acpi_cmd_list_1.json")
        retval = setup_run_destroy_util(init_replay_file, "acpi", "list", util_replay_file=acpi_list_replay_file)
        self.assertEqual(retval, ExitCode.OK)

    def test_table(self) -> None:
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate.json")
        acpi_table_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "acpi_cmd", "acpi_cmd_table_1.json")
        retval = setup_run_destroy_util(init_replay_file, "acpi", "table XSDT", util_replay_file=acpi_table_replay_file)
        self.assertEqual(retval, ExitCode.OK)


class TestACPIChipsecUtil(util.TestChipsecUtil):
    def test_acpi_xsdt_list(self):

        class ACPIHelper(mock_helper.ACPIHelper):

            USE_RSDP_REV_0 = False

            def __init__(self):
                super(ACPIHelper, self).__init__()
                self._add_entry_to_xsdt(0x400)

            def read_phys_mem(self, pa, length):
                if (pa & 0xffffffff) == 0x400:
                    return b"EFGH"
                else:
                    parent = super(ACPIHelper, self)
                    return parent.read_phys_mem(pa, length)

        self._chipsec_util("acpi list", ACPIHelper)
        self._assertLogValue("EFGH", "0x0000000000000400")

    def test_acpi_rsdt_list(self):

        class ACPIHelper(mock_helper.ACPIHelper):

            def __init__(self):
                super(ACPIHelper, self).__init__()
                self._add_entry_to_rsdt(0x300)

            def read_phys_mem(self, pa, length):
                pa_lo = pa & 0xFFFFFFFF
                if (pa_lo >= self.EBDA_ADDRESS and
                        pa_lo < self.RSDP_ADDRESS + len(self.rsdp_descriptor)):
                    # Simulate a condition where there is no RSDP in EBDA
                    return b"\xFF" * length
                elif pa_lo == 0xE0000:
                    return self.rsdp_descriptor[:length]
                elif pa_lo == 0x300:
                    return b"ABCD"
                else:
                    parent = super(ACPIHelper, self)
                    return parent.read_phys_mem(pa, length)

        self._chipsec_util("acpi list", ACPIHelper)
        self._assertLogValue("ABCD", "0x0000000000000300")

    def test_acpi_facp_list(self):
        self._chipsec_util("acpi table FACP", mock_helper.DSDTParsingHelper)
        self._assertLogValue("DSDT", "0x00000000")
        self._assertLogValue("X_DSDT", "0x0000000000000000")

    def test_mismatch_dsdt_x_dsdt_error(self):

        class DSDTParsingHelper(mock_helper.DSDTParsingHelper):

            DSDT_ADDRESS = 0x400
            X_DSDT_ADDRESS = 0x312

        self._chipsec_util("acpi table FACP", DSDTParsingHelper)
        self._assertLogValue("DSDT", "0x00000400")
        self._assertLogValue("X_DSDT", "0x0000000000000312")
        self.assertIn(b"Unable to determine the correct DSDT address", self.log)

    def test_mismatch_dsdt_x_dsdt_ok_dsdt_zero(self):

        class DSDTParsingHelper(mock_helper.DSDTParsingHelper):

            DSDT_ADDRESS = 0x0
            X_DSDT_ADDRESS = 0x400

        self._chipsec_util("acpi table FACP", DSDTParsingHelper)
        self._assertLogValue("DSDT", "0x00000000")
        self._assertLogValue("X_DSDT", "0x0000000000000400")
        self.assertNotIn(b"Unable to determine the correct DSDT address",
                         self.log)

    def test_mismatch_dsdt_x_dsdt_ok_x_dsdt_zero(self):

        class DSDTParsingHelper(mock_helper.DSDTParsingHelper):

            DSDT_ADDRESS = 0x400
            X_DSDT_ADDRESS = 0x0

        self._chipsec_util("acpi table FACP", DSDTParsingHelper)
        self._assertLogValue("DSDT", "0x00000400")
        self._assertLogValue("X_DSDT", "0x0000000000000000")
        self.assertNotIn(b"Unable to determine the correct DSDT address",
                         self.log)

    def test_no_x_dsdt(self):

        class DSDTParsingHelper(mock_helper.DSDTParsingHelper):

            USE_FADT_WITH_X_DSDT = False
            DSDT_ADDRESS = 0x400

        self._chipsec_util("acpi table FACP", DSDTParsingHelper)
        self._assertLogValue("DSDT", "0x00000400")
        self._assertLogValue("X_DSDT", "Not found")
        self.assertIn(b"Cannot find X_DSDT entry in FADT.", self.log)

    def test_show_dsdt(self):

        class DSDTParsingHelper(mock_helper.DSDTParsingHelper):

            DSDT_ADDRESS = 0x600

            DSDT_DESCRIPTOR = (b"DSDT" +                   # Signature
                               struct.pack("<I", 0x30) +  # Length
                               struct.pack("<B", 0x1) +   # Revision
                               struct.pack("<B", 0x1) +   # Checksum
                               b"OEMDSD" +                 # OEMID
                               b"OEMTBLID" +               # OEM Table ID
                               b"OEMR" +                   # OEM Revision
                               b"CRID" +                   # Creator ID
                               b"CRRV" +                   # Creator Revision
                               struct.pack("<Q", 0x129))  # AML code

            def read_phys_mem(self, pa, length):
                pa_lo = pa & 0xFFFFFFFF
                if pa_lo == self.DSDT_ADDRESS:
                    return self.DSDT_DESCRIPTOR[:length]
                else:
                    parent = super(DSDTParsingHelper, self)
                    return parent.read_phys_mem(pa, length)

        self._chipsec_util("acpi table DSDT", DSDTParsingHelper)
        self.assertIn(b"OEMDSD", self.log)

    def test_parse_multi_table(self):
        """Test to verify that tables with same signature are parsed correctly.

        Since usually there are several SSDT tables with the
        same signature, we test SSDT parsing.
        """

        class SSDTParsingHelper(mock_helper.ACPIHelper):
            """Test helper containing generic descriptor for SSDT to parse SSDT

            Three regions are defined:
              * SSDT table [0x400, 0x430]
              * SSDT table [0x600, 0x630]
              * SSDT table [0x800, 0x830]
            """
            SSDT1_DESCRIPTOR = (b"SSDT" +                   # Signature
                                struct.pack("<I", 0x30) +  # Length
                                struct.pack("<B", 0x1) +   # Revision
                                struct.pack("<B", 0x1) +   # Checksum
                                b"OEMSS1" +                 # OEMID
                                b"OEMTBLID" +               # OEM Table ID
                                b"OEMR" +                   # OEM Revision
                                b"CRID" +                   # Creator ID
                                b"CRRV" +                   # Creator Revision
                                struct.pack("<Q", 0x129))  # AML code

            SSDT2_DESCRIPTOR = (b"SSDT" +                   # Signature
                                struct.pack("<I", 0x30) +  # Length
                                struct.pack("<B", 0x1) +   # Revision
                                struct.pack("<B", 0x1) +   # Checksum
                                b"OEMSS2" +                 # OEMID
                                b"OEMTBLID" +               # OEM Table ID
                                b"OEMR" +                   # OEM Revision
                                b"CRID" +                   # Creator ID
                                b"CRRV" +                   # Creator Revision
                                struct.pack("<Q", 0x929))  # AML code

            SSDT3_DESCRIPTOR = (b"SSDT" +                   # Signature
                                struct.pack("<I", 0x30) +  # Length
                                struct.pack("<B", 0x1) +   # Revision
                                struct.pack("<B", 0x1) +   # Checksum
                                b"OEMSS3" +                 # OEMID
                                b"OEMTBLID" +               # OEM Table ID
                                b"OEMR" +                   # OEM Revision
                                b"CRID" +                   # Creator ID
                                b"CRRV" +                   # Creator Revision
                                struct.pack("<Q", 0x199))  # AML code

            def __init__(self):
                super(SSDTParsingHelper, self).__init__()
                self._add_entry_to_rsdt(0x400)
                self._add_entry_to_rsdt(0x600)
                self._add_entry_to_rsdt(0x800)

            def read_phys_mem(self, pa, length):
                pa_lo = pa & 0xFFFFFFFF
                if pa_lo == 0x400:
                    return self.SSDT1_DESCRIPTOR[:length]
                elif pa_lo == 0x600:
                    return self.SSDT2_DESCRIPTOR[:length]
                elif pa_lo == 0x800:
                    return self.SSDT3_DESCRIPTOR[:length]
                else:
                    parent = super(SSDTParsingHelper, self)
                    return parent.read_phys_mem(pa, length)

        self._chipsec_util("acpi list", SSDTParsingHelper)
        self._assertLogValue("SSDT", ("0x0000000000000400, "
                                      "0x0000000000000600, "
                                      "0x0000000000000800"))
        self._chipsec_util("acpi table SSDT", SSDTParsingHelper)
        self.assertIn(b"OEMSS1", self.log)
        self.assertIn(b"OEMSS2", self.log)
        self.assertIn(b"OEMSS3", self.log)


if __name__ == '__main__':
    unittest.main()
