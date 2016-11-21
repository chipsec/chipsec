import struct
import unittest

from tests.software import mock_helper, util


class TestACPIChipsecUtil(util.TestChipsecUtil):
    """Test the ACPI commands exposed by chipsec_utils."""

    def test_acpi_xsdt_list(self):

        class ACPIHelper(mock_helper.ACPIHelper):

            USE_RSDP_REV_0 = False

            def __init__(self):
                super(ACPIHelper, self).__init__()
                self._add_entry_to_xsdt(0x400)

            def read_phys_mem(self, pa_hi, pa_lo, length):
                if pa_lo == 0x400:
                    return "EFGH"
                else:
                    parent = super(ACPIHelper, self)
                    return parent.read_phys_mem(pa_hi, pa_lo, length)

        self._chipsec_util("acpi list", ACPIHelper)
        self._assertLogValue("EFGH", "0x0000000000000400")

    def test_acpi_rsdt_list(self):

        class ACPIHelper(mock_helper.ACPIHelper):

            def __init__(self):
                super(ACPIHelper, self).__init__()
                self._add_entry_to_rsdt(0x300)

            def read_phys_mem(self, pa_hi, pa_lo, length):
                if (pa_lo >= self.EBDA_ADDRESS and
                        pa_lo < self.RSDP_ADDRESS + len(self.rsdp_descriptor)):
                    # Simulate a condition where there is no RSDP in EBDA
                    return "\xFF" * length
                elif pa_lo == 0xE0000:
                    return self.rsdp_descriptor[:length]
                elif pa_lo == 0x300:
                    return "ABCD"
                else:
                    parent = super(ACPIHelper, self)
                    return parent.read_phys_mem(pa_hi, pa_lo, length)

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
        self.assertIn("Unable to determine the correct DSDT address", self.log)

    def test_mismatch_dsdt_x_dsdt_ok_dsdt_zero(self):

        class DSDTParsingHelper(mock_helper.DSDTParsingHelper):

            DSDT_ADDRESS = 0x0
            X_DSDT_ADDRESS = 0x400

        self._chipsec_util("acpi table FACP", DSDTParsingHelper)
        self._assertLogValue("DSDT", "0x00000000")
        self._assertLogValue("X_DSDT", "0x0000000000000400")
        self.assertNotIn("Unable to determine the correct DSDT address",
                         self.log)

    def test_mismatch_dsdt_x_dsdt_ok_x_dsdt_zero(self):

        class DSDTParsingHelper(mock_helper.DSDTParsingHelper):

            DSDT_ADDRESS = 0x400
            X_DSDT_ADDRESS = 0x0

        self._chipsec_util("acpi table FACP", DSDTParsingHelper)
        self._assertLogValue("DSDT", "0x00000400")
        self._assertLogValue("X_DSDT", "0x0000000000000000")
        self.assertNotIn("Unable to determine the correct DSDT address",
                         self.log)

    def test_no_x_dsdt(self):

        class DSDTParsingHelper(mock_helper.DSDTParsingHelper):

            USE_FADT_WITH_X_DSDT = False
            DSDT_ADDRESS = 0x400

        self._chipsec_util("acpi table FACP", DSDTParsingHelper)
        self._assertLogValue("DSDT", "0x00000400")
        self._assertLogValue("X_DSDT", "Not found")
        self.assertIn("Cannot find X_DSDT entry in FADT.", self.log)

    def test_show_dsdt(self):

        class DSDTParsingHelper(mock_helper.DSDTParsingHelper):

            DSDT_ADDRESS = 0x600

            DSDT_DESCRIPTOR = ("DSDT" +                   # Signature
                               struct.pack("<I", 0x30) +  # Length
                               struct.pack("<B", 0x1) +   # Revision
                               struct.pack("<B", 0x1) +   # Checksum
                               "OEMDSD" +                 # OEMID
                               "OEMTBLID" +               # OEM Table ID
                               "OEMR" +                   # OEM Revision
                               "CRID" +                   # Creator ID
                               "CRRV" +                   # Creator Revision
                               struct.pack("<Q", 0x129))  # AML code

            def read_phys_mem(self, pa_hi, pa_lo, length):
                if pa_lo == self.DSDT_ADDRESS:
                    return self.DSDT_DESCRIPTOR[:length]
                else:
                    parent = super(DSDTParsingHelper, self)
                    return parent.read_phys_mem(pa_hi, pa_lo, length)

        self._chipsec_util("acpi table DSDT", DSDTParsingHelper)
        self.assertIn("OEMDSD", self.log)

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
            SSDT1_DESCRIPTOR = ("SSDT" +                   # Signature
                                struct.pack("<I", 0x30) +  # Length
                                struct.pack("<B", 0x1) +   # Revision
                                struct.pack("<B", 0x1) +   # Checksum
                                "OEMSS1" +                 # OEMID
                                "OEMTBLID" +               # OEM Table ID
                                "OEMR" +                   # OEM Revision
                                "CRID" +                   # Creator ID
                                "CRRV" +                   # Creator Revision
                                struct.pack("<Q", 0x129))  # AML code

            SSDT2_DESCRIPTOR = ("SSDT" +                   # Signature
                                struct.pack("<I", 0x30) +  # Length
                                struct.pack("<B", 0x1) +   # Revision
                                struct.pack("<B", 0x1) +   # Checksum
                                "OEMSS2" +                 # OEMID
                                "OEMTBLID" +               # OEM Table ID
                                "OEMR" +                   # OEM Revision
                                "CRID" +                   # Creator ID
                                "CRRV" +                   # Creator Revision
                                struct.pack("<Q", 0x929))  # AML code

            SSDT3_DESCRIPTOR = ("SSDT" +                   # Signature
                                struct.pack("<I", 0x30) +  # Length
                                struct.pack("<B", 0x1) +   # Revision
                                struct.pack("<B", 0x1) +   # Checksum
                                "OEMSS3" +                 # OEMID
                                "OEMTBLID" +               # OEM Table ID
                                "OEMR" +                   # OEM Revision
                                "CRID" +                   # Creator ID
                                "CRRV" +                   # Creator Revision
                                struct.pack("<Q", 0x199))  # AML code

            def __init__(self):
                super(SSDTParsingHelper, self).__init__()
                self._add_entry_to_rsdt(0x400)
                self._add_entry_to_rsdt(0x600)
                self._add_entry_to_rsdt(0x800)

            def read_phys_mem(self, pa_hi, pa_lo, length):
                if pa_lo == 0x400:
                    return self.SSDT1_DESCRIPTOR[:length]
                elif pa_lo == 0x600:
                    return self.SSDT2_DESCRIPTOR[:length]
                elif pa_lo == 0x800:
                    return self.SSDT3_DESCRIPTOR[:length]
                else:
                    parent = super(SSDTParsingHelper, self)
                    return parent.read_phys_mem(pa_hi, pa_lo, length)

        self._chipsec_util("acpi list", SSDTParsingHelper)
        self._assertLogValue("SSDT", ("0x0000000000000400, "
                                      "0x0000000000000600, "
                                      "0x0000000000000800"))
        self._chipsec_util("acpi table SSDT", SSDTParsingHelper)
        self.assertIn("OEMSS1", self.log)
        self.assertIn("OEMSS2", self.log)
        self.assertIn("OEMSS3", self.log)


if __name__ == '__main__':
    unittest.main()
