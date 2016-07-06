import os
import struct
import tempfile
import unittest

from tests.software import mock_helper

import chipsec_util
from chipsec import logger
from chipsec import chipset
from chipsec.helper import oshelper

class TestChipsecUtil(unittest.TestCase):
    """Test the commands exposed by chipsec_utils.

    Each test may define its virtual helper and then call the _chipsec_util
    method with the command line arguments.
    """

    def setUp(self):
        """Setup the environment for the utils tests.

        We mock the helper registry to only contain our emulated helper.
        """
        fileno, self.log_file = tempfile.mkstemp()
        os.close(fileno)
        self.old_registry = oshelper.Helper.registry
        oshelper.Helper.registry = []
        oshelper._helper = None
        chipset._chipset = None

    def tearDown(self):
        os.remove(self.log_file)
        oshelper._helper = None
        chipset._chipset = None
        chipsec_util._cs = None
        oshelper.Helper.registry = self.old_registry

    def _chipsec_util(self, arg, helper_class=mock_helper.TestHelper):
        """Run the chipsec_util command with the arguments.

        Each test may setup a virtual helper to emulate the expected behaviour
        from the hardware. If no helper is provided, TestHelper will be used.
        It verifies that no error is being reported. self.log will be populated
        with the output.
        """
        oshelper.Helper.registry = [(helper_class.__name__, helper_class)]
        chipsec_util._cs = chipset.cs()
        util = chipsec_util.ChipsecUtil()
        util.VERBOSE = True
        util.set_logfile(self.log_file)
        err_code = util.main(["chipsec_utils.py"] + arg.split())
        logger.logger().close()
        self.log = open(self.log_file).read()
        self.assertEqual(err_code, 0)

    def test_acpi_xsdt_list(self):

        class ACPIHelper(mock_helper.ACPIHelper):

            USE_RSDP_REV_0 = False

            XSDT_ENTRIES = [0x400]

            def read_phys_mem(self, pa_hi, pa_lo, length):
                if pa_lo == 0x400:
                    return "EFGH"
                else:
                    return super(ACPIHelper, self).read_phys_mem(pa_hi, pa_lo, length)

        self._chipsec_util("acpi list", ACPIHelper)
        self.assertIn("EFGH: 0x0000000000000400", self.log)

    def test_acpi_rsdt_list(self):

        class ACPIHelper(mock_helper.ACPIHelper):

            RSDT_ENTRIES = [0x300]

            def read_phys_mem(self, pa_hi, pa_lo, length):
                if pa_lo >= self.EBDA_ADDRESS and \
                    pa_lo < self.RSDP_ADDRESS + len(self.RSDP_DESCRIPTOR):
                    # Simulate a condition where there is no RSDP in EBDA
                    return "\xFF" * length
                elif pa_lo == 0xE0000:
                    return self.RSDP_DESCRIPTOR[:length]
                elif pa_lo == 0x300:
                    return "ABCD"
                else:
                    return super(ACPIHelper, self).read_phys_mem(pa_hi, pa_lo, length)

        self._chipsec_util("acpi list", ACPIHelper)
        self.assertIn("ABCD: 0x0000000000000300", self.log)

    def test_platform(self):
        self._chipsec_util("platform")


    def test_cmos_dump(self):
        """Test to verify the output of 'cmos dump'.

        Check that we only access CMOS IO ports.
        """

        class CMOSHelper(mock_helper.TestHelper):
            def read_io_port(self, io_port, size):
                if io_port < 0x70 or io_port > 0x73:
                    raise Exception("Reading outside CMOS IO port")
                return io_port

            def write_io_port(self, io_port, value, size):
                if io_port < 0x70 or io_port > 0x73:
                    raise Exception("Writing outside CMOS IO port")

        self._chipsec_util("cmos dump", CMOSHelper)

    def test_msr(self):

        class MSRHelper(mock_helper.TestHelper):

            def get_threads_count(self):
                return 1

            def read_msr(self, thread_id, msr_addr):
                if msr_addr == 0x2FF:
                    return [0x1234, 0xcdef]
                else:
                    return [0x0, 0x0]

        self._chipsec_util("msr 0x2FF", MSRHelper)
        self.assertIn("EAX=00001234, EDX=0000CDEF", self.log)

    def test_gdt(self):

        class GDTHelper(mock_helper.TestHelper):

            def get_descriptor_table(self, cpu_thread_id, desc_table_code):
                return (63, 0x1000, 0x0)

            def read_phys_mem(self, pa_hi, pa_lo, length):
                return "\xff" * length

        self._chipsec_util("gdt 0", GDTHelper)
        self.assertIn("# of entries    : 4", self.log)


    def test_spi_info(self):
        """Test to verify the ouput of 'spi info'.

        Validates that BC and FRAP are correctly read.
        """

        self._chipsec_util("spi info", mock_helper.SPIHelper)
        self.assertIn("BC = 0xDEADBEEF", self.log)
        self.assertIn("FRAP = 0xEEEEEEEE", self.log)

    def test_spi_dump(self):
        """Test to verify the ouput of 'spi dump'.

        Validates that the flash size is correctly calculated (based on the
        assumption that the BIOS region is last) and match it with the output
        file size.
        """

        fileno, rom_file = tempfile.mkstemp()
        os.close(fileno)
        self._chipsec_util("spi dump %s" % rom_file, mock_helper.SPIHelper)
        self.assertEqual(os.stat(rom_file).st_size, 0x3000)
        os.remove(rom_file)

    def test_parse_multi_table(self):
        """Test to verify that tables with same signature are parsed correctly.

        Since usually there are several SSDT tables with the same signature, we test SSDT parsing.
        """

        class SSDTParsingHelper(mock_helper.ACPIHelper):
            """Test helper containing generic descriptor for SSDT to parse SSDT

            Three regions are defined:
              * SSDT table [0x400, 0x430]
              * SSDT table [0x600, 0x630]
              * SSDT table [0x800, 0x830]
            """
            RSDT_ENTRIES = [0x400, 0x600, 0x800]

            SSDT1_DESCRIPTOR = ("SSDT" +                  # Signature
                                struct.pack("<I", 0x30) + # Length
                                struct.pack("<B", 0x1) +  # Revision
                                struct.pack("<B", 0x1) +  # Checksum
                                "OEMSS1" +                # OEMID
                                "OEMTBLID" +              # OEM Table ID
                                "OEMR" +                  # OEM Revision
                                "CRID" +                  # Creator ID
                                "CRRV" +                  # Creator Revision
                                struct.pack("<Q", 0x129)) # AML code

            SSDT2_DESCRIPTOR = ("SSDT" +                  # Signature
                                struct.pack("<I", 0x30) + # Length
                                struct.pack("<B", 0x1) +  # Revision
                                struct.pack("<B", 0x1) +  # Checksum
                                "OEMSS2" +                # OEMID
                                "OEMTBLID" +              # OEM Table ID
                                "OEMR" +                  # OEM Revision
                                "CRID" +                  # Creator ID
                                "CRRV" +                  # Creator Revision
                                struct.pack("<Q", 0x929)) # AML code

            SSDT3_DESCRIPTOR = ("SSDT" +                  # Signature
                                struct.pack("<I", 0x30) + # Length
                                struct.pack("<B", 0x1) +  # Revision
                                struct.pack("<B", 0x1) +  # Checksum
                                "OEMSS3" +                # OEMID
                                "OEMTBLID" +              # OEM Table ID
                                "OEMR" +                  # OEM Revision
                                "CRID" +                  # Creator ID
                                "CRRV" +                  # Creator Revision
                                struct.pack("<Q", 0x199)) # AML code

            def read_phys_mem(self, pa_hi, pa_lo, length):
                if pa_lo == 0x400:
                    return self.SSDT1_DESCRIPTOR[:length]
                elif pa_lo == 0x600:
                    return self.SSDT2_DESCRIPTOR[:length]
                elif pa_lo == 0x800:
                    return self.SSDT3_DESCRIPTOR[:length]
                else:
                    return super(SSDTParsingHelper, self).read_phys_mem(pa_hi, pa_lo, length)

        self._chipsec_util("acpi list", SSDTParsingHelper)
        self.assertIn("SSDT: 0x0000000000000400, 0x0000000000000600, 0x0000000000000800", self.log)
        self._chipsec_util("acpi table SSDT", SSDTParsingHelper)
        self.assertIn("OEMSS1", self.log)
        self.assertIn("OEMSS2", self.log)
        self.assertIn("OEMSS3", self.log)
