import os
import struct
import tempfile
import unittest

from tests.software import mock_helper

import chipsec_util
from chipsec import logger
from chipsec import chipset
from chipsec.helper import oshelper

class TestChipsec(unittest.TestCase):

    def setUp(self):
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

        class ACPIHelper(mock_helper.TestHelper):

            RSDP_DESCRIPTOR = ("RSD PTR " +               # Signature
                               struct.pack("<B", 0x1) +   # Checksum
                               "TEST00" +                 # OEMID
                               struct.pack("<B", 0x2) +   # Revision
                               struct.pack("<I", 0x200) + # RSDT Address
                               struct.pack("<I", 0x0) +   # Length
                               struct.pack("<Q", 0x100) + # XSDT Address
                               struct.pack("<B", 0x0) +   # Extended Checksum
                               "AAA")                     # Reserved

            XSDT_DESCRIPTOR = ("XSDT" +                  # Signature
                               struct.pack("<I", 0x32) + # Length
                               struct.pack("<B", 0x1) +  # Revision
                               struct.pack("<B", 0x1) +  # Checksum
                               "OEMIDT" +                # OEMID
                               "OEMTBLID" +              # OEM Table ID
                               "OEMR" +                  # OEM Revision
                               "CRID" +                  # Creator ID
                               "CRRV" +                  # Creator Revision
                               struct.pack("<Q", 0x400)) # Address of table

            EBDA_ADDRESS = 0x96000
            EBDA_PADDING = 0x100
            RSDP_ADDRESS = EBDA_ADDRESS + EBDA_PADDING

            def read_phys_mem(self, pa_hi, pa_lo, length):
                if pa_lo == 0x40E:
                    return struct.pack("<H", self.EBDA_ADDRESS >> 4)
                elif pa_lo >= self.EBDA_ADDRESS and \
                     pa_lo < self.RSDP_ADDRESS + len(self.RSDP_DESCRIPTOR):
                    mem = "\x00" * self.EBDA_PADDING + self.RSDP_DESCRIPTOR
                    offset = pa_lo - self.EBDA_ADDRESS
                    return mem[offset:offset+length]
                elif pa_lo == 0x100:
                    return self.XSDT_DESCRIPTOR[:length]
                elif pa_lo == 0x400:
                    return "EFGH"

        self._chipsec_util("acpi list", ACPIHelper)
        self.assertIn("EFGH: 0x0000000000000400", self.log)

    def test_acpi_rsdt_list(self):

        class ACPIHelper(mock_helper.TestHelper):

            RSDP_DESCRIPTOR = ("RSD PTR " +               # Signature
                               struct.pack("<B", 0x1) +   # Checksum
                               "TEST00" +                 # OEMID
                               struct.pack("<B", 0x0) +   # Revision
                               struct.pack("<I", 0x200))  # RSDT Address

            RSDT_DESCRIPTOR = ("RSDT" +                  # Signature
                               struct.pack("<I", 0x28) + # Length
                               struct.pack("<B", 0x1) +  # Revision
                               struct.pack("<B", 0x1) +  # Checksum
                               "OEMIDT" +                # OEMID
                               "OEMTBLID" +              # OEM Table ID
                               "OEMR" +                  # OEM Revision
                               "CRID" +                  # Creator ID
                               "CRRV" +                  # Creator Revision
                               struct.pack("<I", 0x300)) # Address of table

            def read_phys_mem(self, pa_hi, pa_lo, length):
                if pa_lo == 0xE0000:
                    return self.RSDP_DESCRIPTOR[:length]
                elif pa_lo == 0x200:
                    return self.RSDT_DESCRIPTOR[:length]
                elif pa_lo == 0x300:
                    return "ABCD"
                else:
                    return "\xFF" * length

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

