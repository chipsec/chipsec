import os
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

    def test_platform(self):
        self._chipsec_util("platform")

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

