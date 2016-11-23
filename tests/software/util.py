import os
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
        logger.logger().HAL = True
        util.set_logfile(self.log_file)
        err_code = util.main(["chipsec_utils.py"] + arg.split())
        logger.logger().close()
        self.log = open(self.log_file).read()
        self.assertEqual(err_code, 0)

    def _assertLogValue(self, name, value):
        """Shortcut to validate the output.

        Assert that at least one line exists within the log which matches the
        expression: name [:=] value.
        """
        exp = r'(^|\W){}\s*[:=]\s*{}($|\W)'
        self.assertRegexpMatches(self.log, exp.format(name, value))
