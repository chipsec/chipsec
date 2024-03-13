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
import os
import tempfile
import unittest

from tests.software import mock_helper

from chipsec.library import logger
from chipsec import chipset
from chipsec.helper import oshelper


class TestChipsecCs(unittest.TestCase):
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
        chipset._chipset = None

    def tearDown(self):
        os.remove(self.log_file)
        chipset._chipset = None

    def _chipsec_cs(self, arg, helper_class=mock_helper.TestHelper, platform=None, pch=None):
        """Run the chipsec chipset commands

        Each test may setup a virtual helper to emulate the expected behaviour
        from the hardware. If no helper is provided, TestHelper will be used.
        It verifies that no error is being reported. self.log will be populated
        with the output.
        """
        _cs = chipset.cs()
        logger.logger().HAL = True
        logger.logger().VERBOSE = True
        logger.logger().set_log_file(self.log_file)
        try:
            _cs.init(platform, pch, helper_class())
            ret = getattr(_cs.Cfg, arg.split()[0])()
        finally:
            logger.logger().close()
        with open(self.log_file, 'rb') as log:
            self.log = log.read()
        return ret
