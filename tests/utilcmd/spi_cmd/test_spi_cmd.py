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

from tests.software import mock_helper, util
from chipsec.library.file import get_main_dir
from chipsec.testcase import ExitCode
from tests.utilcmd.run_chipsec_util import setup_run_destroy_util_get_log_output, assertLogValue


class TestSPIChipsecUtil(unittest.TestCase):
    """Test the SPI commands exposed by chipsec_utils."""

    def test_spi_info(self):
        """Test to verify the ouput of 'spi info'.

        Validates that BC and FRAP are correctly read.
        """
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate2.json")
        spi_info_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "spi_cmd", "spi_cmd_info_1.json")
        retval, log = setup_run_destroy_util_get_log_output(init_replay_file, "spi", "info", util_replay_file=spi_info_replay_file)
        self.assertEqual(retval, ExitCode.OK)
        assertLogValue("BC", "0x10000888", log)

class TestSPIChipsecUtil2(util.TestChipsecUtil):
    def test_spi_dump(self):
        """Test to verify the ouput of 'spi dump'.

        Validates that the flash size is correctly calculated (based on the
        assumption that the BIOS region is last) and match it with the output
        file size.
        """

        fileno, rom_file = tempfile.mkstemp()
        os.close(fileno)
        self._chipsec_util(f"spi dump {rom_file}", mock_helper.SPIHelper)
        self.assertEqual(os.stat(rom_file).st_size, 0x3000)
        os.remove(rom_file)


if __name__ == '__main__':
    unittest.main()
