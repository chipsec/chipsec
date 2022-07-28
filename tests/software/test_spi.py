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


class TestSPIChipsecUtil(util.TestChipsecUtil):
    """Test the SPI commands exposed by chipsec_utils."""

    def test_spi_info(self):
        """Test to verify the ouput of 'spi info'.

        Validates that BC and FRAP are correctly read.
        """

        self._chipsec_util("spi info", mock_helper.SPIHelper)
        self._assertLogValue("BC", "0xDEADBEEF")
        self._assertLogValue("FRAP", "0xEEEEEEEE")

    def test_spi_dump(self):
        """Test to verify the ouput of 'spi dump'.

        Validates that the flash size is correctly calculated (based on the
        assumption that the BIOS region is last) and match it with the output
        file size.
        """

        fileno, rom_file = tempfile.mkstemp()
        os.close(fileno)
        self._chipsec_util("spi dump {}".format(rom_file), mock_helper.SPIHelper)
        self.assertEqual(os.stat(rom_file).st_size, 0x3000)
        os.remove(rom_file)


if __name__ == '__main__':
    unittest.main()
