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
        self._chipsec_util("spi dump %s" % rom_file, mock_helper.SPIHelper)
        self.assertEqual(os.stat(rom_file).st_size, 0x3000)
        os.remove(rom_file)


if __name__ == '__main__':
    unittest.main()
