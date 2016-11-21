import unittest

from tests.software import mock_helper, util


class TestCMOSChipsecUtil(util.TestChipsecUtil):
    """Test the CMOS commands exposed by chipsec_utils."""

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

if __name__ == '__main__':
    unittest.main()
