import unittest

from tests.software import util


class TestPlatformChipsecUtil(util.TestChipsecUtil):
    """Test the platform commands exposed by chipsec_utils."""

    def test_platform(self):
        self._chipsec_util("platform")


if __name__ == '__main__':
    unittest.main()
