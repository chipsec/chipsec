from tests.software import mock_helper, util

class TestPlatformChipsecUtil(util.TestChipsecUtil):
    """Test the platform commands exposed by chipsec_utils."""

    def test_platform(self):
        self._chipsec_util("platform")
