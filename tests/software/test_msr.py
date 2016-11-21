import unittest

from tests.software import mock_helper, util


class TestMSRChipsecUtil(util.TestChipsecUtil):
    """Test the MSR commands exposed by chipsec_utils."""

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
        self._assertLogValue("EAX", "00001234")
        self._assertLogValue("EDX", "0000CDEF")

if __name__ == '__main__':
    unittest.main()
