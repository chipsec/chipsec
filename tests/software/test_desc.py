import unittest

from tests.software import mock_helper, util


class TestDescChipsecUtil(util.TestChipsecUtil):
    """Test the Desc commands (gdt, idt, ldt) exposed by chipsec_utils."""

    def test_gdt(self):

        class GDTHelper(mock_helper.TestHelper):

            def get_descriptor_table(self, cpu_thread_id, desc_table_code):
                return (63, 0x1000, 0x0)

            def read_phys_mem(self, pa_hi, pa_lo, length):
                return "\xff" * length

        self._chipsec_util("gdt 0", GDTHelper)
        self.assertIn("# of entries    : 4", self.log)

if __name__ == '__main__':
    unittest.main()
