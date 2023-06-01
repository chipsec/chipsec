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

import unittest

from tests.software import mock_helper, util


class TestDescChipsecUtil(util.TestChipsecUtil):
    """Test the Desc commands (gdt, idt, ldt) exposed by chipsec_utils."""

    def test_gdt(self):

        class GDTHelper(mock_helper.TestHelper):

            def get_descriptor_table(self, cpu_thread_id, desc_table_code):
                return (63, 0x1000, 0x0)

            def read_phys_mem(self, pa, length):
                return b"\xff" * length

        self._chipsec_util("gdt 0", GDTHelper)
        self.assertIn(b"# of entries    : 4", self.log)


if __name__ == '__main__':
    unittest.main()
