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

from chipsec.library.exceptions import UnknownChipsetError
from chipsec.config import CHIPSET_CODE_UNKNOWN
from tests.software import cs
from tests.software import mock_helper


class TestPlatformChipsecCs(cs.TestChipsecCs, unittest.TestCase):
    """Test the platform commands exposed by chipsec chipset."""

    def test_platform(self):
        p = self._chipsec_cs("get_chipset_code", mock_helper.ValidChipsetHelper)
        self.assertEqual('SKL', p)

    def test_platform_given(self):
        p = self._chipsec_cs("get_chipset_code", mock_helper.InvalidChipsetHelper, 'CML')
        self.assertEqual('CML', p)

    def test_platform_invalid(self):
        self.assertRaises(UnknownChipsetError, self._chipsec_cs, "get_chipset_code", mock_helper.InvalidChipsetHelper)
        # self.assertEqual(CHIPSET_CODE_UNKNOWN, p)

    def test_pch(self):
        p = self._chipsec_cs("get_pch_code", mock_helper.ValidChipsetHelper)
        self.assertEqual('PCH_1XX', p)

    def test_pch_invalid(self):
        p = self._chipsec_cs("get_pch_code", mock_helper.InvalidPchHelper)
        self.assertEqual(CHIPSET_CODE_UNKNOWN, p)

    def test_pch_given(self):
        p = self._chipsec_cs("get_pch_code", mock_helper.InvalidPchHelper, None, 'PCH_495')
        self.assertEqual('PCH_495', p)


if __name__ == '__main__':
    unittest.main()
