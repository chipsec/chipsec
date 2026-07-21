# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2026, Intel Corporation
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
# Contact information:
# chipsec@intel.com
#

import unittest
from unittest.mock import MagicMock

from chipsec.hal.hal_base import HALBase
from chipsec.library.exceptions import UnimplementedAPIError


class TestHALBase(unittest.TestCase):
    """Cover the base HAL component in chipsec.hal.hal_base."""

    def setUp(self):
        self.cs = MagicMock()
        self.hal = HALBase(self.cs)

    def test_init_stores_chipset_and_logger(self):
        self.assertIs(self.hal.cs, self.cs)
        self.assertIsNotNone(self.hal.logger)

    def test_getattr_unknown_raises_unimplemented(self):
        with self.assertRaises(UnimplementedAPIError):
            self.hal.some_missing_api()

    def test_getattr_message_includes_name(self):
        try:
            _ = self.hal.does_not_exist
        except UnimplementedAPIError as exc:
            self.assertIn('does_not_exist', str(exc))
        else:
            self.fail('Expected UnimplementedAPIError')

    def test_mfgids_enum_values(self):
        self.assertEqual(HALBase.MfgIds.Intel.value, ['GenuineIntel'])
        self.assertIn('AuthenticAMD', HALBase.MfgIds.AMD.value)
        self.assertEqual(HALBase.MfgIds.Any.value, ['Any'])


if __name__ == '__main__':
    unittest.main()
