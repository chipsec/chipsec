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
from unittest.mock import patch

from chipsec.library import gil


class TestGil(unittest.TestCase):
    """Cover the GIL state helpers in chipsec.library.gil."""

    def test_gil_enabled_when_macro_none(self):
        with patch.object(gil, 'gil_macro', return_value=None):
            self.assertTrue(gil.gil_enabled())
            self.assertFalse(gil.gil_disabled())

    def test_gil_enabled_when_macro_zero(self):
        with patch.object(gil, 'gil_macro', return_value=0):
            self.assertTrue(gil.gil_enabled())
            self.assertFalse(gil.gil_disabled())

    def test_gil_disabled_when_macro_one(self):
        with patch.object(gil, 'gil_macro', return_value=1):
            self.assertFalse(gil.gil_enabled())
            self.assertTrue(gil.gil_disabled())

    def test_gil_status_enabled_string(self):
        with patch.object(gil, 'gil_enabled', return_value=True):
            self.assertEqual(gil.gil_status(), 'Enabled')

    def test_gil_status_disabled_string(self):
        with patch.object(gil, 'gil_enabled', return_value=False):
            self.assertEqual(gil.gil_status(), 'Disabled')

    def test_gil_macro_reads_sysconfig(self):
        with patch.object(gil.sysconfig, 'get_config_vars', return_value={'Py_GIL_DISABLED': 1}):
            self.assertEqual(gil.gil_macro(), 1)


if __name__ == '__main__':
    unittest.main()
