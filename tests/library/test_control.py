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
from types import SimpleNamespace
from unittest.mock import MagicMock

from chipsec.library.control import Control


def make_cs(controls):
    return SimpleNamespace(Cfg=SimpleNamespace(CONTROLS=controls))


class TestControl(unittest.TestCase):
    """Cover the control accessor in chipsec.library.control."""

    def setUp(self):
        self.ctrl0 = MagicMock(instance=0)
        self.ctrl1 = MagicMock(instance=1)
        self.cs = make_cs({'LOCK_BIT': [self.ctrl0, self.ctrl1]})
        self.control = Control(self.cs)

    def test_get_list_by_name_found(self):
        result = self.control.get_list_by_name('lock_bit')
        self.assertEqual(list(result), [self.ctrl0, self.ctrl1])

    def test_get_list_by_name_missing_returns_empty(self):
        result = self.control.get_list_by_name('missing')
        self.assertEqual(list(result), [])

    def test_get_instance_by_name_found(self):
        self.assertIs(self.control.get_instance_by_name('LOCK_BIT', 1), self.ctrl1)

    def test_get_instance_by_name_instance_not_found(self):
        self.assertIsNone(self.control.get_instance_by_name('LOCK_BIT', 99))

    def test_get_instance_by_name_control_not_found(self):
        self.assertIsNone(self.control.get_instance_by_name('missing', 0))

    def test_get_def_returns_control_list(self):
        self.assertEqual(self.control.get_def('lock_bit'), [self.ctrl0, self.ctrl1])

    def test_get_def_missing_raises_keyerror(self):
        with self.assertRaises(KeyError):
            self.control.get_def('missing')

    def test_is_defined_true(self):
        self.assertTrue(self.control.is_defined('lock_bit'))

    def test_is_defined_false(self):
        self.assertFalse(self.control.is_defined('missing'))


if __name__ == '__main__':
    unittest.main()
