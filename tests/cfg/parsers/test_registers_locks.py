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

from chipsec.cfg.parsers.registers.locks import LOCKSHelper, create_lock_helper
from chipsec.library.exceptions import LockHelperError


def make_lock(**overrides):
    defaults = dict(
        register='REG',
        field='LOCK',
        attributes='RW',
        lock_value=None,
        dependency=None,
        dependency_value=None,
    )
    defaults.update(overrides)
    return LOCKSHelper(**defaults)


class TestLocksHelperQueries(unittest.TestCase):
    """Cover the boolean/query methods of LOCKSHelper."""

    def test_has_lock_value(self):
        self.assertFalse(make_lock().has_lock_value())
        self.assertTrue(make_lock(lock_value=1).has_lock_value())
        # 0 is a valid lock value and must be considered "present".
        self.assertTrue(make_lock(lock_value=0).has_lock_value())

    def test_is_access_type(self):
        lock = make_lock(attributes='RW')
        self.assertTrue(lock.is_access_type('RW'))
        self.assertFalse(lock.is_access_type('RO'))

    def test_has_dependency(self):
        self.assertFalse(make_lock().has_dependency())
        self.assertTrue(make_lock(dependency='DEP_REG').has_dependency())

    def test_has_dependency_value(self):
        self.assertFalse(make_lock().has_dependency_value())
        # 0 is a valid dependency value and must be considered "present".
        self.assertTrue(make_lock(dependency_value=0).has_dependency_value())

    def test_is_read_only(self):
        self.assertTrue(make_lock(attributes='RO').is_read_only())
        self.assertTrue(make_lock(attributes='ROS').is_read_only())
        self.assertFalse(make_lock(attributes='RW').is_read_only())

    def test_is_write_once(self):
        self.assertTrue(make_lock(attributes='RW1S').is_write_once())
        self.assertTrue(make_lock(attributes='WO1S').is_write_once())
        self.assertFalse(make_lock(attributes='RW').is_write_once())

    def test_is_clearable(self):
        for attr in ('RW', 'RW1C', 'WO1C'):
            self.assertTrue(make_lock(attributes=attr).is_clearable(), attr)
        self.assertFalse(make_lock(attributes='RO').is_clearable())


class TestLocksHelperInfoAndRepr(unittest.TestCase):
    """Cover get_lock_info, __str__ and __repr__."""

    def test_get_lock_info_contents(self):
        lock = make_lock(attributes='RO', lock_value=1, dependency='DEP', dependency_value=2)
        info = lock.get_lock_info()
        self.assertEqual(info['register'], 'REG')
        self.assertEqual(info['field'], 'LOCK')
        self.assertEqual(info['attributes'], 'RO')
        self.assertEqual(info['lock_value'], 1)
        self.assertEqual(info['dependency'], 'DEP')
        self.assertEqual(info['dependency_value'], 2)
        self.assertTrue(info['has_lock_value'])
        self.assertTrue(info['has_dependency'])
        self.assertTrue(info['is_read_only'])
        self.assertFalse(info['is_write_once'])
        self.assertFalse(info['is_clearable'])

    def test_str_with_lock_and_dependency(self):
        s = str(make_lock(attributes='RW1S', lock_value=1, dependency='DEP', dependency_value=2))
        self.assertIn('Lock: REG.LOCK', s)
        self.assertIn('Attributes: RW1S', s)
        self.assertIn('Lock Value: 0x1', s)
        self.assertIn('Dependency: DEP = 0x2', s)

    def test_str_without_optional_fields(self):
        s = str(make_lock())
        self.assertIn('Lock: REG.LOCK', s)
        self.assertIn('Attributes: RW', s)
        self.assertNotIn('Lock Value', s)
        self.assertNotIn('Dependency', s)

    def test_repr(self):
        r = repr(make_lock(attributes='RW', lock_value=1))
        self.assertIn("register='REG'", r)
        self.assertIn("field='LOCK'", r)
        self.assertIn("attributes='RW'", r)
        self.assertIn('lock_value=1', r)


class TestCreateLockHelper(unittest.TestCase):
    """Cover the validated factory create_lock_helper."""

    def test_valid_creation(self):
        lock = create_lock_helper('REG', 'LOCK', 'RW', lock_value=1,
                                  dependency='DEP', dependency_value=2)
        self.assertIsInstance(lock, LOCKSHelper)
        self.assertEqual(lock.register, 'REG')
        self.assertEqual(lock.field, 'LOCK')
        self.assertEqual(lock.attributes, 'RW')
        self.assertEqual(lock.lock_value, 1)
        self.assertEqual(lock.dependency, 'DEP')
        self.assertEqual(lock.dependency_value, 2)

    def test_all_valid_attributes_accepted(self):
        for attr in ('RO', 'RW', 'ROS', 'RW1S', 'RW1C', 'WO1S', 'WO1C'):
            self.assertIsInstance(create_lock_helper('REG', 'LOCK', attr), LOCKSHelper)

    def test_empty_register_raises(self):
        with self.assertRaises(LockHelperError):
            create_lock_helper('', 'LOCK', 'RW')

    def test_empty_field_raises(self):
        with self.assertRaises(LockHelperError):
            create_lock_helper('REG', '', 'RW')

    def test_empty_attributes_raises(self):
        with self.assertRaises(LockHelperError):
            create_lock_helper('REG', 'LOCK', '')

    def test_invalid_attributes_raises(self):
        with self.assertRaises(LockHelperError):
            create_lock_helper('REG', 'LOCK', 'BOGUS')


if __name__ == '__main__':
    unittest.main()
