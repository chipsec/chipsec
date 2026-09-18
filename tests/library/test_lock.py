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
from unittest.mock import MagicMock, patch

from chipsec.library.lock import Lock


class LockTestBase(unittest.TestCase):
    """Builds a chipset stub exposing only the Cfg members Lock touches."""

    def setUp(self):
        self.cs = MagicMock()
        self.cs.Cfg.LOCKS = {}
        self.cs.Cfg.LOCKEDBY = {}
        self.cs.Cfg.convert_internal_scope.return_value = ('8086', '', '', '')
        self.lock = Lock(self.cs)


class TestLockGet(LockTestBase):
    """Cover Lock.get."""

    def test_returns_lock_object_when_defined(self):
        lock_obj = {'register': 'BC', 'field': 'BLE'}
        self.cs.Cfg.LOCKS['BiosLockEnable'] = lock_obj
        self.assertIs(self.lock.get('BiosLockEnable'), lock_obj)

    def test_returns_none_when_not_defined(self):
        with patch('chipsec.library.lock.logger') as mock_logger:
            self.assertIsNone(self.lock.get('MissingLock'))
        mock_logger.return_value.log.assert_called_once()

    def test_logs_lock_name_when_not_defined(self):
        with patch('chipsec.library.lock.logger') as mock_logger:
            self.lock.get('MissingLock')
        message = mock_logger.return_value.log.call_args[0][0]
        self.assertIn('MissingLock', message)

    def test_lookup_is_case_sensitive(self):
        self.cs.Cfg.LOCKS['BiosLockEnable'] = object()
        with patch('chipsec.library.lock.logger'):
            self.assertIsNone(self.lock.get('bioslockenable'))


class TestLockGetList(LockTestBase):
    """Cover Lock.get_list."""

    def test_empty_config_returns_empty_list(self):
        self.assertEqual(self.lock.get_list(), [])

    def test_returns_all_configured_lock_names(self):
        self.cs.Cfg.LOCKS = {'LockA': object(), 'LockB': object()}
        self.assertEqual(sorted(self.lock.get_list()), ['LockA', 'LockB'])

    def test_returned_list_is_a_copy(self):
        self.cs.Cfg.LOCKS = {'LockA': object()}
        result = self.lock.get_list()
        result.append('LockB')
        self.assertEqual(list(self.cs.Cfg.LOCKS.keys()), ['LockA'])


class TestLockGetLockedby(LockTestBase):
    """Cover Lock.get_lockedby."""

    def test_returns_registers_for_known_lock(self):
        locked = [{'8086.SPI.BC.BLE'}]
        self.cs.Cfg.LOCKEDBY = {'8086': {'BiosLockEnable': locked}}
        self.assertIs(self.lock.get_lockedby('BiosLockEnable'), locked)

    def test_scope_is_resolved_through_cfg(self):
        self.cs.Cfg.LOCKEDBY = {'8086': {'BiosLockEnable': []}}
        self.lock.get_lockedby('BiosLockEnable')
        self.cs.Cfg.convert_internal_scope.assert_called_once_with('', 'BiosLockEnable')

    def test_returns_none_for_unknown_vendor_id(self):
        self.cs.Cfg.LOCKEDBY = {'1022': {'BiosLockEnable': []}}
        self.assertIsNone(self.lock.get_lockedby('BiosLockEnable'))

    def test_returns_none_for_unknown_lock_name(self):
        self.cs.Cfg.LOCKEDBY = {'8086': {'OtherLock': []}}
        self.assertIsNone(self.lock.get_lockedby('BiosLockEnable'))


if __name__ == '__main__':
    unittest.main()
