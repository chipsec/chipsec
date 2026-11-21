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

from chipsec.hal.common.physmem import Memory
from tests.software.mock_helper import TestHelper


def make_memory():
    cs = MagicMock()
    hal = Memory.__new__(Memory)
    hal.cs = cs
    hal.helper = cs.helper
    hal.logger = MagicMock()
    hal.logger.HAL = False
    return hal, cs.helper


class TestUnsafePhysicalMemory(unittest.TestCase):

    def test_unsafe_read_uses_the_unchecked_helper_api(self):
        hal, helper = make_memory()
        helper.read_phys_mem_unsafe.return_value = b'\xAA\xBB'

        self.assertEqual(hal.read_physical_mem_unsafe(0x1000, 2), b'\xAA\xBB')
        helper.read_phys_mem_unsafe.assert_called_once_with(0x1000, 2)
        helper.read_phys_mem.assert_not_called()

    def test_unsafe_write_uses_the_unchecked_helper_api(self):
        hal, helper = make_memory()
        helper.write_phys_mem_unsafe.return_value = 0

        self.assertEqual(hal.write_physical_mem_unsafe(0x1000, 2, b'\x01\x02'), 0)
        helper.write_phys_mem_unsafe.assert_called_once_with(0x1000, 2, b'\x01\x02')
        helper.write_phys_mem.assert_not_called()


class TestHelperUnsafeDefaults(unittest.TestCase):
    """Helpers without access checks fall back to their regular read/write."""

    def test_unsafe_read_defaults_to_read_phys_mem(self):
        helper = TestHelper()
        with patch.object(helper, 'read_phys_mem', return_value=b'\xAA') as read:
            self.assertEqual(helper.read_phys_mem_unsafe(0x1000, 1), b'\xAA')
        read.assert_called_once_with(0x1000, 1)

    def test_unsafe_write_defaults_to_write_phys_mem(self):
        helper = TestHelper()
        with patch.object(helper, 'write_phys_mem', return_value=0) as write:
            self.assertEqual(helper.write_phys_mem_unsafe(0x1000, 1, b'\x01'), 0)
        write.assert_called_once_with(0x1000, 1, b'\x01')


if __name__ == '__main__':
    unittest.main()
