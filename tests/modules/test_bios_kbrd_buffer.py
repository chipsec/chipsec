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

# To execute: python[3] -m unittest tests.modules.test_bios_kbrd_buffer

import unittest
from unittest.mock import Mock, patch

from chipsec.library.exceptions import PhysicalMemoryAccessError
from chipsec.library.returncode import ModuleResult
from chipsec.modules.common.bios_kbrd_buffer import bios_kbrd_buffer


def _build_test_context(memory):
    module_self = Mock()
    module_self.cs.hals.memory = memory
    module_self.result.getReturnCode.side_effect = lambda value: value
    return module_self


class TestBiosKbrdBuffer(unittest.TestCase):

    def test_not_applicable_when_the_bios_data_area_is_not_accessible(self):
        memory = Mock()
        memory.read_physical_mem_dword.side_effect = PhysicalMemoryAccessError('page 0 is not mapped', 17)
        module_self = _build_test_context(memory)

        result = bios_kbrd_buffer.check_BIOS_keyboard_buffer(module_self)

        self.assertEqual(result, ModuleResult.NOTAPPLICABLE)
        module_self.result.setStatusBit.assert_called_once_with(module_self.result.status.NOT_APPLICABLE)
        module_self.logger.log_important.assert_called_once()

    @patch('chipsec.modules.common.bios_kbrd_buffer.print_buffer_bytes')
    def test_passes_when_the_buffer_is_readable_and_empty(self, _):
        memory = Mock()
        memory.read_physical_mem_dword.return_value = 0x1E
        memory.read_physical_mem.return_value = bytes(32)
        module_self = _build_test_context(memory)

        result = bios_kbrd_buffer.check_BIOS_keyboard_buffer(module_self)

        self.assertEqual(result, ModuleResult.PASSED)
        module_self.result.setStatusBit.assert_called_once_with(module_self.result.status.SUCCESS)


if __name__ == '__main__':
    unittest.main()
