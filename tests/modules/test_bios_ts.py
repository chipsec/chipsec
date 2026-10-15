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
# Foundation, Inc., 51 Franklin Street, Fifth Floor,
# Boston, MA 02110-1301, USA.
#
# Contact information:
# chipsec@intel.com
#

import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from chipsec.library.returncode import ModuleResult
from chipsec.modules.common.bios_ts import bios_ts


class FakeControlList(list):
    def read_and_print(self):
        return None

    def is_any_value(self, value):
        return any(control_value == value for control_value in self)


class FakeRegister:
    def __init__(self, value, bild, read_error=None):
        self.value = value
        self.size = 4
        self.bild = bild
        self.read_error = read_error

    def read(self):
        if self.read_error:
            raise self.read_error
        return self.value

    def has_field(self, field):
        return field == 'BILD'

    def get_field(self, field, preserve_field_position=False):
        return self.bild


class FakeRegisterList(list):
    def read(self):
        return [register.read() for register in self]

    def filter_with_field(self, field):
        return FakeRegisterList(
            register for register in self if register.has_field(field)
        )

    def is_all_field_value(self, value, field):
        return all(register.get_field(field) == value for register in self)


def _build_module(spi_lock_value, rtc_registers):
    module_self = Mock()
    module_self.cs.control.get_list_by_name.return_value = FakeControlList(
        [spi_lock_value]
    )
    module_self.cs.control.is_defined.return_value = False
    module_self.cs.register.get_list_by_name.return_value = FakeRegisterList(
        rtc_registers
    )
    module_self.result.status = SimpleNamespace(
        LOCKS=object(), VERIFY=object()
    )
    module_self.result.getReturnCode.side_effect = lambda result: result
    return module_self


class TestBiosTs(unittest.TestCase):
    def test_fails_when_rtc_bios_interface_lock_is_clear(self):
        module_self = _build_module(1, [FakeRegister(0, 0)])

        result = bios_ts.check_bios_iface_lock(module_self)

        self.assertEqual(ModuleResult.FAILED, result)
        module_self.result.setStatusBit.assert_called_once_with(
            module_self.result.status.LOCKS
        )

    def test_warns_when_rtc_register_is_unreadable(self):
        module_self = _build_module(1, [FakeRegister(0xFFFFFFFF, 1)])

        result = bios_ts.check_bios_iface_lock(module_self)

        self.assertEqual(ModuleResult.WARNING, result)
        module_self.result.setStatusBit.assert_called_once_with(
            module_self.result.status.VERIFY
        )

    def test_warns_when_rtc_register_read_raises(self):
        module_self = _build_module(
            1,
            [FakeRegister(None, 1, read_error=RuntimeError('read failed'))],
        )

        result = bios_ts.check_bios_iface_lock(module_self)

        self.assertEqual(ModuleResult.WARNING, result)
        module_self.result.setStatusBit.assert_called_once_with(
            module_self.result.status.VERIFY
        )

    def test_passes_when_both_interface_locks_are_set(self):
        module_self = _build_module(1, [FakeRegister(0x80000008, 1)])

        result = bios_ts.check_bios_iface_lock(module_self)

        self.assertEqual(ModuleResult.PASSED, result)


if __name__ == '__main__':
    unittest.main()
