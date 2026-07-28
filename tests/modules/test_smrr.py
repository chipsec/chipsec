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
from unittest.mock import Mock

from chipsec.library.returncode import ModuleResult
from chipsec.modules.common.smrr import smrr


class FakeReg:
    def __init__(self, fields, value=0):
        self._fields = fields
        self.value = value

    def get_field(self, name, preserve_field_position=False):
        return self._fields[name]

    def has_field(self, name):
        return name in self._fields


class FakeRegList(list):
    def read(self):
        return None

    def read_and_print(self):
        return None

    def read_and_verbose_print(self):
        return None

    def is_all_value(self, value, mask=None):
        if not self:

            return False

        if mask is None:
            return all(reg.value == value for reg in self)
        masked_value = value & mask

        return all((reg.value & mask) == masked_value for reg in self)


def _build_test_context(base_regs, mask_regs):
    if isinstance(base_regs, FakeReg):
        base_regs = [base_regs]
    if isinstance(mask_regs, FakeReg):
        mask_regs = [mask_regs]

    status = SimpleNamespace(CONFIGURATION=object(), NOT_APPLICABLE=object())

    base_list = FakeRegList(base_regs)
    mask_list = FakeRegList(mask_regs)

    register = Mock()

    def _get_list_by_name(name):
        if name == 'IA32_SMRR_PHYSBASE':
            return base_list
        if name == 'IA32_SMRR_PHYSMASK':
            return mask_list
        raise KeyError(name)

    register.get_list_by_name.side_effect = _get_list_by_name

    memory = Mock()
    memory.read_physical_mem_dword.return_value = 0xFFFFFFFF

    cpu = Mock()
    cpu.check_SMRR_supported.return_value = True

    cs = Mock()
    cs.hals.cpu = cpu
    cs.hals.memory = memory
    cs.register = register

    result = Mock()
    result.status = status
    result.getReturnCode.side_effect = lambda value, print_output=True: value

    module_self = Mock()
    module_self.cs = cs
    module_self.result = result
    module_self.logger = Mock()

    return module_self


class TestSmrr(unittest.TestCase):
    def test_smrr_passes_when_enabled_and_reads_blocked(self):
        base_reg = FakeReg({'PHYSBASE': 0x88400000, 'TYPE': 0x6}, value=0x88400006)
        mask_reg = FakeReg({'PHYSMASK': 0xFFF00000, 'VALID': 1}, value=0x00000C00)
        module_self = _build_test_context(base_reg, mask_reg)

        result = smrr.check_SMRR(module_self, False)

        self.assertEqual(result, ModuleResult.PASSED)

    def test_smrr_fails_when_range_not_enabled(self):
        base_reg = FakeReg({'PHYSBASE': 0x88400000, 'TYPE': 0x6}, value=0x88400006)
        mask_reg = FakeReg({'PHYSMASK': 0xFFF00000, 'VALID': 0}, value=0x00000000)
        module_self = _build_test_context(base_reg, mask_reg)

        result = smrr.check_SMRR(module_self, False)

        self.assertEqual(result, ModuleResult.FAILED)

    def test_smrr_fails_when_reads_not_blocked(self):
        base_reg = FakeReg({'PHYSBASE': 0x88400000, 'TYPE': 0x6}, value=0x88400006)
        mask_reg = FakeReg({'PHYSMASK': 0xFFF00000, 'VALID': 1}, value=0x00000C00)
        module_self = _build_test_context(base_reg, mask_reg)
        module_self.cs.hals.memory.read_physical_mem_dword.return_value = 0x12345678

        result = smrr.check_SMRR(module_self, False)

        self.assertEqual(result, ModuleResult.FAILED)

    def test_smrr_fails_when_memory_type_is_invalid(self):
        base_reg = FakeReg({'PHYSBASE': 0x88400000, 'TYPE': 0x2}, value=0x88400002)
        mask_reg = FakeReg({'PHYSMASK': 0xFFF00000, 'VALID': 1}, value=0x00000C00)
        module_self = _build_test_context(base_reg, mask_reg)

        result = smrr.check_SMRR(module_self, False)

        self.assertEqual(result, ModuleResult.FAILED)

    def test_smrr_fails_when_base_not_programmed(self):
        base_reg = FakeReg({'PHYSBASE': 0x0, 'TYPE': 0x6}, value=0x00000006)
        mask_reg = FakeReg({'PHYSMASK': 0xFFF00000, 'VALID': 1}, value=0x00000C00)
        module_self = _build_test_context(base_reg, mask_reg)

        result = smrr.check_SMRR(module_self, False)

        self.assertEqual(result, ModuleResult.FAILED)

    def test_smrr_fails_when_cpus_do_not_match(self):
        base_regs = [
            FakeReg({'PHYSBASE': 0x88400000, 'TYPE': 0x6}, value=0x88400006),
            FakeReg({'PHYSBASE': 0x88400000, 'TYPE': 0x6}, value=0x88400006),
        ]
        mask_regs = [
            FakeReg({'PHYSMASK': 0xFFF00000, 'VALID': 1}, value=0x00000C00),
            FakeReg({'PHYSMASK': 0xFFE00000, 'VALID': 1}, value=0x00000C01),
        ]
        module_self = _build_test_context(base_regs, mask_regs)

        result = smrr.check_SMRR(module_self, False)

        self.assertEqual(result, ModuleResult.FAILED)

    def test_smrr_passes_with_modify_when_writes_blocked(self):
        base_reg = FakeReg({'PHYSBASE': 0x88400000, 'TYPE': 0x6}, value=0x88400006)
        mask_reg = FakeReg({'PHYSMASK': 0xFFF00000, 'VALID': 1}, value=0x00000C00)
        module_self = _build_test_context(base_reg, mask_reg)

        result = smrr.check_SMRR(module_self, True)

        self.assertEqual(result, ModuleResult.PASSED)

    def test_smrr_fails_with_modify_when_writes_not_blocked(self):
        base_reg = FakeReg({'PHYSBASE': 0x88400000, 'TYPE': 0x6}, value=0x88400006)
        mask_reg = FakeReg({'PHYSMASK': 0xFFF00000, 'VALID': 1}, value=0x00000C00)
        module_self = _build_test_context(base_reg, mask_reg)
        module_self.cs.hals.memory.read_physical_mem_dword.side_effect = [0xFFFFFFFF, 0x90909090]

        result = smrr.check_SMRR(module_self, True)

        self.assertEqual(result, ModuleResult.FAILED)

    def test_smrr_sets_not_applicable_when_cpu_does_not_support_smrr(self):
        base_reg = FakeReg({'PHYSBASE': 0x88400000, 'TYPE': 0x6}, value=0x88400006)
        mask_reg = FakeReg({'PHYSMASK': 0xFFF00000, 'VALID': 1}, value=0x00000C00)
        module_self = _build_test_context(base_reg, mask_reg)
        module_self.cs.hals.cpu.check_SMRR_supported.return_value = False

        result = smrr.check_SMRR(module_self, False)

        module_self.result.setStatusBit.assert_called_once_with(module_self.result.status.NOT_APPLICABLE)
        self.assertEqual(result, ModuleResult.PASSED)

    def test_smrr_not_applicable_path_falls_through_to_not_applicable_when_misconfigured(self):
        base_reg = FakeReg({'PHYSBASE': 0x88400000, 'TYPE': 0x6}, value=0x88400006)
        mask_reg = FakeReg({'PHYSMASK': 0xFFF00000, 'VALID': 0}, value=0x00000000)
        module_self = _build_test_context(base_reg, mask_reg)
        module_self.cs.hals.cpu.check_SMRR_supported.return_value = False

        result = smrr.check_SMRR(module_self, False)

        module_self.result.setStatusBit.assert_any_call(module_self.result.status.NOT_APPLICABLE)
        module_self.result.setStatusBit.assert_any_call(module_self.result.status.CONFIGURATION)
        self.assertEqual(result, ModuleResult.NOTAPPLICABLE)


if __name__ == '__main__':
    unittest.main()