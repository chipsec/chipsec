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
# Boston, MA  02110-1301, USA.
#
# Contact information:
# chipsec@intel.com
#

import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from chipsec.modules.common.remap import remap


class FakeReg:
    def __init__(self, bar, field_value, instance=None):
        self.bar = bar
        self.field_value = field_value
        self.instance = instance

    def get_instance(self):
        return self.instance

    def get_field(self, field, preserve_field_position=False):
        return self.field_value


class TestRemap(unittest.TestCase):
    def test_checks_multiple_register_pairs_on_same_bar(self):
        module_self = Mock()
        module_self.logger = Mock()
        base_regs = [
            FakeReg('MCHBARMC1', 0x300000),
            FakeReg('MCHBARMC1', 0x500000),
        ]
        limit_regs = [
            FakeReg('MCHBARMC1', 0x200000),
            FakeReg('MCHBARMC1', 0x400000),
        ]

        is_warning, remap_ok = remap.check_remap_base_and_limit(
            module_self, base_regs, limit_regs, 0x800000, False, True
        )

        self.assertFalse(is_warning)
        self.assertTrue(remap_ok)
        self.assertEqual(module_self.logger.log.call_count, 2)

    def test_skips_unbound_register_pair_and_warns(self):
        module_self = Mock()
        module_self.logger = Mock()
        unbound_instance = SimpleNamespace(bus=None)
        base_regs = [
            FakeReg('MCHBARMC1', 0x700000, unbound_instance),
            FakeReg('MCHBARMC1', 0x300000),
        ]
        limit_regs = [
            FakeReg('MCHBARMC1', 0x600000, unbound_instance),
            FakeReg('MCHBARMC1', 0x200000),
        ]

        is_warning, remap_ok = remap.check_remap_base_and_limit(
            module_self, base_regs, limit_regs, 0x800000, False, True
        )

        self.assertTrue(is_warning)
        self.assertTrue(remap_ok)
        module_self.logger.log_warning.assert_called_once()
        module_self.logger.log.assert_called_once_with(
            '[*]   Memory Remap is disabled'
        )

    def test_warns_when_register_pair_is_incomplete(self):
        module_self = Mock()
        module_self.logger = Mock()
        base_regs = [FakeReg('MCHBAR', 0x300000)]
        limit_regs = [
            FakeReg('MCHBAR', 0x200000),
            FakeReg('MCHBARMC1', 0x100000),
        ]

        is_warning, remap_ok = remap.check_remap_base_and_limit(
            module_self, base_regs, limit_regs, 0x800000, False, True
        )

        self.assertTrue(is_warning)
        self.assertTrue(remap_ok)
        module_self.logger.log_warning.assert_called_once_with(
            'Unpaired REMAPBASE/REMAPLIMIT registers for MCHBARMC1'
        )


if __name__ == '__main__':
    unittest.main()
