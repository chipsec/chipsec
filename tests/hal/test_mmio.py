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

from chipsec.cfg.parsers.ip.pci_device import PCIObj
from chipsec.hal.common.mmio import MMIO


class TestMMIOMultiBus(unittest.TestCase):
    def setUp(self):
        self.cs = MagicMock()
        self.mmio = MMIO.__new__(MMIO)
        self.mmio.cs = self.cs
        self.mmio.logger = MagicMock()
        self.mmio.cached_bar_addresses = {}
        self.mmio.cache_bar_addresses_resolution = True

        self.instance_1 = PCIObj({'bus': 0x10, 'dev': 0x02, 'fun': 0})
        self.instance_2 = PCIObj({'bus': 0x20, 'dev': 0x02, 'fun': 0})
        self.bases = {self.instance_1: None, self.instance_2: None}
        self.bar = MagicMock()
        self.bar.register = 'BAR_REG'
        self.bar.registerh = None
        self.bar.base_field = 'BASE'
        self.bar.baseh_field = None
        self.bar.reg_align = None
        self.bar.regh_align = None
        self.bar.registertype = None
        self.bar.mmio_base = None
        self.bar.mmio_align = None
        self.bar.limit_register = None
        self.bar.limit_field = None
        self.bar.limit_align = None
        self.bar.fixed_address = None
        self.bar.offset = 0
        self.bar.size = 0x1000
        self.bar.get_base.side_effect = lambda instance: (
            self.bases.get(instance), self.bar.size)

        def update_base(base, instance):
            if instance is None:
                for key in self.bases:
                    self.bases[key] = base
            else:
                self.bases[instance] = base

        self.bar.update_base_address.side_effect = update_base
        self.cs.register.mmio.get_def.return_value = self.bar

    def _register(self, instance, base):
        register = MagicMock()
        register.get_instance.return_value = instance
        register.read_field.return_value = base
        register.get_field_mask.return_value = 0xFFFF
        return register

    def test_default_base_resolution_does_not_cache_to_other_bus(self):
        first = self._register(self.instance_1, 0x1000)
        second = self._register(self.instance_2, 0x2000)
        self.cs.register.get_list_by_name.return_value = [first, second]
        self.cs.register.get_instance_by_name.return_value = second

        self.assertEqual(
            (0x1000, 0x1000),
            self.mmio.get_MMIO_BAR_base_address('BAR'))
        self.assertEqual(0x1000, self.bases[self.instance_1])
        self.assertIsNone(self.bases[self.instance_2])

        self.assertEqual(
            (0x2000, 0x1000),
            self.mmio.get_MMIO_BAR_base_address('BAR', self.instance_2))
        self.cs.helper.read_mmio_reg.return_value = 0xA5
        self.assertEqual(
            0xA5,
            self.mmio.read_MMIO_BAR_reg('BAR', 0x10, 4, self.instance_2))
        self.cs.helper.read_mmio_reg.assert_called_once_with(0x2010, 4)

        self.mmio.write_MMIO_BAR_reg('BAR', 0x20, 0xBB, 4, self.instance_2)
        self.cs.helper.write_mmio_reg.assert_called_once_with(0x2020, 4, 0xBB)

    def test_default_base_resolution_uses_matching_high_register(self):
        low = self._register(self.instance_1, 0x2000)
        high = self._register(self.instance_1, 0x100000000)
        self.bar.registerh = 'BAR_REG_H'
        self.bar.baseh_field = 'BASE_HI'
        self.cs.register.get_list_by_name.return_value = [low]
        self.cs.register.get_instance_by_name.return_value = high

        self.assertEqual(
            (0x100002000, 0x1000),
            self.mmio.get_MMIO_BAR_base_address('BAR'))
        self.cs.register.get_instance_by_name.assert_called_once_with(
            'BAR_REG_H', self.instance_1)


if __name__ == '__main__':
    unittest.main()