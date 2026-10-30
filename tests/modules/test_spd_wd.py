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

import unittest
from unittest.mock import Mock

from chipsec.library.register import ObjList
from chipsec.modules.common.spd_wd import spd_wd


class TestSpdWd(unittest.TestCase):
    def setUp(self) -> None:
        self.module = Mock()

    def test_is_supported_without_spd_wd_field(self) -> None:
        hcfg = Mock()
        hcfg.has_field.return_value = False
        self.module.cs.register.get_list_by_name.return_value = ObjList([hcfg])

        self.assertFalse(spd_wd.is_supported(self.module))
        hcfg.has_field.assert_called_once_with('SPD_WD')
        self.assertEqual(self.module.hcfg, [])

    def test_is_supported_with_empty_hcfg_list(self) -> None:
        self.module.cs.register.get_list_by_name.return_value = ObjList()

        self.assertFalse(spd_wd.is_supported(self.module))
        self.module.cs.register.get_list_by_name.assert_called_once_with(
            'HCFG'
        )
        self.module.logger.log_important.assert_called_once_with(
            'SMBUS*.HCFG.SPD_WD is not available. Skipping test.'
        )

    def test_is_supported_with_enabled_smbus_and_hcfg(self) -> None:
        hcfg = Mock()
        hcfg.has_field.return_value = True
        self.module.cs.register.get_list_by_name.return_value = ObjList([hcfg])

        self.assertTrue(spd_wd.is_supported(self.module))
        hcfg.has_field.assert_called_once_with('SPD_WD')
        self.assertEqual(self.module.hcfg, [hcfg])
        self.module.logger.log_important.assert_not_called()

    def test_is_supported_filters_hcfg_without_spd_wd(self) -> None:
        hcfg_without_spd_wd = Mock()
        hcfg_without_spd_wd.has_field.return_value = False
        hcfg_with_spd_wd = Mock()
        hcfg_with_spd_wd.has_field.return_value = True
        self.module.cs.register.get_list_by_name.return_value = ObjList([
            hcfg_without_spd_wd, hcfg_with_spd_wd
        ])

        self.assertTrue(spd_wd.is_supported(self.module))
        self.assertEqual(self.module.hcfg, [hcfg_with_spd_wd])


if __name__ == '__main__':
    unittest.main()
