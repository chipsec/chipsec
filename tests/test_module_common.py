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

import chipsec.module_common as module_common
from chipsec.library.returncode import ModuleResult


class TestBaseModule(unittest.TestCase):
    """Cover the BaseModule base class in chipsec.module_common."""

    def setUp(self):
        patcher_cs = patch('chipsec.chipset.cs', return_value=MagicMock())
        patcher_rc = patch.object(module_common, 'ReturnCode', return_value=MagicMock())
        self.addCleanup(patcher_cs.stop)
        self.addCleanup(patcher_rc.stop)
        patcher_cs.start()
        patcher_rc.start()
        self.module = module_common.BaseModule()

    def test_is_supported_defaults_true(self):
        self.assertTrue(self.module.is_supported())

    def test_run_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            self.module.run([])

    def test_initial_legacy_result_is_passed(self):
        self.assertEqual(self.module.res, ModuleResult.PASSED)

    def test_update_res_ignores_invalid_value(self):
        self.module.update_res('NOT_A_RESULT')
        self.assertEqual(self.module.res, ModuleResult.PASSED)

    def test_update_res_escalates_to_higher_priority(self):
        self.module.update_res(ModuleResult.FAILED)
        self.assertEqual(self.module.res, ModuleResult.FAILED)

    def test_update_res_does_not_downgrade(self):
        self.module.update_res(ModuleResult.FAILED)
        self.module.update_res(ModuleResult.PASSED)
        self.assertEqual(self.module.res, ModuleResult.FAILED)


if __name__ == '__main__':
    unittest.main()
