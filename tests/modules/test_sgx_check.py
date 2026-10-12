# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2023, Intel Corporation
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

# To execute: python[3] -m unittest tests.modules.test_sgx_check

import unittest
import os
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock

from chipsec.testcase import  ExitCode
from chipsec.library.file import get_main_dir
from chipsec.library.returncode import ModuleResult
from chipsec.modules.common.sgx_check import sgx_check
from tests.modules.run_chipsec_module import setup_run_destroy_module

class TestSgxCheck(unittest.TestCase):
    def test_missing_sgx_debug_mode_register_is_unverified(self) -> None:
        module = sgx_check.__new__(sgx_check)
        module.res = ModuleResult.PASSED
        module.logger = Mock()
        module.result = Mock()
        module.result.status = SimpleNamespace(
            VERIFY=object(), DEBUG_FEATURE=object(), CONFIGURATION=object(), LOCKS=object()
        )

        missing_debug_registers = MagicMock()
        missing_debug_registers.__bool__.return_value = False
        debug_interface_registers = MagicMock()
        debug_interface_registers.is_all_field_value.side_effect = lambda value, field: field == 'LOCK'

        module.cs = SimpleNamespace(register=Mock())
        module.cs.register.get_list_by_name.side_effect = {
            'SGX_DEBUG_MODE': missing_debug_registers,
            'IA32_DEBUG_INTERFACE': debug_interface_registers,
        }.__getitem__

        result, status = module.check_debug()

        self.assertEqual(ModuleResult.WARNING, result)
        self.assertEqual(module.result.status.VERIFY, status)
        good_messages = [call.args[0] for call in module.logger.log_good.call_args_list]
        self.assertNotIn('SGX debug mode is disabled', good_messages)
        module.logger.log_warning.assert_called_once()

    def test_sgx_check_warning(self) -> None:
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate2.json")
        sgx_replay_file = os.path.join(get_main_dir(), "tests", "modules", "sgx_check_2.json")
        retval = setup_run_destroy_module(init_replay_file, "common.sgx_check", module_replay_file=sgx_replay_file)

        self.assertEqual(retval, ExitCode.NOTAPPLICABLE)


if __name__ == '__main__':
    unittest.main()
