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
from unittest.mock import MagicMock, Mock, patch

from chipsec.testcase import  ExitCode
from chipsec.library.defines import BIT0
from chipsec.library.file import get_main_dir
from chipsec.library.returncode import ModuleResult
from chipsec.modules.common.sgx_check import sgx_check
from tests.modules.run_chipsec_module import setup_run_destroy_module

SGX_SUPPORTED_MSG = 'Intel SGX instructions are supported and available to use'
SGX_UNSUPPORTED_MSG = 'Intel SGX instructions are not supported on system'


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
        good_messages = [call[0][0] for call in module.logger.log_good.call_args_list]
        self.assertNotIn('SGX debug mode is disabled', good_messages)
        module.logger.log_warning.assert_called_once()

    def test_sgx_check_warning(self) -> None:
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate2.json")
        sgx_replay_file = os.path.join(get_main_dir(), "tests", "modules", "sgx_check_2.json")
        retval = setup_run_destroy_module(init_replay_file, "common.sgx_check", module_replay_file=sgx_replay_file)

        self.assertEqual(retval, ExitCode.NOTAPPLICABLE)


class TestSgxCheckAffinityFailure(unittest.TestCase):
    """CPUID results must only be used from CPUs the module actually pinned to."""

    START_CPU = 'start'

    def _make_module(self, cpu_sgx1: dict, affinity_failures: dict) -> sgx_check:
        # cpu_sgx1: CPU -> SGX-1 support (START_CPU is where the process runs before any pinning).
        # affinity_failures: tid -> 'none' (helper returns None) or 'raise' (helper raises).
        module = sgx_check.__new__(sgx_check)
        module.cs = MagicMock()
        module.logger = MagicMock()
        module.result = MagicMock()
        module.res = ModuleResult.PASSED
        module.PRMRR = MagicMock(return_value=MagicMock(uniform=True))

        fc_list = MagicMock()
        fc_list.is_all_field_value.return_value = True
        mtrrcap_list = MagicMock()
        mtrrcap_list.is_any_field_value.return_value = False
        module.cs.register.get_list_by_name.side_effect = \
            lambda name: mtrrcap_list if name == 'MTRRCAP' else fc_list
        module.cs.register.is_defined.return_value = False
        module.cs.control.get_list_by_name.return_value.is_all_field_value.return_value = True
        module.cs.control.is_defined.return_value = False

        threads = [tid for tid in cpu_sgx1 if tid != self.START_CPU]
        module.cs.hals.msr.get_cpu_thread_count.return_value = len(threads)
        pinned = {'cpu': self.START_CPU}

        def set_affinity(tid):
            failure = affinity_failures.get(tid)
            if failure == 'raise':
                raise OSError(f'cannot pin CPU{tid}')
            if failure == 'none':
                return None
            pinned['cpu'] = tid
            return tid

        def cpuid(eax, ecx):
            return (BIT0 if cpu_sgx1[pinned['cpu']] else 0, 0, 0, 0)

        module.helper = MagicMock()
        module.helper.set_affinity.side_effect = set_affinity
        module.cs.hals.cpu.cpuid.side_effect = cpuid
        return module

    def _run(self, module: sgx_check) -> None:
        with patch.object(module, 'check_prmrr_values'), \
                patch.object(module, 'check_debug', return_value=(ModuleResult.PASSED, None)):
            module.check_sgx_config()

    def _good_msgs(self, module: sgx_check) -> list:
        return [c[0][0] for c in module.logger.log_good.call_args_list]

    def _bad_msgs(self, module: sgx_check) -> list:
        return [c[0][0] for c in module.logger.log_bad.call_args_list]

    def test_affinity_returning_none_skips_cpuid(self) -> None:
        module = self._make_module({self.START_CPU: True, 0: False}, {0: 'none'})
        self._run(module)

        module.cs.hals.cpu.cpuid.assert_not_called()
        self.assertIn(SGX_UNSUPPORTED_MSG, self._bad_msgs(module))
        self.assertNotIn(SGX_SUPPORTED_MSG, self._good_msgs(module))

    def test_affinity_raising_skips_cpuid(self) -> None:
        module = self._make_module({self.START_CPU: True, 0: False}, {0: 'raise'})
        self._run(module)

        module.cs.hals.cpu.cpuid.assert_not_called()
        self.assertIn(SGX_UNSUPPORTED_MSG, self._bad_msgs(module))
        self.assertNotIn(SGX_SUPPORTED_MSG, self._good_msgs(module))

    def test_failed_cpu_then_successful_cpu_uses_only_pinned_result(self) -> None:
        for failure in ('none', 'raise'):
            with self.subTest(failure=failure):
                module = self._make_module({self.START_CPU: True, 0: False, 1: False}, {0: failure})
                self._run(module)

                self.assertEqual(module.cs.hals.cpu.cpuid.call_count, 1)
                self.assertIn(SGX_UNSUPPORTED_MSG, self._bad_msgs(module))
                self.assertNotIn(SGX_SUPPORTED_MSG, self._good_msgs(module))

    def test_failed_cpu_then_successful_sgx_cpu_reports_supported(self) -> None:
        for failure in ('none', 'raise'):
            with self.subTest(failure=failure):
                module = self._make_module({self.START_CPU: False, 0: False, 1: True}, {0: failure})
                self._run(module)

                self.assertEqual(module.cs.hals.cpu.cpuid.call_count, 1)
                self.assertIn(SGX_SUPPORTED_MSG, self._good_msgs(module))
                self.assertNotIn(SGX_UNSUPPORTED_MSG, self._bad_msgs(module))


if __name__ == '__main__':
    unittest.main()
