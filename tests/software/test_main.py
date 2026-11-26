# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2017, Google
# Copyright (c) 2018-2021, Intel Corporation
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
#

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from typing import Optional, Tuple
from unittest.mock import Mock, patch

import chipsec_main
from chipsec.library import module_helper
from chipsec.library.returncode import ModuleResult, ReturnCode
from chipsec.module import Module
from chipsec.module_common import BaseModule
from chipsec.testcase import ExitCode


class TestChipsecMain(unittest.TestCase):
    """Test the main entry point script."""

    def test_help(self):
        """Run chipsec_main --help"""
        # Basic test. This should run without loading the driver.
        m = chipsec_main.main(['--help'])
        self.assertEqual(ExitCode.OK, m)

    def test_module_enumeration(self):
        """Run chipsec_main --enum_tools"""
        module_helper.enumerate_modules()

    def test_include_path_is_a_list(self):
        pars = chipsec_main.parse_args(['-I', 'chipsec/modules/common'])
        self.assertEqual(['chipsec/modules/common'], pars['IMPORT_PATHS'])

    def test_include_accepts_multiple_paths(self):
        pars = chipsec_main.parse_args(
            ['-I', 'chipsec/modules/common', 'chipsec/modules/tools'])
        self.assertEqual(['chipsec/modules/common', 'chipsec/modules/tools'],
                         pars['IMPORT_PATHS'])

    def test_read_files_in_tool_folder(self):
        res = module_helper.enumerate_modules()
        expected = ['tools.wsmt', 'tools.cpu.sinkhole', 'tools.secureboot.te', 'tools.smm.rogue_mmio_bar', 'tools.smm.smm_ptr', 'tools.uefi.reputation', 'tools.uefi.s3script_modify', 'tools.uefi.scan_blocked', 'tools.uefi.scan_image', 'tools.uefi.uefivar_fuzz', 'tools.vmm.cpuid_fuzz', 'tools.vmm.ept_finder', 'tools.vmm.hypercallfuzz', 'tools.vmm.iofuzz', 'tools.vmm.msr_fuzz', 'tools.vmm.pcie_fuzz', 'tools.vmm.pcie_overlap_fuzz', 'tools.vmm.venom', 'tools.vmm.hv.define', 'tools.vmm.hv.hypercall', 'tools.vmm.hv.hypercallfuzz', 'tools.vmm.hv.synth_dev', 'tools.vmm.hv.synth_kbd', 'tools.vmm.hv.vmbus', 'tools.vmm.hv.vmbusfuzz', 'tools.vmm.vbox.vbox_crash_apicbase', 'tools.vmm.xen.define', 'tools.vmm.xen.hypercall', 'tools.vmm.xen.hypercallfuzz', 'tools.vmm.xen.xsa188']
        for exp in expected:
            self.assertIn(exp, res)

    @patch("chipsec.library.module_helper.logger")
    def test_print_modules_empty_list(self, logger_mock):
        list = []
        module_helper.print_modules(list)
        self.assertTrue(logger_mock().log.called)

    @patch("chipsec.library.module_helper.logger")
    def test_print_modules_one_module(self, logger_mock):
        list = ['common.cpu.cpu_info']
        module_helper.print_modules(list)
        self.assertEqual(logger_mock().log.call_count, len(list) + 1)

    @patch("chipsec_main.print_modules")
    def test_chipsec_main_print_modules(self, print_modules_mock):
        list_module_option = ['-lm']
        chipsec_main.parse_args(list_module_option)
        self.assertTrue(print_modules_mock.called)


class TestChipsecJsonReporting(unittest.TestCase):
    MODULE_NAME = 'synthetic.check'
    MODULE_ID = 0x1234567
    CASES = (
        (ModuleResult.PASSED, ReturnCode.status.SUCCESS, 'Passed', 'Passed', ExitCode.OK),
        (ModuleResult.NOTAPPLICABLE, ReturnCode.status.NOT_APPLICABLE,
         'Passed', 'NotApplicable', ExitCode.NOTAPPLICABLE),
        (ModuleResult.INFORMATION, ReturnCode.status.INFORMATION, 'Passed', 'Information', ExitCode.INFORMATION),
        (ModuleResult.ARCHIVED, ReturnCode.status.ARCHIVED, 'Archived', 'Archived', ExitCode.ARCHIVED),
        (ModuleResult.ERROR, ReturnCode.status.ACCESS_RW, 'Failed', 'Error', ExitCode.ERROR),
        (ModuleResult.FAILED, ReturnCode.status.LOCKS, 'Failed', 'Failed', ExitCode.FAIL),
    )

    def run_report(self, outcome: ModuleResult, status: ReturnCode.status,
                   return_codes: bool, previous: Optional[Path] = None) -> Tuple[int, str]:
        cs = Mock(using_return_codes=False)
        cs.Cfg.get_supported_platforms.return_value = []
        cs.Cfg.get_supported_pchs.return_value = []
        check = Mock(spec=BaseModule)
        check.result = ReturnCode(cs)
        check.is_supported.return_value = outcome != ModuleResult.NOTAPPLICABLE

        def run_check(_args):
            if status != ReturnCode.status.SUCCESS:
                check.result.setStatusBit(status)
            return check.result.getReturnCode(outcome, False)

        check.run.side_effect = run_check
        module = Module(self.MODULE_NAME)
        module.mod_obj = check
        tags = ['ARCHIVED'] if outcome == ModuleResult.ARCHIVED else []
        module.module = SimpleNamespace(TAGS=[], METADATA_TAGS=tags)

        with TemporaryDirectory() as temp_dir:
            report_path = Path(temp_dir) / 'report.json'
            args = ['-nl', '--no_time', '--json', str(report_path)]
            if return_codes:
                args.append('-rc')
            if previous is not None:
                args.extend(['--deltas', str(previous)])
            with patch('chipsec_main.chipset.cs', return_value=cs):
                switches = chipsec_main.parse_args(args)
                assert switches is not None
                app = chipsec_main.ChipsecMain(switches, args)
            app.Loaded_Modules.append((module, []))
            with patch.object(module, 'do_import', return_value=True), \
                    patch.object(module, 'get_module_id', return_value=self.MODULE_ID), \
                    patch.object(app, 'properties', return_value={}):
                exit_code = app.run_loaded_modules()
            if outcome in (ModuleResult.NOTAPPLICABLE, ModuleResult.ARCHIVED):
                check.run.assert_not_called()
            else:
                check.run.assert_called_once()
            return exit_code, report_path.read_text(encoding='utf-8')

    def test_return_code_json_preserves_module_status(self):
        for outcome, status, label, _, _ in self.CASES:
            with self.subTest(outcome=outcome):
                exit_code, report = self.run_report(outcome, status, return_codes=True)
                self.assertEqual(exit_code >> 32, status.value[0])
                expected_id = 0 if outcome == ModuleResult.ARCHIVED else self.MODULE_ID
                self.assertEqual(exit_code & 0xFFFFFFFF, expected_id << 4)
                self.assertEqual(json.loads(report), {
                    self.MODULE_NAME: {'result': label, 'code': f'0x{exit_code:016X}'},
                })

    def test_legacy_json_keeps_result_labels_and_exit_codes(self):
        for outcome, status, _, label, expected_exit_code in self.CASES:
            with self.subTest(outcome=outcome):
                exit_code, report = self.run_report(outcome, status, return_codes=False)
                self.assertEqual(exit_code, expected_exit_code)
                self.assertEqual(json.loads(report), {self.MODULE_NAME: {'result': label}})

    def test_return_code_json_accepts_old_and_new_delta_input(self):
        with TemporaryDirectory() as temp_dir:
            previous = Path(temp_dir) / 'previous.json'
            previous.write_text(json.dumps({self.MODULE_NAME: {'result': 'Failed'}}), encoding='utf-8')
            with patch('chipsec.library.result_deltas.display_deltas') as display_deltas:
                _, report = self.run_report(ModuleResult.PASSED, ReturnCode.status.SUCCESS, True, previous)
                self.assertEqual(display_deltas.call_args[0][0], {
                    self.MODULE_NAME: {'previous': 'Failed', 'current': 'Passed'},
                })
            previous.write_text(report, encoding='utf-8')
            with patch('chipsec.library.result_deltas.display_deltas') as display_deltas:
                _, repeated = self.run_report(ModuleResult.PASSED, ReturnCode.status.SUCCESS, True, previous)
                self.assertEqual(display_deltas.call_args[0][0], {})
            self.assertEqual(report, repeated)
