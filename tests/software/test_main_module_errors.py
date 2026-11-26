# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2026, Isaac Thor
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

import csv
import json
import unittest
from contextlib import ExitStack
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import Mock, patch

import chipsec_main
from chipsec.library.returncode import ModuleResult, ReturnCode
from chipsec.module import Module
from chipsec.module_common import BaseModule
from chipsec.testcase import ExitCode, TestCase as ResultTestCase

INVALID_CODE = ReturnCode.status.INVALID.value[0]


def legacy_error_code():
    test_case = ResultTestCase('legacy')
    test_case.end_module('Error', ModuleResult.ERROR, '')
    return test_case.get_fields()['code']


LEGACY_ERROR_CODE = legacy_error_code()


def json_results(report):
    return {name: record['result'] for name, record in report.items()}


class TestModuleErrorReporting(unittest.TestCase):
    """Modules that raise or fail to import are reported in legacy and return-code modes."""

    def make_module(self, name, cs, behavior):
        check = Mock(spec=BaseModule)
        check.result = ReturnCode(cs)
        check.is_supported.return_value = True
        if behavior == 'raise':
            check.run.side_effect = RuntimeError('synthetic module failure')
        else:
            check.run.side_effect = lambda _args: check.result.getReturnCode(ModuleResult.PASSED, False)
        module = Module(name)
        module.mod_obj = check
        module.module = SimpleNamespace(TAGS=[], METADATA_TAGS=[])
        return module, check

    def run_modules(self, specs, return_codes, failfast=False):
        """Run (name, behavior) specs through ChipsecMain; behavior is 'pass', 'raise' or 'import_error'."""
        cs = Mock(using_return_codes=False)
        cs.Cfg.get_supported_platforms.return_value = []
        cs.Cfg.get_supported_pchs.return_value = []
        with TemporaryDirectory() as temp_dir:
            json_path = Path(temp_dir) / 'report.json'
            csv_path = Path(temp_dir) / 'report.csv'
            args = ['-nl', '--no_time', '--json', str(json_path), '--csv', str(csv_path)]
            if return_codes:
                args.append('-rc')
            if failfast:
                args.append('--failfast')
            with patch('chipsec_main.chipset.cs', return_value=cs):
                app = chipsec_main.ChipsecMain(chipsec_main.parse_args(args), args)
            checks = {}
            with ExitStack() as stack:
                stack.enter_context(patch.object(app, 'properties', return_value={}))
                for name, behavior in specs:
                    module, checks[name] = self.make_module(name, cs, behavior)
                    stack.enter_context(patch.object(module, 'do_import', return_value=behavior != 'import_error'))
                    stack.enter_context(patch.object(module, 'get_module_id', return_value=0x1234567))
                    app.Loaded_Modules.append((module, []))
                exit_code = app.run_loaded_modules()
            report = json.loads(json_path.read_text(encoding='utf-8'))
            with csv_path.open(newline='', encoding='utf-8') as csv_file:
                rows = {row['name']: row for row in csv.DictReader(csv_file)}
            return exit_code, report, rows, app, checks

    def test_return_code_mode_reports_module_exception_as_error(self):
        exit_code, report, rows, _, checks = self.run_modules([('synthetic.raises', 'raise')], return_codes=True)
        checks['synthetic.raises'].run.assert_called_once_with([])
        self.assertEqual(exit_code, INVALID_CODE)
        self.assertEqual(json_results(report), {'synthetic.raises': 'Failed'})
        self.assertEqual(rows['synthetic.raises']['result'], 'Failed')
        self.assertEqual(rows['synthetic.raises']['code'], f'0x{INVALID_CODE:016X}')

    def test_return_code_mode_reports_import_failure_as_error(self):
        exit_code, report, rows, _, checks = self.run_modules([('synthetic.missing', 'import_error')], return_codes=True)
        checks['synthetic.missing'].run.assert_not_called()
        self.assertEqual(exit_code, INVALID_CODE)
        self.assertEqual(json_results(report), {'synthetic.missing': 'Failed'})
        self.assertEqual(rows['synthetic.missing']['code'], f'0x{INVALID_CODE:016X}')

    def test_return_code_mode_continues_after_module_exception(self):
        specs = [('synthetic.raises', 'raise'), ('synthetic.passes', 'pass')]
        exit_code, report, rows, _, checks = self.run_modules(specs, return_codes=True)
        checks['synthetic.passes'].run.assert_called_once_with([])
        self.assertEqual(exit_code, ExitCode.FAIL)
        self.assertEqual(json_results(report), {'synthetic.raises': 'Failed', 'synthetic.passes': 'Passed'})
        self.assertEqual(rows['synthetic.raises']['code'], f'0x{INVALID_CODE:016X}')
        self.assertEqual(rows['synthetic.passes']['code'], f'0x{0x1234567 << 4:016X}')

    def test_legacy_mode_module_errors_are_unchanged(self):
        for behavior in ('raise', 'import_error'):
            with self.subTest(behavior=behavior):
                exit_code, report, rows, _, _ = self.run_modules([('synthetic.error', behavior)], return_codes=False)
                self.assertEqual(exit_code, ExitCode.ERROR)
                self.assertEqual(report, {'synthetic.error': {'result': 'Error'}})
                self.assertEqual(rows['synthetic.error']['result'], 'Error')
                self.assertEqual(rows['synthetic.error']['code'], LEGACY_ERROR_CODE)

    def test_failfast_reraises_original_module_exception(self):
        for return_codes in (False, True):
            with self.subTest(return_codes=return_codes):
                with self.assertRaisesRegex(RuntimeError, 'synthetic module failure'):
                    self.run_modules([('synthetic.raises', 'raise')], return_codes, failfast=True)


if __name__ == '__main__':
    unittest.main()
