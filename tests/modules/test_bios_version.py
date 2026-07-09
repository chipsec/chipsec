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
from unittest.mock import Mock

from chipsec.library.returncode import ModuleResult
from chipsec.modules.common.bios_version import bios_version


def _make_mock_self():
    """Build a mock module instance wired to the real methods under test."""
    mock_self = Mock()
    # Bind the real implementations so calls between methods use production code.
    mock_self._get_smbios_string = lambda strings, idx: \
        bios_version._get_smbios_string(mock_self, strings, idx)
    # getReturnCode echoes the ModuleResult so tests can assert on it.
    mock_self.result.getReturnCode.side_effect = lambda res: res
    return mock_self


class TestBiosVersion(unittest.TestCase):

    def test_init(self):
        instance = bios_version()
        self.assertIsInstance(instance, bios_version)

    def test_is_supported_true(self):
        self.assertTrue(bios_version.is_supported(Mock()))

    # ------------------------------------------------------------------
    # _get_smbios_string
    # ------------------------------------------------------------------

    def test_get_smbios_string_valid(self):
        result = bios_version._get_smbios_string(
            Mock(), ['Vendor', '1.2.3', '01/01/2026'], 2)
        self.assertEqual(result, '1.2.3')

    def test_get_smbios_string_index_zero_returns_none(self):
        result = bios_version._get_smbios_string(Mock(), ['A', 'B'], 0)
        self.assertIsNone(result)

    def test_get_smbios_string_out_of_range_returns_none(self):
        result = bios_version._get_smbios_string(Mock(), ['A', 'B'], 3)
        self.assertIsNone(result)

    def test_get_smbios_string_none_strings_returns_none(self):
        self.assertIsNone(bios_version._get_smbios_string(Mock(), None, 1))

    def test_get_smbios_string_empty_list_returns_none(self):
        self.assertIsNone(bios_version._get_smbios_string(Mock(), [], 1))

    def test_get_smbios_string_strips_whitespace(self):
        result = bios_version._get_smbios_string(Mock(), ['  1.2.3  '], 1)
        self.assertEqual(result, '1.2.3')

    def test_get_smbios_string_blank_returns_none(self):
        self.assertIsNone(bios_version._get_smbios_string(Mock(), ['   '], 1))

    # ------------------------------------------------------------------
    # get_bios_version
    # ------------------------------------------------------------------

    def test_get_bios_version_success(self):
        mock_self = _make_mock_self()
        bios_info = Mock(
            vendor_str=1, version_str=2, release_str=3,
            strings=['ACME BIOS', '1.2.3', '01/01/2026'])
        mock_self.cs.hals.smbios.find_smbios_table.return_value = True
        mock_self.cs.hals.smbios.get_decoded_structs.return_value = [bios_info]

        result = bios_version.get_bios_version(mock_self)

        self.assertEqual(result, ModuleResult.INFORMATION)
        logged = ' '.join(str(c.args[0]) for c in mock_self.logger.log.call_args_list)
        self.assertIn('1.2.3', logged)
        self.assertIn('ACME BIOS', logged)
        self.assertIn('01/01/2026', logged)

    def test_get_bios_version_missing_strings_reports_unknown(self):
        mock_self = _make_mock_self()
        bios_info = Mock(
            vendor_str=0, version_str=0, release_str=0, strings=[])
        mock_self.cs.hals.smbios.find_smbios_table.return_value = True
        mock_self.cs.hals.smbios.get_decoded_structs.return_value = [bios_info]

        result = bios_version.get_bios_version(mock_self)

        self.assertEqual(result, ModuleResult.INFORMATION)
        logged = ' '.join(str(c.args[0]) for c in mock_self.logger.log.call_args_list)
        self.assertIn('Unknown', logged)

    def test_get_bios_version_no_table_returns_error(self):
        mock_self = _make_mock_self()
        mock_self.cs.hals.smbios.find_smbios_table.return_value = False

        result = bios_version.get_bios_version(mock_self)

        self.assertEqual(result, ModuleResult.ERROR)
        mock_self.logger.log_error.assert_called_once()

    def test_get_bios_version_no_entries_returns_error(self):
        mock_self = _make_mock_self()
        mock_self.cs.hals.smbios.find_smbios_table.return_value = True
        mock_self.cs.hals.smbios.get_decoded_structs.return_value = []

        result = bios_version.get_bios_version(mock_self)

        self.assertEqual(result, ModuleResult.ERROR)
        mock_self.logger.log_error.assert_called_once()

    # ------------------------------------------------------------------
    # run
    # ------------------------------------------------------------------

    def test_run_starts_test_and_returns_result(self):
        mock_self = Mock()
        mock_self.get_bios_version.return_value = ModuleResult.INFORMATION

        result = bios_version.run(mock_self, [])

        self.assertEqual(result, ModuleResult.INFORMATION)
        mock_self.logger.start_test.assert_called_once()
        mock_self.get_bios_version.assert_called_once()


if __name__ == '__main__':
    unittest.main()
