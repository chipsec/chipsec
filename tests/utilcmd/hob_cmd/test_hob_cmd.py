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

"""
To execute: python[3] -m unittest tests.utilcmd.hob_cmd.test_hob_cmd
"""

import os
import shutil
import tempfile
import unittest

from unittest.mock import MagicMock

from chipsec.library.uefi.hob import Hob, EFI_HOB_TYPE_FV, EFI_HOB_TYPE_END_OF_HOB_LIST
from chipsec.utilcmd.hob_cmd import HOBCommand


class TestHOBChipsecUtil(unittest.TestCase):
    """Test the 'hob list' and 'hob dump' commands.

    These exercise the command logic (EFI-environment guard and per-HOB file
    dumping) with the HOB HAL mocked, so no live memory / replay data is needed.
    """

    def setUp(self):
        self._cwd = os.getcwd()
        self._tmpdir = tempfile.mkdtemp()
        os.chdir(self._tmpdir)

    def tearDown(self):
        os.chdir(self._cwd)
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _make_command(self, is_efi: bool = True) -> HOBCommand:
        cs = MagicMock()
        cs.os_helper.is_efi.return_value = is_efi
        cmd = HOBCommand([], cs=cs)
        # Mock the logger so set_log_file / log calls do not touch real files.
        cmd.logger = MagicMock()
        cmd.hob_type = None
        cmd.guid = None
        return cmd

    def test_list_not_efi_warns(self):
        cmd = self._make_command(is_efi=False)
        cmd.hob_list()
        cmd.logger.log_warning.assert_called_once()

    def test_list_efi_calls_dump(self):
        cmd = self._make_command(is_efi=True)
        cmd.hob_list()
        cmd.cs.hals.hob.dump_HOB_list.assert_called_once_with(None, None)

    def test_list_passes_filters_through(self):
        cmd = self._make_command(is_efi=True)
        cmd.hob_type = 0x4
        cmd.guid = 'EA296D92'
        cmd.hob_list()
        cmd.cs.hals.hob.dump_HOB_list.assert_called_once_with(0x4, 'EA296D92')

    def test_dump_not_efi_warns(self):
        cmd = self._make_command(is_efi=False)
        cmd.cs.hals.hob.found = False
        cmd.hob_dump()
        cmd.logger.log_warning.assert_called_once()
        self.assertFalse(os.path.exists("efi_hobs.dir"))

    def test_dump_not_found_logs_and_creates_nothing(self):
        cmd = self._make_command(is_efi=True)
        cmd.cs.hals.hob.found = False
        cmd.hob_dump()
        cmd.logger.log_important.assert_called_once()
        self.assertFalse(os.path.exists("efi_hobs.dir"))

    def test_dump_writes_one_file_per_hob(self):
        cmd = self._make_command(is_efi=True)
        fv = Hob(EFI_HOB_TYPE_FV, 0x18, 0x1000, b"\x05\x00\x18\x00" + b"\x00" * 20)
        end = Hob(EFI_HOB_TYPE_END_OF_HOB_LIST, 0x08, 0x1018, b"\xff\xff\x08\x00\x00\x00\x00\x00")
        cmd.cs.hals.hob.found = True
        cmd.cs.hals.hob.hob_pa = 0x1000
        cmd.cs.hals.hob.filter_HOBs.return_value = [fv, end]

        cmd.hob_dump()

        cmd.cs.hals.hob.filter_HOBs.assert_called_once_with(None, None)
        self.assertTrue(os.path.isdir("efi_hobs.dir"))
        files = sorted(os.listdir("efi_hobs.dir"))
        self.assertEqual(len(files), 2)
        # Filenames encode index, HOB type, and address.
        self.assertTrue(files[0].startswith("hob_0000_0x0005_"))
        self.assertTrue(files[1].startswith("hob_0001_0xFFFF_"))
        # File contents are the raw HOB bytes.
        with open(os.path.join("efi_hobs.dir", files[0]), "rb") as fh:
            self.assertEqual(fh.read(), fv.raw)
        with open(os.path.join("efi_hobs.dir", files[1]), "rb") as fh:
            self.assertEqual(fh.read(), end.raw)

    def test_dump_only_writes_filtered_hobs(self):
        cmd = self._make_command(is_efi=True)
        cmd.hob_type = EFI_HOB_TYPE_FV
        fv = Hob(EFI_HOB_TYPE_FV, 0x18, 0x1000, b"\x05\x00\x18\x00" + b"\x00" * 20)
        cmd.cs.hals.hob.found = True
        cmd.cs.hals.hob.hob_pa = 0x1000
        cmd.cs.hals.hob.filter_HOBs.return_value = [fv]

        cmd.hob_dump()

        cmd.cs.hals.hob.filter_HOBs.assert_called_once_with(EFI_HOB_TYPE_FV, None)
        self.assertEqual(len(os.listdir("efi_hobs.dir")), 1)

    def test_dump_no_match_creates_nothing(self):
        cmd = self._make_command(is_efi=True)
        cmd.guid = 'NOTAGUID'
        cmd.cs.hals.hob.found = True
        cmd.cs.hals.hob.filter_HOBs.return_value = []

        cmd.hob_dump()

        cmd.logger.log_important.assert_called_once()
        self.assertFalse(os.path.exists("efi_hobs.dir"))

    def test_parse_arguments_reads_filters(self):
        cmd = self._make_command()
        cmd.argv = ['list', '0x4', 'EA296D92']
        cmd.parse_arguments()
        self.assertEqual(cmd.func, cmd.hob_list)
        self.assertEqual(cmd.hob_type, 0x4)
        self.assertEqual(cmd.guid, 'EA296D92')

    def test_parse_arguments_filters_are_optional(self):
        cmd = self._make_command()
        cmd.argv = ['dump']
        cmd.parse_arguments()
        self.assertEqual(cmd.func, cmd.hob_dump)
        self.assertIsNone(cmd.hob_type)
        self.assertIsNone(cmd.guid)

    def test_parse_arguments_reads_register(self):
        cmd = self._make_command()
        cmd.argv = ['read', '8086.HOB.PEI_PCD_DATABASE']
        cmd.parse_arguments()
        self.assertEqual(cmd.func, cmd.hob_read)
        self.assertEqual(cmd.register, '8086.HOB.PEI_PCD_DATABASE')

    def test_read_logs_each_matching_register(self):
        cmd = self._make_command(is_efi=True)
        cmd.register = '8086.HOB.PEI_PCD_DATABASE'
        reg = MagicMock()
        reg.address = 0x1000
        reg.__str__.return_value = 'PEI_PCD_DATABASE fields'
        cmd.cs.hals.hob.get_list_by_name.return_value = [reg]

        cmd.hob_read()

        cmd.cs.hals.hob.get_list_by_name.assert_called_once_with('8086.HOB.PEI_PCD_DATABASE')
        logged = [call.args[0] for call in cmd.logger.log.call_args_list]
        self.assertIn('PEI_PCD_DATABASE fields', logged)
        self.assertIn('[0x0000000000001000]', logged)

    def test_read_undeclared_definition_reports_it(self):
        cmd = self._make_command(is_efi=True)
        cmd.register = 'NOT_A_HOB'
        cmd.cs.hals.hob.get_list_by_name.return_value = []
        cmd.cs.hals.hob.get_HOB_definition.return_value = None

        cmd.hob_read()

        cmd.logger.log_important.assert_called_once()
        self.assertIn('No HOB definition declared', cmd.logger.log_important.call_args.args[0])

    def test_read_declared_but_absent_reports_no_match(self):
        cmd = self._make_command(is_efi=True)
        cmd.register = 'PEI_PCD_DATABASE'
        cmd.cs.hals.hob.get_list_by_name.return_value = []
        cmd.cs.hals.hob.get_HOB_definition.return_value = MagicMock()

        cmd.hob_read()

        cmd.logger.log_important.assert_called_once()
        self.assertIn('No HOBs found matching', cmd.logger.log_important.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
