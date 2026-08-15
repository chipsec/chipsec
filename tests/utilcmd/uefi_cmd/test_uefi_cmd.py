# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2024, Intel Corporation
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
To execute: python[3] -m unittest tests.utilcmd.uefi_cmd.test_uefi_cmd
"""

import os
import shutil
import tempfile
import unittest
import uuid

from unittest.mock import MagicMock

from chipsec.library.logger import logger
from chipsec.library.file import get_main_dir
from chipsec.testcase import ExitCode
from chipsec.utilcmd.uefi_cmd import UEFICommand
from chipsec.library.uefi.hob import Hob, EFI_HOB_TYPE_FV, EFI_HOB_TYPE_END_OF_HOB_LIST
from tests.utilcmd.run_chipsec_util import setup_run_destroy_util


class TestUEFIDecodeChipsecUtil(unittest.TestCase):
    """Test the 'uefi decode' command exposed by chipsec_util."""

    def setUp(self):
        self.init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate.json")
        self._tmpfiles = []

    def tearDown(self):
        for path in self._tmpfiles:
            try:
                if os.path.isfile(path):
                    os.remove(path)
                elif os.path.isdir(path):
                    shutil.rmtree(path)
            except OSError as exc:
                logger().log_error(f"Failed to remove temporary path {path}: {exc}")

    def _make_temp_file(self, content: bytes, suffix: str = ".bin") -> str:
        """Create a temporary file and register it for cleanup."""
        fd, path = tempfile.mkstemp(suffix=suffix)
        os.write(fd, content)
        os.close(fd)
        self._tmpfiles.append(path)
        # Register derived paths that decode_uefi_region may create
        self._tmpfiles.append(path + ".dir")
        self._tmpfiles.append(path + ".UEFI.json")
        self._tmpfiles.append(path + ".UEFI.lst")
        return path

    def test_decode_non_firmware_file_returns_error(self):
        """'uefi decode' must return ExitCode.ERROR for non-firmware input.

        Verifies that parsing a file that contains no EFI firmware volumes
        and no recognizable NVRAM (e.g. a plain-text file) causes the command
        to exit with ExitCode.ERROR rather than ExitCode.OK.
        """
        non_fw_file = self._make_temp_file(b"This is not EFI firmware content.\n")
        retval = setup_run_destroy_util(
            self.init_replay_file, "uefi", f"decode {non_fw_file}"
        )
        self.assertEqual(retval, ExitCode.ERROR)

    def test_decode_missing_file_returns_error(self):
        """'uefi decode' must return ExitCode.ERROR when the input file is absent."""
        missing_path = os.path.join(
            tempfile.gettempdir(), f"chipsec_nonexistent_fw_{uuid.uuid4().hex}.bin"
        )
        retval = setup_run_destroy_util(
            self.init_replay_file, "uefi", f"decode {missing_path}"
        )
        self.assertEqual(retval, ExitCode.ERROR)


class TestUEFIHobChipsecUtil(unittest.TestCase):
    """Test the 'uefi hoblist' and 'uefi hobdump' commands.

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

    def _make_command(self, is_efi: bool = True) -> UEFICommand:
        cs = MagicMock()
        cs.os_helper.is_efi.return_value = is_efi
        cmd = UEFICommand([], cs=cs)
        # Mock the logger so set_log_file / log calls do not touch real files.
        cmd.logger = MagicMock()
        # Mock the UEFI HAL so no hardware access is attempted.
        cmd._uefi = MagicMock()
        return cmd

    def test_hoblist_not_efi_logs_error_and_skips_dump(self):
        cmd = self._make_command(is_efi=False)
        cmd.hoblist()
        cmd.logger.log_error.assert_called_once()
        cmd.cs.hals.hob.dump_HOB_list.assert_not_called()

    def test_hoblist_efi_calls_dump(self):
        cmd = self._make_command(is_efi=True)
        cmd.hoblist()
        cmd.cs.hals.hob.dump_HOB_list.assert_called_once()

    def test_hobdump_not_efi_logs_error_and_skips(self):
        cmd = self._make_command(is_efi=False)
        cmd.hobdump()
        cmd.logger.log_error.assert_called_once()
        cmd.cs.hals.hob.get_HOB_list.assert_not_called()
        self.assertFalse(os.path.exists("efi_hobs.dir"))

    def test_hobdump_not_found_logs_and_creates_nothing(self):
        cmd = self._make_command(is_efi=True)
        cmd.cs.hals.hob.get_HOB_list.return_value = (False, 0, [])
        cmd.hobdump()
        cmd.logger.log_important.assert_called_once()
        self.assertFalse(os.path.exists("efi_hobs.dir"))

    def test_hobdump_writes_one_file_per_hob(self):
        cmd = self._make_command(is_efi=True)
        fv = Hob(EFI_HOB_TYPE_FV, 0x18, 0x1000, b"\x05\x00\x18\x00" + b"\x00" * 20)
        end = Hob(EFI_HOB_TYPE_END_OF_HOB_LIST, 0x08, 0x1018, b"\xff\xff\x08\x00\x00\x00\x00\x00")
        cmd.cs.hals.hob.get_HOB_list.return_value = (True, 0x1000, [fv, end])

        cmd.hobdump()

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


if __name__ == "__main__":
    unittest.main()
