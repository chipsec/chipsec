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

from chipsec.library.file import get_main_dir
from chipsec.testcase import ExitCode
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
            except OSError:
                pass

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
        missing_path = os.path.join(tempfile.gettempdir(), "chipsec_nonexistent_fw.bin")
        retval = setup_run_destroy_util(
            self.init_replay_file, "uefi", f"decode {missing_path}"
        )
        self.assertEqual(retval, ExitCode.ERROR)


if __name__ == "__main__":
    unittest.main()
