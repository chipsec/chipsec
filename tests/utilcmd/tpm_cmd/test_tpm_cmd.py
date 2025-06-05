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

""""
To execute: python[3] -m unittest tests.utilcmd.tpm_cmd.test_tpm_cmd
"""

import unittest
from unittest.mock import MagicMock, patch
import os

from chipsec.library.file import get_main_dir
from chipsec.testcase import ExitCode
from tests.utilcmd.run_chipsec_util import setup_run_destroy_util


class TestTpmUtilcmd(unittest.TestCase):
    def test_parse_log(self) -> None:
        pass

    def test_command_pcrread(self) -> None:
        pass

    def test_command_nvread(self) -> None:
        pass

    @patch("chipsec.hal.acpi.ACPI")
    def test_command_startup(self, mock_acpi) -> None:
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate.json")
        tpm_command_startup_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "tpm_cmd", "tpm_cmd_startup_1.json")
        mock_acpi().is_ACPI_table_present.side_effect = [True, False]
        retval = setup_run_destroy_util(init_replay_file, "tpm", "command startup 1", util_replay_file=tpm_command_startup_replay_file)
        self.assertEqual(retval, ExitCode.OK)

    def test_command_continueselftest(self) -> None:
        pass

    def test_command_getcap(self) -> None:
        pass

    def test_command_forceclear(self) -> None:
        pass

    @patch("chipsec.hal.acpi.ACPI")
    def test_state(self, mock_acpi) -> None:
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate.json")
        tpm_command_state_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "tpm_cmd", "tpm_cmd_state_1.json")
        mock_acpi().is_ACPI_table_present.side_effect = [True, False]
        retval = setup_run_destroy_util(init_replay_file, "tpm", "state 0", util_replay_file=tpm_command_state_replay_file)
        self.assertEqual(retval, ExitCode.OK)


if __name__ == '__main__':
    unittest.main()
