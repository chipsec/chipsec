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

""""
To execute: python[3] -m unittest tests.utilcmd.ec_cmd.test_ec_cmd
"""

import unittest
import os

from chipsec.library.file import get_main_dir
from tests.utilcmd.run_chipsec_util import setup_run_destroy_util
from chipsec.testcase import ExitCode


class TestEcUtilcmd(unittest.TestCase):
    def test_dump(self) -> None:
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate.json")
        ec_cmd_dump_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "ec_cmd", "ec_cmd_dump_1.json")
        retval = setup_run_destroy_util(init_replay_file, "ec", "dump", util_replay_file=ec_cmd_dump_replay_file)
        self.assertEqual(retval, ExitCode.OK)

    def test_command_1(self) -> None:
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate.json")
        ec_cmd_command_1_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "ec_cmd", "ec_cmd_command_1_1.json")
        retval = setup_run_destroy_util(init_replay_file, "ec", "command 0x001", util_replay_file=ec_cmd_command_1_replay_file)
        self.assertEqual(retval, ExitCode.OK)

    def test_read_2f_1(self) -> None:
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate.json")
        ec_cmd_read_2f_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "ec_cmd", "ec_cmd_read_2f_1.json")
        retval = setup_run_destroy_util(init_replay_file, "ec", "read 0x2f", util_replay_file=ec_cmd_read_2f_replay_file)
        self.assertEqual(retval, ExitCode.OK)

    def test_write_2f_0(self) -> None:
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate.json")
        ec_cmd_write_2f_0_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "ec_cmd", "ec_cmd_write_2f_0_1.json")
        retval = setup_run_destroy_util(init_replay_file, "ec", "write 0x2f 0x00", util_replay_file=ec_cmd_write_2f_0_replay_file)
        self.assertEqual(retval, ExitCode.OK)

    def test_index(self) -> None:
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate.json")
        ec_cmd_index_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "ec_cmd", "ec_cmd_index_1.json")
        retval = setup_run_destroy_util(init_replay_file, "ec", "index", util_replay_file=ec_cmd_index_replay_file)
        self.assertEqual(retval, ExitCode.OK)

    def test_read_2f_4_1(self) -> None:
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate.json")
        ec_cmd_read_2f_4_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "ec_cmd", "ec_cmd_read_2f_4_1.json")
        retval = setup_run_destroy_util(init_replay_file, "ec", "read 0x2f 0x4", util_replay_file=ec_cmd_read_2f_4_replay_file)
        self.assertEqual(retval, ExitCode.OK)


if __name__ == '__main__':
    unittest.main()
