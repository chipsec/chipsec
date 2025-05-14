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
To execute: python[3] -m unittest tests.utilcmd.msr_cmd.test_msr_cmd
"""

import unittest
import os

from chipsec.library.file import get_main_dir
from tests.utilcmd.run_chipsec_util import setup_run_destroy_util
from chipsec.testcase import ExitCode


class TestMsrUtilcmd(unittest.TestCase):
    def test_read(self) -> None:
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate.json")
        msr_read_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "msr_cmd", "msr_read_1.json")
        retval = setup_run_destroy_util(init_replay_file, "msr", "0x3A", util_replay_file=msr_read_replay_file)
        self.assertEqual(retval, ExitCode.OK)

    def test_read_core(self) -> None:
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate.json")
        msr_read_core_0_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "msr_cmd", "msr_read_core_0_1.json")
        retval = setup_run_destroy_util(init_replay_file, "msr", "0x3A 0x0", util_replay_file=msr_read_core_0_replay_file)
        self.assertEqual(retval, ExitCode.OK)

    def test_write(self) -> None:
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate.json")
        msr_write_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "msr_cmd", "msr_write_1.json")
        retval = setup_run_destroy_util(init_replay_file, "msr", "0x8B 0x0 0x0 0x0", util_replay_file=msr_write_replay_file)
        self.assertEqual(retval, ExitCode.OK)


if __name__ == '__main__':
    unittest.main()
