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

""""
To execute: python[3] -m unittest tests.utilcmd.smbus_cmd.test_smbus_cmd
"""

import unittest
import os

from chipsec.library.file import get_main_dir
from chipsec.testcase import ExitCode
from tests.utilcmd.run_chipsec_util import setup_run_destroy_util


class TestSMBusUtilcmd(unittest.TestCase):
    def test_block_read(self) -> None:
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate.json")
        smbus_block_read_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "smbus_cmd", "smbus_cmd_block_read_1.json")
        retval = setup_run_destroy_util(init_replay_file, "smbus", "block_read 0x50 0x0", util_replay_file=smbus_block_read_replay_file)
        self.assertEqual(retval, ExitCode.OK)

    def test_block_write(self) -> None:
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate.json")
        smbus_block_write_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "smbus_cmd", "smbus_cmd_block_write_1.json")
        retval = setup_run_destroy_util(init_replay_file, "smbus", "block_write 0x50 0x0 0102030405", util_replay_file=smbus_block_write_replay_file)
        self.assertEqual(retval, ExitCode.OK)


if __name__ == '__main__':
    unittest.main()
