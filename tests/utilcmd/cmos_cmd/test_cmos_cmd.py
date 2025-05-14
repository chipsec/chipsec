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
To execute: python[3] -m unittest tests.utilcmd.cmos_cmd.test_cmos_cmd
"""

import unittest
import os

from chipsec.library.file import get_main_dir
from chipsec.testcase import ExitCode
from tests.utilcmd.run_chipsec_util import setup_run_destroy_util


class TestCmosUtilcmd(unittest.TestCase):
    def test_dump(self) -> None:
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate.json")
        cmos_dump_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "cmos_cmd", "cmos_cmd_dump_1.json")
        retval = setup_run_destroy_util(init_replay_file, "cmos", "dump", util_replay_file=cmos_dump_replay_file)
        self.assertEqual(retval, ExitCode.OK)

    def test_readl(self) -> None:
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate.json")
        cmos_readl_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "cmos_cmd", "cmos_cmd_readl_1.json")
        retval = setup_run_destroy_util(init_replay_file, "cmos", "readl 0x0", util_replay_file=cmos_readl_replay_file)
        self.assertEqual(retval, ExitCode.OK)

    def test_writel(self) -> None:
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate.json")
        cmos_writel_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "cmos_cmd", "cmos_cmd_writel_1.json")
        retval = setup_run_destroy_util(init_replay_file, "cmos", "writel 0x0 0xCC", util_replay_file=cmos_writel_replay_file)
        self.assertEqual(retval, ExitCode.OK)

    def test_readh(self) -> None:
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate.json")
        cmos_readh_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "cmos_cmd", "cmos_cmd_readh_1.json")
        retval = setup_run_destroy_util(init_replay_file, "cmos", "readh 0x0", util_replay_file=cmos_readh_replay_file)
        self.assertEqual(retval, ExitCode.OK)

    def test_writeh(self) -> None:
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate.json")
        cmos_writeh_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "cmos_cmd", "cmos_cmd_writeh_1.json")
        retval = setup_run_destroy_util(init_replay_file, "cmos", "writeh 0x0 0xCC", util_replay_file=cmos_writeh_replay_file)
        self.assertEqual(retval, ExitCode.OK)


if __name__ == '__main__':
    unittest.main()
