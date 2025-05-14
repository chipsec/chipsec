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
To execute: python[3] -m unittest tests.utilcmd.interrupts_cmd.test_interrupts_cmd
"""

import unittest
import os

from chipsec.library.file import get_main_dir
from tests.utilcmd.run_chipsec_util import setup_run_destroy_util
from chipsec.testcase import ExitCode


class TestInterruptsUtilcmd(unittest.TestCase):
    def test_count(self) -> None:
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate.json")
        interrupts_dump_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "interrupts_cmd", "interrupts_cmd_smi_count_1.json")
        retval = setup_run_destroy_util(init_replay_file, "smi", "count", util_replay_file=interrupts_dump_replay_file)
        self.assertEqual(retval, ExitCode.OK)

    def test_send(self) -> None:
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate.json")
        interrupts_dump_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "interrupts_cmd", "interrupts_cmd_smi_send_1.json")
        retval = setup_run_destroy_util(init_replay_file, "smi", "send 0x0 0xDE 0x0", util_replay_file=interrupts_dump_replay_file)
        self.assertEqual(retval, ExitCode.OK)

    def test_smmc(self) -> None:
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate.json")
        interrupts_dump_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "interrupts_cmd", "interrupts_cmd_smi_smmc_1.json")
        retval = setup_run_destroy_util(init_replay_file, "smi smmc 0x79dfe000 0x79efdfff ed32d533-99e6-4209-9cc02d72cdd998a7 0x79dfaaaa FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", util_replay_file=interrupts_dump_replay_file)
        self.assertEqual(retval, ExitCode.OK)

    def test_nmi(self) -> None:
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate.json")
        interrupts_dump_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "interrupts_cmd", "interrupts_cmd_nmi_1.json")
        retval = setup_run_destroy_util(init_replay_file, "nmi", "", util_replay_file=interrupts_dump_replay_file)
        self.assertEqual(retval, ExitCode.OK)


if __name__ == '__main__':
    unittest.main()
