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
To execute: python[3] -m unittest tests.utilcmd.desc_cmd.test_desc_cmd
"""

import unittest
import os

from chipsec.library.file import get_main_dir
from tests.utilcmd.run_chipsec_util import setup_run_destroy_util
from chipsec.testcase import ExitCode


class TestDescUtilcmd(unittest.TestCase):
    def test_gdt(self) -> None:
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate.json")
        desc_gdt_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "desc_cmd", "gdt_0_1.json")
        retval = setup_run_destroy_util(init_replay_file, "gdt", "0", util_replay_file=desc_gdt_replay_file)
        self.assertEqual(retval, ExitCode.OK)

    def test_idt(self) -> None:
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate.json")
        desc_idt_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "desc_cmd", "idt_0_1.json")
        retval = setup_run_destroy_util(init_replay_file, "idt", "0", util_replay_file=desc_idt_replay_file)
        self.assertEqual(retval, ExitCode.OK)


if __name__ == '__main__':
    unittest.main()
