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
To execute: python[3] -m unittest tests.utilcmd.acpi_cmd.test_acpi_cmd
"""

import unittest
import os

from chipsec.library.file import get_main_dir
from tests.utilcmd.run_chipsec_util import setup_run_destroy_util
from chipsec.testcase import ExitCode

class TestAcpiUtilcmd(unittest.TestCase):
    def test_list(self) -> None:
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate.json")
        acpi_list_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "acpi_cmd", "acpi_cmd_list_1.json")
        retval = setup_run_destroy_util(init_replay_file, "acpi", "list", util_replay_file=acpi_list_replay_file)
        self.assertEqual(retval, ExitCode.OK)

    def test_table(self) -> None:
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate.json")
        acpi_table_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "acpi_cmd", "acpi_cmd_table_1.json")
        retval = setup_run_destroy_util(init_replay_file, "acpi", "table XSDT", util_replay_file=acpi_table_replay_file)
        self.assertEqual(retval, ExitCode.OK)

if __name__ == '__main__':
    unittest.main()
