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
To execute: python[3] -m unittest tests.utilcmd.iommu_cmd.test_iommu_cmd
"""

import unittest
import os

from chipsec.library.file import get_main_dir
from tests.utilcmd.run_chipsec_util import setup_run_destroy_util
from chipsec.testcase import ExitCode


class TestIommuUtilcmd(unittest.TestCase):
    def test_list(self) -> None:
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate.json")
        iommu_dump_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "iommu_cmd", "iommu_cmd_list_1.json")
        retval = setup_run_destroy_util(init_replay_file, "iommu", "list", util_replay_file=iommu_dump_replay_file)
        self.assertEqual(retval, ExitCode.OK)

    def test_config(self) -> None:
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate.json")
        iommu_dump_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "iommu_cmd", "iommu_cmd_config_1.json")
        retval = setup_run_destroy_util(init_replay_file, "iommu", "config", util_replay_file=iommu_dump_replay_file)
        self.assertEqual(retval, ExitCode.OK)

    def test_config_vtd(self) -> None:
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate.json")
        iommu_dump_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "iommu_cmd", "iommu_cmd_config_vtd_1.json")
        retval = setup_run_destroy_util(init_replay_file, "iommu", "config VTD", util_replay_file=iommu_dump_replay_file)
        self.assertEqual(retval, ExitCode.OK)

    def test_pt(self) -> None:
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate.json")
        iommu_dump_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "iommu_cmd", "iommu_cmd_pt_1.json")
        retval = setup_run_destroy_util(init_replay_file, "iommu", "pt", util_replay_file=iommu_dump_replay_file)
        self.assertEqual(retval, ExitCode.OK)

    def test_status(self) -> None:
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate.json")
        iommu_dump_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "iommu_cmd", "iommu_cmd_status_1.json")
        retval = setup_run_destroy_util(init_replay_file, "iommu", "status", util_replay_file=iommu_dump_replay_file)
        self.assertEqual(retval, ExitCode.OK)

    def test_status_gfxvtd(self) -> None:
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate.json")
        iommu_dump_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "iommu_cmd", "iommu_cmd_status_gfxvtd_1.json")
        retval = setup_run_destroy_util(init_replay_file, "iommu", "status GFXVTD", util_replay_file=iommu_dump_replay_file)
        self.assertEqual(retval, ExitCode.OK)


if __name__ == '__main__':
    unittest.main()
