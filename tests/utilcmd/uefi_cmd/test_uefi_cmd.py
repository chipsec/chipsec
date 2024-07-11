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
To execute: python[3] -m unittest tests.utilcmd.uefi_cmd.test_uefi_cmd
"""

import unittest
import os
from unittest.mock import patch

from chipsec.library.file import get_main_dir
from tests.utilcmd.run_chipsec_util import setup_run_destroy_util
from chipsec.testcase import ExitCode

"""
>>> chipsec_util uefi var-list
>>> chipsec_util uefi var-find db
>>> chipsec_util uefi var-read db D719B2CB-3D3A-4596-A3BC-DAD00E67656F
>>> chipsec_util uefi var-write db D719B2CB-3D3A-4596-A3BC-DAD00E67656F
>>> chipsec_util uefi var-delete db D719B2CB-3D3A-4596-A3BC-DAD00E67656F
>>> chipsec_util uefi nvram uefi.rom vss_auth
>>> chipsec_util uefi keys db.bin
>>> chipsec_util uefi tables
"""


class TestUefiUtilcmd(unittest.TestCase):
    @patch('chipsec.library.file.write_file', spec=True)
    def test_var_list(self, mock_write_file):
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate.json")
        uefi_var_list_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "uefi_cmd", "uefi_cmd_var-list_1.json")
        retval = setup_run_destroy_util(init_replay_file, "uefi", "var-list", util_replay_file=uefi_var_list_replay_file)
        self.assertEqual(retval, ExitCode.OK)

    @patch('chipsec.library.file.write_file', spec=True)
    def test_var_find_name(self, mock_write_file):
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate.json")
        uefi_var_find_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "uefi_cmd", "uefi_cmd_var-find_1.json")
        retval = setup_run_destroy_util(init_replay_file, "uefi", "var-find db", util_replay_file=uefi_var_find_replay_file)
        self.assertEqual(retval, ExitCode.OK)

    @patch('chipsec.library.file.write_file', spec=True)
    def test_var_find_guid(self, mock_write_file):
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate.json")
        uefi_var_find_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "uefi_cmd", "uefi_cmd_var-find_1.json")
        retval = setup_run_destroy_util(init_replay_file, "uefi", "var-find D719B2CB-3D3A-4596-A3BC-DAD00E67656F", util_replay_file=uefi_var_find_replay_file)
        self.assertEqual(retval, ExitCode.OK)
    
    def test_var_read(self):
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate.json")
        uefi_var_read_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "uefi_cmd", "uefi_cmd_var-read_1.json")
        retval = setup_run_destroy_util(init_replay_file, "uefi", "var-read db D719B2CB-3D3A-4596-A3BC-DAD00E67656F", util_replay_file=uefi_var_read_replay_file)
        self.assertEqual(retval, ExitCode.OK)