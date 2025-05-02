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
To execute: python[3] -m unittest tests.utilcmd.vmem_cmd.test_vmem_cmd
"""

import unittest
import os

from chipsec.library.file import get_main_dir
from unittest.mock import patch
from tests.utilcmd.run_chipsec_util import setup_run_destroy_util_get_log_output
from chipsec.testcase import ExitCode


class TestVmemUtilCmd(unittest.TestCase):
    def test_readval(self) -> None:
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate.json")
        vmem_dump_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "vmem_cmd", "vmem_cmd_readval_1.json")
        retval, log_call_string = setup_run_destroy_util_get_log_output(init_replay_file, "mem", "readval 0xFED40000 dword", util_replay_file=vmem_dump_replay_file)
        self.assertEqual(retval, ExitCode.OK)

    @patch('chipsec.utilcmd.vmem_cmd.write_file')
    def test_read(self, mock_write_file) -> None:
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate.json")
        vmem_dump_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "vmem_cmd", "vmem_cmd_read_1.json")
        retval, log_call_string = setup_run_destroy_util_get_log_output(init_replay_file, "vmem", "read 0x41E 0x10 mock_buffer.bin", util_replay_file=vmem_dump_replay_file)
        self.assertRegex(log_call_string, r'41E.*0x10')
        self.assertEqual(retval, ExitCode.OK)

    def test_writeval(self) -> None:
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate.json")
        vmem_dump_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "vmem_cmd", "vmem_cmd_writeval_1.json")
        retval, log_call_string = setup_run_destroy_util_get_log_output(init_replay_file, "vmem", "writeval 0xA0000 dword 0x9090CCCC", util_replay_file=vmem_dump_replay_file)
        self.assertEqual(retval, ExitCode.OK)

    def test_write(self) -> None:
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate.json")
        vmem_dump_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "vmem_cmd", "vmem_cmd_write_1.json")
        retval, log_call_string = setup_run_destroy_util_get_log_output(init_replay_file, "vmem", "write 0x100000000 0x10 000102030405060708090A0B0C0D0E0F", util_replay_file=vmem_dump_replay_file)
        self.assertEqual(retval, ExitCode.OK)

    def test_allocate(self) -> None:
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate.json")
        vmem_dump_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "vmem_cmd", "vmem_cmd_allocate_1.json")
        retval, log_call_string = setup_run_destroy_util_get_log_output(init_replay_file, "vmem", "allocate 0x1000", util_replay_file=vmem_dump_replay_file)
        self.assertEqual(retval, ExitCode.OK)

    def test_search(self) -> None:
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate.json")
        vmem_dump_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "vmem_cmd", "vmem_cmd_allocate_1.json")
        retval, log_call_string = setup_run_destroy_util_get_log_output(init_replay_file, "vmem", "search 0xF0000 0x10 _SM_", util_replay_file=vmem_dump_replay_file)
        self.assertEqual(retval, ExitCode.OK)

    def test_getphys(self) -> None:
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate.json")
        vmem_dump_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "vmem_cmd", "vmem_cmd_getphys_1.json")
        retval, log_call_string = setup_run_destroy_util_get_log_output(init_replay_file, "vmem", "getphys 0xFFFF9752F773F000", util_replay_file=vmem_dump_replay_file)
        self.assertEqual(retval, ExitCode.OK)
