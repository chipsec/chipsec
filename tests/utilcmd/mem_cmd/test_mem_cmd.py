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
To execute: python[3] -m unittest tests.utilcmd.mem_cmd.test_mem_cmd
"""

import unittest
import os

from chipsec.library.file import get_main_dir
from unittest.mock import patch
from tests.utilcmd.run_chipsec_util import setup_run_destroy_util
from chipsec.testcase import ExitCode

class TestMemUtilCmd(unittest.TestCase):
    def test_readval(self) -> None:
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate.json")
        mem_dump_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "mem_cmd", "mem_cmd_readval_1.json")
        retval = setup_run_destroy_util(init_replay_file, "mem", "readval 0xFED40000 dword", util_replay_file=mem_dump_replay_file)
        self.assertEqual(retval, ExitCode.OK)

    @patch('chipsec.utilcmd.mem_cmd.write_file')
    def test_read(self, mock_write_file) -> None:
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate.json")
        mem_dump_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "mem_cmd", "mem_cmd_read_1.json")
        retval = setup_run_destroy_util(init_replay_file, "mem", "read 0x41E 0x10 mock_buffer.bin", util_replay_file=mem_dump_replay_file)
        self.assertEqual(retval, ExitCode.OK)

    def test_writeval(self) -> None:
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate.json")
        mem_dump_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "mem_cmd", "mem_cmd_writeval_1.json")
        retval = setup_run_destroy_util(init_replay_file, "mem", "writeval 0xA0000 dword 0x9090CCCC", util_replay_file=mem_dump_replay_file)
        self.assertEqual(retval, ExitCode.OK)

    def test_write(self) -> None:
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate.json")
        mem_dump_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "mem_cmd", "mem_cmd_write_1.json")
        retval = setup_run_destroy_util(init_replay_file, "mem", "write 0x100000000 0x10 000102030405060708090A0B0C0D0E0F", util_replay_file=mem_dump_replay_file)
        self.assertEqual(retval, ExitCode.OK)

    def test_allocate(self) -> None:
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate.json")
        mem_dump_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "mem_cmd", "mem_cmd_allocate_1.json")
        retval = setup_run_destroy_util(init_replay_file, "mem", "allocate 0x10000", util_replay_file=mem_dump_replay_file)
        self.assertEqual(retval, ExitCode.OK)

    @patch('chipsec.utilcmd.mem_cmd.open')
    def test_pagedump(self, mock_open) -> None:
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate.json")
        mem_dump_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "mem_cmd", "mem_cmd_allocate_1.json")
        retval = setup_run_destroy_util(init_replay_file, "mem", "pagedump 0xFED00000 0x10", util_replay_file=mem_dump_replay_file)
        self.assertEqual(retval, ExitCode.OK)

    def test_search(self) -> None:
        init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate.json")
        mem_dump_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "mem_cmd", "mem_cmd_allocate_1.json")
        retval = setup_run_destroy_util(init_replay_file, "mem", "search 0xF0000 0x10000 _SM_", util_replay_file=mem_dump_replay_file)
        self.assertEqual(retval, ExitCode.OK)