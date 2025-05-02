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

# To execute: python[3] -m unittest tests.modules.test_sgx_check

import unittest
import os

from chipsec.library.returncode import ModuleResult
from chipsec.library.file import get_main_dir
from tests.modules.run_chipsec_module import setup_run_destroy_module


class TestSgxCheck(unittest.TestCase):
    def test_sgx_check_warning(self) -> None:
        init_replay_file = os.path.join(get_main_dir(), "tests", "modules", "adlenumerate.json")
        sgx_replay_file = os.path.join(get_main_dir(), "tests", "modules", "sgx_check_1.json")
        retval = setup_run_destroy_module(init_replay_file, "common.sgx_check", module_replay_file=sgx_replay_file)
        self.assertEqual(retval, ModuleResult.WARNING.value)


if __name__ == '__main__':
    unittest.main()
