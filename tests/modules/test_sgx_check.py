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

import unittest
import os
from chipsec.module_common import ModuleResult
import chipsec.helper.replay.replayhelper as rph
from chipsec_main import ChipsecMain, parse_args
from chipsec.file import get_main_dir


class TestSgxCheck(unittest.TestCase):
    def test_sgx_check_warning(self) -> None:
        cli_cmds = "-m common.sgx_check".strip().split(' ')
        par = parse_args(cli_cmds)
        csm = ChipsecMain(par, cli_cmds)
        replayHelper = rph.ReplayHelper(os.path.join(get_main_dir(), "tests", "modules", "sgx_check_1.json"))
        csm._helper = replayHelper
        self.assertEqual(csm.main(), ModuleResult.WARNING)


if __name__ == '__main__':
    unittest.main()
