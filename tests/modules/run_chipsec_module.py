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


from unittest.mock import Mock

import chipsec.helper.replay.replayhelper as rph
from chipsec_main import ChipsecMain, parse_args
import chipsec.logger


def run_chipsec_module(csm: ChipsecMain, module_replay_file: str) -> int:
    csm._cs.init(csm._platform, csm._pch, csm._helper, not csm._no_driver, csm._load_config, csm._ignore_platform)
    if module_replay_file:
        csm._helper.config_file = module_replay_file
        csm._helper._load()
    csm.load_module(csm._module, csm._module_argv)
    ret = csm.run_loaded_modules()
    return ret

def setup_run_destroy_module(init_replay_file: str, module_str: str, module_args: str = "", module_replay_file: str = "") -> int:
    chipsec.logger._logger = Mock()
    arg_str = f" {module_args}" if module_args else ""
    cli_cmds = f"-m {module_str}{arg_str}".strip().split(' ')
    par = parse_args(cli_cmds)
    csm = ChipsecMain(par, cli_cmds)
    replayHelper = rph.ReplayHelper(init_replay_file)
    csm._helper = replayHelper
    retval = run_chipsec_module(csm, module_replay_file)
    chipsec.logger._logger = chipsec.logger.Logger()
    return retval