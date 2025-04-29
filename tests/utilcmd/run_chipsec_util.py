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
from typing import Tuple, List
import chipsec.helper.replay.replayhelper as rph
from chipsec_util import ChipsecUtil, parse_args
import chipsec.library.logger


def run_chipsec_util(csu: ChipsecUtil, util_replay_file: str) -> int:
    csu._cs.init(csu._platform, csu._pch, csu._helper, not csu._no_driver, csu._load_config, csu._ignore_platform)
    if util_replay_file:
        csu._helper.config_file = util_replay_file
        csu._helper._load()
    comm = csu.commands[csu._cmd](csu._cmd_args, cs=csu._cs)
    comm.parse_arguments()
    comm.set_up()
    comm.run()
    comm.tear_down()
    return comm.ExitCode


def setup_run_destroy_util_get_log_output(init_replay_file: str, util_name: str, util_args: str = "", util_replay_file: str = "", logging_fucntions_to_capture: List = ['log']) -> Tuple[int, str]:
    chipsec.library.logger._logger.remove_chipsec_logger()
    chipsec.library.logger._logger = Mock()
    chipsec.library.logger._logger.VERBOSE = False
    chipsec.library.logger._logger.DEBUG = False
    chipsec.library.logger._logger.HAL = False
    arg_str = f" {util_args}" if util_args else ""
    cli_cmds = f"{util_name}{arg_str}".strip().split(' ')
    par = parse_args(cli_cmds)
    csu = ChipsecUtil(par, cli_cmds)
    replayHelper = rph.ReplayHelper(init_replay_file)
    csu._helper = replayHelper
    retval = run_chipsec_util(csu, util_replay_file)
    logger_calls = []
    for func in logging_fucntions_to_capture:
        if hasattr(chipsec.library.logger._logger, func):
            logger_calls += getattr(chipsec.library.logger._logger, func).mock_calls
    chipsec.library.logger._logger = chipsec.library.logger.Logger()
    return retval, " ".join([call.args[0] for call in logger_calls])


def setup_run_destroy_util(init_replay_file: str, util_name: str, util_args: str = "", util_replay_file: str = "") -> int:
    retval, _ = setup_run_destroy_util_get_log_output(init_replay_file, util_name, util_args, util_replay_file)
    return retval
