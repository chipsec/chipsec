#!/usr/bin/env python3
# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2021, Intel Corporation
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


"""
Standalone utility
"""

import argparse
import importlib
import os
import sys
from time import time

from typing import Sequence, Optional, Dict, Any
from chipsec.helper.oshelper import helper
from chipsec.library.logger import logger, level
from chipsec.library.banner import print_banner, print_banner_properties
from chipsec.library.exceptions import UnknownChipsetError
from chipsec.library.options import Options
from chipsec.testcase import ExitCode
from chipsec.chipset import cs
from chipsec.library.file import get_main_dir
from chipsec.library.defines import get_version, get_message, os_version

CMD_OPTS_WIDTH = {'byte': 0x1, 'word': 0x2, 'dword': 0x4}


def is_option_valid_width(width_op):
    return (width_op.lower() in CMD_OPTS_WIDTH.keys())


def get_option_width(width_op):
    width_op = width_op.lower()
    return CMD_OPTS_WIDTH.get(width_op, 0)


def import_cmds() -> Dict[str, Any]:
    """Determine available chipsec_util commands"""
    cmds_dir = os.path.join(get_main_dir(), "chipsec", "utilcmd")
    cmds = [i[:-3] for i in os.listdir(cmds_dir) if i[-3:] == ".py" and not i[:2] == "__"]

    if logger().DEBUG:
        logger().log('[CHIPSEC] Loaded command-line extensions:')
        logger().log(f'   {cmds}')
    module = None
    commands = {}
    for cmd in cmds:
        try:
            cmd_path = f'chipsec.utilcmd.{cmd}'
            module = importlib.import_module(cmd_path)
            cu = getattr(module, 'commands')
            commands.update(cu)
        except ImportError as msg:
            # Display the import error and continue to import commands
            logger().log_error(f"Exception occurred during import of {cmd}: '{str(msg)}'")
            continue
    commands.update({"help": ""})
    return commands


def parse_args(argv: Sequence[str]) -> Optional[Dict[str, Any]]:
    """Parse the arguments provided on the command line."""
    options = Options()

    default_helper = options.get_section_data('Util_Config', 'default_helper', None)
    global_usage = "Additional arguments for specific command.\n\n All numeric values are in hex\n<width> is in {1, byte, 2, word, 4, dword}\n\n"
    cmds = import_cmds()
    parser = argparse.ArgumentParser(usage='%(prog)s [options] <command>', add_help=False)
    options = parser.add_argument_group('Options')
    options.add_argument('-h', '--help', dest='show_help', help="Show this message and exit", action='store_true')
    options.add_argument('-v', '--verbose', help='Verbose logging', action='store_true')
    options.add_argument('--hal', help='HAL logging', action='store_true')
    options.add_argument('-d', '--debug', help='Debug logging', action='store_true')
    options.add_argument('-vv', '--vverbose', help='Very verbose logging (Verbose + HAL + Debug)', action='store_true')
    options.add_argument('-l', '--log', help='Output to log file')
    options.add_argument('-p', '--platform', dest='_platform', help='Explicitly specify platform code', choices=cs().Cfg.proc_codes, type=str.upper)
    options.add_argument('--pch', dest='_pch', help='Explicitly specify PCH code', choices=cs().Cfg.pch_codes, type=str.upper)
    options.add_argument('-n', '--no_driver', dest='_no_driver', action='store_true',
                         help="Chipsec won't need kernel mode functions so don't load chipsec driver")
    options.add_argument('-i', '--ignore_platform', dest='_ignore_platform', action='store_true',
                         help='Run chipsec even if the platform is not recognized (Deprecated)')
    options.add_argument('--helper', dest='_helper', help='Specify OS Helper', choices=helper().get_available_helpers(), default=default_helper)
    options.add_argument('-nb', '--no_banner', dest='_show_banner', action='store_false', help="Chipsec won't display banner information")
    options.add_argument('--skip_config', dest='_load_config', action='store_false', help='Skip configuration and driver loading')
    options.add_argument('-nl', dest='_autolog_disable', action='store_true', help="Chipsec won't save logs automatically")
    options.add_argument('-rc', dest='_return_codes', help='Return codes mode', action='store_true')
    options.add_argument('_cmd', metavar='Command', nargs='?', choices=sorted(cmds.keys()), type=str.lower, default="help",
                         help=f"Util command to run: {{{','.join(sorted(cmds.keys()))}}}")
    options.add_argument('_cmd_args', metavar='Command Args', nargs=argparse.REMAINDER, help=global_usage)
    par = vars(parser.parse_args(argv))

    if par['_cmd'] == 'help' or par['show_help']:
        if par['_show_banner']:
            print_banner(argv, get_version(), get_message())
        parser.print_help()
        return None
    else:
        par['commands'] = cmds
        return par


class ChipsecUtil:

    def __init__(self, switches, argv):
        self.logger = logger()
        self.logger.UTIL_TRACE = True
        self.commands = switches['commands']
        self.__dict__.update(switches)
        self.argv = argv
        self.parse_switches()
        self._cs = cs()

    def parse_switches(self) -> None:
        self.logger.set_log_level(self.verbose, self.hal, self.debug, self.vverbose)
        if self.log:
            self.logger.set_log_file(self.log)
            self._autolog_disable = True
        if self._autolog_disable is False:
            self.logger.set_autolog_file()
        if self._return_codes:
            self.logger.log_warning("Return codes feature is currently Work in Progress!!!")
            self._cs.using_return_codes = True

        if not self._cmd_args:
            self._cmd_args = ["--help"]

    ##################################################################################
    # Entry point
    ##################################################################################

    def main(self) -> int:
        """Receives and executes the commands"""
        if self._show_banner:
            print_banner(self.argv, get_version(), get_message())

        comm = self.commands[self._cmd](self._cmd_args, cs=self._cs)
        comm.parse_arguments()
        reqs = comm.requirements()
        if reqs.load_driver() and self._no_driver:
            self.logger.log("Cannot run command without a driver loaded.", level.ERROR)
            return ExitCode.ERROR
            
        if reqs.load_config() and not self._load_config:
            self.logger.log("Cannot run command without a config loaded. Please run with -p and/or --pch if needed.", level.ERROR)
            return ExitCode.ERROR

        try:
            self._cs.init(self._platform, self._pch, self._helper, reqs.load_driver(), reqs.load_config(), self._ignore_platform)
        except UnknownChipsetError as msg:
            self.logger.log_error(f'Platform is not supported ({str(msg)}).')
            self.logger.log_error('To specify a cpu please use -p command-line option')
            self.logger.log_error('To specify a pch please use --pch command-line option\n')
            self.logger.log_error('If the correct configuration is not loaded, results should not be trusted.')
            return ExitCode.EXCEPTION
        except Exception as msg:
            self.logger.log(str(msg), level.ERROR)
            return ExitCode.EXCEPTION

        if self._show_banner:
            print_banner_properties(self._cs, os_version())

        self.logger.log(f"[CHIPSEC] Executing command '{self._cmd}' with args {self._cmd_args}\n")
        
        try:
            comm.set_up()
        except Exception as msg:
            self.logger.log_error(msg)
            return
        
        t = time()
        comm.run()
        self.logger.log(f"[CHIPSEC] Time elapsed {time()-t:.3f}")
        
        comm.tear_down()
        if reqs.load_driver() and not self._no_driver:
            self._cs.destroy_helper()
        return comm.ExitCode


def run(cli_cmd: str = '') -> int:
    cli_cmds = []
    if cli_cmd:
        cli_cmds = cli_cmd.strip().split(' ')
    return main(cli_cmds)


def main(argv: Sequence[str] = sys.argv[1:]) -> int:
    par = parse_args(argv)
    if par is not None:
        chipsecMain = ChipsecUtil(par, argv)
        return chipsecMain.main()
    return ExitCode.OK


if __name__ == "__main__":
    sys.exit(main())
