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

import os
import sys
import importlib
import argparse

from typing import Sequence, Optional, Dict, Any
from chipsec.helper import oshelper
from chipsec.logger import logger, level
from chipsec.banner import print_banner, print_banner_properties
from chipsec.exceptions import UnknownChipsetError
from chipsec.testcase import ExitCode
from chipsec.chipset import cs
from chipsec.file import get_main_dir
from chipsec.defines import get_version, get_message, os_version

CMD_OPTS_WIDTH = ['byte', 'word', 'dword']


def is_option_valid_width(width_op):
    return (width_op.lower() in CMD_OPTS_WIDTH)


def get_option_width(width_op):
    width_op = width_op.lower()
    if 'byte' == width_op:
        return 0x1
    elif 'word' == width_op:
        return 0x2
    elif 'dword' == width_op:
        return 0x4
    else:
        return 0x0


def import_cmds() -> Dict[str, Any]:
    """Determine available chipsec_util commands"""
    # determine if CHIPSEC is loaded as chipsec_*.exe or in python
    CHIPSEC_LOADED_AS_EXE = True if (hasattr(sys, "frozen") or hasattr(sys, "importers")) else False
    if CHIPSEC_LOADED_AS_EXE:
        import zipfile
        myzip = zipfile.ZipFile(os.path.join(get_main_dir(), "library.zip"))
        cmds = [i.replace('/', '.').replace('chipsec.utilcmd.', '')[:-4] for i in myzip.namelist()
                if 'chipsec/utilcmd/' in i and i[-4:] == ".pyc" and not os.path.basename(i)[:2] == '__']
    else:
        cmds_dir = os.path.join(get_main_dir(), "chipsec", "utilcmd")
        cmds = [i[:-3] for i in os.listdir(cmds_dir) if i[-3:] == ".py" and not i[:2] == "__"]

    if logger().DEBUG:
        logger().log('[CHIPSEC] Loaded command-line extensions:')
        logger().log('   {}'.format(cmds))
    module = None
    commands = {}
    for cmd in cmds:
        try:
            cmd_path = 'chipsec.utilcmd.' + cmd
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
    global_usage = "All numeric values are in hex\n<width> is in {1, byte, 2, word, 4, dword}\n\n"
    cmds = import_cmds()
    parser = argparse.ArgumentParser(usage='%(prog)s [options] <command>', add_help=False)
    options = parser.add_argument_group('Options')
    options.add_argument('-h', '--help', dest='show_help', help="show this message and exit", action='store_true')
    options.add_argument('-v', '--verbose', help='verbose mode', action='store_true')
    options.add_argument('--hal', help='HAL mode', action='store_true')
    options.add_argument('-d', '--debug', help='debug mode', action='store_true')
    options.add_argument('-vv', '--vverbose', help='very verbose HAL debug mode', action='store_true')
    options.add_argument('-l', '--log', help='output to log file')
    options.add_argument('-p', '--platform', dest='_platform', help='explicitly specify platform code', choices=cs().chipset_codes, type=str.upper)
    options.add_argument('--pch', dest='_pch', help='explicitly specify PCH code', choices=cs().pch_codes, type=str.upper)
    options.add_argument('-n', '--no_driver', dest='_no_driver', action='store_true',
                         help="chipsec won't need kernel mode functions so don't load chipsec driver")
    options.add_argument('-i', '--ignore_platform', dest='_unknownPlatform', action='store_false',
                         help='run chipsec even if the platform is not recognized')
    options.add_argument('--helper', dest='_driver_exists', help='specify OS Helper', choices=[i for i in oshelper.avail_helpers])
    options.add_argument('_cmd', metavar='Command', nargs='?', choices=sorted(cmds.keys()), type=str.lower, default="help",
                         help="Util command to run: {{{}}}".format(','.join(sorted(cmds.keys()))))
    options.add_argument('_cmd_args', metavar='Command Args', nargs=argparse.REMAINDER, help=global_usage)
    options.add_argument('-nb', '--no_banner', dest='_show_banner', action='store_false', help="chipsec won't display banner information")
    options.add_argument('--skip_config', dest='_load_config', action='store_false', help='skip configuration and driver loading')

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

    def init_cs(self):
        self._cs = cs()

    def parse_switches(self) -> None:
        if self.verbose:
            self.logger.VERBOSE = True
        if self.hal:
            self.logger.HAL = True
        if self.debug:
            self.logger.DEBUG = True
        if self.vverbose:
            self.logger.VERBOSE = True
            self.logger.DEBUG = True
            self.logger.HAL = True
        self.logger.setlevel()
        if self.log:
            self.logger.set_log_file(self.log)
        if not self._cmd_args:
            self._cmd_args = ["--help"]

    ##################################################################################
    # Entry point
    ##################################################################################

    def main(self) -> int:
        """Receives and executes the commands"""

        if self._show_banner:
            print_banner(self.argv, get_version(), get_message())

        self.init_cs()

        # @TODO: change later
        # all util cmds assume 'chipsec_util.py' as the first arg so adding dummy first arg
        self.argv = ['dummy'] + [self._cmd] + self._cmd_args
        comm = self.commands[self._cmd](self.argv, cs=self._cs)

        if self._load_config:
            try:
                self._cs.init(self._platform, self._pch, comm.requires_driver() and not self._no_driver,
                              self._driver_exists)
            except UnknownChipsetError as msg:
                self.logger.log("*******************************************************************\n"
                                "* Unknown platform!\n"
                                "* Platform dependent functionality will likely be incorrect\n"
                                f"* Error Message: \"{str(msg)}\"\n"
                                "*******************************************************************", level.WARNING)
                if self._unknownPlatform:
                    self.logger.log('To run anyways please use -i command-line option\n\n', level.ERROR)
                    sys.exit(ExitCode.OK)
            except Exception as msg:
                self.logger.log(str(msg), level.ERROR)
                sys.exit(ExitCode.EXCEPTION)

            if self._show_banner:
                print_banner_properties(self._cs, os_version())
        else:
            if comm.requires_driver():
                self.logger.log("Cannot run without driver loaded", level.ERROR)
                sys.exit(ExitCode.OK)

        self.logger.log("[CHIPSEC] Executing command '{}' with args {}\n".format(self._cmd, self.argv[2:]))
        comm.run()
        if comm.requires_driver() and not self._no_driver:
            self._cs.destroy(True)
        return comm.ExitCode


def main(argv: Sequence[str] = sys.argv[1:]) -> int:
    par = parse_args(argv)
    if par is not None:
        chipsecMain = ChipsecUtil(par, argv)
        return chipsecMain.main()
    return ExitCode.OK


if __name__ == "__main__":
    sys.exit(main())
