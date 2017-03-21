#!/usr/bin/env python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2016, Intel Corporation
# 
#This program is free software; you can redistribute it and/or
#modify it under the terms of the GNU General Public License
#as published by the Free Software Foundation; Version 2.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with this program; if not, write to the Free Software
#Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
#Contact information:
#chipsec@intel.com
#



"""
Standalone utility
"""

__version__ = '1.3.0'

import re
import os
import sys
import time
import importlib
import imp
import getopt

from chipsec.logger  import logger
from chipsec.chipset import UnknownChipsetError

logger().UTIL_TRACE = True

class ExitCode:
    OK = 0
    EXCEPTION = 32

#CMD_OPTS_WIDTH = [ 'byte', 'word', 'dword', 'qword' ]
CMD_OPTS_WIDTH = [ 'byte', 'word', 'dword' ]
def is_option_valid_width( width_op ):
    return (width_op.lower() in CMD_OPTS_WIDTH)

def get_option_width( width_op ):
    width_op = width_op.lower()
    if   'byte'  == width_op: return 0x1
    elif 'word'  == width_op: return 0x2
    elif 'dword' == width_op: return 0x4
    #elif 'qword' == width_op: return 0x8
    else:               return 0x0


commands = {}

class ChipsecUtil:

    def __init__(self, argv):
        self.global_usage = "CHIPSEC UTILITIES\n\n" + \
                   "All numeric values are in hex\n" + \
                   "<width> is in {1, byte, 2, word, 4, dword}\n\n"
        self.commands = {}
        # determine if CHIPSEC is loaded as chipsec_*.exe or in python
        self.CHIPSEC_LOADED_AS_EXE = True if (hasattr(sys, "frozen") or hasattr(sys, "importers")) else False

        self._platform       = None
        self._unkownPlatform = True
        self._no_driver      = False

        self.show_help = False
        self.help_cmd  = None

        # parse command-line arguments
        self._cmd_args       = None
        self.argv = argv
        self.parse_args()

        from chipsec.chipset import cs
        self._cs = cs()


    def chipsec_util_help(self, command=None):
        """
        Shows the list of available command line extensions
        """
        from chipsec.chipset import Chipset_Code
        logger().log("\nUsage:"
                     "\n\nchipsec_util.py [options] <command>"
                     "\n\nOptions:"
                     "\n-v --verbose          verbose mode"
                     "\n-d --debug            show debug output"
                     "\n-l --log              output to log file"
                     "\n-p --platform         platform code. Should be among the supported platforms:"
                     "\n                      %s"
                     "\n-n --no_driver        don't load chipsec kernel module"
                     "\n-i --ignore_platform  run chipsec even if the platform is not recognized"  % Chipset_Code.keys())
        logger().log("\nAll numeric values are in hex. <width> can be one of {1, byte, 2, word, 4, dword}")

        if command is None or command not in self.commands:
            logger().log("\n<command> can be one of the following:")
            for cmd in sorted(self.commands.keys() + ['help']):
                logger().log( '    %s' % cmd )
        else:
            logger().log("\nhelp for '%s' <command>:" % command)
            logger().log(self.commands[command].__doc__)

    def f_mod_zip(self, x):
        ZIP_UTILCMD_RE = re.compile("^chipsec\/utilcmd\/\w+\.pyc$", re.IGNORECASE)
        return ( x.find('__init__') == -1 and ZIP_UTILCMD_RE.match(x) )
        
    def map_modname_zip(self, x):
        return ((x.split('/', 2)[2]).rpartition('.')[0]).replace('/','.')

    def f_mod(self, x):
        MODFILE_RE = re.compile("^\w+\.py$")
        return ( x.lower().find('__init__') == -1 and MODFILE_RE.match(x.lower()) )
    def map_modname(self, x):
        return x.split('.')[0]


    def parse_args(self):
        import getopt
        try:
            opts, args = getopt.getopt(self.argv, "ip:h:vdnl:", ["ignore_platform", "platform=", "help=", "verbose", "debug", "no_driver", "log="])
        except getopt.GetoptError, err:
            logger().error(str(err))
            self.chipsec_util_help()
            sys.exit(ExitCode.EXCEPTION)
        self._cmd_args = args
        for o, a in opts:
            if o in ("-v", "--verbose"):
                logger().VERBOSE = True
                logger().HAL     = True
                logger().DEBUG   = True
            elif o in ("-d", "--debug"):
                logger().DEBUG   = True
            elif o in ("-h", "--help"):
                self.show_help = True
                self.help_cmd  = a
            elif o in ("-p", "--platform"):
                self._platform = a.upper()
            elif o in ("-i", "--ignore_platform"):
                self._unkownPlatform = False
                logger().log( "[*] Ignoring unsupported platform warning and continue execution" )
            elif o in ("-l", "--log"):
                self.set_logfile(a)
            elif o in ("-n", "--no_driver"):
                self._no_driver = True
            else:
                pass



    ##################################################################################
    # Entry point
    ##################################################################################


    def main(self):
        """
        Receives and executes the commands
        """
        self.print_banner()

        #import traceback
        if self.CHIPSEC_LOADED_AS_EXE:
            import zipfile
            myzip = zipfile.ZipFile("library.zip")
            cmds = map( self.map_modname_zip, filter(self.f_mod_zip, myzip.namelist()) )
        else:
            #traceback.print_stack()
            mydir = imp.find_module('chipsec')[1]
            cmds_dir = os.path.join(mydir,os.path.join("utilcmd"))
            cmds = map( self.map_modname, filter(self.f_mod, os.listdir(cmds_dir)) )

        if logger().VERBOSE:
            logger().log( '[CHIPSEC] Loaded command-line extensions:' )
            logger().log( '   %s' % cmds )
        module = None
        for cmd in cmds:
            try:
                cmd_path = 'chipsec.utilcmd.' + cmd
                module = importlib.import_module( cmd_path )
                cu = getattr(module, 'commands')
                self.commands.update(cu)
            except ImportError, msg:
                logger().error( "Couldn't import util command extension '%s'" % cmd )
                raise ImportError, msg

        if self.show_help:
            self.chipsec_util_help(self.help_cmd)
            return ExitCode.OK

        # @TODO: change later
        # all util cmds assume 'chipsec_util.py' as the first arg so adding dummy first arg
        if self._cmd_args:
            cmd = self._cmd_args[0]
            self.argv = ['dummy'] + self._cmd_args
        else:
            cmd = 'help'
            self.argv = ['dummy']

        if self.commands.has_key( cmd ):
            comm = self.commands[cmd](self.argv, cs = self._cs)

            try:
                self._cs.init( self._platform, comm.requires_driver() and not self._no_driver)
            except UnknownChipsetError, msg:
                logger().warn("*******************************************************************")
                logger().warn("* Unknown platform!")
                logger().warn("* Platform dependent functionality will likely be incorrect")
                logger().warn("* Error Message: \"%s\"" % str(msg))
                logger().warn("*******************************************************************")
            except (None,Exception) , msg:
                logger().error(str(msg))
                sys.exit(ExitCode.EXCEPTION)

            logger().log( "[CHIPSEC] Executing command '%s' with args %s\n" % (cmd,self.argv[2:]) )
            comm.run()
            if comm.requires_driver():
                self._cs.destroy(True)

        elif cmd == 'help':
            if len(self.argv) <= 2:
                self.chipsec_util_help()
            else:
                self.chipsec_util_help(self.argv[2])
        else:
            logger().error( "Unknown command '%.32s'" % cmd )
        return ExitCode.OK

    def set_logfile(self, logfile):
        """
        Calls logger's set_log_file function
        """
        logger().set_log_file(logfile)

    def print_banner(self):
        """
        Prints chipsec banner
        """
        logger().log( '' )
        logger().log( "################################################################\n"
                      "##                                                            ##\n"
                      "##  CHIPSEC: Platform Hardware Security Assessment Framework  ##\n"
                      "##                                                            ##\n"
                      "################################################################" )
        logger().log( "[CHIPSEC] Version %s" % __version__ )

def main(argv=None):
    chipsecUtil = ChipsecUtil(argv if argv else sys.argv[1:])
    return chipsecUtil.main()

       
if __name__ == "__main__":
    sys.exit( main() )

