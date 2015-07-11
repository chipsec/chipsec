#!/usr/bin/env python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2015, Intel Corporation
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

__version__ = '1.2.1'

#import glob
import re
import os
import sys
import time
import importlib

from chipsec.logger     import *
from chipsec.file       import *
from chipsec.helper.oshelper   import helper

from chipsec.chipset import cs, UnknownChipsetError
_cs = cs()

#
# If you want to turn verbose logging change this line to True
#
logger().VERBOSE    = False
logger().UTIL_TRACE = True
logger().HAL        = False

# If you want to specify a different platform change this line to a string from chipset.py
# _Platform = 'SNB'
_Platform = None


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

    def __init__(self):
        self.global_usage = "CHIPSEC UTILITIES\n\n" + \
                   "All numeric values are in hex\n" + \
                   "<width> is in {1, byte, 2, word, 4, dword}\n\n"
        self.commands = {}
        self.commands['help'] = {'func' : self.chipsec_util_help, 'start_driver' : False,  'help' : 'chipsec_util help <command>'}
        # determine if CHIPSEC is loaded as chipsec_*.exe or in python
        self.CHIPSEC_LOADED_AS_EXE = True if (hasattr(sys, "frozen") or hasattr(sys, "importers")) else False


    def chipsec_util_help(self, argv):
        """
        Shows the list of available command line extensions
        """
        if len(argv) <= 2:
            logger().log(  '\n[CHIPSEC] chipsec_util command-line extensions should be one of the following:' )
            for cmd in self.commands.keys():
                logger().log( '    %s' % cmd )
                #logger().log( chipsec_util_commands[cmd]['help'] )

        else:
            print self.global_usage
            print "\nHelp for %s command:\n" % argv[2]
            print self.commands[argv[2]]['help']

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

    ##################################################################################
    # Entry point
    ##################################################################################


    def main(self, argv):
        """
        Receives and executes the commands
        """
        global _cs
        #import traceback
        if self.CHIPSEC_LOADED_AS_EXE:
            import zipfile
            myzip = zipfile.ZipFile("library.zip")
            cmds = map( self.map_modname_zip, filter(self.f_mod_zip, myzip.namelist()) )
        else:
            #traceback.print_stack()
            mydir = os.path.dirname(__file__)
            cmds_dir = os.path.join(mydir,os.path.join("chipsec","utilcmd"))
            cmds = map( self.map_modname, filter(self.f_mod, os.listdir(cmds_dir)) )

        if logger().VERBOSE:
            logger().log( '[CHIPSEC] Loaded command-line extensions:' )
            logger().log( '   %s' % cmds )
        exit_code = 0
        module = None
        for cmd in cmds:
            try:
                #exec 'from chipsec.utilcmd.' + cmd + ' import *'
                cmd_path = 'chipsec.utilcmd.' + cmd
                module = importlib.import_module( cmd_path )
                cu = getattr(module, 'chipsec_util')
                self.commands.update(cu.commands)
            except ImportError, msg:
                logger().error( "Couldn't import util command extension '%s'" % cmd )
                raise ImportError, msg

        if 1 < len(argv):
            cmd = argv[ 1 ]
            if self.commands.has_key( cmd ):
                if self.commands[ cmd ]['start_driver']:
                    try:
                        _cs.init( _Platform, True )
                    except UnknownChipsetError, msg:
                        logger().warn("*******************************************************************")
                        logger().warn("* Unknown platform!")
                        logger().warn("* Platform dependent functionality will likely be incorrect")
                        logger().warn("* Error Message: \"%s\"" % str(msg))
                        logger().warn("*******************************************************************")
                    except (None,Exception) , msg:
                        logger().error(str(msg))
                        exit(-1)

                logger().log( "[CHIPSEC] Executing command '%s' with args %s\n" % (cmd,argv[2:]) )
                self.commands[ cmd ]['func']( argv )

                if self.commands[ cmd ]['start_driver']: _cs.destroy( True )
            else:
                logger().error( "Unknown command '%.32s'" % cmd )
        else:
            logger().error( "Not enough parameters" )
            self.chipsec_util_help([])
            del _cs
            exit_code = 32
        return exit_code

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

        
if __name__ == "__main__":
    argv = sys.argv
    chipsecUtil = ChipsecUtil()
    chipsecUtil.print_banner()
    ec = chipsecUtil.main(argv)
    sys.exit(ec)


