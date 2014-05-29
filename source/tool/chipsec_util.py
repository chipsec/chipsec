#!/usr/local/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2014, Intel Corporation
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




#
## \addtogroup core
# __chipsec_util.py__ - standalone utility
#

__version__ = '1.0'

#import glob
import re
import os
import sys
import time

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

global_usage = "CHIPSEC UTILITIES\n\n" + \
               "All numeric values are in hex\n" + \
               "<width> is in {1, byte, 2, word, 4, dword}\n\n"

def help(argv):
    print "\n[CHIPSEC] chipsec_util command-line extensions should be one of the following:"
    for cmd in chipsec_util_commands.keys():
        print cmd
    print global_usage

chipsec_util_commands = {}
chipsec_util_commands['help'] = {'func' : help, 'start_driver' : False  }


ZIP_UTILCMD_RE = re.compile("^chipsec\/utilcmd\/\w+\.pyc$", re.IGNORECASE)
def f_mod_zip(x):
    return ( x.find('__init__') == -1 and ZIP_UTILCMD_RE.match(x) )
def map_modname_zip(x):
    return ((x.split('/', 2)[2]).rpartition('.')[0]).replace('/','.')

MODFILE_RE = re.compile("^\w+\.py$")
def f_mod(x):
    return ( x.find('__init__') == -1 and MODFILE_RE.match(x) )
def map_modname(x):
    return x.split('.')[0]

##################################################################################
# Entry point
##################################################################################

# determine if CHIPSEC is loaded as chipsec_*.exe or in python
CHIPSEC_LOADED_AS_EXE = True if (hasattr(sys, "frozen") or hasattr(sys, "importers")) else False
#CHIPSEC_LOADED_AS_EXE = not sys.argv[0].endswith('.py')

if __name__ == "__main__":
    
    argv = sys.argv
    
    #import traceback
    if CHIPSEC_LOADED_AS_EXE:
        import zipfile
        myzip = zipfile.ZipFile("library.zip")
        cmds = map( map_modname_zip, filter(f_mod_zip, myzip.namelist()) )
    else:
        #traceback.print_stack()
        mydir = os.path.dirname(__file__)
        cmds_dir = os.path.join(mydir,os.path.join("chipsec","utilcmd"))
        cmds = map( map_modname, filter(f_mod, os.listdir(cmds_dir)) )

    #print "[CHIPSEC] Loaded command-line extensions:"
    #print '   %s' % cmds
    #print ' '

    for cmd in cmds:
        try:
           #__import__('chipsec.utilcmd.' + cmd)
           exec 'from chipsec.utilcmd.' + cmd + ' import *'
        except ImportError, msg:
           logger().error( "Couldn't import util command extension '%s'" % cmd )
           raise ImportError, msg

    if 1 < len(argv):
       cmd = argv[ 1 ]
       if chipsec_util_commands.has_key( cmd ):
          if chipsec_util_commands[ cmd ]['start_driver']:
             try:
                _cs.init( None, True )
             except UnknownChipsetError, msg:
                logger().warn("***************************************************************************************")
                logger().warn("* Unknown platform vendor. Platform dependent functionality is likely incorrect")
                logger().warn("* Error Message: \"%s\"" % str(msg))
                logger().warn("***************************************************************************************")
             except (None,Exception) , msg:
                logger().error(str(msg))
                exit(-1)

          logger().log("[CHIPSEC] Executing command '%s' with args %s"%(cmd,argv[2:]))
          chipsec_util_commands[ cmd ]['func']( argv )

          if chipsec_util_commands[ cmd ]['start_driver']: _cs.destroy( True )
       else:                                
          print "ERROR: Unknown command '%.32s'" % cmd
          print chipsec_util.global_usage
    else:
       print chipsec_util.global_usage

    del _cs
