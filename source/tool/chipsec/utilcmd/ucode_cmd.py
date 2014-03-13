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
# usage as a standalone utility:
#
## \addtogroup standalone
#chipsec_util ucode
#------
#~~~
#chipsec_util ucode id|load|decode [ucode_update_file (in .PDB or .BIN format)] [cpu_id]
#''
#    Examples:
#''
#        chipsec_util ucode id
#        chipsec_util ucode load ucode.bin 0
#        chipsec_util ucode decode ucode.pdb
#~~~

__version__ = '1.0'

import os
import sys
import time

import chipsec_util
from chipsec_util import chipsec_util_commands, _cs

from chipsec.logger     import *
from chipsec.file       import *

from chipsec.hal.ucode  import Ucode, dump_ucode_update_header

#_cs = cs()


usage = "chipsec_util ucode id|load|decode [ucode_update_file (in .PDB or .BIN format)] [cpu_id]\n" + \
        "Examples:\n" + \
        "  chipsec_util ucode id\n" + \
        "  chipsec_util ucode load ucode.bin 0\n" + \
        "  chipsec_util ucode decode ucode.pdb\n\n"

chipsec_util.global_usage += usage


# ###################################################################
#
# Microcode patches
#
# ###################################################################
def ucode(argv):

    if 3 > len(argv):
      print usage
      return

    ucode_op = argv[2]
    t = time.time()

    if ( 'load' == ucode_op ):
       if (4 == len(argv)):
          ucode_filename = argv[3]
          logger().log( "[CHIPSEC] Loading Microcode update on all cores from '%.64s'" % ucode_filename )
          _cs.ucode.update_ucode_all_cpus( ucode_filename )
       elif (5 == len(argv)):
          ucode_filename = argv[3]
          cpu_thread_id = int(argv[4],16)
          logger().log( "[CHIPSEC] Loading Microcode update on CPU%d from '%.64s'" % (cpu_thread_id, ucode_filename) )
          _cs.ucode.update_ucode( cpu_thread_id, ucode_filename )
       else:
          print usage
          return
    elif ( 'decode' == ucode_op ):
       if (4 == len(argv)):
          ucode_filename = argv[3]
          if (not ucode_filename.endswith('.pdb')):
             logger().log( "[CHIPSEC] Ucode update file is not PDB file: '%.256s'" % ucode_filename )
             return
          pdb_ucode_buffer = read_file( ucode_filename )
          logger().log( "[CHIPSEC] Decoding Microcode Update header of PDB file: '%.256s'" % ucode_filename )
          dump_ucode_update_header( pdb_ucode_buffer )
    elif ( 'id' == ucode_op ):
       if (3 == len(argv)):
          for tid in range(_cs.msr.get_cpu_thread_count()):
             ucode_update_id = _cs.ucode.ucode_update_id( tid )
             logger().log( "[CHIPSEC] CPU%d: Microcode update ID = 0x%08X" % (tid, ucode_update_id) )
       elif (4 == len(argv)):
          cpu_thread_id = int(argv[3],16)
          ucode_update_id = _cs.ucode.ucode_update_id( cpu_thread_id )
          logger().log( "[CHIPSEC] CPU%d: Microcode update ID = 0x%08X" % (cpu_thread_id, ucode_update_id) )
    else:
       logger().error( "unknown command-line option '%.32s'" % ucode_op )
       print usage
       return

    logger().log( "[CHIPSEC] (ucode) time elapsed %.3f" % (time.time()-t) )



chipsec_util_commands['ucode'] = {'func' : ucode,   'start_driver' : True  }

