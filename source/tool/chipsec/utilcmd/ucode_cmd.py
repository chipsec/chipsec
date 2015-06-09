#!/usr/local/bin/python
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



__version__ = '1.0'

import os
import sys
import time

import chipsec_util

from chipsec.logger     import *
from chipsec.file       import *

from chipsec.hal.ucode  import Ucode, dump_ucode_update_header

# ###################################################################
#
# Microcode patches
#
# ###################################################################
def ucode(argv):
    """
    >>> chipsec_util ucode id|load|decode [ucode_update_file (in .PDB or .BIN format)] [cpu_id]

    Examples:

    >>> chipsec_util ucode id
    >>> chipsec_util ucode load ucode.bin 0
    >>> chipsec_util ucode decode ucode.pdb
    """
    if 3 > len(argv):
        print ucode.__doc__
        return

    ucode_op = argv[2]
    t = time.time()

    if ( 'load' == ucode_op ):
        if (4 == len(argv)):
            ucode_filename = argv[3]
            logger().log( "[CHIPSEC] Loading Microcode update on all cores from '%s'" % ucode_filename )
            chipsec_util._cs.ucode.update_ucode_all_cpus( ucode_filename )
        elif (5 == len(argv)):
            ucode_filename = argv[3]
            cpu_thread_id = int(argv[4],16)
            logger().log( "[CHIPSEC] Loading Microcode update on CPU%d from '%s'" % (cpu_thread_id, ucode_filename) )
            chipsec_util._cs.ucode.update_ucode( cpu_thread_id, ucode_filename )
        else:
            print ucode.__doc__
            return
    elif ( 'decode' == ucode_op ):
        if (4 == len(argv)):
            ucode_filename = argv[3]
            if (not ucode_filename.endswith('.pdb')):
                logger().log( "[CHIPSEC] Ucode update file is not PDB file: '%s'" % ucode_filename )
                return
            pdb_ucode_buffer = read_file( ucode_filename )
            logger().log( "[CHIPSEC] Decoding Microcode Update header of PDB file: '%s'" % ucode_filename )
            dump_ucode_update_header( pdb_ucode_buffer )
    elif ( 'id' == ucode_op ):
        if (3 == len(argv)):
            for tid in range(chipsec_util._cs.msr.get_cpu_thread_count()):
                ucode_update_id = chipsec_util._cs.ucode.ucode_update_id( tid )
                logger().log( "[CHIPSEC] CPU%d: Microcode update ID = 0x%08X" % (tid, ucode_update_id) )
        elif (4 == len(argv)):
            cpu_thread_id = int(argv[3],16)
            ucode_update_id = chipsec_util._cs.ucode.ucode_update_id( cpu_thread_id )
            logger().log( "[CHIPSEC] CPU%d: Microcode update ID = 0x%08X" % (cpu_thread_id, ucode_update_id) )
    else:
        logger().error( "unknown command-line option '%.32s'" % ucode_op )
        print ucode.__doc__
        return

    logger().log( "[CHIPSEC] (ucode) time elapsed %.3f" % (time.time()-t) )



chipsec_util.commands['ucode'] = {'func' : ucode, 'start_driver' : True, 'help' : ucode.__doc__  }
