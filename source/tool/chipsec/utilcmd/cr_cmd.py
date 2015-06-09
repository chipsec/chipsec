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

# ###################################################################
#
# Crs
#
# ###################################################################
def crx(argv):
    """
    >>> chipsec_util cr <cpu_id> <cr_number> [value]

    Examples:

    >>> chipsec_util cr 0 0
    >>> chipsec_util cr 0 4 0x0
    """
    if 4 > len(argv):
        print crx.__doc__
        return

    try:
        cpu_thread_id = int(argv[2],10)
        cr_number = int(argv[3],16)
       
    except:
        print crx.__doc__
        return

    if 5 == len(argv):
        try:
            value = int(argv[4], 16)
        except:
            print crx.__doc__
            return

        logger().log( "[CHIPSEC] CPU: %d write CR%d <- 0x%08X" % (cpu_thread_id, cr_number, value) )
        try:
            chipsec_util._cs.cr.write_cr( cpu_thread_id, cr_number, value )
        except:
            logger().error( "Write CR failed.")
    else:
        try:
            value = chipsec_util._cs.cr.read_cr( cpu_thread_id, cr_number )
            logger().log( "[CHIPSEC] CPU: %d read CR%d -> 0x%08X" % (cpu_thread_id, cr_number, value) )
        except:
            logger().error( "Read CR failed.")

chipsec_util.commands['cr'] = {'func' : crx, 'start_driver' : True, 'help' : crx.__doc__  }

