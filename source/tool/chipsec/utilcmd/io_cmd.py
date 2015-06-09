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



"""
The io command allows direct access to read and write I/O port space.
"""

__version__ = '1.0'

import os
import sys
import time

import chipsec_util

from chipsec.logger     import *
from chipsec.file       import *


# Port I/O
def port_io(argv):
    """
    >>> chipsec_util io <io_port> <width> [value]

    Examples:

    >>> chipsec_util io 0x61 1
    >>> chipsec_util io 0x430 byte 0x0
    """
    if 3 > len(argv):
        print port_io.__doc__
        return

    try:
        io_port = int(argv[2],16)

        if 3 == len(argv):
            width = 1
        else:
            if 'byte' == argv[3]:
                width = 1
            elif 'word' == argv[3]:
                width = 2
            elif 'dword' == argv[3]:
                width = 4
            else:
                width = int(argv[3])
    except:
        print port_io.__doc__
        return

    if 5 == len(argv):
        value = int(argv[4], 16)
        logger().log( "[CHIPSEC] OUT 0x%04X <- 0x%08X (size = 0x%02x)" % (io_port, value, width) )
        if 1 == width:
            chipsec_util._cs.io.write_port_byte( io_port, value )
        elif 2 == width:
            chipsec_util._cs.io.write_port_word( io_port, value )
        elif 4 == width:
            chipsec_util._cs.io.write_port_dword( io_port, value )
        else:
            print "ERROR: Unsupported width 0x%x" % width
            return
    else:
        if 1 == width:
            value = chipsec_util._cs.io.read_port_byte( io_port )
        elif 2 == width:
            value = chipsec_util._cs.io.read_port_word( io_port )
        elif 4 == width:
            value = chipsec_util._cs.io.read_port_dword( io_port )
        else:
            print "ERROR: Unsupported width 0x%x" % width
            return
        logger().log( "[CHIPSEC] IN 0x%04X -> 0x%08X (size = 0x%02x)" % (io_port, value, width) )

chipsec_util.commands['io'] = {'func' : port_io, 'start_driver' : True, 'help' : port_io.__doc__  }
