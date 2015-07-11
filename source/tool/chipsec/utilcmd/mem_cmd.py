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
The mem command provides direct access to read and write physical memory.
"""

__version__ = '1.0'

import os
import sys
import time

import chipsec_util

import chipsec.file
import chipsec.logger

from chipsec.logger     import *
from chipsec.file       import *


# Physical Memory
def mem(argv):
    """
    >>> chipsec_util mem <op> <physical_address> <length> [value|buffer_file]
    >>>
    >>> <physical_address> : 64-bit physical address
    >>> <op>               : read|readval|write|writeval|allocate
    >>> <length>           : byte|word|dword or length of the buffer from <buffer_file>
    >>> <value>            : byte, word or dword value to be written to memory at <physical_address>
    >>> <buffer_file>      : file with the contents to be written to memory at <physical_address>

    Examples:

    >>> chipsec_util mem <op>     <physical_address> <length> [value|file]
    >>> chipsec_util mem readval  0xFED40000         dword
    >>> chipsec_util mem read     0x41E              0x20     buffer.bin
    >>> chipsec_util mem writeval 0xA0000            dword    0x9090CCCC
    >>> chipsec_util mem write    0x100000000        0x1000   buffer.bin
    >>> chipsec_util mem write    0x100000000        0x10     000102030405060708090A0B0C0D0E0F
    >>> chipsec_util mem allocate                    0x1000
    """

    phys_address    = 0
    size = 0x100

    if 3 > len(argv):
        print mem.__doc__
        return

    op = argv[2]
    t = time.time()

    if 'allocate'   == op and 4 == len(argv):
        size = int(argv[3],16)
        (va, pa) = chipsec_util._cs.mem.alloc_physical_mem( size )
        logger().log( '[CHIPSEC] Allocated %X bytes of physical memory: VA = 0x%016X, PA = 0x%016X' % (size, va, pa) )

    elif 'read'     == op:
        phys_address = int(argv[3],16)
        size         = int(argv[4],16) if len(argv) > 4 else 0x100
        logger().log( '[CHIPSEC] reading buffer from memory: PA = 0x%016X, len = 0x%X..' % (phys_address, size) )
        buffer = chipsec_util._cs.mem.read_physical_mem( phys_address, size )
        if len(argv) > 5:
            buf_file = argv[5]
            chipsec.file.write_file( buf_file, buffer )
            logger().log( "[CHIPSEC] written 0x%X bytes to '%s'" % (len(buffer), buf_file) )
        else:
            print_buffer( buffer )

    elif 'readval'  == op:
        phys_address = int(argv[3],16)
        width        = 0x4
        if len(argv) > 4: 
            width = chipsec_util.get_option_width(argv[4]) if chipsec_util.is_option_valid_width(argv[4]) else int(argv[4],16)
        logger().log( '[CHIPSEC] reading value from memory: PA = 0x%016X, width = 0x%X..' % (phys_address, size) )
        if   0x1 == width: value = chipsec_util._cs.mem.read_physical_mem_byte ( phys_address )
        elif 0x2 == width: value = chipsec_util._cs.mem.read_physical_mem_word ( phys_address )
        elif 0x4 == width: value = chipsec_util._cs.mem.read_physical_mem_dword( phys_address )
        logger().log( '[CHIPSEC] value = 0x%X' % value )

    elif 'write'    == op:
        phys_address = int(argv[3],16)
        if len(argv) > 4: 
            size = int(argv[4],16)
        else:
            logger().error( "must specify <length> argument in 'mem write'" )
            return
        if len(argv) > 5:
            buf_file = argv[5]
            if not os.path.exists( buf_file ):
                #buffer = buf_file.decode('hex')
                try:
                  buffer = bytearray.fromhex(buf_file)
                except ValueError, e:
                    logger().error( "incorrect <value> specified: '%s'" % buf_file )
                    logger().error( str(e) )
                    return
                logger().log( "[CHIPSEC] read 0x%X hex bytes from command-line: %s'" % (len(buffer), buf_file) )
            else:
                buffer = chipsec.file.read_file( buf_file )
                logger().log( "[CHIPSEC] read 0x%X bytes from file '%s'" % (len(buffer), buf_file) )

            if len(buffer) < size:
                logger().error( "number of bytes read (0x%X) is less than the specified <length> (0x%X)" % (len(buffer),size) )
                return

            logger().log( '[CHIPSEC] writing buffer to memory: PA = 0x%016X, len = 0x%X..' % (phys_address, size) )
            chipsec_util._cs.mem.write_physical_mem( phys_address, size, buffer )
        else:
            logger().error( "must specify <buffer>|<file> argument in 'mem write'" )
            return

    elif 'writeval' == op:
        phys_address = int(argv[3],16)
        if len(argv) > 4: 
            width = chipsec_util.get_option_width(argv[4]) if chipsec_util.is_option_valid_width(argv[4]) else int(argv[4],16)
        else:
            logger().error( "must specify <length> argument in 'mem writeval' as one of %s" % chipsec_util.CMD_OPTS_WIDTH )
            return
        if len(argv) > 5: 
            value = int(argv[5],16)
        else:
            logger().error( "must specify <value> argument in 'mem writeval'" )
            return

        logger().log( '[CHIPSEC] writing value to memory: PA = 0x%016X, width = 0x%X, value = 0x%X..' % (phys_address, width, value) )
        if   0x1 == width: chipsec_util._cs.mem.write_physical_mem_byte ( phys_address, value )
        elif 0x2 == width: chipsec_util._cs.mem.write_physical_mem_word ( phys_address, value )
        elif 0x4 == width: chipsec_util._cs.mem.write_physical_mem_dword( phys_address, value )

    else:
            print mem.__doc__
            return

    logger().log( "[CHIPSEC] (mem) time elapsed %.3f" % (time.time()-t) )

chipsec_util.commands['mem'] = {'func' : mem, 'start_driver' : True, 'help' : mem.__doc__  }
