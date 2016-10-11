#!/usr/local/bin/python
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



__version__ = '1.0'

import os
import sys
import time

import chipsec_util
from chipsec.command import BaseCommand

from chipsec.logger  import *
from chipsec.file    import *
from chipsec.hal.ec  import *


# Embedded Controller
class ECCommand(BaseCommand):
    """
    >>> chipsec_util ec dump    [<size>]
    >>> chipsec_util ec command <command>
    >>> chipsec_util ec read    <start_offset> [<size>]
    >>> chipsec_util ec write   <offset> <byte_val>
    >>> chipsec_util ec index   [<offset>]

    Examples:

    >>> chipsec_util ec dump
    >>> chipsec_util ec command 0x001
    >>> chipsec_util ec read    0x2F
    >>> chipsec_util ec write   0x2F 0x00
    >>> chipsec_util ec index
    """
    def requires_driver(self):
        # No driver required when printing the util documentation
        if len(self.argv) < 3:
            return False
        return True

    def run(self):
        if len(self.argv) < 3:
            print ECCommand.__doc__
            return

        op = self.argv[2]
        t = time.time()

        try:
            _ec = EC( self.cs )
        except BaseException, msg:
            print msg
            return

        if ( 'command' == op ):
            cmd   = int(self.argv[3],16)
            self.logger.log( "[CHIPSEC] Sending EC command 0x%X" % cmd )
            _ec.write_command( cmd )
        elif ( 'dump' == op ):
            size = int(self.argv[3],16) if len(self.argv) > 3 else 0x100
            buf = _ec.read_range( 0, size )
            self.logger.log( "[CHIPSEC] EC RAM:" )
            print_buffer( buf )
        elif ( 'read' == op ):
            start_off = int(self.argv[3],16)
            if len(self.argv) > 4:
                size   = int(self.argv[4],16)
                buf = _ec.read_range( start_off, size )
                self.logger.log( "[CHIPSEC] EC memory read: offset 0x%X size 0x%X" % (start_off, size) )
                print_buffer( buf )
            else:
                val = _ec.read_memory( start_off ) if start_off < 0x100 else _ec.read_memory_extended( start_off )
                self.logger.log( "[CHIPSEC] EC memory read: offset 0x%X = 0x%X" % (start_off, val) )
        elif ( 'write' == op ):
            off      = int(self.argv[3],16)
            val      = int(self.argv[4],16)
            self.logger.log( "[CHIPSEC] EC memory write: offset 0x%X = 0x%X" % (off, val) )
            if off < 0x100: _ec.write_memory( off, val )
            else:           _ec.write_memory_extended( off, val )
        elif ( 'index' == op ):
            if len(self.argv) == 3:
                self.logger.log( "[CHIPSEC] EC index I/O: dumping memory..." )
                mem = []
                for off in range(0x10000):
                    mem.append( chr(_ec.read_idx( off )) )
                print_buffer( mem )
                del mem
            elif len(self.argv) == 4:
                off = int(self.argv[3],16)       
                val = _ec.read_idx(off)
                self.logger.log( "[CHIPSEC] EC index I/O: reading memory offset 0x%X: 0x%X" % (off, val) )
        else:
            self.logger.error( "unknown command-line option '%.32s'" % op )
            print ECCommand.__doc__
            return

        self.logger.log( "[CHIPSEC] (ec) time elapsed %.3f" % (time.time()-t) )


commands = { 'ec': ECCommand }
