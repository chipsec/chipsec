#!/usr/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2019, Intel Corporation
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


import os
import sys
import time
from argparse import ArgumentParser

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
        parser = ArgumentParser(usage=ECCommand.__doc__)
        subparsers = parser.add_subparsers()

        parser_command = subparsers.add_parser('command')
        parser_command.add_argument("cmd",type=lambda sz: int(sz,0),help="EC command to issue")
        parser_command.set_defaults(func=self.command)

        parser_dump = subparsers.add_parser('dump')
        parser_dump.add_argument("size",type=lambda sz: int(sz,0), nargs='?', default=0x160,help="number of EC RAM bytes to read")
        parser_dump.set_defaults(func=self.dump)

        parser_read = subparsers.add_parser('read')
        parser_read.add_argument("start_offset",type=lambda sz: int(sz,0),help="offset to start reading EC memory")
        parser_read.add_argument("size",type=lambda sz: int(sz,0), nargs='?',help="number of EC RAM bytes to read")
        parser_read.set_defaults(func=self.read)

        parser_write = subparsers.add_parser('write')
        parser_write.add_argument("offset",type=lambda sz: int(sz,0),help="offset of byte to write")
        parser_write.add_argument("wval",type=lambda sz: int(sz,0),help="byte value to write into EC memory")
        parser_write.set_defaults(func=self.write)

        parser_index = subparsers.add_parser('index')
        parser_index.add_argument("offset",type=lambda sz: int(sz,0),nargs='?',help="offset to start reading EC memory")
        parser_index.set_defaults(func=self.index)


        parser.parse_args(self.argv[2:], namespace=self)
        if hasattr(self, 'func'):
            return True
        else:
            return False

    def dump(self):
        self.logger.log("[CHIPSEC] EC dump")

        buf = self._ec.read_range(0,self.size)
        print_buffer(buf)

    def command(self):
        self.logger.log("[CHIPSEC] Sending EC command 0x{:X}".format(self.cmd))

        self._ec.write_command(self.cmd)

    def read(self):
        if self.size:
            buf = self._ec.read_range( self.start_offset, self.size )
            self.logger.log("[CHIPSEC] EC memory read: offset 0x{:X} size 0x{:X}".format(self.start_offset, self.size))
            print_buffer(buf)
        else:
            val = self._ec.read_memory(self.start_offset) if self.start_offset < 0x100 else self._ec.read_memory_extended(self.start_offset)
            self.logger.log( "[CHIPSEC] EC memory read: offset 0x{:X} = 0x{:X}".format(self.start_offset, val) )

    def write(self):
        self.logger.log( "[CHIPSEC] EC memory write: offset 0x{:X} = 0x{:X}".format(self.offset, self.wval) )

        if self.offset < 0x100: 
            self._ec.write_memory( self.offset, self.wval )
        else:
            self._ec.write_memory_extended( self.offset, self.wval )
    
    def index(self):

        if self.offset:
            val = self._ec.read_idx(self.offset)
            self.logger.log( "[CHIPSEC] EC index I/O: reading memory offset 0x{:X}: 0x{:X}".format(self.offset, val) )
        else:
            self.logger.log( "[CHIPSEC] EC index I/O: dumping memory..." )
            mem =[]
            for off in range(0x10000):
                mem.append(chr(self._ec.read_idx(off)))
            print_buffer(mem)
            del mem
    
    def run(self):
        t = time.time()
        try:
            self._ec = EC( self.cs )
        except BaseException as msg:
            print (msg)
            return
        self.func()
        self.logger.log( "[CHIPSEC] (ec) time elapsed {:.3f}".format(time.time()-t) )


commands = { 'ec': ECCommand }
