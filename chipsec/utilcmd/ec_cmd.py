# !/usr/bin/python
# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2021, Intel Corporation
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; Version 2.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
# Contact information:
# chipsec@intel.com
#

"""
>>> chipsec_util ec dump    [<size>]
>>> chipsec_util ec command <command>
>>> chipsec_util ec read    <offset> [<size>]
>>> chipsec_util ec write   <offset> <byte_val>
>>> chipsec_util ec index   [<offset>]

Examples:

>>> chipsec_util ec dump
>>> chipsec_util ec command 0x001
>>> chipsec_util ec read    0x2F
>>> chipsec_util ec write   0x2F 0x00
>>> chipsec_util ec index
"""

import time
from argparse import ArgumentParser

from chipsec.command import BaseCommand

from chipsec.logger import print_buffer
from chipsec.hal.ec import EC


# Embedded Controller
class ECCommand(BaseCommand):

    def requires_driver(self):
        parser = ArgumentParser(usage=__doc__)

        parser_offset = ArgumentParser(add_help=False)
        parser_offset.add_argument('offset', type=lambda x: int(x, 0), nargs='?', default=0, help="offset")

        parser_sz = ArgumentParser(add_help=False)
        parser_sz.add_argument("size", type=lambda sz: int(sz, 0), nargs='?', help="size")

        subparsers = parser.add_subparsers()

        parser_command = subparsers.add_parser('command')
        parser_command.add_argument("cmd", type=lambda sz: int(sz, 0), help="EC command to issue")
        parser_command.set_defaults(func=self.command)

        parser_dump = subparsers.add_parser('dump', parents=[parser_sz])
        parser_dump.set_defaults(func=self.dump, size=0x160)

        parser_read = subparsers.add_parser('read', parents=[parser_offset])
        parser_read.set_defaults(func=self.read, size=None)

        parser_write = subparsers.add_parser('write', parents=[parser_offset])
        parser_write.add_argument("wval", type=lambda sz: int(sz, 0), help="byte value to write into EC memory")
        parser_write.set_defaults(func=self.write)

        parser_index = subparsers.add_parser('index', parents=[parser_offset])
        parser_index.set_defaults(func=self.index)

        parser.parse_args(self.argv[2:], namespace=self)
        return hasattr(self, 'func')

    def dump(self):
        self.logger.log("[CHIPSEC] EC dump")

        buf = self._ec.read_range(0, self.size)
        print_buffer(buf)

    def command(self):
        self.logger.log("[CHIPSEC] Sending EC command 0x{:X}".format(self.cmd))

        self._ec.write_command(self.cmd)

    def read(self):
        if self.size:
            buf = self._ec.read_range(self.offset, self.size)
            self.logger.log("[CHIPSEC] EC memory read: offset 0x{:X} size 0x{:X}".format(self.offset, self.size))
            print_buffer(buf)
        else:
            val = self._ec.read_memory(
                self.offset) if self.offset < 0x100 else self._ec.read_memory_extended(self.offset)
            self.logger.log("[CHIPSEC] EC memory read: offset 0x{:X} = 0x{:X}".format(self.start_offset, val))

    def write(self):
        self.logger.log("[CHIPSEC] EC memory write: offset 0x{:X} = 0x{:X}".format(self.offset, self.wval))

        if self.offset < 0x100:
            self._ec.write_memory(self.offset, self.wval)
        else:
            self._ec.write_memory_extended(self.offset, self.wval)

    def index(self):

        if self.offset:
            val = self._ec.read_idx(self.offset)
            self.logger.log("[CHIPSEC] EC index I/O: reading memory offset 0x{:X}: 0x{:X}".format(self.offset, val))
        else:
            self.logger.log("[CHIPSEC] EC index I/O: dumping memory...")
            mem = []
            for off in range(0x10000):
                mem.append(chr(self._ec.read_idx(off)))
            print_buffer(mem)

    def run(self):
        t = time.time()
        try:
            self._ec = EC(self.cs)
        except BaseException as msg:
            print(msg)
            return
        self.func()
        self.logger.log("[CHIPSEC] (ec) time elapsed {:.3f}".format(time.time() - t))


commands = {'ec': ECCommand}
