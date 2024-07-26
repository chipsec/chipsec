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

from argparse import ArgumentParser

from chipsec.command import BaseCommand, toLoad

from chipsec.library.logger import print_buffer_bytes
from chipsec.hal.ec import EC


# Embedded Controller
class ECCommand(BaseCommand):

    def requirements(self) -> toLoad:
        if hasattr(self, 'func'):
            return toLoad.Driver
        return toLoad.Nil

    def parse_arguments(self) -> None:
        parser = ArgumentParser(usage=__doc__)

        parser_offset = ArgumentParser(add_help=False)
        parser_offset.add_argument('offset', type=lambda x: int(x, 0), nargs='?', default=0, help="offset")

        parser_dmpsz = ArgumentParser(add_help=False)
        parser_dmpsz.add_argument("size", type=lambda sz: int(sz, 0), nargs='?', default=0x160, help="size")

        parser_rdsz = ArgumentParser(add_help=False)
        parser_rdsz.add_argument("size", type=lambda sz: int(sz, 0), nargs='?', default=None, help="size")

        subparsers = parser.add_subparsers()

        parser_command = subparsers.add_parser('command')
        parser_command.add_argument("cmd", type=lambda sz: int(sz, 0), help="EC command to issue")
        parser_command.set_defaults(func=self.command)

        parser_dump = subparsers.add_parser('dump', parents=[parser_dmpsz])
        parser_dump.set_defaults(func=self.dump)

        parser_read = subparsers.add_parser('read', parents=[parser_offset, parser_rdsz])
        parser_read.set_defaults(func=self.read)

        parser_write = subparsers.add_parser('write', parents=[parser_offset])
        parser_write.add_argument("wval", type=lambda sz: int(sz, 0), help="byte value to write into EC memory")
        parser_write.set_defaults(func=self.write)

        parser_index = subparsers.add_parser('index', parents=[parser_offset])
        parser_index.set_defaults(func=self.index)

        parser.parse_args(self.argv, namespace=self)
        
    def set_up(self) -> None:
        self._ec = EC(self.cs)

    def dump(self) -> None:
        self.logger.log("[CHIPSEC] EC dump")

        buf = self._ec.read_range(0, self.size)
        print_buffer_bytes(buf)

    def command(self) -> None:
        self.logger.log(f'[CHIPSEC] Sending EC command 0x{self.cmd:X}')

        self._ec.write_command(self.cmd)

    def read(self) -> None:
        if self.size:
            buf = self._ec.read_range(self.offset, self.size)
            self.logger.log(f'[CHIPSEC] EC memory read: offset 0x{self.offset:X} size 0x{self.size:X}')
            print_buffer_bytes(buf)
        else:
            val = self._ec.read_memory(
                self.offset) if self.offset < 0x100 else self._ec.read_memory_extended(self.offset)
            self.logger.log(f'[CHIPSEC] EC memory read: offset 0x{self.offset:X} = 0x{val:X}')

    def write(self) -> None:
        self.logger.log(f'[CHIPSEC] EC memory write: offset 0x{self.offset:X} = 0x{self.wval:X}')

        if self.offset < 0x100:
            self._ec.write_memory(self.offset, self.wval)
        else:
            self._ec.write_memory_extended(self.offset, self.wval)

    def index(self) -> None:

        if self.offset:
            val = self._ec.read_idx(self.offset)
            self.logger.log(f'[CHIPSEC] EC index I/O: reading memory offset 0x{self.offset:X}: 0x{val:X}')
        else:
            self.logger.log("[CHIPSEC] EC index I/O: dumping memory...")
            mem = [self._ec.read_idx(off) for off in range(0x10000)]
            print_buffer_bytes(mem)



commands = {'ec': ECCommand}
