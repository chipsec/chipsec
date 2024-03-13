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
The mem command provides direct access to read and write physical memory.

>>> chipsec_util mem <op> <physical_address> <length> [value|buffer_file]
>>> <physical_address> : 64-bit physical address
>>> <op>               : read|readval|write|writeval|allocate|pagedump|search
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
>>> chipsec_util mem pagedump 0xFED00000         0x100000
>>> chipsec_util mem search   0xF0000            0x10000  _SM_
"""

import os

from chipsec.command import BaseCommand, toLoad
from chipsec.library.defines import ALIGNED_4KB, BOUNDARY_4KB, bytestostring
from chipsec_util import get_option_width, is_option_valid_width, CMD_OPTS_WIDTH
from chipsec.library.file import read_file, write_file, get_main_dir
from chipsec.library.logger import print_buffer_bytes
from argparse import ArgumentParser

# Physical Memory


class MemCommand(BaseCommand):

    def requirements(self) -> toLoad:
        return toLoad.Driver

    def parse_arguments(self) -> None:
        parser = ArgumentParser(prog='chipsec_util mem', usage=__doc__)
        subparsers = parser.add_subparsers()

        parser_read = subparsers.add_parser('read')
        parser_read.add_argument('phys_address', type=lambda x: int(x, 16), help='64-bit physical address (hex)')
        parser_read.add_argument('buffer_length', type=lambda x: int(x, 16), default=0x100, nargs='?', help='Length of buffer (hex)')
        parser_read.add_argument('file_name', type=str, default='', nargs='?', help='Buffer file name')
        parser_read.set_defaults(func=self.mem_read)

        parser_readval = subparsers.add_parser('readval')
        parser_readval.add_argument('phys_address', type=lambda x: int(x, 16), help='64-bit physical address (hex)')
        parser_readval.add_argument('length', type=str, nargs='?', default='', help='Length to read (byte|word|dword)')
        parser_readval.set_defaults(func=self.mem_readval)

        parser_write = subparsers.add_parser('write')
        parser_write.add_argument('phys_address', type=lambda x: int(x, 16), help='64-bit physical address (hex)')
        parser_write.add_argument('buffer_length', type=lambda x: int(x, 16), help='Length of buffer (hex)')
        parser_write.add_argument('buffer_data', type=str, help='Buffer data or file name')
        parser_write.set_defaults(func=self.mem_write)

        parser_writeval = subparsers.add_parser('writeval')
        parser_writeval.add_argument('phys_address', type=lambda x: int(x, 16), help='64-bit physical address (hex)')
        parser_writeval.add_argument('length', type=str, help='Length to write (byte|word|dword)')
        parser_writeval.add_argument('write_data', type=lambda x: int(x, 16), help='Data to write')
        parser_writeval.set_defaults(func=self.mem_writeval)

        parser_allocate = subparsers.add_parser('allocate')
        parser_allocate.add_argument('allocate_length', type=lambda x: int(x, 16), help='Length to allocate (hex)')
        parser_allocate.set_defaults(func=self.mem_allocate)

        parser_pagedump = subparsers.add_parser('pagedump')
        parser_pagedump.add_argument('start_address', type=lambda x: int(x, 16), help='64-bit physical address (hex)')
        parser_pagedump.add_argument('length', type=lambda x: int(x, 16), nargs='?', default=BOUNDARY_4KB, help='Length to allocate (hex)')
        parser_pagedump.set_defaults(func=self.mem_pagedump)

        parser_search = subparsers.add_parser('search')
        parser_search.add_argument('phys_address', type=lambda x: int(x, 16), help='64-bit physical address (hex)')
        parser_search.add_argument('length', type=lambda x: int(x, 16), help='Length to search (hex)')
        parser_search.add_argument('value', type=str, help='Value to search for')
        parser_search.set_defaults(func=self.mem_search)
        parser.parse_args(self.argv, namespace=self)


    def dump_region_to_path(self, path: str, pa_start: int, pa_end: int) -> None:
        if pa_start >= pa_end:
            return
        head_len = pa_start & ALIGNED_4KB
        tail_len = pa_end & ALIGNED_4KB
        pa = pa_start - head_len + ALIGNED_4KB + 1
        fname = os.path.join(path, f'm{pa_start:016X}.bin')
        end = pa_end - tail_len
        with open(fname, 'wb') as f:
            # read leading bytes to the next boundary
            if (head_len > 0):
                f.write(self.cs.mem.read_physical_mem(pa_start, ALIGNED_4KB + 1 - head_len))

            for addr in range(pa, end, ALIGNED_4KB + 1):
                f.write(self.cs.mem.read_physical_mem(addr, ALIGNED_4KB + 1))

            # read trailing bytes
            if (tail_len > 0):
                f.write(self.cs.mem.read_physical_mem(end, tail_len))

    def mem_allocate(self) -> None:
        (va, pa) = self.cs.mem.alloc_physical_mem(self.allocate_length)
        self.logger.log(f'[CHIPSEC] Allocated {self.allocate_length:X} bytes of physical memory: VA = 0x{va:016X}, PA = 0x{pa:016X}')

    def mem_search(self) -> None:
        buffer = self.cs.mem.read_physical_mem(self.phys_address, self.length)
        buffer = bytestostring(buffer)
        offset = buffer.find(self.value)

        if (offset != -1):
            self.logger.log(f'[CHIPSEC] Search buffer from memory: PA = 0x{self.phys_address:016X}, len = 0x{self.length:X}, target address= 0x{self.phys_address + offset:X}..')
        else:
            self.logger.log(f'[CHIPSEC] Search buffer from memory: PA = 0x{self.phys_address:016X}, len = 0x{self.length:X}, can not find the target in the searched range..')

    def mem_pagedump(self) -> None:
        end = self.start_address + self.length
        self.dump_region_to_path(get_main_dir(), self.start_address, end)

    def mem_read(self) -> None:
        self.logger.log(f'[CHIPSEC] Reading buffer from memory: PA = 0x{self.phys_address:016X}, len = 0x{self.buffer_length:X}..')
        buffer = self.cs.mem.read_physical_mem(self.phys_address, self.buffer_length)
        if self.file_name:
            write_file(self.file_name, buffer)
            self.logger.log(f'[CHIPSEC] Written 0x{len(buffer):X} bytes to \'{self.file_name}\'')
        else:
            print_buffer_bytes(buffer)

    def mem_readval(self) -> None:
        width = 0x4
        value = 0x0
        if self.length:
            try:
                width = get_option_width(self.length) if is_option_valid_width(self.length) else int(self.length, 16)
            except ValueError:
                self.logger.log_error(f'[CHIPSEC] Bad length given \'{self.length}\'')
                return

        if width not in (0x1, 0x2, 0x4):
            self.logger.log_error(f'Must specify <length> argument in \'mem readval\' as one of {CMD_OPTS_WIDTH}')
            return
        self.logger.log(f'[CHIPSEC] Reading {width:X}-byte value from PA 0x{self.phys_address:016X}..')
        if 0x1 == width:
            value = self.cs.mem.read_physical_mem_byte(self.phys_address)
        elif 0x2 == width:
            value = self.cs.mem.read_physical_mem_word(self.phys_address)
        elif 0x4 == width:
            value = self.cs.mem.read_physical_mem_dword(self.phys_address)
        self.logger.log(f'[CHIPSEC] Value = 0x{value:X}')

    def mem_write(self) -> None:
        if not os.path.exists(self.buffer_data):
            try:
                buffer = bytearray.fromhex(self.buffer_data)
            except ValueError:
                self.logger.log_error(f'Incorrect <value> specified: \'{self.buffer_data}\'')
                return
            self.logger.log(f'[CHIPSEC] Read 0x{len(buffer):X} hex bytes from command-line: \'{self.buffer_data}\'')
        else:
            buffer = read_file(self.buffer_data)
            self.logger.log(f'[CHIPSEC] Read 0x{len(buffer):X} bytes from file \'{self.buffer_data}\'')

        if len(buffer) < self.buffer_length:
            self.logger.log_error(f'Number of bytes read (0x{len(buffer):X}) is less than the specified <length> (0x{self.buffer_length:X})')
            return

        self.logger.log(f'[CHIPSEC] writing buffer to memory: PA = 0x{self.phys_address:016X}, len = 0x{self.buffer_length:X}..')
        self.cs.mem.write_physical_mem(self.phys_address, self.buffer_length, buffer)

    def mem_writeval(self) -> None:
        try:
            width = get_option_width(self.length) if is_option_valid_width(self.length) else int(self.length, 16)
        except ValueError:
            self.logger.log_error(f'Must specify <length> argument in \'mem writeval\' as one of {CMD_OPTS_WIDTH}')
            return

        if width not in (0x1, 0x2, 0x4):
            self.logger.log_error(f'Must specify <length> argument in \'mem writeval\' as one of {CMD_OPTS_WIDTH}')
            return
        self.logger.log(f'[CHIPSEC] Writing {width:X}-byte value 0x{self.write_data:X} to PA 0x{self.phys_address:016X}..')
        if 0x1 == width:
            self.cs.mem.write_physical_mem_byte(self.phys_address, self.write_data)
        elif 0x2 == width:
            self.cs.mem.write_physical_mem_word(self.phys_address, self.write_data)
        elif 0x4 == width:
            self.cs.mem.write_physical_mem_dword(self.phys_address, self.write_data)

commands = {'mem': MemCommand}
