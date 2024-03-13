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
The vmem command provides direct access to read and write virtual memory.

>>> chipsec_util vmem <op> <physical_address> <length> [value|buffer_file]
>>>
>>> <physical_address> : 64-bit physical address
>>> <op>               : read|readval|write|writeval|allocate|pagedump|search|getphys
>>> <length>           : byte|word|dword or length of the buffer from <buffer_file>
>>> <value>            : byte, word or dword value to be written to memory at <physical_address>
>>> <buffer_file>      : file with the contents to be written to memory at <physical_address>

Examples:

>>> chipsec_util vmem <op>     <virtual_address>  <length> [value|file]
>>> chipsec_util vmem readval  0xFED40000         dword
>>> chipsec_util vmem read     0x41E              0x20     buffer.bin
>>> chipsec_util vmem writeval 0xA0000            dword    0x9090CCCC
>>> chipsec_util vmem write    0x100000000        0x1000   buffer.bin
>>> chipsec_util vmem write    0x100000000        0x10     000102030405060708090A0B0C0D0E0F
>>> chipsec_util vmem allocate                    0x1000
>>> chipsec_util vmem search   0xF0000            0x10000  _SM_
>>> chipsec_util vmem getphys  0xFED00000
"""

import os
import chipsec_util

from chipsec.command import BaseCommand, toLoad
from chipsec.hal import virtmem
from chipsec.library.defines import bytestostring
from chipsec.library.logger import print_buffer_bytes
from chipsec.library.file import write_file, read_file
from argparse import ArgumentParser


# Virtual Memory
class VMemCommand(BaseCommand):

    def requirements(self) -> toLoad:
        return toLoad.Driver

    def parse_arguments(self) -> None:
        parser = ArgumentParser(usage=__doc__)
        subparsers = parser.add_subparsers()

        parser_read = subparsers.add_parser('read')
        parser_read.add_argument('virt_address', type=lambda x: int(x, 16), help='Address (hex)')
        parser_read.add_argument('size', type=lambda x: int(x, 16), nargs='?', default=0x100, help='Length (hex)')
        parser_read.add_argument('buf_file', type=str, nargs='?', default='', help='Buffer file name')
        parser_read.set_defaults(func=self.vmem_read)

        parser_readval = subparsers.add_parser('readval')
        parser_readval.add_argument('virt_address', type=lambda x: int(x, 16), help='Address (hex)')
        parser_readval.add_argument('length', type=str, nargs='?', default=None, help='Length [byte, word, dword] or (hex)')
        parser_readval.set_defaults(func=self.vmem_readval)

        parser_write = subparsers.add_parser('write')
        parser_write.add_argument('virt_address', type=lambda x: int(x, 16), help='Address (hex)')
        parser_write.add_argument('size', type=lambda x: int(x, 16), default=0x100, help='Length (hex)')
        parser_write.add_argument('buf_file', type=str, help='Buffer file name')
        parser_write.set_defaults(func=self.vmem_write)

        parser_writeval = subparsers.add_parser('writeval')
        parser_writeval.add_argument('virt_address', type=lambda x: int(x, 16), help='Address (hex)')
        parser_writeval.add_argument('length', type=str, help='Length [byte, word, dword] or (hex)')
        parser_writeval.add_argument('value', type=lambda x: int(x, 16), help='Value (hex)')
        parser_writeval.set_defaults(func=self.vmem_writeval)

        parser_search = subparsers.add_parser('search')
        parser_search.add_argument('virt_address', type=lambda x: int(x, 16), help='Address (hex)')
        parser_search.add_argument('size', type=lambda x: int(x, 16), help='Size of memory to search (hex)')
        parser_search.add_argument('value', type=str, help='Value (string)')
        parser_search.set_defaults(func=self.vmem_search)

        parser_allocate = subparsers.add_parser('allocate')
        parser_allocate.add_argument('size', type=lambda x: int(x, 16), help='Size of memory to allocate (hex)')
        parser_allocate.set_defaults(func=self.vmem_allocate)

        parser_getphys = subparsers.add_parser('getphys')
        parser_getphys.add_argument('virt_address', type=lambda x: int(x, 16), help='Address (hex)')
        parser_getphys.set_defaults(func=self.vmem_getphys)
        parser.parse_args(self.argv, namespace=self)

    def set_up(self) -> None:
        self._vmem = virtmem.VirtMemory(self.cs)

    def vmem_read(self):
        self.logger.log('[CHIPSEC] Reading buffer from memory: VA = 0x{:016X}, len = 0x{:X}.'.format(self.virt_address, self.size))
        try:
            buffer = self._vmem.read_virtual_mem(self.virt_address, self.size)
        except (TypeError, OSError):
            self.logger.log_error('Error mapping VA to PA.')
            return

        if self.buf_file:
            write_file(self.buf_file, buffer)
            self.logger.log("[CHIPSEC] Written 0x{:X} bytes to '{}'".format(len(buffer), self.buf_file))
        else:
            print_buffer_bytes(buffer)

    def vmem_readval(self):
        width = 0x4
        value = 0x0
        if self.length is not None:
            if chipsec_util.is_option_valid_width(self.length):
                width = chipsec_util.get_option_width(self.length)
            else:
                try:
                    width = int(self.length, 16)
                except:
                    width = 0

        self.logger.log('[CHIPSEC] Reading {:X}-byte value from VA 0x{:016X}.'.format(width, self.virt_address))
        try:
            if 0x1 == width:
                value = self._vmem.read_virtual_mem_byte(self.virt_address)
            elif 0x2 == width:
                value = self._vmem.read_virtual_mem_word(self.virt_address)
            elif 0x4 == width:
                value = self._vmem.read_virtual_mem_dword(self.virt_address)
            else:
                self.logger.log_error("Must specify <length> argument in 'mem readval' as one of {}".format(chipsec_util.CMD_OPTS_WIDTH))
                return
        except (TypeError, OSError):
            self.logger.log_error('Error mapping VA to PA.')
            return
        self.logger.log('[CHIPSEC] value = 0x{:X}'.format(value))

    def vmem_write(self):
        if not os.path.exists(self.buf_file):
            try:
                buffer = bytearray.fromhex(self.buf_file)
            except ValueError as e:
                self.logger.log_error("Incorrect <value> specified: '{}'".format(self.buf_file))
                self.logger.log_error(str(e))
                return
            self.logger.log("[CHIPSEC] Read 0x{:X} hex bytes from command-line: {}'".format(len(buffer), self.buf_file))
        else:
            buffer = read_file(self.buf_file)
            self.logger.log("[CHIPSEC] Read 0x{:X} bytes from file '{}'".format(len(buffer), self.buf_file))

        if len(buffer) < self.size:
            self.logger.log_error("Number of bytes read (0x{:X}) is less than the specified <length> (0x{:X})".format(len(buffer), self.size))
            return

        self.logger.log('[CHIPSEC] Writing buffer to memory: VA = 0x{:016X}, len = 0x{:X}.'.format(self.virt_address, self.size))
        self._vmem.write_virtual_mem(self.virt_address, self.size, buffer)

    def vmem_writeval(self):
        if chipsec_util.is_option_valid_width(self.length):
            width = chipsec_util.get_option_width(self.length)
        else:
            try:
                width = int(self.length, 16)
            except ValueError:
                width = 0

        self.logger.log('[CHIPSEC] Writing {:X}-byte value 0x{:X} to VA 0x{:016X}..'.format(width, self.value, self.virt_address))
        try:
            if 0x1 == width:
                self._vmem.write_virtual_mem_byte(self.virt_address, self.value)
            elif 0x2 == width:
                self._vmem.write_virtual_mem_word(self.virt_address, self.value)
            elif 0x4 == width:
                self._vmem.write_virtual_mem_dword(self.virt_address, self.value)
            else:
                self.logger.log_error("Must specify <length> argument in 'mem writeval' as one of {}".format(chipsec_util.CMD_OPTS_WIDTH))
        except (TypeError, OSError):
            self.logger.log_error('Error mapping VA to PA.')

    def vmem_search(self):
        try:
            buffer = self._vmem.read_virtual_mem(self.virt_address, self.size)
        except (TypeError, OSError):
            self.logger.log_error('Error mapping VA to PA.')
            return

        buffer = bytestostring(buffer)
        offset = buffer.find(self.value)

        self.logger.log("[CHIPSEC] Search buffer for '{}':".format(self.value))
        self.logger.log('          VA = 0x{:016X}, len = 0x{:X}'.format(self.virt_address, self.size))
        if offset != -1:
            self.logger.log('[CHIPSEC] Target address = 0x{:X}.'.format(self.virt_address + offset))
        else:
            self.logger.log('[CHIPSEC] Could not find the target in the searched range.')

    def vmem_allocate(self):
        try:
            (va, pa) = self._vmem.alloc_virtual_mem(self.size)
        except (TypeError, OSError):
            self.logger.log_error('Error mapping VA to PA.')
            return
        self.logger.log('[CHIPSEC] Allocated {:X} bytes of virtual memory:'.format(self.size))
        self.logger.log('          VA = 0x{:016X}'.format(va))
        self.logger.log('          PA = 0x{:016X}'.format(pa))

    def vmem_getphys(self):
        try:
            pa = self._vmem.va2pa(self.virt_address)
        except (TypeError, OSError):
            self.logger.log_error('Error mapping VA to PA.')
            return
        if pa is not None:
            self.logger.log('[CHIPSEC] Virtual memory:')
            self.logger.log('          VA = 0x{:016X}'.format(self.virt_address))
            self.logger.log('          PA = 0x{:016X}'.format(pa))


commands = {'vmem': VMemCommand}
