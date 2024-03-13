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
The igd command allows memory read/write operations using igd dma.

>>> chipsec_util igd
>>> chipsec_util igd dmaread <address> [width] [file_name]
>>> chipsec_util igd dmawrite <address> <width> <value|file_name>

Examples:

>>> chipsec_util igd dmaread 0x20000000 4
>>> chipsec_util igd dmawrite 0x2217F1000 0x4 deadbeef
"""

from chipsec.command import BaseCommand, toLoad
from chipsec.library.logger import print_buffer_bytes
from argparse import ArgumentParser
from chipsec.library.file import read_file, write_file
from chipsec.hal import igd
import os


# Port I/O
class IgdCommand(BaseCommand):

    def requirements(self) -> toLoad:
        return toLoad.All

    def parse_arguments(self) -> None:
        parser = ArgumentParser(prog='chipsec_util igd', usage=__doc__)
        subparsers = parser.add_subparsers()

        parser_read = subparsers.add_parser('dmaread')
        parser_read.add_argument('address', type=lambda x: int(x, 16), help='Address (hex)')
        parser_read.add_argument('width', type=lambda x: int(x, 16), nargs='?', default=0x100, help='Width of read (hex)')
        parser_read.add_argument('file_name', type=str, nargs='?', default='', help='File name to save data')
        parser_read.set_defaults(func=self.read_dma)

        parser_write = subparsers.add_parser('dmawrite')
        parser_write.add_argument('address', type=lambda x: int(x, 16), help='Address (hex)')
        parser_write.add_argument('size', type=lambda x: int(x, 16), help='Size of data to write (hex)')
        parser_write.add_argument('file_value', type=str, help='Data to write [Value|<file_name>]')
        parser_write.set_defaults(func=self.write_dma)

        parser.parse_args(self.argv, namespace=self)
        

    def read_dma(self) -> None:
        self.logger.log(f'[CHIPSEC] Reading buffer from memory: PA = 0x{self.address:016X}, len = 0x{self.width:X}..')
        buffer = self.cs.igd.gfx_aperture_dma_read_write(self.address, self.width)
        if self.file_name:
            write_file(self.file_name, buffer)
            self.logger.log(f'[CHIPSEC] Written 0x{len(buffer):X} bytes to \'{self.file_name}\'')
        else:
            print_buffer_bytes(buffer)

    def write_dma(self) -> None:
        if not os.path.exists(self.file_value):
            buffer_value = self.file_value.lower().strip('0x')
            try:
                buffer = bytearray.fromhex(buffer_value)
            except ValueError as e:
                self.logger.log_error(f'Incorrect <value> specified: \'{self.file_value}\'')
                self.logger.log_error(str(e))
                return
            self.logger.log(f'[CHIPSEC] Read 0x{len(buffer):X} hex bytes from command-line: \'{buffer_value}\'')
        else:
            buffer = read_file(self.file_value)
            self.logger.log(f'[CHIPSEC] Read 0x{len(buffer):X} bytes from file \'{self.file_value}\'')

        if len(buffer) < self.size:
            self.logger.log_error(f'Number of bytes read (0x{len(buffer):X}) is less than the specified <length> (0x{self.size:X})')
            return

        self.logger.log(f'[CHIPSEC] Writing buffer to memory: PA = 0x{self.address:016X}, len = 0x{self.size:X}..')
        self.cs.igd.gfx_aperture_dma_read_write(self.address, self.size, buffer)

    def run(self) -> None:

        if not self.cs.igd.is_device_enabled():
            self.logger.log('[CHIPSEC] Looks like internal graphics device is not enabled')
            return

        self.func()


commands = {'igd': IgdCommand}
