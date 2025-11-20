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
>>> chipsec_util smbus read <device_addr> <start_offset> [size]
>>> chipsec_util smbus write <device_addr> <offset> <byte_val>

Examples:

>>> chipsec_util smbus read 0xA0 0x0 0x100
"""

from chipsec.command import BaseCommand, toLoad
from chipsec.library.logger import print_buffer_bytes
from chipsec.hal.smbus import SMBus
from argparse import ArgumentParser


class SMBusCommand(BaseCommand):

    def requirements(self) -> toLoad:
        return toLoad.All

    def parse_arguments(self) -> None:
        parser = ArgumentParser(prog='chipsec_util smbus', usage=__doc__)
        subparsers = parser.add_subparsers()
        parser_read = subparsers.add_parser('read')
        parser_read.add_argument('dev_addr', type=lambda x: int(x, 16), help='Start Address (hex)')
        parser_read.add_argument('start_off', type=lambda x: int(x, 16), help='Start Offset (hex)')
        parser_read.add_argument('size', type=lambda x: int(x, 16), default=None, nargs='?', help='Size [Default=Byte] (hex)')
        parser_read.set_defaults(func=self.smbus_read)

        parser_write = subparsers.add_parser('write')
        parser_write.add_argument('dev_addr', type=lambda x: int(x, 16), help='Start Address (hex)')
        parser_write.add_argument('off', type=lambda x: int(x, 16), help='Start Offset (hex)')
        parser_write.add_argument('val', type=lambda x: int(x, 16), help='Byte Value (hex)')
        parser_write.set_defaults(func=self.smbus_write)

        parser_block_read = subparsers.add_parser('block_read')
        parser_block_read.add_argument('dev_addr', type=lambda x: int(x, 16), help='Start Address (hex)')
        parser_block_read.add_argument('start_off', type=lambda x: int(x, 16), help='Start Offset (hex)')
        parser_block_read.set_defaults(func=self.smbus_block_read)

        parser_block_write = subparsers.add_parser('block_write')
        parser_block_write.add_argument('dev_addr', type=lambda x: int(x, 16), help='Start Address (hex)')
        parser_block_write.add_argument('off', type=lambda x: int(x, 16), help='Start Offset (hex)')
        parser_block_write.add_argument('data', type=lambda x: bytearray.fromhex(x), default=None, nargs='?', help='Data (hex)')
        parser_block_write.set_defaults(func=self.smbus_block_write)

        parser.parse_args(self.argv, namespace=self)

    def set_up(self) -> None:
        self._smbus = SMBus(self.cs)

    def smbus_block_read(self):
        buf = self._smbus.read_block(self.dev_addr, self.start_off)
        self.logger.log("[CHIPSEC] SMBus block read: device 0x{:X} offset 0x{:X} size 0x{:X}".format(self.dev_addr, self.start_off, len(buf)))
        print_buffer_bytes(buf)

    
    def smbus_block_write(self):
        self.logger.log("[CHIPSEC] SMBus block write: device 0x{:X} offset 0x{:X} = 0x{}".format(self.dev_addr, self.off, ''.join('{:02x}'.format(x) for x in self.data)))
        self._smbus.write_block(self.dev_addr, self.off, self.data)

    def smbus_read(self):
        if self.size is not None:
            buf = self._smbus.read_range(self.dev_addr, self.start_off, self.size)
            self.logger.log("[CHIPSEC] SMBus read: device 0x{:X} offset 0x{:X} size 0x{:X}".format(self.dev_addr, self.start_off, self.size))
            print_buffer_bytes(buf)
        else:
            val = self._smbus.read_byte(self.dev_addr, self.start_off)
            self.logger.log("[CHIPSEC] SMBus read: device 0x{:X} offset 0x{:X} = 0x{:X}".format(self.dev_addr, self.start_off, val))

    def smbus_write(self):
        self.logger.log("[CHIPSEC] SMBus write: device 0x{:X} offset 0x{:X} = 0x{:X}".format(self.dev_addr, self.off, self.val))
        self._smbus.write_byte(self.dev_addr, self.off, self.val)

    def run(self):
        if not self._smbus.is_SMBus_supported():
            self.logger.log("[CHIPSEC] SMBus controller is not supported")
            return
        self._smbus.display_SMBus_info()
        self.func()


commands = {'smbus': SMBusCommand}
