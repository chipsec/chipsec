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
>>> chipsec_util msgbus read     <port> <register>
>>> chipsec_util msgbus write    <port> <register> <value>
>>> chipsec_util msgbus mm_read  <port> <register>
>>> chipsec_util msgbus mm_write <port> <register> <value>
>>> chipsec_util msgbus message  <port> <register> <opcode> [value]
>>>
>>> <port>    : message bus port of the target unit
>>> <register>: message bus register/offset in the target unit port
>>> <value>   : value to be written to the message bus register/offset
>>> <opcode>  : opcode of the message on the message bus

Examples:

>>> chipsec_util msgbus read     0x3 0x2E
>>> chipsec_util msgbus mm_write 0x3 0x27 0xE0000001
>>> chipsec_util msgbus message  0x3 0x2E 0x10
>>> chipsec_util msgbus message  0x3 0x2E 0x11 0x0
"""

from chipsec.command import BaseCommand, toLoad
from argparse import ArgumentParser


# Message Bus
class MsgBusCommand(BaseCommand):

    def requirements(self) -> toLoad:
        return toLoad.All

    def parse_arguments(self) -> None:
        parser = ArgumentParser(prog='chipsec_util msgbus', usage=__doc__)
        subparsers = parser.add_subparsers()

        parser_read = subparsers.add_parser('read')
        parser_read.add_argument('port', type=lambda x: int(x, 16), help='Port (hex)')
        parser_read.add_argument('reg', type=lambda x: int(x, 16), help='Register (hex)')
        parser_read.set_defaults(func=self.msgbus_read)

        parser_write = subparsers.add_parser('write')
        parser_write.add_argument('port', type=lambda x: int(x, 16), help='Port (hex)')
        parser_write.add_argument('reg', type=lambda x: int(x, 16), help='Register (hex)')
        parser_write.add_argument('val', type=lambda x: int(x, 16), help='Value (hex)')
        parser_write.set_defaults(func=self.msgbus_write)

        parser_mmread = subparsers.add_parser('mm_read')
        parser_mmread.add_argument('port', type=lambda x: int(x, 16), help='Port (hex)')
        parser_mmread.add_argument('reg', type=lambda x: int(x, 16), help='Register (hex)')
        parser_mmread.set_defaults(func=self.msgbus_mm_read)

        parser_mmwrite = subparsers.add_parser('mm_write')
        parser_mmwrite.add_argument('port', type=lambda x: int(x, 16), help='Port (hex)')
        parser_mmwrite.add_argument('reg', type=lambda x: int(x, 16), help='Register (hex)')
        parser_mmwrite.add_argument('val', type=lambda x: int(x, 16), help='Value (hex)')
        parser_mmwrite.set_defaults(func=self.msgbus_mm_write)

        parser_message = subparsers.add_parser('message')
        parser_message.add_argument('port', type=lambda x: int(x, 16), help='Port (hex)')
        parser_message.add_argument('reg', type=lambda x: int(x, 16), help='Register (hex)')
        parser_message.add_argument('opcode', type=lambda x: int(x, 16), help='OPCODE (hex)')
        parser_message.add_argument('val', type=lambda x: int(x, 16), nargs='?', default=None, help='Value (hex)')
        parser_message.set_defaults(func=self.msgbus_message)

        parser.parse_args(self.argv, namespace=self)

    def msgbus_read(self):
        self.logger.log(f'[CHIPSEC] msgbus read: port 0x{self.port:02X} + 0x{self.reg:08X}')
        return self._msgbus.msgbus_reg_read(self.port, self.reg)

    def msgbus_write(self):
        self.logger.log(f'[CHIPSEC] msgbus write: port 0x{self.port:02X} + 0x{self.reg:08X} < 0x{self.val:08X}')
        return self._msgbus.msgbus_reg_write(self.port, self.reg, self.val)

    def msgbus_mm_read(self):
        self.logger.log(f'[CHIPSEC] MMIO msgbus read: port 0x{self.port:02X} + 0x{self.reg:08X}')
        return self._msgbus.mm_msgbus_reg_read(self.port, self.reg)

    def msgbus_mm_write(self):
        self.logger.log(f'[CHIPSEC] MMIO msgbus write: port 0x{self.port:02X} + 0x{self.reg:08X} < 0x{self.val:08X}')
        return self._msgbus.mm_msgbus_reg_write(self.port, self.reg, self.val)

    def msgbus_message(self):
        self.logger.log(f'[CHIPSEC] msgbus message: port 0x{self.port:02X} + 0x{self.reg:08X}, opcode: 0x{self.opcode:02X}')
        if self.val is not None:
            self.logger.log(f'[CHIPSEC]                 Data: 0x{self.val:08X}')
        return self._msgbus.msgbus_send_message(self.port, self.reg, self.opcode, self.val)

    def run(self):
        self._msgbus = self.cs.msgbus

        res = self.func()

        if res is not None:
            self.logger.log(f'[CHIPSEC] Result: {hex(res)}')


commands = {'msgbus': MsgBusCommand}
