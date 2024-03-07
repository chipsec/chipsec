# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2017, Google
# Copyright (c) 2021, Intel Corporation
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

"""
>>> chipsec_util reg read <reg_name> [<field_name>]
>>> chipsec_util reg read_field <reg_name> <field_name>
>>> chipsec_util reg write <reg_name> <value>
>>> chipsec_util reg write_field <reg_name> <field_name> <value>
>>> chipsec_util reg get_control <control_name>
>>> chipsec_util reg set_control <control_name> <value>

Examples:

>>> chipsec_util reg read SMBUS_VID
>>> chipsec_util reg read HSFC FGO
>>> chipsec_util reg read_field HSFC FGO
>>> chipsec_util reg write SMBUS_VID 0x8088
>>> chipsec_util reg write_field BC BLE 0x1
>>> chipsec_util reg get_control BiosWriteEnable
>>> chipsec_util reg set_control BiosLockEnable 0x1
"""

from chipsec.command import BaseCommand, toLoad
from argparse import ArgumentParser


class RegisterCommand(BaseCommand):

    def requirements(self) -> toLoad:
        return toLoad.All

    def parse_arguments(self) -> None:
        parser = ArgumentParser(prog='chipsec_util reg', usage=__doc__)
        subparsers = parser.add_subparsers()

        parser_read = subparsers.add_parser('read')
        parser_read.add_argument('reg_name', type=str, help='Register name')
        parser_read.add_argument('field_name', type=str, nargs='?', default=None, help='Field name')
        parser_read.set_defaults(func=self.reg_read)

        parser_readfield = subparsers.add_parser('read_field')
        parser_readfield.add_argument('reg_name', type=str, help='Register name')
        parser_readfield.add_argument('field_name', type=str, help='Field name')
        parser_readfield.set_defaults(func=self.reg_read_field)

        parser_write = subparsers.add_parser('write')
        parser_write.add_argument('reg_name', type=str, help='Register name')
        parser_write.add_argument('value', type=lambda x: int(x, 16), help='Value (hex)')
        parser_write.set_defaults(func=self.reg_write)

        parser_writefield = subparsers.add_parser('write_field')
        parser_writefield.add_argument('reg_name', type=str, help='Register name')
        parser_writefield.add_argument('field_name', type=str, help='Field name')
        parser_writefield.add_argument('value', type=lambda x: int(x, 16), help='Value (hex)')
        parser_writefield.set_defaults(func=self.reg_write_field)

        parser_getcontrol = subparsers.add_parser('get_control')
        parser_getcontrol.add_argument('control_name', type=str, help='Control name')
        parser_getcontrol.set_defaults(func=self.reg_get_control)

        parser_setcontrol = subparsers.add_parser('set_control')
        parser_setcontrol.add_argument('control_name', type=str, help='Control name')
        parser_setcontrol.add_argument('value', type=lambda x: int(x, 16), help='Value (hex)')
        parser_setcontrol.set_defaults(func=self.reg_set_control)

        parser.parse_args(self.argv, namespace=self)

    def reg_read(self):
        if self.field_name is not None:
            value = self.cs.register.read_field(self.reg_name, self.field_name)
            self.logger.log("[CHIPSEC] {}.{}=0x{:X}".format(self.reg_name, self.field_name, value))
        else:
            value = self.cs.register.read(self.reg_name)
            self.logger.log("[CHIPSEC] {}=0x{:X}".format(self.reg_name, value))
            self.cs.register.print(self.reg_name, value)

    def reg_read_field(self):
        if self.cs.register.has_field(self.reg_name, self.field_name):
            value = self.cs.register.read_field(self.reg_name, self.field_name)
            self.logger.log("[CHIPSEC] {}.{}=0x{:X}".format(self.reg_name, self.field_name, value))
        else:
            self.logger.log_error("[CHIPSEC] Register '{}' doesn't have field '{}' defined".format(self.reg_name, self.field_name))

    def reg_write(self):
        self.logger.log("[CHIPSEC] Writing {} < 0x{:X}".format(self.reg_name, self.value))
        self.cs.register.write(self.reg_name, self.value)

    def reg_write_field(self):
        if self.cs.register.has_field(self.reg_name, self.field_name):
            self.logger.log("[CHIPSEC] Writing {}.{} < 0x{:X}".format(self.reg_name, self.field_name, self.value))
            self.cs.register.write_field(self.reg_name, self.field_name, self.value)
        else:
            self.logger.log_error("[CHIPSEC] Register '{}' doesn't have field '{}' defined".format(self.reg_name, self.field_name))

    def reg_get_control(self):
        if self.cs.control.is_defined(self.control_name):
            value = self.cs.control.get(self.control_name)
            self.logger.log("[CHIPSEC] {} = 0x{:X}".format(self.control_name, value))
        else:
            self.logger.log_error("[CHIPSEC] Control '{}' isn't defined".format(self.control_name))

    def reg_set_control(self):
        if self.cs.control.is_defined(self.control_name):
            self.cs.control.set(self.control_name, self.value)
            self.logger.log("[CHIPSEC] Setting control {} < 0x{:X}".format(self.control_name, self.value))
        else:
            self.logger.log_error("[CHIPSEC] Control '{}' isn't defined".format(self.control_name))

commands = {'reg': RegisterCommand}
