# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2017, Google
# Copyright (c) 2021, Intel Corporation

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; Version 2.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.


"""
>>> chipsec_util reg find_reg <vid> <dev> <reg_name> <field>
>>> chipsec_util reg read <reg_name>
>>> chipsec_util reg read_field <reg_name> <field_name>
>>> chipsec_util reg write <reg_name> <value>
>>> chipsec_util reg write_field <reg_name> <field_name> <value>
>>> chipsec_util reg get_control <control_name>
>>> chipsec_util reg set_control <control_name> <value>

Examples:

>>> chipsec_util reg find 8086
>>> chipsec_util reg find '*' SPI 
>>> chipsec_util reg find '*' '*' HSFC
>>> chipsec_util reg find '*' '*' HSFC FGO
>>> chipsec_util reg read '*' '*' HSFC 
>>> chipsec_util reg read 8086.SPI.HSFC
>>> chipsec_util reg read_field 8086.SPI.HSFC.FGO
>>> chipsec_util reg read_field *.*.HSFC.FGO
>>> chipsec_util reg write *.*.VID 0x8088
>>> chipsec_util reg write_field 8086.SPI.BC.BLE 0x1
>>> chipsec_util reg write_field 8086.*.BC.BLE 0x1
>>> chipsec_util reg get_control BiosWriteEnable
>>> chipsec_util reg set_control BiosLockEnable 0x1
"""

from chipsec.command import BaseCommand
from argparse import ArgumentParser


class RegisterCommand(BaseCommand):

    def requires_driver(self):
        parser = ArgumentParser(prog='chipsec_util reg', usage=__doc__)
        subparsers = parser.add_subparsers()

        parser_find = subparsers.add_parser('find')
        parser_find.add_argument('vid', type=str, help="Vendor ID - use '*' for wildcard")
        parser_find.add_argument('dev_name', type=str, help="Device Name - use '*' for wildcard")
        parser_find.add_argument('reg_name', type=str, help="Register Name - use '*' for wildcard")
        parser_find.add_argument('field_name', type=str, nargs="*", default="*", help="Field Name - use '*' for wildcard")
        parser.set_defaults(func=self.reg_find)

        parser_read = subparsers.add_parser('read')
        parser_read.add_argument('reg_name', type=str, help='Register name - use vid.dev_name.reg_name format with * for wildcards')
        parser_read.set_defaults(func=self.reg_read)

        parser_readfield = subparsers.add_parser('read_field')
        parser_readfield.add_argument('field_name', type=str, help='Field name - use vid.dev_nam.reg_name.field_name format with * for wildcards')
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
        return True

    def reg_find(self):
        matches = self.cs.get_REGISTERS_match("{}.{}.{}.{}".format(self.vid, self.dev_name, self.reg_name, self.field_name))
        self.logger.log(matches)

    def reg_read(self):
        matches = self.cs.get_REGISTERS_match(self.reg_name)  # matches contains fields and registers
        matches = list(set([i[:i.rfind('.')] for i in matches]))  # find only unique registers from the results
        for reg in matches:
            value = self.cs.read_register_all(reg)
            self.cs.print_register_all(reg, value)

    def reg_read_field(self):
        matches = self.cs.get_REGISTERS_match(self.field_name)
        if not matches:
            self.logger.log("[CHIPSEC] Register '{}' doesn't have field '{}' defined".format(self.reg_name, self.field_name))
            return
        for field in matches:
            reg_name = field[:field.rfind('.')]
            field_name = field[field.rfind('.') + 1:]
            values = self.cs.read_register_field_all(reg_name, field_name)
            for value in values:
                self.logger.log("[CHIPSEC] {}.{}=0x{:X}".format(reg_name, field_name, value))

    def reg_write(self):
        matches = self.cs.get_REGISTERS_match(self.reg_name)
        for reg in matches:
            self.logger.log("[CHIPSEC] Writing {} < 0x{:X}".format(reg, self.value))
            self.cs.write_register_all_single(reg, self.value)

    def reg_write_field(self):
        matches = self.cs.get_REGISTERS_match(self.reg_name)
        if not matches:
            self.logger.error("[CHIPSEC] Register '{}' doesn't have field '{}' defined".format(self.reg_name, self.field_name))
        for field in matches:
            reg_name = field[:field.rfind('.')]
            field_name = field[field.rfind('.') + 1:]
            self.logger.log("[CHIPSEC] Writing {}.{} < 0x{:X}".format(reg_name, field_name, self.value))
            self.cs.write_register_field_all(reg_name, field_name, self.value)

    def reg_get_control(self):
        if self.cs.is_control_defined(self.control_name):
            value = self.cs.get_control(self.control_name)
            self.logger.log("[CHIPSEC] {} = 0x{:X}".format(self.control_name, value))
        else:
            self.logger.error("[CHIPSEC] Control '{}' isn't defined".format(self.control_name))

    def reg_set_control(self):
        if self.cs.is_control_defined(self.control_name):
            self.cs.set_control(self.control_name, self.value)
            self.logger.log("[CHIPSEC] Setting control {} < 0x{:X}".format(self.control_name, self.value))
        else:
            self.logger.error("[CHIPSEC] Control '{}' isn't defined".format(self.control_name))

    def run(self):
        self.func()


commands = {'reg': RegisterCommand}
