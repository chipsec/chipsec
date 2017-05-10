#!/usr/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2017, Google
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

from chipsec import command


class RegisterCommand(command.BaseCommand):
    """
    >>> chipsec_util reg read <reg_name>
    >>> chipsec_util reg read <reg_name> <field_name>

    Examples:

    >>> chipsec_util reg read SMBUS_VID
    >>> chipsec_util reg read HSFC FGO
    """

    def requires_driver(self):
        # No driver required when printing the util documentation
        if len(self.argv) < 3:
            return False
        return True

    def run(self):
        if len(self.argv) < 3:
            print RegisterCommand.__doc__
            return

        op = self.argv[2]
        if ( 'read' == op ):
            if len(self.argv) < 4:
                print RegisterCommand.__doc__
                return
            reg_name = self.argv[3]
            if len(self.argv) == 5:
                field_name = self.argv[4]
                value = self.cs.read_register_field(reg_name, field_name)
                self.logger.log("[CHIPSEC] %s.%s=0x%X" % (reg_name, field_name, value))
            else:
                value = self.cs.read_register(reg_name)
                self.logger.log("[CHIPSEC] %s=0x%X" % (reg_name, value))
        else:
            print RegisterCommand.__doc__
            return


commands = { 'reg': RegisterCommand }
