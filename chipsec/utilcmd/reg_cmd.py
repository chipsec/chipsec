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
                self.cs.print_register(reg_name, value)
        elif ( 'read_field' == op ):
            if len(self.argv) < 5:
                print RegisterCommand.__doc__
                return
            reg_name   = self.argv[3]
            field_name = self.argv[4]
            if self.cs.register_has_field(reg_name, field_name):
                value = self.cs.read_register_field(reg_name, field_name)
                self.logger.log("[CHIPSEC] %s.%s=0x%X" % (reg_name, field_name, value))
            else:
                self.logger.error("[CHIPSEC] register %s doesn't have field %s defined" % (reg_name, field_name))
        elif ( 'write' == op ):
            if len(self.argv) < 5:
                print RegisterCommand.__doc__
                return
            reg_name = self.argv[3]
            value    = int(self.argv[4],16)
            self.logger.log("[CHIPSEC] writing %s < 0x%X" % (reg_name, value))
            self.cs.write_register(reg_name, value)
        elif ( 'write_field' == op ):
            if len(self.argv) < 6:
                print RegisterCommand.__doc__
                return
            reg_name    = self.argv[3]
            field_name  = self.argv[4]
            field_value = int(self.argv[5],16)
            if self.cs.register_has_field(reg_name, field_name):
                self.logger.log("[CHIPSEC] writing %s.%s < 0x%X" % (reg_name, field_name, field_value))
                self.cs.write_register_field(reg_name, field_name, field_value)
            else:
                self.logger.error("[CHIPSEC] register %s doesn't have field %s defined" % (reg_name, field_name))
        elif ( 'get_control' == op ):
            if len(self.argv) < 4:
                print RegisterCommand.__doc__
                return
            control_name = self.argv[3]
            if self.cs.is_control_defined(control_name):
                value = self.cs.get_control(control_name)
                self.logger.log("[CHIPSEC] %s = 0x%X" % (control_name, value))
            else:
                self.logger.error("[CHIPSEC] control %s isn't defined" % control_name)
        elif ( 'set_control' == op ):
            if len(self.argv) < 5:
                print RegisterCommand.__doc__
                return
            control_name = self.argv[3]
            value        = int(self.argv[4],16)
            if self.cs.is_control_defined(control_name):
                self.cs.set_control(control_name, value)
                self.logger.log("[CHIPSEC] setting control %s < 0x%X" % (control_name, value))
            else:
                self.logger.error("[CHIPSEC] control %s isn't defined" % control_name)
        else:
            print RegisterCommand.__doc__
            return


commands = { 'reg': RegisterCommand }
