#!/usr/local/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2015, Intel Corporation
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
#Contact information:
#chipsec@intel.com
#



__version__ = '1.0'

from chipsec.command        import BaseCommand
from chipsec.hal.interrupts import Interrupts

# ###################################################################
#
# CPU Interrupts
#
# ###################################################################
class SMICommand(BaseCommand):
    """
    >>> chipsec_util smi <thread_id> <SMI_code> <SMI_data> [RAX] [RBX] [RCX] [RDX] [RSI] [RDI]

    Examples:

    >>> chipsec_util smi 0x0 0xDE 0x0
    >>> chipsec_util smi 0x0 0xDE 0x0 0xAAAAAAAAAAAAAAAA ..
    """
    def requires_driver(self):
        # No driver required when printing the util documentation
        if len(self.argv) < 3:
            return False
        return True

    def run(self):
        try:
            interrupts = Interrupts( self.cs )
        except RuntimeError, msg:
            print msg
            return

        SMI_code_port_value = 0xF
        SMI_data_port_value = 0x0
        if (2 == len(self.argv)):
            print SMICommand.__doc__
        elif (4 < len(self.argv)):
            thread_id = int(self.argv[2],16)
            SMI_code_port_value = int(self.argv[3],16)
            SMI_data_port_value = int(self.argv[4],16)
            self.logger.log( "[CHIPSEC] Sending SW SMI (code: 0x%02X, data: 0x%02X).." % (SMI_code_port_value, SMI_data_port_value) )
            if (5 == len(self.argv)):
                interrupts.send_SMI_APMC( SMI_code_port_value, SMI_data_port_value )
            elif (11 == len(self.argv)):
                _rax = int(self.argv[5],16)
                _rbx = int(self.argv[6],16)
                _rcx = int(self.argv[7],16)
                _rdx = int(self.argv[8],16)
                _rsi = int(self.argv[9],16)
                _rdi = int(self.argv[10],16)
                self.logger.log( "          RAX: 0x%016X (AX will be overwridden with values of SW SMI ports B2/B3)" % _rax )
                self.logger.log( "          RBX: 0x%016X" % _rbx )
                self.logger.log( "          RCX: 0x%016X" % _rcx )
                self.logger.log( "          RDX: 0x%016X (DX will be overwridden with 0x00B2)" % _rdx )
                self.logger.log( "          RSI: 0x%016X" % _rsi )
                self.logger.log( "          RDI: 0x%016X" % _rdi )
                interrupts.send_SW_SMI( thread_id, SMI_code_port_value, SMI_data_port_value, _rax, _rbx, _rcx, _rdx, _rsi, _rdi )
            else: print SMICommand.__doc__
        else: print SMICommand.__doc__


class NMICommand(BaseCommand):
    """
    >>> chipsec_util nmi

    Examples:

    >>> chipsec_util nmi
    """
    def requires_driver(self):
        return True

    def run(self):
        try:
            interrupts = Interrupts( self.cs )
        except RuntimeError, msg:
            print msg
            return

        self.logger.log( "[CHIPSEC] Sending NMI#.." )
        interrupts.send_NMI()

commands = { 'smi': SMICommand, 'nmi': NMICommand }
