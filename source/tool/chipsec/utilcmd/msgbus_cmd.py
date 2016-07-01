#!/usr/local/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2016, Intel Corporation
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

import os
import sys
import time

import chipsec_util
from chipsec.command    import BaseCommand

from chipsec.logger     import *
from chipsec.file       import *
from chipsec.hal.msgbus import MsgBus


# Message Bus
class MsgBusCommand(BaseCommand):
    """
    >>> chipsec_util msgbus read    <port> <register>
    >>> chipsec_util msgbus write   <port> <register> <value>
    >>> chipsec_util msgbus message <port> <register> <opcode> [value]
    >>>
    >>> <port>    : message bus port of the target unit
    >>> <register>: message bus register/offset in the target unit port
    >>> <value>   : value to be written to the message bus register/offset
    >>> <opcode>  : opcode of the message on the message bus

    Examples:

    >>> chipsec_util msgbus read    0x3 0x2E
    >>> chipsec_util msgbus write   0x3 0x27 0xE0000001
    >>> chipsec_util msgbus message 0x3 0x2E 0x10
    >>> chipsec_util msgbus message 0x3 0x2E 0x11 0x0
    """
    def requires_driver(self):
        # No driver required when printing the util documentation
        if len(self.argv) < 3:
            return False
        return True

    def run(self):
        if len(self.argv) > 7 or len(self.argv) < 5:
            print MsgBusCommand.__doc__
            return

        op = self.argv[2]
        t = time.time()

        _msgbus = self.cs.msgbus

        res  = None
        port = int(self.argv[3], 16)
        reg  = int(self.argv[4], 16)

        if 'read' == op:
            self.logger.log("[CHIPSEC] msgbus read: port 0x%02X + 0x%08X" % (port, reg))
            res = _msgbus.msgbus_reg_read( port, reg )
        elif 'write' == op:
            if len(self.argv) < 6:
                print msgbuscmd.__doc__
                return
            val = int(self.argv[5], 16)
            self.logger.log("[CHIPSEC] msgbus write: port 0x%02X + 0x%08X < 0x%08X" % (port, reg, val))
            res = _msgbus.msgbus_reg_write( port, reg, val )
        elif 'message' == op:
            opcode = int(self.argv[5], 16)
            val = None if len(self.argv) < 7 else int(self.argv[6], 16)
            self.logger.log("[CHIPSEC] msgbus message: port 0x%02X + 0x%08X, opcode: 0x%02X" % (port, reg, opcode))
            if val is not None: self.logger.log("[CHIPSEC]                 data: 0x%08X" % val)
            res = _msgbus.msgbus_send_message( port, reg, opcode, val )
        else:
             print msgbuscmd.__doc__
             return

        if res is not None: self.logger.log("[CHIPSEC] result: 0x%08X" % res)
        self.logger.log( "[CHIPSEC] (msgbus) time elapsed %.3f" % (time.time()-t) )

commands = { 'msgbus': MsgBusCommand }
