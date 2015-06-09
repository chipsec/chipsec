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

import os
import sys
import time

import chipsec_util

from chipsec.logger     import *
from chipsec.file       import *

from chipsec.hal.interrupts import Interrupts

# ###################################################################
#
# CPU Interrupts
#
# ###################################################################
def smi(argv):
    """
    >>> chipsec_util smi <thread_id> <SMI_code> <SMI_data> [RAX] [RBX] [RCX] [RDX] [RSI] [RDI]

    Examples:

    >>> chipsec_util smi 0x0 0xDE 0x0
    >>> chipsec_util smi 0x0 0xDE 0x0 0xAAAAAAAAAAAAAAAA ..
    """
    try:
        interrupts = Interrupts( chipsec_util._cs )
    except RuntimeError, msg:
        print msg
        return

    SMI_code_port_value = 0xF
    SMI_data_port_value = 0x0
    if (2 == len(argv)):
        print smi.__doc__
    elif (4 < len(argv)):
        thread_id = int(argv[2],16)
        SMI_code_port_value = int(argv[3],16)
        SMI_data_port_value = int(argv[4],16)
        logger().log( "[CHIPSEC] Sending SW SMI (code: 0x%02X, data: 0x%02X).." % (SMI_code_port_value, SMI_data_port_value) )
        if (5 == len(argv)):
            interrupts.send_SMI_APMC( SMI_code_port_value, SMI_data_port_value )
        elif (11 == len(argv)):
            _rax = int(argv[5],16)
            _rbx = int(argv[6],16)
            _rcx = int(argv[7],16)
            _rdx = int(argv[8],16)
            _rsi = int(argv[9],16)
            _rdi = int(argv[10],16)
            logger().log( "          RAX: 0x%016X (AX will be overwridden with values of SW SMI ports B2/B3)" % _rax )
            logger().log( "          RBX: 0x%016X" % _rbx )
            logger().log( "          RCX: 0x%016X" % _rcx )
            logger().log( "          RDX: 0x%016X (DX will be overwridden with 0x00B2)" % _rdx )
            logger().log( "          RSI: 0x%016X" % _rsi )
            logger().log( "          RDI: 0x%016X" % _rdi )
            interrupts.send_SW_SMI( thread_id, SMI_code_port_value, SMI_data_port_value, _rax, _rbx, _rcx, _rdx, _rsi, _rdi )
        else: print smi.__doc__
    else: print smi.__doc__


def nmi(argv):
    """
    >>> chipsec_util nmi

    Examples:

    >>> chipsec_util nmi
    """
    if 2 < len(argv):
        print nmi.__doc__

    try:
        interrupts = Interrupts( chipsec_util._cs )
    except RuntimeError, msg:
        print msg
        return

    logger().log( "[CHIPSEC] Sending NMI#.." )
    interrupts.send_NMI()


chipsec_util.commands['nmi'] = {'func' : nmi,     'start_driver' : True, 'help' : nmi.__doc__  }
chipsec_util.commands['smi'] = {'func' : smi,     'start_driver' : True, 'help' : smi.__doc__  }
