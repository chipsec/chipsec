#!/usr/local/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2014, Intel Corporation
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




#
# usage as a standalone utility:
#
## \addtogroup standalone
#chipsec_util smi / chipsec_util nmi
#-----------
#~~~
#chipsec_util smi <SMI_code> <SMI_data> [RAX] [RBX] [RCX] [RDX] [RSI] [RDI]
#chipsec_util nmi
#''
#    Examples:
#''
#        chipsec_util smi 0xDE 0x0
#        chipsec_util nmi
#~~~
__version__ = '1.0'

import os
import sys
import time

import chipsec_util
#from chipsec_util import global_usage, chipsec_util_commands, _cs
from chipsec_util import chipsec_util_commands, _cs

from chipsec.logger     import *
from chipsec.file       import *

from chipsec.hal.interrupts import Interrupts

#_cs = cs()

usage = "chipsec_util smi <SMI_code> <SMI_data> [RAX] [RBX] [RCX] [RDX] [RSI] [RDI]\n\n" + \
        "chipsec_util nmi\n" + \
        "Examples:\n" + \
        "  chipsec_util smi 0xDE 0x0\n" + \
        "  chipsec_util nmi\n\n"

chipsec_util.global_usage += usage


# ###################################################################
#
# CPU Interrupts
#
# ###################################################################
def smi(argv):
    try:
       interrupts = Interrupts( _cs )
    except RuntimeError, msg:
       print msg
       return

    SMI_code_port_value = 0xF
    SMI_data_port_value = 0x0
    if (2 == len(argv)):
       pass
    elif (3 < len(argv)):
       SMI_code_port_value = int(argv[2],16)
       SMI_data_port_value = int(argv[3],16)
       logger().log( "[CHIPSEC] Sending SW SMI (code: 0x%02X, data: 0x%02X).." % (SMI_code_port_value, SMI_data_port_value) )
       if (4 == len(argv)):
           interrupts.send_SMI_APMC( SMI_code_port_value, SMI_data_port_value )
       elif (10 == len(argv)):
           _rax = int(argv[4],16)
           _rbx = int(argv[5],16)
           _rcx = int(argv[6],16)
           _rdx = int(argv[7],16)
           _rsi = int(argv[8],16)
           _rdi = int(argv[9],16)
           logger().log( "          RAX: 0x%016X (AX will be overwridden with values of SW SMI ports B2/B3)" % _rax )
           logger().log( "          RBX: 0x%016X" % _rbx )
           logger().log( "          RCX: 0x%016X" % _rcx )
           logger().log( "          RDX: 0x%016X (DX will be overwridden with 0x00B2)" % _rdx )
           logger().log( "          RSI: 0x%016X" % _rsi )
           logger().log( "          RDI: 0x%016X" % _rdi )
           interrupts.send_SW_SMI( SMI_code_port_value, SMI_data_port_value, _rax, _rbx, _rcx, _rdx, _rsi, _rdi )
       else: print usage
    else: print usage


def nmi(argv):
    if 2 < len(argv):
       print usage

    try:
       interrupts = Interrupts( _cs )
    except RuntimeError, msg:
       print msg
       return

    logger().log( "[CHIPSEC] Sending NMI#.." )
    interrupts.send_NMI()


chipsec_util_commands['nmi'] = {'func' : nmi,     'start_driver' : True  }
chipsec_util_commands['smi'] = {'func' : smi,     'start_driver' : True  }

