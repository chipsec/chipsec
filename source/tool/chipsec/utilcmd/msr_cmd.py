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



"""
The msr command allows direct access to read and write MSRs.
"""

__version__ = '1.0'

import os
import sys
import time

import chipsec_util


from chipsec.logger     import *
from chipsec.file       import *

from chipsec.hal.msr    import Msr


# CPU Model Specific Registers
def msr(argv):
    """
    >>> chipsec_util msr <msr> [eax] [edx] [cpu_id]

    Examples:

    >>> chipsec_util msr 0x3A
    >>> chipsec_util msr 0x8B 0x0 0x0 0
    """
    if 3 > len(argv):
        print msr.__doc__
        return

    #msr = Msr( os_helper )
    msr_addr = int(argv[2],16)

    if (3 == len(argv)):
        for tid in range(chipsec_util._cs.msr.get_cpu_thread_count()):
            (eax, edx) = chipsec_util._cs.msr.read_msr( tid, msr_addr )
            val64 = ((edx << 32) | eax)
            logger().log( "[CHIPSEC] CPU%d: RDMSR( 0x%x ) = %016X (EAX=%08X, EDX=%08X)" % (tid, msr_addr, val64, eax, edx) )
    elif (4 == len(argv)):
        cpu_thread_id = int(argv[3], 16)
        (eax, edx) = chipsec_util._cs.msr.read_msr( cpu_thread_id, msr_addr )
        val64 = ((edx << 32) | eax)
        logger().log( "[CHIPSEC] CPU%d: RDMSR( 0x%x ) = %016X (EAX=%08X, EDX=%08X)" % (cpu_thread_id, msr_addr, val64, eax, edx) )
    else:
        eax = int(argv[3], 16)
        edx = int(argv[4], 16)
        val64 = ((edx << 32) | eax)
        if (5 == len(argv)):
            logger().log( "[CHIPSEC] All CPUs: WRMSR( 0x%x ) = %016X" % (msr_addr, val64) )
            for tid in range(chipsec_util._cs.msr.get_cpu_thread_count()):
                chipsec_util._cs.msr.write_msr( tid, msr_addr, eax, edx )
        elif (6 == len(argv)):
            cpu_thread_id = int(argv[5], 16)
            logger().log( "[CHIPSEC] CPU%d: WRMSR( 0x%x ) = %016X" % (cpu_thread_id, msr_addr, val64) )
            chipsec_util._cs.msr.write_msr( cpu_thread_id, msr_addr, eax, edx )

chipsec_util.commands['msr'] = {'func' : msr , 'start_driver' : True, 'help' : msr.__doc__ }
