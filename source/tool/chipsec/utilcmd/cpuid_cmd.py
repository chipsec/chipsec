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

from chipsec.logger             import *
from chipsec.file               import *
#_cs = cs()

# ###################################################################
#
# CPUid
#
# ###################################################################
def cpuid(argv):
    """
    >>> chipsec_util cpuid <eax> [ecx]

    Examples:

    >>> chipsec_util cpuid 40000000
    """
    if 3 > len(argv):
        print cpuid.__doc__
        return

    eax = int(argv[2],16)
    ecx = int(argv[3],16) if 4 == len(argv) else 0

    logger().log( "[CHIPSEC] CPUID < EAX: 0x%08X" % eax)
    logger().log( "[CHIPSEC]         ECX: 0x%08X" % ecx)

    val = chipsec_util._cs.cpuid.cpuid( eax, ecx )

    logger().log( "[CHIPSEC] CPUID > EAX: 0x%08X" % (val[0]) )
    logger().log( "[CHIPSEC]         EBX: 0x%08X" % (val[1]) )
    logger().log( "[CHIPSEC]         ECX: 0x%08X" % (val[2]) )
    logger().log( "[CHIPSEC]         EDX: 0x%08X" % (val[3]) )


chipsec_util.commands['cpuid'] = {'func' : cpuid , 'start_driver' : True, 'help' : cpuid.__doc__  }
