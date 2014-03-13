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




## \addtogroup standalone
#chipsec_util cpuid
#------
#~~~
#chipsec_util cpuid [eax]
#''
#    Examples:
#''
#         chipsec_util cpuid 40000000
#~~~

__version__ = '1.0'

import os
import sys
import time

import chipsec_util
#from chipsec_util import global_usage, chipsec_util_commands, _cs
from chipsec_util import chipsec_util_commands, _cs

from chipsec.logger     	import *
from chipsec.file       	import *
#_cs = cs()

usage = "chipsec_util cpuid <eax> \n" + \
        "Examples:\n" + \
        "  chipsec_util cpuid 40000000\n\n"

chipsec_util.global_usage += usage



# ###################################################################
#
# CPUid
#
# ###################################################################
def cpuid(argv):

    if 3 > len(argv):
      print usage
      return

    eax = int(argv[2],16)

    if (3 == len(argv)):
		logger().log( "[CHIPSEC] CPUID in EAX=0x%x " % (eax))
		val = _cs.cpuid.cpuid(eax)
		logger().log( "[CHIPSEC] CPUID out EAX: 0x%x" % (val[0]) )
		logger().log( "[CHIPSEC] CPUID out EBX: 0x%x" % (val[1]) )
		logger().log( "[CHIPSEC] CPUID out ECX: 0x%x" % (val[2]) )
		logger().log( "[CHIPSEC] CPUID out EDX: 0x%x" % (val[3]) )


chipsec_util_commands['cpuid'] = {'func' : cpuid ,    'start_driver' : True  }

