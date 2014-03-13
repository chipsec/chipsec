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
#
## \addtogroup standalone
#chipsec_util idt / chipsec_util gdt / chipsec_util ldt
#---------
#~~~
#chipsec_util idt|gdt [cpu_id]
#''
#    Examples:
#''
#        chipsec_util idt 0
#        chipsec_util gdt
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

#from chipsec.hal.msr        import Msr
#_cs = cs()

usage = "chipsec_util idt|gdt|ldt [cpu_id]\n" + \
        "Examples:\n" + \
        "  chipsec_util idt 0\n" + \
        "  chipsec_util gdt\n\n"

chipsec_util.global_usage += usage


# ###################################################################
#
# CPU descriptor tables
#
# ###################################################################
def idt(argv):
    if (2 == len(argv)):
       logger().log( "[CHIPSEC] Dumping IDT of %d CPU threads" % _cs.msr.get_cpu_thread_count() )
       _cs.msr.IDT_all( 4 )
    elif (3 == len(argv)):
       tid = int(argv[2],16)
       _cs.msr.IDT( tid, 4 )
   
def gdt(argv):
    if (2 == len(argv)):
       logger().log( "[CHIPSEC] Dumping GDT of %d CPU threads" % _cs.msr.get_cpu_thread_count() )
       _cs.msr.GDT_all( 4 )
    elif (3 == len(argv)):
       tid = int(argv[2],16)
       _cs.msr.GDT( tid, 4 )

def ldt(argv):
    logger().error( "[CHIPSEC] ldt not implemented" )


chipsec_util_commands['idt'] = {'func' : idt,     'start_driver' : True  }
chipsec_util_commands['gdt'] = {'func' : gdt,     'start_driver' : True  }
