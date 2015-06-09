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
The idt and gdt commands print the IDT and GDT, respectively.
"""

__version__ = '1.0'

import os
import sys
import time

import chipsec_util


from chipsec.logger     import *
from chipsec.file       import *

#from chipsec.hal.msr        import Msr


# CPU descriptor tables
def idt(argv):
    """
    >>> chipsec_util idt|gdt|ldt [cpu_id]

    Examples:

    >>> chipsec_util idt 0
    >>> chipsec_util gdt
    """
    if (2 == len(argv)):
        logger().log( "[CHIPSEC] Dumping IDT of %d CPU threads" % chipsec_util._cs.msr.get_cpu_thread_count() )
        chipsec_util._cs.msr.IDT_all( 4 )
    elif (3 == len(argv)):
        tid = int(argv[2],16)
        chipsec_util._cs.msr.IDT( tid, 4 )

def gdt(argv):
    """
    >>> chipsec_util idt|gdt|ldt [cpu_id]

    Examples:

    >>> chipsec_util idt 0
    >>> chipsec_util gdt
    """
    if (2 == len(argv)):
        logger().log( "[CHIPSEC] Dumping GDT of %d CPU threads" % chipsec_util._cs.msr.get_cpu_thread_count() )
        chipsec_util._cs.msr.GDT_all( 4 )
    elif (3 == len(argv)):
        tid = int(argv[2],16)
        chipsec_util._cs.msr.GDT( tid, 4 )

def ldt(argv):
    """
    >>> chipsec_util idt|gdt|ldt [cpu_id]

    Examples:

    >>> chipsec_util idt 0
    >>> chipsec_util gdt
    """
    logger().error( "[CHIPSEC] ldt not implemented" )


chipsec_util.commands['idt'] = {'func' : idt, 'start_driver' : True, 'help' : idt.__doc__ }
chipsec_util.commands['gdt'] = {'func' : gdt, 'start_driver' : True, 'help' : gdt.__doc__ }
