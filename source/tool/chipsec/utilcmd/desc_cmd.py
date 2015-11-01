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

from chipsec.command import BaseCommand

# CPU descriptor tables
class IDTCommand(BaseCommand):
    """
    >>> chipsec_util idt|gdt|ldt [cpu_id]

    Examples:

    >>> chipsec_util idt 0
    >>> chipsec_util gdt
    """

    def requires_driver(self):
        return True

    def run(self):
        if (2 == len(self.argv)):
            self.logger.log( "[CHIPSEC] Dumping IDT of %d CPU threads" % self.cs.msr.get_cpu_thread_count() )
            self.cs.msr.IDT_all( 4 )
        elif (3 == len(self.argv)):
            tid = int(self.argv[2],16)
            self.cs.msr.IDT( tid, 4 )

class GDTCommand(BaseCommand):
    """
    >>> chipsec_util idt|gdt|ldt [cpu_id]

    Examples:

    >>> chipsec_util idt 0
    >>> chipsec_util gdt
    """

    def requires_driver(self):
        return True

    def run(self):
        if (2 == len(self.argv)):
            self.logger.log( "[CHIPSEC] Dumping GDT of %d CPU threads" % self.cs.msr.get_cpu_thread_count() )
            self.cs.msr.GDT_all( 4 )
        elif (3 == len(self.argv)):
            tid = int(self.argv[2],16)
            self.cs.msr.GDT( tid, 4 )

class LDTCommand(BaseCommand):
    """
    >>> chipsec_util idt|gdt|ldt [cpu_id]

    Examples:

    >>> chipsec_util idt 0
    >>> chipsec_util gdt
    """
    def requires_driver(self):
        return True

    def run(self):
        self.logger.error( "[CHIPSEC] ldt not implemented" )

commands = { 'idt': IDTCommand, 'gdt': GDTCommand }
