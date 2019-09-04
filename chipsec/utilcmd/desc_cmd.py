#!/usr/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2019, Intel Corporation
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

from time import time
from argparse import ArgumentParser

from chipsec.command import BaseCommand

# CPU descriptor tables
class IDTCommand(BaseCommand):
    """
    >>> chipsec_util idt [cpu_id]

    Examples:

    >>> chipsec_util idt 0
    >>> chipsec_util idt
    """

    def requires_driver(self):
        parser = ArgumentParser(usage=IDTCommand.__doc__)
        parser.add_argument('_thread', metavar='thread', type=lambda x: int(x,0), nargs='?', default=None, help="thread")
        parser.parse_args(self.argv[2:], namespace=self)
        return True

    def run(self):
        t = time()
        num_threads = self.cs.msr.get_cpu_thread_count()
        if self._thread and self._thread < num_threads:
            self.logger.log( "[CHIPSEC] Dumping IDT of CPU thread {:d}".format(self._thread) )
            self.cs.msr.IDT( self._thread, 4 )
        else:
            self.logger.log( "[CHIPSEC] Dumping IDT of {:d} CPU threads".format(num_threads) )
            self.cs.msr.IDT_all( 4 )
        self.logger.log( "[CHIPSEC] (acpi) time elapsed {:.3f}".format(time()-t) )

class GDTCommand(BaseCommand):
    """
    >>> chipsec_util gdt [cpu_id]

    Examples:

    >>> chipsec_util gdt 0
    >>> chipsec_util gdt
    """

    def requires_driver(self):
        parser = ArgumentParser(usage=GDTCommand.__doc__)
        parser.add_argument('_thread', metavar='thread', type=lambda x: int(x,0), nargs='?', default=None, help="thread")
        parser.parse_args(self.argv[2:], namespace=self)
        return True

    def run(self):
        t = time()
        num_threads = self.cs.msr.get_cpu_thread_count()
        if self._thread and self._thread < num_threads:
            self.logger.log( "[CHIPSEC] Dumping IDT of CPU thread {:d}".format(self._thread) )
            self.cs.msr.GDT( self._thread, 4 )
        else:
            self.logger.log( "[CHIPSEC] Dumping IDT of {:d} CPU threads".format(num_threads) )
            self.cs.msr.GDT_all( 4 )
        self.logger.log( "[CHIPSEC] (acpi) time elapsed {:.3f}".format(time()-t) )

class LDTCommand(BaseCommand):
    """
    >>> chipsec_util ldt [cpu_id]

    Examples:

    >>> chipsec_util ldt 0
    >>> chipsec_util ldt
    """
    def requires_driver(self):
        return True

    def run(self):
        self.logger.error( "[CHIPSEC] ldt not implemented" )

commands = { 'idt': IDTCommand, 'gdt': GDTCommand }
