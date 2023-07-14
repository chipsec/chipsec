# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2021, Intel Corporation
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; Version 2.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
# Contact information:
# chipsec@intel.com
#

"""
The idt, gdt and ldt commands print the IDT, GDT and LDT, respectively.

IDT command:

>>> chipsec_util idt [cpu_id]

Examples:

>>> chipsec_util idt 0
>>> chipsec_util idt

GDT command:

>>> chipsec_util gdt [cpu_id]

Examples:

>>> chipsec_util gdt 0
>>> chipsec_util gdt

LDT command:

>>> chipsec_util ldt [cpu_id]

Examples:

>>> chipsec_util ldt 0
>>> chipsec_util ldt
"""

from argparse import ArgumentParser

from chipsec.command import BaseCommand, toLoad

# CPU descriptor tables


class IDTCommand(BaseCommand):
    """
    >>> chipsec_util idt [cpu_id]

    Examples:

    >>> chipsec_util idt 0
    >>> chipsec_util idt
    """

    def requirements(self) -> toLoad:
        return toLoad.Driver
    
    def parse_arguments(self) -> None:
        parser = ArgumentParser(usage=IDTCommand.__doc__)
        parser.add_argument('_thread', metavar='thread', type=lambda x: int(x, 0), nargs='?', default=None, help="thread")
        parser.parse_args(self.argv, namespace=self)

    def run(self) -> None:
        num_threads = self.cs.msr.get_cpu_thread_count()
        if self._thread and self._thread < num_threads:
            self.logger.log(f'[CHIPSEC] Dumping IDT of CPU thread {self._thread:d}')
            self.cs.msr.IDT(self._thread, 4)
        else:
            self.logger.log(f'[CHIPSEC] Dumping IDT of {num_threads:d} CPU threads')
            self.cs.msr.IDT_all(4)


class GDTCommand(BaseCommand):
    """
    >>> chipsec_util gdt [cpu_id]

    Examples:

    >>> chipsec_util gdt 0
    >>> chipsec_util gdt
    """

    def requirements(self) -> toLoad:
        return toLoad.Driver
    
    def parse_arguments(self) -> None:
        parser = ArgumentParser(usage=GDTCommand.__doc__)
        parser.add_argument('_thread', metavar='thread', type=lambda x: int(x, 0), nargs='?', default=None, help="thread")
        parser.parse_args(self.argv, namespace=self)

    def run(self) -> None:
        num_threads = self.cs.msr.get_cpu_thread_count()
        if self._thread and self._thread < num_threads:
            self.logger.log(f'[CHIPSEC] Dumping IDT of CPU thread {self._thread:d}')
            self.cs.msr.GDT(self._thread, 4)
        else:
            self.logger.log(f'[CHIPSEC] Dumping IDT of {num_threads:d} CPU threads')
            self.cs.msr.GDT_all(4)


class LDTCommand(BaseCommand):
    """
    >>> chipsec_util ldt [cpu_id]

    Examples:

    >>> chipsec_util ldt 0
    >>> chipsec_util ldt
    """

    def requirements(self) -> toLoad:
        return toLoad.Nil
    
    def parse_arguments(self) -> None:
        return

    def run(self) -> None:
        self.logger.log_error("[CHIPSEC] ldt not implemented")


commands = {'idt': IDTCommand, 'gdt': GDTCommand}
