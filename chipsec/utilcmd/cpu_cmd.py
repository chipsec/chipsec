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
>>> chipsec_util cpu info
>>> chipsec_util cpu cr <thread> <cr_number> [value]
>>> chipsec_util cpu cpuid <eax> [ecx]
>>> chipsec_util cpu pt [paging_base_cr3]
>>> chipsec_util cpu topology

Examples:

>>> chipsec_util cpu info
>>> chipsec_util cpu cr 0 0
>>> chipsec_util cpu cr 0 4 0x0
>>> chipsec_util cpu cpuid 0x40000000
>>> chipsec_util cpu pt
>>> chipsec_util cpu topology
"""

from argparse import ArgumentParser

from chipsec.command import BaseCommand, toLoad
from typing import Dict, List, Optional, Union

# ###################################################################
#
# CPU utility
#
# ###################################################################


class CPUCommand(BaseCommand):
    
    def requirements(self) -> toLoad:
        return toLoad.All

    def parse_arguments(self) -> None:
        parser = ArgumentParser(usage=__doc__)
        subparsers = parser.add_subparsers()
        parser_info = subparsers.add_parser('info')
        parser_cr = subparsers.add_parser('cr')
        parser_cpuid = subparsers.add_parser('cpuid')
        parser_pt = subparsers.add_parser('pt')
        parser_topology = subparsers.add_parser('topology')
        parser_info.set_defaults(func=self.cpu_info)
        parser_cr.set_defaults(func=self.cpu_cr)
        parser_cpuid.set_defaults(func=self.cpu_cpuid)
        parser_pt.set_defaults(func=self.cpu_pt)
        parser_topology.set_defaults(func=self.cpu_topology)
        parser_cr.add_argument('thread', type=int, nargs='?', default=None)
        parser_cr.add_argument('cr_number', type=int, nargs='?', default=None)
        parser_cr.add_argument('value', type=lambda x: int(x, 0), nargs='?', default=None)
        parser_cpuid.add_argument('eax', type=lambda x: int(x, 0))
        parser_cpuid.add_argument('ecx', type=lambda x: int(x, 0), nargs='?', default=0)
        parser_pt.add_argument('cr3', type=lambda x: int(x, 0), nargs='?', default=None)

        parser.parse_args(self.argv, namespace=CPUCommand)

    def cpu_info(self) -> None:
        self.logger.log("[CHIPSEC] CPU information:")
        ht = self.cs.cpu.is_HT_active()
        threads_per_core = self.cs.cpu.get_number_logical_processor_per_core()
        threads_per_pkg = self.cs.cpu.get_number_logical_processor_per_package()
        cores_per_pkg = self.cs.cpu.get_number_physical_processor_per_package()
        self.logger.log(f'          Hyper-Threading         : {"Enabled" if ht else "Disabled"}')
        self.logger.log(f'          CPU cores per package   : {cores_per_pkg:d}')
        self.logger.log(f'          CPU threads per core    : {threads_per_core:d}')
        self.logger.log(f'          CPU threads per package : {threads_per_pkg:d}')
        try:
            threads_count = self.cs.cpu.get_number_threads_from_APIC_table()
            sockets_count = self.cs.cpu.get_number_sockets_from_APIC_table()
            self.logger.log(f'          Number of sockets       : {sockets_count:d}')
            self.logger.log(f'          Number of CPU threads   : {threads_count:d}')
        except Exception:
            pass

    def cpu_topology(self) -> Dict[str, Dict[int, List[int]]]:
        self.logger.log("[CHIPSEC] CPU information:")
        ht = self.cs.cpu.is_HT_active()
        threads_per_core = self.cs.cpu.get_number_logical_processor_per_core()
        threads_per_pkg = self.cs.cpu.get_number_logical_processor_per_package()
        cores_per_pkg = self.cs.cpu.get_number_physical_processor_per_package()
        num_threads = self.cs.helper.get_threads_count()
        self.logger.log(f'          Hyper-Threading         : {"Enabled" if ht else "Disabled"}')
        self.logger.log(f'          CPU cores per package   : {cores_per_pkg:d}')
        self.logger.log(f'          CPU threads per core    : {threads_per_core:d}')
        self.logger.log(f'          CPU threads per package : {threads_per_pkg:d}')
        self.logger.log(f'          Total threads           : {num_threads:d}')
        topology = self.cs.cpu.get_cpu_topology()
        self.logger.log("          Packages:")
        for p in topology['packages']:
            self.logger.log(f'              {p:d}: {topology["packages"][p]}')
        self.logger.log("          Cores:")
        for c in topology['cores']:
            self.logger.log(f'              {c:d}: {topology["cores"][c]}')

        return topology

    def cpu_cr(self) -> Optional[Union[bool, int]]:
        if self.value is not None:
            self.logger.log(f'[CHIPSEC] CPU{self.thread:d}: write CR{self.cr_number:d} <- 0x{self.value:08X}')
            self.cs.cpu.write_cr(self.thread, self.cr_number, self.value)
            return True
        elif self.cr_number is not None:
            value = self.cs.cpu.read_cr(self.thread, self.cr_number)
            self.logger.log(f'[CHIPSEC] CPU{self.thread:d}: read CR{self.cr_number:d} -> 0x{value:08X}')
            return value
        else:
            for tid in range(self.cs.msr.get_cpu_thread_count()):
                cr0 = self.cs.cpu.read_cr(tid, 0)
                cr2 = self.cs.cpu.read_cr(tid, 2)
                cr3 = self.cs.cpu.read_cr(tid, 3)
                cr4 = self.cs.cpu.read_cr(tid, 4)
                cr8 = self.cs.cpu.read_cr(tid, 8)
                self.logger.log(f'[CHIPSEC][cpu{tid:d}] x86 Control Registers:')
                self.logger.log(f'  CR0: 0x{cr0:016X}')
                self.logger.log(f'  CR2: 0x{cr2:016X}')
                self.logger.log(f'  CR3: 0x{cr3:016X}')
                self.logger.log(f'  CR4: 0x{cr4:016X}')
                self.logger.log(f'  CR8: 0x{cr8:016X}')

    def cpu_cpuid(self) -> None:
        self.logger.log(f'[CHIPSEC] CPUID < EAX: 0x{self.eax:08X}')
        self.logger.log(f'[CHIPSEC]         ECX: 0x{self.ecx:08X}')

        (_eax, _ebx, _ecx, _edx) = self.cs.cpu.cpuid(self.eax, self.ecx)

        self.logger.log("[CHIPSEC] CPUID > EAX: 0x%08X" % _eax)
        self.logger.log("[CHIPSEC]         EBX: 0x%08X" % _ebx)
        self.logger.log("[CHIPSEC]         ECX: 0x%08X" % _ecx)
        self.logger.log("[CHIPSEC]         EDX: 0x%08X" % _edx)

    def cpu_pt(self) -> None:
        if self.cr3 is not None:
            pt_fname = f'pt_{self.cr3:08X}'
            self.logger.log(f'[CHIPSEC] paging physical base (CR3): 0x{self.cr3:016X}')
            self.logger.log(f'[CHIPSEC] dumping paging hierarchy to \'{pt_fname}\'...')
            self.cs.cpu.dump_page_tables(self.cr3, pt_fname)
        else:
            for tid in range(self.cs.msr.get_cpu_thread_count()):
                cr3 = self.cs.cpu.read_cr(tid, 3)
                pt_fname = f'cpu{tid:d}_pt_{cr3:08X}'
                self.logger.log(f'[CHIPSEC][cpu{tid:d}] paging physical base (CR3): 0x{cr3:016X}')
                self.logger.log(f'[CHIPSEC][cpu{tid:d}] dumping paging hierarchy to \'{pt_fname}\'...')
                self.cs.cpu.dump_page_tables(cr3, pt_fname)


commands = {'cpu': CPUCommand}
