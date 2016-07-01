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

import time

import chipsec.hal.cpu
from chipsec.command import BaseCommand

# ###################################################################
#
# CPU utility
#
# ###################################################################
class CPUCommand(BaseCommand):
    """
    >>> chipsec_util cpu info
    >>> chipsec_util cpu cr <cpu_id> <cr_number> [value]
    >>> chipsec_util cpu cpuid <eax> [ecx]
    >>> chipsec_util cpu pt [paging_base_cr3]

    Examples:

    >>> chipsec_util cpu info
    >>> chipsec_util cpu cr 0 0
    >>> chipsec_util cpu cr 0 4 0x0
    >>> chipsec_util cpu cpuid 40000000
    >>> chipsec_util cpu pt
    """

    def requires_driver(self):
        # No driver required when printing the util documentation
        if len(self.argv) < 3:
            return False
        return True

    def run(self):
        if len(self.argv) < 3:
            print CPUCommand.__doc__
            return
        op = self.argv[2]
        t = time.time()

        if 'info' == op:
            self.logger.log( "[CHIPSEC] CPU information:" )
            ht               = self.cs.cpu.is_HT_active()      
            threads_per_core = self.cs.cpu.get_number_logical_processor_per_core()
            threads_per_pkg  = self.cs.cpu.get_number_logical_processor_per_package()
            cores_per_pkg    = self.cs.cpu.get_number_physical_processor_per_package()
            self.logger.log( "          Hyper-Threading         : %s" % ('Enabled' if ht else 'Disabled') )
            self.logger.log( "          CPU cores per package   : %d" % cores_per_pkg )
            self.logger.log( "          CPU threads per core    : %d" % threads_per_core )
            self.logger.log( "          CPU threads per package : %d" % threads_per_pkg )
            try:
                threads_count = self.cs.cpu.get_number_threads_from_APIC_table()
                sockets_count = self.cs.cpu.get_number_sockets_from_APIC_table()
                self.logger.log( "          Number of sockets       : %d" % sockets_count )
                self.logger.log( "          Number of CPU threads   : %d" % threads_count )
            except:
                pass

        elif 'cr' == op:

            if len(self.argv) > 5:
                cpu_thread_id = int(self.argv[3],10)
                cr_number     = int(self.argv[4],16)
                value         = int(self.argv[5], 16)
                self.logger.log( "[CHIPSEC] CPU%d: write CR%d <- 0x%08X" % (cpu_thread_id, cr_number, value) )
                self.cs.cpu.write_cr( cpu_thread_id, cr_number, value )
                return True
            elif len(self.argv) > 4:
                cpu_thread_id = int(self.argv[3],10)
                cr_number     = int(self.argv[4],16)
                value = self.cs.cpu.read_cr( cpu_thread_id, cr_number )
                self.logger.log( "[CHIPSEC] CPU%d: read CR%d -> 0x%08X" % (cpu_thread_id, cr_number, value) )
                return value
            else:
                for tid in range(self.cs.msr.get_cpu_thread_count()):
                    cr0 = self.cs.cpu.read_cr( tid, 0 )
                    cr2 = self.cs.cpu.read_cr( tid, 2 )
                    cr3 = self.cs.cpu.read_cr( tid, 3 )
                    cr4 = self.cs.cpu.read_cr( tid, 4 )
                    cr8 = self.cs.cpu.read_cr( tid, 8 )
                    self.logger.log( "[CHIPSEC][cpu%d] x86 Control Registers:" % tid )
                    self.logger.log( "  CR0: 0x%016X" % cr0 )
                    self.logger.log( "  CR2: 0x%016X" % cr2 )
                    self.logger.log( "  CR3: 0x%016X" % cr3 )
                    self.logger.log( "  CR4: 0x%016X" % cr4 )
                    self.logger.log( "  CR8: 0x%016X" % cr8 )

        elif 'cpuid' == op:
            if len(self.argv) < 4:
                print CPUCommand.__doc__
                return

            eax = int(self.argv[3],16)
            ecx = int(self.argv[4],16) if 5 == len(self.argv) else 0

            self.logger.log( "[CHIPSEC] CPUID < EAX: 0x%08X" % eax)
            self.logger.log( "[CHIPSEC]         ECX: 0x%08X" % ecx)

            (_eax,_ebx,_ecx,_edx) = self.cs.cpu.cpuid( eax, ecx )

            self.logger.log( "[CHIPSEC] CPUID > EAX: 0x%08X" % _eax )
            self.logger.log( "[CHIPSEC]         EBX: 0x%08X" % _ebx )
            self.logger.log( "[CHIPSEC]         ECX: 0x%08X" % _ecx )
            self.logger.log( "[CHIPSEC]         EDX: 0x%08X" % _edx )
        
        elif op == "pt":

            if len(self.argv) == 4:
                cr3 = int(self.argv[3],16) 
                pt_fname = 'pt_%08X' % cr3
                self.logger.log( "[CHIPSEC] paging physical base (CR3): 0x%016X" % cr3 )
                self.logger.log( "[CHIPSEC] dumping paging hierarchy to '%s'..." % pt_fname )
                self.cs.cpu.dump_page_tables( cr3, pt_fname )
            else:
                for tid in range(self.cs.msr.get_cpu_thread_count()):
                    cr3 = self.cs.cpu.read_cr( tid, 3 )
                    pt_fname = 'cpu%d_pt_%08X' % (tid,cr3)
                    self.logger.log( "[CHIPSEC][cpu%d] paging physical base (CR3): 0x%016X" % (tid,cr3) )
                    self.logger.log( "[CHIPSEC][cpu%d] dumping paging hierarchy to '%s'..." % (tid,pt_fname) )
                    self.cs.cpu.dump_page_tables( cr3, pt_fname )

        else:
            print CPUCommand.__doc__
            return
        
        self.logger.log( "[CHIPSEC] (cpu) time elapsed %.3f" % (time.time()-t) )


commands = { 'cpu': CPUCommand }
