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

    Examples:

    >>> chipsec_util cpu info
    >>> chipsec_util cpu cr 0 0
    >>> chipsec_util cpu cr 0 4 0x0
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

        try:
            _cpu = chipsec.hal.cpu.CPU(self.cs)
        except chipsec.hal.cpu.CPURuntimeError, msg:
            print msg
            return

        if 'info' == op:
            self.logger.log( "[CHIPSEC] CPU information:" )
            ht               = _cpu.is_HT_active()      
            threads_per_core = _cpu.get_number_logical_processor_per_core()
            threads_per_pkg  = _cpu.get_number_logical_processor_per_package()
            cores_per_pkg    = _cpu.get_number_physical_processor_per_package()
            threads_count    = _cpu.get_number_threads_from_APIC_table()
            sockets_count    = _cpu.get_number_sockets_from_APIC_table()
            self.logger.log( "          Hyper-Threading         : %s" % ('Enabled' if ht else 'Disabled') )
            self.logger.log( "          CPU cores per package   : %d" % cores_per_pkg )
            self.logger.log( "          CPU threads per core    : %d" % threads_per_core )
            self.logger.log( "          CPU threads per package : %d" % threads_per_pkg )
            self.logger.log( "          Number of sockets       : %d" % sockets_count )
            self.logger.log( "          Number of CPU threads   : %d" % threads_count )

        elif 'cr' == op:
            if len(self.argv) < 5:
                print CPUCommand.__doc__
                return

            cpu_thread_id = int(self.argv[3],10)
            cr_number     = int(self.argv[4],16)

            if len(self.argv) > 5:
                value = int(self.argv[5], 16)
                self.logger.log( "[CHIPSEC] CPU: %d write CR%d <- 0x%08X" % (cpu_thread_id, cr_number, value) )
                self.cs.cpu.write_cr( cpu_thread_id, cr_number, value )
                return True
            else:
                value = self.cs.cpu.read_cr( cpu_thread_id, cr_number )
                self.logger.log( "[CHIPSEC] CPU: %d read CR%d -> 0x%08X" % (cpu_thread_id, cr_number, value) )
                return value

        else:
            print CPUCommand.__doc__
            return
        
        self.logger.log( "[CHIPSEC] (cpu) time elapsed %.3f" % (time.time()-t) )


commands = { 'cpu': CPUCommand }
