#!/usr/bin/python
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
The temperature command allows to get the temperature of CPU.
"""

from chipsec.command    import BaseCommand
from chipsec.hal.msr    import Msr
import chipsec.hal.cpu
from chipsec.defines import BIT0, BIT6
import time
import sched
import os

def get_ia32_thermal_status_addr():
    return 0x19C

def get_msr_temperature_target_addr():
    return 0x1A2

def get_ia32_package_thermal_status_addr():
    return 0x1B1


# CPU temperature
class TemperatureCommand(BaseCommand):
    """
    >>> chipsec_util temperature

    Examples:

    >>> chipsec_util temperature
    """
    def __init__(self, argv, cs=None):
        self.argv = argv
        self.logger = chipsec.logger.logger()
        self.cs = cs
        self.read_tmp_sched = sched.scheduler(time.time, time.sleep)
        
    def IsSupportDtsRead(self):
        (eax, ebx, ecx, edx) = self.cs.cpu.cpuid( 0x06, 0 )
        if ((eax & BIT0) and (eax & BIT6)):
            return True
        else:
            return False
        
    def requires_driver(self):
        # No driver required when printing the util documentation
        #if len(self.argv) < 3:
        #    return False
        return True

    def get_cpu_temperature(self):
        (eax, edx) = self.cs.msr.read_msr( 0, get_msr_temperature_target_addr() )
        tjmax = (eax >> 16) & 0xFF

        (eax, edx) = self.cs.msr.read_msr( 0, get_ia32_package_thermal_status_addr() )
        pkg_dis_tjmax = (eax & 0x007F0000) >> 16

        self.logger.log( "[CHIPSEC] CPU package: temperature = %d degree C" % (tjmax - pkg_dis_tjmax) )
        self.logger.log( "" )
        
        processor_per_core = self.cs.cpu.get_number_logical_processor_per_core()
        core_per_package = self.cs.cpu.get_number_physical_processor_per_package()
        for cid in range(core_per_package):
            tid = cid * processor_per_core
            (eax, edx) = self.cs.msr.read_msr( tid, get_ia32_thermal_status_addr() )
            dis_tjmax = (eax & 0x007F0000) >> 16
            self.logger.log( "[CHIPSEC] CPU core%d: temperature = %d degree C" % (cid, tjmax - dis_tjmax) )

    def get_cpu_temperature_period(self, inc = 0.5):
        if os.name == 'nt':
            os.system('cls')
        elif os.name == 'posix':
            os.system('clear')

        self.get_cpu_temperature()

        if os.name != 'edk2':
            self.logger.log( "" )
            self.logger.log( "press Ctrl+C to stop..." )
            self.event = self.read_tmp_sched.enter(inc, 0, self.get_cpu_temperature_period, ())       

    def run(self):
        #if len(self.argv) < 3:
        #    print TemperatureCommand.__doc__
        #    return
        
        if (self.IsSupportDtsRead() == False):
            self.logger.log( "The CPU doesn't support digital read out..." )
            return

        self.event = self.read_tmp_sched.enter(0.5, 0, self.get_cpu_temperature_period, ())
        
        try:
            self.read_tmp_sched.run()
        except KeyboardInterrupt:
            self.read_tmp_sched.cancel(self.event)
            pass

commands = { 'temperature': TemperatureCommand }
