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


from define                           import *
from chipsec.modules.tools.vmm.common import *
from chipsec.hal.vmm                  import *

"""
Xen hypercall information tool

 Usage:
   ``chipsec_main.py -i -m tools.vmm.xen.hypercallinfo``
"""

class HypercallInfo(BaseModuleDebug):
    def __init__(self):
        BaseModuleDebug.__init__(self)
        self.vmm = VMM(self.cs)
        self.vmm.init()
        self.hypercalls = {}

    def probe_hypercall(self, vector):
        self.logger.log('[*] Probing hypercall: 0x%04x' % vector)
        try:
            status = self.vmm.hypercall64_five_args(vector, 0, 0, 0, 0, 0)
        except Exception as e:
            self.logger.error('Exception on hypercall (0x%08x): %s' % (vector, str(e)))
        return {'status': status}

    def scan_hypercalls(self, vector_list):
        for vector in vector_list:
            result = self.probe_hypercall(vector)
            if result['status'] <> get_invalid_hypercall_code():
                self.hypercalls[vector] = result

    def print_hypercall_status(self):
        self.logger.log('*** Hypervisor Hypercall Status Codes ***')
        for vector in sorted(self.hypercalls.keys()):
            data   = self.hypercalls[vector]
            name   = get_hypercall_name(vector)
            status = get_hypercall_status(data['status'])
            self.logger.log("[*] HYPERCALL %04x  %016x  %-50s '%s'" % (vector, data['status'], status, name))

    def usage(self):
        self.logger.log('  Usage:')
        self.logger.log('    chipsec_main.py -i -m tools.vmm.xen.hypercallinfo')


    def run(self, module_argv):
        self.logger.start_test( "Xen hypercall information utility" )

        hv = HypercallInfo()
        hv.promt = 'CHIPSEC'

        hv.scan_hypercalls(xrange(256))
        hv.print_hypercall_status()
