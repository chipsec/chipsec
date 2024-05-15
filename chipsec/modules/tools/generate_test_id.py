# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2023, Intel Corporation
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
Generate a test ID using hashlib from the test's file name (no file extension).
Hash is truncated to 28 bits.

Usage:
    ``chipsec_main -m common.tools.generate_test_id -a <test name>``

Examples:
    >>> chipsec_main.py -m common.tools.generate_test_id -a remap
    >>> chipsec_main.py -m common.tools.generate_test_id -a s3bootscript
    >>> chipsec_main.py -m common.tools.generate_test_id -a bios_ts
"""

from chipsec.module_common import BaseModule
from chipsec.library.returncode import ModuleResult
from typing import List
import hashlib

class generate_test_id(BaseModule):
    def __init__(self):
        BaseModule.__init__(self)

    def usage(self):
        self.logger.log(__doc__.replace('`', ''))
        return

    def is_supported(self) -> bool:
        return True

    def generate_id(self, test_name: str) -> int:
        return hashlib.sha256(test_name.encode('ascii')).hexdigest()[:7]

    def run(self, module_argv: List[str]) -> int:
        self.logger.start_test('Generate test ID')

        if len(module_argv) == 1:
            module_name = module_argv[0]
            self.logger.log_good(f'Test ID for {module_name} is 0x{self.generate_id(module_name)}\n')
            self.result.setStatusBit(self.result.status.SUCCESS)
            self.res = self.result.getReturnCode(ModuleResult.INFORMATION)
        else:
            self.usage()
            self.result.setStatusBit(self.result.status.UNSUPPORTED_OPTION)
            self.res = self.result.getReturnCode(ModuleResult.WARNING)

        return self.res