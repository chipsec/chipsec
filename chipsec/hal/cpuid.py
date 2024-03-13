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
CPUID information

usage:
    >>> cpuid(0)
"""

from typing import Tuple
from chipsec.hal import hal_base
from chipsec.library.logger import logger


class CpuID(hal_base.HALBase):

    def __init__(self, cs):
        super(CpuID, self).__init__(cs)
        self.helper = cs.helper

    def cpuid(self, eax: int, ecx: int) -> Tuple[int, int, int, int]:
        logger().log_hal(f'[cpuid] in: EAX=0x{eax:08X}, ECX=0x{ecx:08X}')
        (eax, ebx, ecx, edx) = self.helper.cpuid(eax, ecx)
        logger().log_hal(f'[cpuid] out: EAX=0x{eax:08X}, EBX=0x{ebx:08X}, ECX=0x{ecx:08X}, EDX=0x{edx:08X}')
        return (eax, ebx, ecx, edx)

    def get_proc_info(self):
        (eax, _, _, _) = self.cpuid(0x01, 0x00)
        return eax
