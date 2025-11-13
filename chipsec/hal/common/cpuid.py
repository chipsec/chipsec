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

from sys import byteorder
from struct import unpack
from typing import Tuple
from chipsec.hal import hal_base
from chipsec.library.logger import logger
from chipsec.library.strings import bytestostring


class CpuId(hal_base.HALBase):

    def __init__(self, cs):
        super(CpuId, self).__init__(cs)
        self.helper = cs.helper

    def cpuid(self, eax: int, ecx: int) -> Tuple[int, int, int, int]:
        return self.cs.hals.cpu.cpuid(eax, ecx)

    def get_proc_info(self):
        (eax, _, _, _) = self.cpuid(0x01, 0x00)
        return eax
    
    def get_mfgid(self) -> str:
        (_,ebx, ecx, edx) = self.cpuid(0x00, 0x00)
        mfg_barray = ebx.to_bytes(4, byteorder) + edx.to_bytes(4, byteorder) + ecx.to_bytes(4, byteorder)
        return bytestostring(unpack('<12s', mfg_barray)[0])
    

        
        

haldata = {"arch":[hal_base.HALBase.MfgIds.Any], 'name': {'cpuid': "CpuId"}}