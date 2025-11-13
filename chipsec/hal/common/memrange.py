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
Access to physical memory

usage:
    >>> read_physical_mem( 0xf0000, 0x100 )
    >>> write_physical_mem( 0xf0000, 0x100, buffer )
    >>> write_physical_mem_dowrd( 0xf0000, 0xdeadbeef )
    >>> read_physical_mem_dowrd( 0xfed40000 )
"""

from struct import unpack, pack
from typing import Any, Dict, Tuple, Optional
from chipsec.hal.hal_base import HALBase
from chipsec.library.logger import print_buffer_bytes
from chipsec.library.bits import make_mask


class MemRange(HALBase):
    def __init__(self, cs):
        super(MemRange, self).__init__(cs)
        self.helper = cs.helper

    ####################################################################################
    #
    # Physical memory API using 64b Physical Address
    # (Same functions as below just using 64b PA instead of High and Low 32b parts of PA)
    #
    ####################################################################################

    # Reading physical memory

    def read(self, phys_address: int, length: int) -> bytes:
        self.logger.log_hal(f'[mem] 0x{phys_address:016X}')
        return self.helper.read_phys_mem(phys_address, length)

    
    def write(self, phys_address: int, length: int, buf: bytes) -> int:
        if self.logger.HAL:
            self.logger.log(f'[mem] buffer len = 0x{length:X} to PA = 0x{phys_address:016X}')
            print_buffer_bytes(buf)
        return self.helper.write_phys_mem(phys_address, length, buf)
    
    def get_def(self, range_name: str) -> Dict[str, Any]:
        '''Return address access of a MEM register'''
        ranges = self.cs.Cfg.get_objlist(range_name)
        if ranges:
            return ranges[0]
        return None


haldata = {"arch":[HALBase.MfgIds.Any], 'name': {'memrange': "MemRange"}}
