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
from typing import Tuple, Optional
from chipsec.hal.hal_base import HALBase
from chipsec.logger import print_buffer_bytes


class Memory(HALBase):
    def __init__(self, cs):
        super(Memory, self).__init__(cs)
        self.helper = cs.helper

    ####################################################################################
    #
    # Physical memory API using 64b Physical Address
    # (Same functions as below just using 64b PA instead of High and Low 32b parts of PA)
    #
    ####################################################################################

    # Reading physical memory

    def read_physical_mem(self, phys_address: int, length: int) -> bytes:
        self.logger.log_hal(f'[mem] 0x{phys_address:016X}')
        return self.helper.read_phys_mem(phys_address, length)

    def read_physical_mem_qword(self, phys_address: int) -> int:
        out_buf = self.read_physical_mem(phys_address, 8)
        value = unpack('=Q', out_buf)[0]
        self.logger.log_hal(f'[mem] qword at PA = 0x{phys_address:016X}: 0x{value:016X}')
        return value

    def read_physical_mem_dword(self, phys_address: int) -> int:
        out_buf = self.read_physical_mem(phys_address, 4)
        value = unpack('=I', out_buf)[0]
        self.logger.log_hal(f'[mem] dword at PA = 0x{phys_address:016X}: 0x{value:08X}')
        return value

    def read_physical_mem_word(self, phys_address: int) -> int:
        out_buf = self.read_physical_mem(phys_address, 2)
        value = unpack('=H', out_buf)[0]
        self.logger.log_hal(f'[mem] word at PA = 0x{phys_address:016X}: 0x{value:04X}')
        return value

    def read_physical_mem_byte(self, phys_address: int) -> int:
        out_buf = self.read_physical_mem(phys_address, 1)
        value = unpack('=B', out_buf)[0]
        self.logger.log_hal(f'[mem] byte at PA = 0x{phys_address:016X}: 0x{value:02X}')
        return value

    # Writing physical memory

    def write_physical_mem(self, phys_address: int, length: int, buf: bytes) -> int:
        if self.logger.HAL:
            self.logger.log(f'[mem] buffer len = 0x{length:X} to PA = 0x{phys_address:016X}')
            print_buffer_bytes(buf)
        return self.helper.write_phys_mem(phys_address, length, buf)

    def write_physical_mem_dword(self, phys_address: int, dword_value: int) -> int:
        self.logger.log_hal(f'[mem] dword to PA = 0x{phys_address:016X} <- 0x{dword_value:08X}')
        return self.write_physical_mem(phys_address, 4, pack('I', dword_value))

    def write_physical_mem_word(self, phys_address: int, word_value: int) -> int:
        self.logger.log_hal(f'[mem] word to PA = 0x{phys_address:016X} <- 0x{word_value:04X}')
        return self.write_physical_mem(phys_address, 2, pack('H', word_value))

    def write_physical_mem_byte(self, phys_address: int, byte_value: int) -> int:
        self.logger.log_hal(f'[mem] byte to PA = 0x{phys_address:016X} <- 0x{byte_value:02X}')
        return self.write_physical_mem(phys_address, 1, pack('B', byte_value))

    # Allocate physical memory buffer

    def alloc_physical_mem(self, length: int, max_phys_address: int = 0xFFFFFFFFFFFFFFFF) -> Tuple[int, int]:
        (va, pa) = self.helper.alloc_phys_mem(length, max_phys_address)
        self.logger.log_hal(f'[mem] Allocated: PA = 0x{pa:016X}, VA = 0x{va:016X}')
        return (va, pa)

    def va2pa(self, va: int) -> Optional[int]:
        (pa, error_code) = self.helper.va2pa(va)
        if error_code:
            self.logger.log_hal(f'[mem] Looks like VA (0x{va:016X}) not mapped')
            return None
        self.logger.log_hal(f'[mem] VA (0x{va:016X}) -> PA (0x{pa:016X})')
        return pa

    # Map physical address to virtual

    def map_io_space(self, pa: int, length: int, cache_type: int) -> int:
        va = self.helper.map_io_space(pa, length, cache_type)
        self.logger.log_hal(f'[mem] Mapped: PA = 0x{pa:016X}, VA = 0x{va:016X}')
        return va

    # Free physical memory buffer

    def free_physical_mem(self, pa: int) -> bool:
        ret = self.helper.free_phys_mem(pa)
        self.logger.log_hal(f'[mem] Deallocated : PA = 0x{pa:016X}')
        return True if ret == 1 else False

    def set_mem_bit(self, addr: int, bit: int) -> int:
        addr += bit >> 3
        byte = self.read_physical_mem_byte(addr)
        self.write_physical_mem_byte(addr, (byte | (0x1 << (bit & 0x7))))
        return byte
