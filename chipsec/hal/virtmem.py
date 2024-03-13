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
Access to virtual memory

usage:
    >>> read_virtual_mem( 0xf0000, 0x100 )
    >>> write_virtual_mem( 0xf0000, 0x100, buffer )
    >>> write_virtual_mem_dowrd( 0xf0000, 0xdeadbeef )
    >>> read_virtual_mem_dowrd( 0xfed40000 )
"""

import struct
from typing import Tuple
from chipsec.library.logger import logger, print_buffer_bytes
from chipsec.hal import hal_base


class VirtMemory(hal_base.HALBase):
    def __init__(self, cs):
        super(VirtMemory, self).__init__(cs)
        self.helper = cs.helper

    ####################################################################################
    #
    # virtual memory API using 64b virtual Address
    # (Same functions as below just using 64b PA instead of High and Low 32b parts of PA)
    #
    ####################################################################################

    # Reading virtual memory

    def read_virtual_mem(self, virt_address: int, length: int) -> int:
        logger().log_hal(f'[mem] 0x{virt_address:016X}')
        phys_address = self.va2pa(virt_address)
        return self.helper.read_phys_mem(phys_address, length)

    def read_virtual_mem_dword(self, virt_address: int) -> int:
        phys_address = self.va2pa(virt_address)
        out_buf = self.helper.read_phys_mem(phys_address, 4)
        value = struct.unpack('=I', out_buf)[0]
        logger().log_hal(f'[mem] dword at VA = 0x{virt_address:016X}: 0x{value:08X}')
        return value

    def read_virtual_mem_word(self, virt_address: int) -> int:
        phys_address = self.va2pa(virt_address)
        out_buf = self.helper.read_phys_mem(phys_address, 2)
        value = struct.unpack('=H', out_buf)[0]
        logger().log_hal(f'[mem] word at VA = 0x{virt_address:016X}: 0x{value:04X}')
        return value

    def read_virtual_mem_byte(self, virt_address: int) -> int:
        phys_address = self.va2pa(virt_address)
        out_buf = self.helper.read_phys_mem(phys_address, 1)
        value = struct.unpack('=B', out_buf)[0]
        logger().log_hal(f'[mem] byte at VA = 0x{virt_address:016X}: 0x{value:02X}')
        return value

    # Writing virtual memory

    def write_virtual_mem(self, virt_address: int, length: int, buf: bytes) -> int:
        logger().log_hal(f'[mem] buffer len = 0x{length:X} to VA = 0x{virt_address:016X}')
        if logger().HAL:
            print_buffer_bytes(buf)
        phys_address = self.va2pa(virt_address)
        return self.helper.write_phys_mem(phys_address, length, buf)

    def write_virtual_mem_dword(self, virt_address: int, dword_value: int) -> int:
        logger().log_hal(f'[mem] dword to VA = 0x{virt_address:016X} <- 0x{dword_value:08X}')
        phys_address = self.va2pa(virt_address)
        return self.helper.write_phys_mem(phys_address, 4, struct.pack('I', dword_value))

    def write_virtual_mem_word(self, virt_address: int, word_value: int) -> int:
        logger().log_hal(f'[mem] word to VA = 0x{virt_address:016X} <- 0x{word_value:04X}')
        phys_address = self.va2pa(virt_address)
        return self.helper.write_phys_mem(phys_address, 2, struct.pack('H', word_value))

    def write_virtual_mem_byte(self, virt_address: int, byte_value: int) -> int:
        logger().log_hal(f'[mem] byte to VA = 0x{virt_address:016X} <- 0x{byte_value:02X}')
        phys_address = self.va2pa(virt_address)
        return self.helper.write_phys_mem(phys_address, 1, struct.pack('B', byte_value))

    # Allocate virtual memory buffer

    def alloc_virtual_mem(self, length: int, max_phys_address: int = 0xFFFFFFFFFFFFFFFF) -> Tuple[int, int]:
        (va, pa) = self.helper.alloc_phys_mem(length, max_phys_address)
        logger().log_hal(f'[mem] Allocated: PA = 0x{pa:016X}, VA = 0x{va:016X}')
        return (va, pa)

    def va2pa(self, va: int) -> int:
        (pa, error_code) = self.helper.va2pa(va)
        if error_code:
            logger().log_hal(f'[mem] Looks like VA (0x{va:016X}) not mapped')
            return va
        logger().log_hal(f'[mem] VA (0x{va:016X}) -> PA (0x{pa:016X})')
        return pa

    def free_virtual_mem(self, virt_address: int) -> bool:
        pa = self.va2pa(virt_address)
        ret = self.helper.free_phys_mem(pa)
        logger().log_hal(f'[mem] Deallocated : VA = 0x{virt_address:016X}')
        return ret == 1
