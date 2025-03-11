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
Access to Port I/O

usage:
    >>> read(0x61, 1)
    >>> read_port_byte(0x61)
    >>> read_port_word(0x61)
    >>> read_port_dword(0x61)
    >>> read_range(0x71, 0x4, 1)
    >>> dump_range(0x71, 0x4, 1)
    >>> write(0x71, 0, 1)
    >>> write_port_byte(0x61, 0xAA)
    >>> write_port_word(0x61, 0xAAAA)
    >>> write_port_dword(0x61, 0xAAAAAAAA)

"""

from typing import List
from chipsec.hal.hal_base import HALBase
from chipsec.library.exceptions import SizeRuntimeError
from chipsec.library.logger import logger


class Io(HALBase):

    def __init__(self, cs):
        super(Io, self).__init__(cs)
        self.helper = cs.helper
        self.valid_sizes = [1, 2, 4]

    def read(self, io_port: int, size: int) -> int:
        if size not in self.valid_sizes:
            message = f'[HAL] [PortIO] Size of {size} is invalid. Valid sizes: {self.valid_sizes}'
            logger().log_bad(message)
            raise SizeRuntimeError(message)
        value = self.helper.read_io_port(io_port, size)
        logger().log_hal(f"[io] IN 0x{io_port:04X}: value = 0x{value:08X}, size = 0x{size:02X}")
        return value

    def write(self, io_port: int, value: int, size: int) -> int:
        if size not in self.valid_sizes:
            message = f'[HAL] [PortIO] Size of {size} is invalid. Valid sizes: {self.valid_sizes}'
            logger().log_bad(message)
            raise SizeRuntimeError(message)
        logger().log_hal(f"[io] OUT 0x{io_port:04X}: value = 0x{value:08X}, size = 0x{size:02X}")
        status = self.helper.write_io_port(io_port, value, size)
        return status


    #
    # Read registers from I/O range
    #
    def read_range(self, range_base: int, range_size: int, size: int = 1) -> List[int]:
        n = range_size // size
        io_ports = []
        for i in range(n):
            io_ports.append(self.read(range_base + i * size, size))
        return io_ports

    #
    # Dump I/O range
    #
    def dump_range(self, range_base: int, range_size: int, size: int = 1) -> None:
        logger().log(f"[io] I/O register range [0x{range_base:04X}:0x{range_base:04X}+{range_size:04X}]:")
        read_ranges = self.read_range(range_base, range_size, size)
        for i, read_val in enumerate(read_ranges):
            logger().log(f'+{size * i:04X}: {read_val:{f"0{size * 2:d}X"}}')

    def read_port_byte(self, io_port: int) -> int:
        return self.read(io_port, 1)
    
    def read_port_word(self, io_port: int) -> int:
        return self.read(io_port, 2)
    
    def read_port_dword(self, io_port: int) -> int:
        return self.read(io_port, 4)
    
    def write_port_byte(self, io_port: int, value: int) -> int:
        return self.write(io_port, value, 1)
    
    def write_port_word(self, io_port: int, value: int) -> int:
        return self.write(io_port, value, 2)
    
    def write_port_dword(self, io_port: int, value: int) -> int:
        return self.write(io_port, value, 4)


haldata = {"arch":[HALBase.MfgIds.Any], 'name': ['Io']}
