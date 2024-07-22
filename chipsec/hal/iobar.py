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
I/O BAR access (dump, read/write)

usage:
    >>> get_IO_BAR_base_address( bar_name )
    >>> read_IO_BAR_reg( bar_name, offset, size )
    >>> write_IO_BAR_reg( bar_name, offset, size, value )
    >>> dump_IO_BAR( bar_name )
"""
from typing import Tuple, List
from chipsec.hal import hal_base
from chipsec.library.logger import logger
from chipsec.library.exceptions import IOBARNotFoundError
from chipsec.library.exceptions import CSReadError

DEFAULT_IO_BAR_SIZE = 0x100


class IOBAR(hal_base.HALBase):

    def __init__(self, cs):
        super(IOBAR, self).__init__(cs)

    #
    # Check if I/O BAR with bar_name has been defined in XML config
    # Use this function to fall-back to hardcoded config in case XML config is not available
    #
    def is_IO_BAR_defined(self, bar_name: str) -> bool:
        try:
            return (self.cs.Cfg.IO_BARS[bar_name] is not None)
        except KeyError:
            if logger().HAL:
                logger().log_error(f"'{bar_name}' I/O BAR definition not found in XML config")
            return False

    #
    # Get base address of I/O range by IO BAR name
    #
    def get_IO_BAR_base_address(self, bar_name: str) -> Tuple[int, int]:
        bar = self.cs.Cfg.IO_BARS[bar_name]
        if bar is None or bar == {}:
            raise IOBARNotFoundError(f'IOBARNotFound: {bar_name}')

        if 'register' in bar:
            bar_reg = bar['register']
            if 'base_field' in bar:
                base_field = bar['base_field']
                try:
                    base = self.cs.register.read_field(bar_reg, base_field, preserve_field_position=True)
                except Exception:
                    base = 0
                try:
                    empty_base = self.cs.register.get_field_mask(bar_reg, base_field, preserve_field_position=True)
                except Exception:
                    empty_base = 0
            else:
                try:
                    base = self.cs.register.read(bar_reg)
                except Exception:
                    base = 0
                try:
                    empty_base = self.cs.register.get_field_mask(bar_reg, preserve_field_position=True)
                except Exception:
                    empty_base = 0
        else:
            # this method is not preferred
            base = self.cs.pci.read_word(self.cs.device.get_first_bus(bar), bar['dev'], bar['fun'], bar['reg'])
            empty_base = 0xFFFF

        if 'fixed_address' in bar and (base == empty_base or base == 0):
            base = bar['fixed_address']
            if logger().HAL:
                logger().log(f'[iobar] Using fixed address for {bar_name}: 0x{base:016X}')

        if 'mask' in bar:
            base = base & bar['mask']
        if 'offset' in bar:
            base = base + bar['offset']
        size = bar['size'] if ('size' in bar) else DEFAULT_IO_BAR_SIZE

        if logger().HAL:
            logger().log(f'[iobar] {bar_name}: 0x{base:04X} (size = 0x{size:X})')
        if base == 0:
            raise CSReadError(f'IOBAR ({bar_name}) base address is 0')
        return base, size

    #
    # Read I/O register from I/O range defined by I/O BAR name
    #
    def read_IO_BAR_reg(self, bar_name: str, offset: int, size: int) -> int:
        if logger().HAL:
            logger().log(f'[iobar] read {bar_name} + 0x{offset:X} ({size:d})')
        (bar_base, bar_size) = self.get_IO_BAR_base_address(bar_name)
        io_port = bar_base + offset
        if offset > bar_size and logger().HAL:
            logger().log_warning(f'offset 0x{offset:X} is outside {bar_name} size (0x{size:X})')
        value = self.cs.io._read_port(io_port, size)
        return value

    #
    # Write I/O register from I/O range defined by I/O BAR name
    #
    def write_IO_BAR_reg(self, bar_name: str, offset: int, size: int, value: int) -> int:
        (bar_base, bar_size) = self.get_IO_BAR_base_address(bar_name)
        if logger().HAL:
            logger().log(f'[iobar] write {bar_name} + 0x{offset:X} ({size:d}): 0x{value:X}')
        io_port = bar_base + offset
        if offset > bar_size and logger().HAL:
            logger().log_warning(f'offset 0x{offset:X} is outside {bar_name} size (0x{size:X})')
        return self.cs.io._write_port(io_port, value, size)

    #
    # Check if I/O range is enabled by BAR name
    #
    def is_IO_BAR_enabled(self, bar_name: str) -> bool:
        bar = self.cs.Cfg.IO_BARS[bar_name]
        is_enabled = True
        if 'register' in bar:
            bar_reg = bar['register']
            if 'enable_field' in bar:
                bar_en_field = bar['enable_field']
                is_enabled = (1 == self.cs.register.read_field(bar_reg, bar_en_field))
        return is_enabled

    def list_IO_BARs(self) -> None:
        logger().log('')
        logger().log('--------------------------------------------------------------------------------')
        logger().log(' I/O Range    | BAR Register   | Base             | Size     | En? | Description')
        logger().log('--------------------------------------------------------------------------------')
        for _bar_name in self.cs.Cfg.IO_BARS:
            if not self.is_IO_BAR_defined(_bar_name):
                continue
            _bar = self.cs.Cfg.IO_BARS[_bar_name]
            bus_data = []
            if 'register' in _bar:
                bus_data = self.cs.register.get_bus(_bar['register'])
                if not bus_data:
                    if 'bus' in self.cs.register.get_def(_bar['register']):
                        bus_data = [self.cs.register.get_def(_bar['register'])['bus']]
            elif 'bus' in _bar:
                bus_data.extend(_bar['bus'])
            else:
                continue

            for bus in bus_data:
                try:
                    (_base, _size) = self.get_IO_BAR_base_address(_bar_name)
                except CSReadError:
                    if self.logger.HAL:
                        self.logger.log(f"Unable to find IO BAR {_bar_name}")
                    continue
                _en = self.is_IO_BAR_enabled(_bar_name)

                if 'register' in _bar:
                    _s = _bar['register']
                    if 'offset' in _bar:
                        _s += (f' + 0x{_bar["offset"]:X}')
                else:
                    _s = f'{bus:02X}:{_bar["dev"]:02X}.{_bar["fun"]:01X} + {_bar["reg"]}'

                logger().log(f' {_bar_name:12} | {_s:14} | {_base:016X} | {_size:08X} | {_en:d}   | {_bar["desc"]}')

    #
    # Read I/O range by I/O BAR name
    #
    def read_IO_BAR(self, bar_name: str, size: int = 1) -> List[int]:
        (range_base, range_size) = self.get_IO_BAR_base_address(bar_name)
        n = range_size // size
        io_ports = []
        for i in range(n):
            io_ports.append(self.cs.io._read_port(range_base + i * size, size))
        return io_ports

    #
    # Dump I/O range by I/O BAR name
    #
    def dump_IO_BAR(self, bar_name: str, size: int = 1) -> None:
        (range_base, range_size) = self.get_IO_BAR_base_address(bar_name)
        n = range_size // size
        fmt = f'0{size * 2:d}X'
        logger().log(f"[iobar] I/O BAR {bar_name}:")
        for i in range(n):
            reg = self.cs.io._read_port(range_base + i * size, size)
            logger().log(f'{size * i:+04X}: {reg:{fmt}}')
