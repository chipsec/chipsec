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
from chipsec.library.registers.io import IO

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
    def get_IO_BAR_base_address(self, bar_name: str, instance) -> Tuple[int, int]:
        reglist = self.cs.register.get_list_by_name(bar_name)
        bar = reglist[0].get_def(bar_name)
        if not bar:
            raise IOBARNotFoundError(f'IOBARNotFound: {bar_name}')
        base = 0
        empmty_base = 0

        if bar.register:
            if instance is not None:
                bar_reg = self.cs.register.get_instance_by_name(bar.register, instance)
            else:
                bar_reg = self.cs.register.get_list_by_name(bar.register)[0]

            if bar.base_field:
                base_field = bar.base_field
                try:
                    base = bar_reg.get_field(base_field)
                except Exception:
                    pass
                try:
                    empty_base = bar_reg.get_field_mask(base_field, True)
                except Exception:
                    pass
            else:
                try:
                    base = bar_reg.read()
                except Exception:
                    pass
                try:
                    empty_base = bar_reg.get_mask()
                except Exception:
                    pass

        if bar.fixed_address and (base == empty_base or base == 0):
            base = bar.fixed_address
            self.logger.log_hal(f'[iobar] Using fixed address for {bar_name}: 0x{base:016X}')

        if bar.mask:
            base = base & bar.mask
        if bar.offset:
            base = base + bar.offset
        size = bar.size if bar.size else DEFAULT_IO_BAR_SIZE
        self.logger.log_hal(f'[iobar] {bar_name}: 0x{base:04X} (size = 0x{size:X})')
        if base == 0:
            raise CSReadError(f'IOBAR ({bar_name}) base address is 0')
        return base, size

    #
    # Read I/O register from I/O range defined by I/O BAR name
    #
    def read_IO_BAR_reg(self, bar_name: str, offset: int, size: int) -> int:
        self.logger.log_hal(f'[iobar] read {bar_name} + 0x{offset:X} ({size:d})')
        (bar_base, bar_size) = self.get_IO_BAR_base_address(bar_name)
        io_port = bar_base + offset
        if offset > bar_size and self.logger.HAL:
            self.logger.log_warning(f'offset 0x{offset:X} is outside {bar_name} size (0x{size:X})')
        value = self.cs.hals.Io.read(io_port, size)
        return value

    #
    # Write I/O register from I/O range defined by I/O BAR name
    #
    def write_IO_BAR_reg(self, bar_name: str, offset: int, size: int, value: int) -> int:
        (bar_base, bar_size) = self.get_IO_BAR_base_address(bar_name)
        self.logger.log_hal(f'[iobar] write {bar_name} + 0x{offset:X} ({size:d}): 0x{value:X}')
        io_port = bar_base + offset
        if offset > bar_size and self.logger.HAL:
            self.logger.log_warning(f'offset 0x{offset:X} is outside {bar_name} size (0x{size:X})')
        return self.cs.hals.Io.write(io_port, value, size)

    #
    # Check if I/O range is enabled by BAR name
    #
    def is_IO_BAR_enabled(self, bar_name: str) -> bool:
        if not self.is_IO_BAR_defined(bar_name):
            return False
        bar = IO.get_def(bar_name)
        is_enabled = True
        if bar.register:
            bar_reg = bar.register
            if bar.enable_field:
                bar_en_field = bar.enable_field
                is_enabled = (1 == bar_reg.read_field(bar_en_field))
        return is_enabled

    def list_IO_BARs(self) -> None:
        logger().log('')
        logger().log('--------------------------------------------------------------------------------')
        logger().log(f' {"I/O Range":35} | {"B:D.F":7} | {"Base":16} | {"Size":8} | {"En?":3} | Description')
        logger().log('--------------------------------------------------------------------------------')
        for vid in self.cs.Cfg.IO_BARS:
            for dev in self.cs.Cfg.IO_BARS[vid]:
                for _bar_name in self.cs.Cfg.IO_BARS[vid][dev]:
                    bar_name = f'{vid}.{dev}.{_bar_name}'
                    if not self.is_IO_BAR_defined(bar_name):
                        continue
                    _bar = self.cs.Cfg.IO_BARS[vid][dev][_bar_name]

                    for instance in _bar.instances:
                        (_base, _size) = _bar.get_base(instance)
                        if _base is None:
                            (_base, _size) = self.get_IO_BAR_base_address(bar_name, instance)
                        _en = self.is_IO_BAR_enabled(bar_name, instance)
                        if instance.bus is not None:
                            bdf = f'{instance.bus:02X}:{instance.dev:02X}.{instance.fun:1X}'
                        else:
                            bdf = 'fixed'
                        logger().log(f' {_bar_name:35} | {bdf:7} | {_base:016X} | {_size:08X} | {_en:d}   | {_bar["desc"]}')

    #
    # Read I/O range by I/O BAR name
    #
    def read_IO_BAR(self, bar_name: str, size: int = 1) -> List[int]:
        (range_base, range_size) = self.get_IO_BAR_base_address(bar_name)
        n = range_size // size
        io_ports = []
        for i in range(n):
            io_ports.append(self.cs.hals.Io.read(range_base + i * size, size))
        return io_ports

    #
    # Dump I/O range by I/O BAR name
    #
    def dump_IO_BAR(self, bar_name: str, size: int = 1) -> None:
        (range_base, range_size) = self.get_IO_BAR_base_address(bar_name)
        n = range_size // size
        fmt = f'0{size * 2:d}X'
        self.logger.log(f"[iobar] I/O BAR {bar_name}:")
        for i in range(n):
            reg = self.cs.hals.Io.read(range_base + i * size, size)
            self.logger.log(f'{size * i:+04X}: {reg:{fmt}}')


haldata = {"arch":[hal_base.HALBase.MfgIds.Any], 'name': ['IOBAR']}
