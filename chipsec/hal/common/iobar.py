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
        is_bar_defined = False
        try:
            _bar = self.cs.register.io.get_def(bar_name)
            if _bar is not None:
                if _bar.register:
                    is_bar_defined = self.cs.register.is_defined(_bar.register)
                if not is_bar_defined and _bar.fixed_address:
                    is_bar_defined = True
        except KeyError:
            pass
        if not is_bar_defined:
            if self.logger.HAL:
                self.logger.log_warning(f"'{bar_name}' I/O BAR register definition not found in XML config")
        return is_bar_defined

    #
    # Get base address of I/O range by IO BAR name
    #
    def get_IO_BAR_base_address(self, bar_name: str, instance:'PCIObj') -> Tuple[int, int]:
        try:
            bar_def = self.cs.register.io.get_def(bar_name)
        except IndexError:
            raise IOBARNotFoundError(f'IOBARNotFound: {bar_name} is not defined. Check scoping and configuration')
        if not bar_def:
            raise IOBARNotFoundError(f'IOBARNotFound: {bar_name} is not defined. Check scoping and configuration')
        base, size = bar_def.get_base(instance)
        if base:
            return base, size
        empty_base = 0

        if bar_def.register:
            if instance is not None:
                bar_reg = self.cs.register.get_instance_by_name(bar_def.register, instance)
            else:
                bar_reg = self.cs.register.get_list_by_name(bar_def.register)[0]

            if bar_def.base_field:
                base_field = bar_def.base_field
                try:
                    base = bar_reg.get_field(base_field, True)
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
        if bar_def.fixed_address and (not base or base == empty_base):
            base = bar_def.fixed_address
            self.logger.log_hal(f'[iobar] Using fixed address for {bar_name}: 0x{base:016X}')

        if bar_def.mask:
            base = base & bar_def.mask
        if bar_def.offset:
            base = base + bar_def.offset
        size = bar_def.size if bar_def.size else DEFAULT_IO_BAR_SIZE
        if not base:
            raise CSReadError(f'IOBAR ({bar_name}) base address is 0 or not defined')
        self.logger.log_hal(f'[iobar] {bar_name}: 0x{base:04X} (size = 0x{size:X})')
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
        value = self.cs.hals.io.read(io_port, size)
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
        return self.cs.hals.io.write(io_port, value, size)

    #
    # Check if I/O range is enabled by BAR name
    #
    def is_IO_BAR_enabled(self, bar_name: str) -> bool:
        if not self.is_IO_BAR_defined(bar_name):
            return False
        bar = self.cs.register.io.get_def(bar_name)
        is_enabled = True
        if bar.register:
            bar_reg = bar.register
            if bar.enable_field:
                bar_en_field = bar.enable_field
                is_enabled = bar_reg.is_all_field_value(1, bar_en_field)
        return is_enabled

    def list_IO_BARs(self) -> None:
        self.logger.log('')
        self.logger.log('--------------------------------------------------------------------------------')
        self.logger.log(f' {"I/O Range":35} | {"B:D.F":7} | {"Base":16} | {"Size":8} | {"En?":3} | Description')
        self.logger.log('--------------------------------------------------------------------------------')
        for vid in self.cs.Cfg.IO_BARS.keys():
            for dev in self.cs.Cfg.IO_BARS[vid].keys():
                for _bar_name in self.cs.Cfg.IO_BARS[vid][dev].keys():
                    bar_name = f'{vid}.{dev}.{_bar_name}'
                    if not self.is_IO_BAR_defined(bar_name):
                        continue
                    _bar = self.cs.Cfg.IO_BARS[vid][dev][_bar_name]

                    for instance in _bar.instances:
                        (_base, _size) = _bar.get_base(instance)
                        if _base is None:
                            try:
                                (_base, _size) = self.get_IO_BAR_base_address(bar_name, instance)
                            except CSReadError as err:
                                self.logger.log_hal(f'[iobar] {err}')
                                continue
                        _en = self.is_IO_BAR_enabled(bar_name)
                        if instance.bus is not None:
                            bdf = f'{instance.bus:02X}:{instance.dev:02X}.{instance.fun:1X}'
                        else:
                            bdf = 'fixed'
                        self.logger.log(f' {_bar_name:35} | {bdf:7} | {_base:016X} | {_size:08X} | {_en:d}   | {_bar.desc}')

    #
    # Read I/O range by I/O BAR name
    #
    def read_IO_BAR(self, bar_name: str, size: int = 1) -> List[int]:
        (range_base, range_size) = self.get_IO_BAR_base_address(bar_name)
        n = range_size // size
        io_ports = []
        for i in range(n):
            io_ports.append(self.cs.hals.io.read(range_base + i * size, size))
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
            reg = self.cs.hals.io.read(range_base + i * size, size)
            self.logger.log(f'{size * i:+04X}: {reg:{fmt}}')


haldata = {"arch":[hal_base.HALBase.MfgIds.Any], 'name': {'iobar': "IOBAR"}}
