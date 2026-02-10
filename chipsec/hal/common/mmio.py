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
Access to MMIO (Memory Mapped IO) BARs and Memory-Mapped PCI Configuration Space (MMCFG)

usage:
    >>> read_MMIO_reg(bar_base, 0x0, 4)
    >>> write_MMIO_reg(bar_base, 0x0, 0xFFFFFFFF, 4)
    >>> read_MMIO(bar_base, 0x1000)
    >>> dump_MMIO(bar_base, 0x1000)

    Access MMIO by BAR name:

    >>> read_MMIO_BAR_reg('MCHBAR', 0x0, 4)
    >>> write_MMIO_BAR_reg('MCHBAR', 0x0, 0xFFFFFFFF, 4)
    >>> get_MMIO_BAR_base_address('8086.HOSTCTL.MCHBAR')
    >>> is_MMIO_BAR_enabled('8086.HOSTCTL.MCHBAR')
    >>> is_MMIO_BAR_programmed('8086.HOSTCTL.MCHBAR')
    >>> dump_MMIO_BAR('8086.HOSTCTL.MCHBAR')
    >>> list_MMIO_BARs()

"""
from typing import List, Optional, Tuple
from chipsec.hal import hal_base
from chipsec.library.exceptions import CSConfigError, CSReadError, MMIOBARNotFoundError
from chipsec.library.options import Options

DEFAULT_MMIO_BAR_SIZE = 0x1000


class MMIO(hal_base.HALBase):

    def __init__(self, cs):
        super(MMIO, self).__init__(cs)
        self.cached_bar_addresses = {}
        options = Options()
        self.cache_bar_addresses_resolution = options.get_section_data('HAL_Config', 'mmio_cache_bar_addresses') == "True"

    ###########################################################################
    # Access to MMIO BAR defined by configuration files (chipsec/cfg/*.py)
    ###########################################################################
    #
    # To add your own MMIO bar:
    #   1. Add new MMIO BAR id (any)
    #   2. Write a function get_yourBAR_base_address() with no args that
    #      returns base address of new bar
    #   3. Add a pointer to this function to MMIO_BAR_base map
    #   4. Don't touch read/write_MMIO_reg functions ;)
    #
    ###########################################################################

    #
    # Read MMIO register as an offset off of MMIO range base address
    #

    def read_MMIO_reg(self, bar_base: int, offset: int, size: int = 4, bar_size: Optional[int] = None) -> int:
        if size > 8:
            if self.logger.HAL:
                self.logger.log_warning("[mmio] MMIO read cannot exceed 8")
        if bar_size and offset + size > bar_size:
            self.logger.log_warning(f"[mmio] Offset(0x{offset:x}) + size(0x{size:x}) is > bar_size(0x{bar_size:x})")
        reg_value = self.cs.helper.read_mmio_reg(bar_base+offset, size)
        self.logger.log_hal(f'[mmio] 0x{bar_base:08X} + 0x{offset:08X} = 0x{reg_value:08X}')
        return reg_value

    def read_MMIO_reg_byte(self, bar_base: int, offset: int) -> int:
        return self.read_MMIO_reg(bar_base, offset, 1)

    def read_MMIO_reg_word(self, bar_base: int, offset: int) -> int:
        return self.read_MMIO_reg(bar_base, offset, 2)

    def read_MMIO_reg_dword(self, bar_base: int, offset: int) -> int:
        return self.read_MMIO_reg(bar_base, offset, 4)

    #
    # Write MMIO register as an offset off of MMIO range base address
    #
    def write_MMIO_reg(self, bar_base: int, offset: int, value: int, size: int = 4) -> int:
        address = bar_base + offset
        self.logger.log_hal(f'[mmio] write 0x{bar_base:08X} + 0x{offset:08X} = 0x{value:08X}')
        return self.cs.helper.write_mmio_reg(address, size, value)

    def write_MMIO_reg_byte(self, bar_base: int, offset: int, value: int) -> int:
        address = bar_base + offset
        self.logger.log_hal(f'[mmio] write 0x{bar_base:08X} + 0x{offset:08X} = 0x{value:08X}')
        return self.cs.helper.write_mmio_reg(address, 1, value)

    def write_MMIO_reg_word(self, bar_base: int, offset: int, value: int) -> int:
        address = bar_base + offset
        self.logger.log_hal(f'[mmio] write 0x{bar_base:08X} + 0x{offset:08X} = 0x{value:08X}')
        return self.cs.helper.write_mmio_reg(address, 2, value)

    def write_MMIO_reg_dword(self, bar_base: int, offset: int, value: int) -> int:
        address = bar_base + offset
        self.logger.log_hal(f'[mmio] write 0x{bar_base:08X} + 0x{offset:08X} = 0x{value:08X}')
        return self.cs.helper.write_mmio_reg(address, 4, value)

    #
    # Read MMIO registers as offsets off of MMIO range base address
    #
    def read_MMIO(self, bar_base: int, size: int) -> List[int]:
        regs = []
        size -= size % 4
        for offset in range(0, size, 4):
            regs.append(self.read_MMIO_reg(bar_base, offset))
        return regs

    #
    # Dump MMIO range
    #
    def dump_MMIO(self, bar_base: int, size: int) -> None:
        self.logger.log(f'[mmio] MMIO register range [0x{bar_base:016X}:0x{bar_base:016X}+{size:08X}]:')
        size -= size % 4
        for offset in range(0, size, 4):
            self.logger.log(f'+{offset:08X}: {self.read_MMIO_reg(bar_base, offset):08X}')

    ###############################################################################
    # Access to MMIO BAR defined by XML configuration files (chipsec/cfg/*.xml)
    ###############################################################################

    #
    # Check if MMIO BAR with bar_name has been defined in XML config
    # Use this function to fall-back to hardcoded config in case XML config is not available
    #

    def is_MMIO_BAR_defined(self, bar_name: str) -> bool:
        is_bar_defined = False
        try:
            _bar = self.cs.register.mmio.get_def(bar_name)
            if _bar is not None:
                if _bar.register:
                    is_bar_defined = self.cs.register.is_defined(_bar.register)
                if not is_bar_defined and _bar.fixed_address:
                    is_bar_defined = True
        except KeyError:
            pass

        if not is_bar_defined:
            if self.logger.HAL:
                self.logger.log_warning(f"'{bar_name}' MMIO BAR definition not found/correct in XML config")
        return is_bar_defined

    #
    # Enable caching of BAR addresses
    #
    def enable_cache_address_resolution(self, enable: bool) -> None:
        if enable:
            self.cache_bar_addresses_resolution = True
        else:
            self.cache_bar_addresses_resolution = False
            self.flush_bar_address_cache()

    def flush_bar_address_cache(self) -> None:
        self.cached_bar_addresses = {}

    #
    # Get base address of MMIO range by MMIO BAR name
    #
    def get_MMIO_BAR_base_address(self, bar_name: str, instance: Optional['PCIObj'] = None) -> Tuple[int, int]:
        if self.cache_bar_addresses_resolution and (bar_name, instance) in self.cached_bar_addresses:
            return self.cached_bar_addresses[(bar_name, instance)]
        try:
            bar = self.cs.register.mmio.get_def(bar_name)   # self.cs.Cfg.MMIO_BARS[bar_name]
        except KeyError:
            raise MMIOBARNotFoundError(f'MMIOBARNotFound: {bar_name} is not defined. Check scoping and configuration')
        if not bar:
            raise MMIOBARNotFoundError(f'MMIOBARNotFound: {bar_name} is not defined. Check scoping and configuration')
        base, size = bar.get_base(instance)
        if base:
            return base, size
        base = 0
        reg_mask = 0xFFFF
        limit = 0
        size = 0
        mmioaddr = 0

        if bar.register:
            preserve = True
            if instance is not None:
                bar_reg_list = [self.cs.register.get_instance_by_name(bar.register, instance)]
            else:
                bar_reg_list = self.cs.register.get_list_by_name(bar.register)
            for bar_reg in bar_reg_list:
                if bar_reg is None:
                    raise MMIOBARNotFoundError(f'MMIOBARNotFound: {bar_name} is not defined. Check scoping and configuration')
                if bar.reg_align:
                    preserve = False
                if bar.base_field:
                    base_field = bar.base_field
                    try:
                        base = bar_reg.read_field(base_field, preserve)
                    except (CSReadError, AttributeError):
                        continue
                    try:
                        reg_mask = bar_reg.get_field_mask(base_field, preserve)
                    except (CSReadError, AttributeError):
                        continue
                    break
            if not preserve:
                base <<= bar.reg_align
                reg_mask <<= bar.reg_align
        if bar.registerh and instance is not None:
            preserve = True
            bar_reg = self.cs.register.get_instance_by_name(bar.registerh, instance)
            if bar_reg:
                if bar.regh_align:
                    preserve = False
                if bar.baseh_field:
                    base_field = bar.baseh_field
                    try:
                        baseh = bar_reg.read_field(base_field, preserve)
                    except (CSReadError, AttributeError):
                        self.logger.log_hal('[mmio] Unable to determine MMIO Base registerh.  Using Base = 0x0')
                        baseh = 0
                    try:
                        reg_maskh = bar_reg.get_field_mask(base_field, preserve)
                    except (CSReadError, AttributeError):
                        self.logger.log_hal('[mmio] Unable to determine MMIO Mask registerh.  Using Mask = 0xFFFF')
                        reg_maskh = 0xFFFF
            if not preserve:
                baseh <<= bar.reg_align
                reg_maskh <<= bar.reg_align
            base += baseh
            reg_mask += reg_maskh
        if bar.registertype and bar.registertype == 'dynamic':
            try:
                dynbase = self.read_MMIO_reg(base, 0)
            except (CSReadError, AttributeError):
                self.logger.log_hal('[mmio] Unable to determine MMIO Base.  Using Base = 0x0')
                dynbase = 0x0
            base = dynbase
        if bar.mmio_base:
            mmiobar = bar.mmio_base
            mmioaddr, _ = self.get_MMIO_BAR_base_address(mmiobar, instance)
            if bar.mmio_align:
                mmioaddr <<= bar.mmio_align
            base += mmioaddr

        if bar.limit_register and bar.limit_field and bar.limit_align and instance is not None:
            limit_field = bar.limit_field
            limit_bar = bar.limit_register
            lim_reg = self.cs.register.get_instance_by_name(limit_bar, instance)
            limit = lim_reg.read_field(limit_field)
            if bar.limit_align:
                limit_align = bar.limit_align
                limit <<= limit_align

        if bar.fixed_address and (base == reg_mask or base == 0):
            base = bar.fixed_address
            self.logger.log_hal('[mmio] Using fixed address for {}: 0x{:016X}'.format(bar_name, base))
        if bar.offset:
            base += bar.offset
        if bar.size:
            size = bar.size
        elif limit:
            if bar.mmio_align:
                limit += ((0x1 << bar['mmio_align']) - 1)
            limit += mmioaddr
            size = limit - base
        if size == 0:
            size = DEFAULT_MMIO_BAR_SIZE
        self.logger.log_hal('[mmio] {}: 0x{:016X} (size = 0x{:X})'.format(bar_name, base, size))
        if base == 0 and bar.fixed_address is None:
            self.logger.log_hal('[mmio] Base address was determined to be 0.')
            raise CSReadError('[mmio] Base address was determined to be 0')

        if self.cache_bar_addresses_resolution:
            self.cached_bar_addresses[(bar_name, instance)] = (base, size)
        bar.update_base_address(base, instance)
        return base, size

    #
    # Check if MMIO range is enabled by MMIO BAR name
    #
    def is_MMIO_BAR_enabled(self, bar_name: str, instance: Optional['PCIObj'] = None) -> bool:
        if not self.is_MMIO_BAR_defined(bar_name):
            return False
        bar = self.cs.register.mmio.get_def(bar_name)
        is_enabled = True
        if bar.register:
            bar_reg = self.cs.register.get_list_by_name(bar.register).filter_by_instance(instance)
            if bar.enable_field:
                is_enabled = bar_reg.is_all_field_value(1, bar.enable_field)
            elif bar.enable_bit:
                base = bar_reg.read()[0]
                en_mask = 1 << bar.enable_bit
                is_enabled = (0 != base & en_mask)
            else:
                self.logger.log_hal(f'No enable field/bit defined for MMIO BAR {bar_name}')
        else:
            raise CSConfigError(f"MMIO BAR {bar_name} does not have a register defined")

        return is_enabled

    #
    # Check if MMIO range is programmed by MMIO BAR name
    #
    def is_MMIO_BAR_programmed(self, bar_name: str) -> bool:
        bar = self.cs.Cfg.MMIO_BARS[bar_name]

        if bar.register:
            bar_reg = self.cs.register.get_list_by_name(bar.register)
            if bar.base_field:
                return not bar_reg.is_any_field_value(0, bar.base_field)
            else:
                bar_reg.read()
                return not bar_reg.is_any_value(0)
        else:
            raise CSConfigError(f"MMIO BAR {bar_name} does not have a register defined")

    #
    # Read MMIO register from MMIO range defined by MMIO BAR name
    #
    def read_MMIO_BAR_reg(self, bar_name: str, offset: int, size: int = 4, bus: Optional[int] = None) -> int:
        (bar_base, bar_size) = self.get_MMIO_BAR_base_address(bar_name, bus)
        # @TODO: check offset exceeds BAR size
        return self.read_MMIO_reg(bar_base, offset, size, bar_size)

    #
    # Write MMIO register from MMIO range defined by MMIO BAR name
    #
    def write_MMIO_BAR_reg(self, bar_name: str, offset: int, value: int, size: int = 4, bus: Optional[int] = None) -> Optional[int]:
        (bar_base, _) = self.get_MMIO_BAR_base_address(bar_name, bus)
        # @TODO: check offset exceeds BAR size

        return self.write_MMIO_reg(bar_base, offset, value, size)

    def read_MMIO_BAR(self, bar_name: str, bus: Optional[int] = None) -> List[int]:
        (bar_base, bar_size) = self.get_MMIO_BAR_base_address(bar_name, bus)
        return self.read_MMIO(bar_base, bar_size)

    #
    # Dump MMIO range by MMIO BAR name
    #
    def dump_MMIO_BAR(self, bar_name: str) -> None:
        (bar_base, bar_size) = self.get_MMIO_BAR_base_address(bar_name)
        self.dump_MMIO(bar_base, bar_size)

    def list_MMIO_BARs(self) -> None:
        self.logger.log('')
        self.logger.log('-' * 105)
        self.logger.log(f' {"MMIO Range":35} | {"B:D.F":7} | {"Base":16} | {"Size":8} | En? | Val | Description')
        self.logger.log('-' * 105)
        for vid in self.cs.Cfg.MMIO_BARS:
            for dev in self.cs.Cfg.MMIO_BARS[vid]:
                for bar_name in self.cs.Cfg.MMIO_BARS[vid][dev]:
                    _bar_name = f'{vid}.{dev}.{bar_name}'
                    if not self.is_MMIO_BAR_defined(_bar_name):
                        continue
                    _bar = self.cs.Cfg.MMIO_BARS[vid][dev][bar_name]
                    for instance in _bar.instances:
                        (_base, _size) = _bar.get_base(instance)
                        if _base is None:
                            try:
                                (_base, _size) = self.get_MMIO_BAR_base_address(_bar_name, instance)
                            except CSReadError:
                                continue
                        _valid = self.is_MMIO_BAR_valid(_bar_name, instance)
                        _en = self.is_MMIO_BAR_enabled(_bar_name, instance)
                        if instance.bus is not None:
                            bdf = f'{instance.bus:02X}:{instance.dev:02X}.{instance.fun:1X}'
                        else:
                            bdf = 'fixed'
                        self.logger.log(f' {_bar_name:35} | {bdf:7} | {_base:016X} | {_size:08X} |  {_en:d}  |  {_valid:d}  | {_bar.desc}')

    def is_MMIO_BAR_valid(self, bar_name, instance=None):
        if not self.is_MMIO_BAR_defined(bar_name):
            return False
        bar = self.cs.register.mmio.get_def(bar_name)
        is_valid = True
        if bar.register:
            if bar.valid:
                bar_en_field = bar.valid
                bar_reg = self.cs.register.get_list_by_name(bar.register).filter_by_instance(instance)
                is_valid = bar_reg.is_all_field_value(1, bar_en_field)
        return is_valid

haldata = {"arch": [hal_base.HALBase.MfgIds.Any], 'name': {'mmio': "MMIO"}}
