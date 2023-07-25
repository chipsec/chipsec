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
    >>> read_MMIO_reg(cs, bar_base, 0x0, 4)
    >>> write_MMIO_reg(cs, bar_base, 0x0, 0xFFFFFFFF, 4)
    >>> read_MMIO(cs, bar_base, 0x1000)
    >>> dump_MMIO(cs, bar_base, 0x1000)

    Access MMIO by BAR name:

    >>> read_MMIO_BAR_reg(cs, 'MCHBAR', 0x0, 4)
    >>> write_MMIO_BAR_reg(cs, 'MCHBAR', 0x0, 0xFFFFFFFF, 4)
    >>> get_MMIO_BAR_base_address(cs, 'MCHBAR')
    >>> is_MMIO_BAR_enabled(cs, 'MCHBAR')
    >>> is_MMIO_BAR_programmed(cs, 'MCHBAR')
    >>> dump_MMIO_BAR(cs, 'MCHBAR')
    >>> list_MMIO_BARs(cs)

    Access Memory Mapped Config Space:

    >>> get_MMCFG_base_address(cs)
    >>> read_mmcfg_reg(cs, 0, 0, 0, 0x10, 4)
    >>> read_mmcfg_reg(cs, 0, 0, 0, 0x10, 4, 0xFFFFFFFF)
"""
from typing import List, Optional, Tuple
from chipsec.hal import hal_base
from chipsec.exceptions import CSReadError

DEFAULT_MMIO_BAR_SIZE = 0x1000

PCI_PCIEXBAR_REG_LENGTH_256MB = 0x0
PCI_PCIEXBAR_REG_LENGTH_128MB = 0x1
PCI_PCIEXBAR_REG_LENGTH_64MB = 0x2
PCI_PCIEXBAR_REG_LENGTH_512MB = 0x3
PCI_PCIEXBAR_REG_LENGTH_1024MB = 0x4
PCI_PCIEXBAR_REG_LENGTH_2048MB = 0x5
PCI_PCIEXBAR_REG_LENGTH_4096MB = 0x6
PCI_PCIEBAR_REG_MASK = 0x7FFC000000


class MMIO(hal_base.HALBase):

    def __init__(self, cs):
        super(MMIO, self).__init__(cs)
        self.cached_bar_addresses = {}
        self.cache_bar_addresses_resolution = False

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
                self.logger.log_warning("MMIO read cannot exceed 8")
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
            _bar = self.cs.Cfg.MMIO_BARS[bar_name]
            if _bar is not None:
                if 'register' in _bar:
                    is_bar_defined = self.cs.is_register_defined(_bar['register'])
                elif ('bus' in _bar) and ('dev' in _bar) and ('fun' in _bar) and ('reg' in _bar):
                    # old definition
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
    def get_MMIO_BAR_base_address(self, bar_name: str, bus: Optional[int] = None) -> Tuple[int, int]:
        if self.cache_bar_addresses_resolution and (bar_name, bus) in self.cached_bar_addresses:
            return self.cached_bar_addresses[(bar_name, bus)]
        bar = self.cs.Cfg.MMIO_BARS[bar_name]
        if bar is None or bar == {}:
            return -1, -1
        _bus = bus
        limit = 0

        if 'register' in bar:
            preserve = True
            bar_reg = bar['register']
            if _bus is None:
                _buses = self.cs.get_register_bus(bar_reg)
                _bus = _buses[0] if _buses else None
            if 'align_bits' in bar:
                preserve = False
            if 'base_field' in bar:
                base_field = bar['base_field']
                try:
                    base = self.cs.read_register_field(bar_reg, base_field, preserve, bus=_bus)
                except CSReadError:
                    base = 0
                    self.logger.log_hal(f'[mmio] Unable to determine MMIO Base.  Using Base = 0x{base:X}')
                try:
                    reg_mask = self.cs.get_register_field_mask(bar_reg, base_field, preserve)
                except CSReadError:
                    reg_mask = 0xFFFF
                    self.logger.log_hal(f'[mmio] Unable to determine MMIO Mask.  Using Mask = 0x{reg_mask:X}')
            else:
                base = self.cs.read_register(bar_reg, bus=_bus)
                reg_mask = self.cs.get_register_field_mask(bar_reg, preserve_field_position=preserve)
            if 'limit_field' in bar:
                limit_field = bar['limit_field']
                limit = self.cs.read_register_field(bar_reg, limit_field, bus=_bus)
            else:
                if self.logger.HAL:
                    self.logger.log_warning(f"[mmio] 'limit_field' field not defined for bar, using limit = 0x{limit:X}")
        else:
            # this method is not preferred (less flexible)
            if _bus is not None:
                b = _bus
            else:
                b = bar['bus']
            d = bar['dev']
            f = bar['fun']
            r = bar['reg']
            width = bar['width']
            reg_mask = (1 << (width * 8)) - 1
            if 8 == width:
                base_lo = self.cs.pci.read_dword(b, d, f, r)
                base_hi = self.cs.pci.read_dword(b, d, f, r + 4)
                base = (base_hi << 32) | base_lo
            else:
                base = self.cs.pci.read_dword(b, d, f, r)

        if 'fixed_address' in bar and (base == reg_mask or base == 0):
            base = bar['fixed_address']
            self.logger.log_hal(f'[mmio] Using fixed address for {bar_name}: 0x{base:016X}')
        if 'mask' in bar:
            base &= bar['mask']
        if 'offset' in bar:
            base = base + bar['offset']
        if 'align_bits' in bar:
            _buses = self.cs.get_register_bus(bar['base_reg'])
            _bus = _buses[0] if _buses else None
            start = self.cs.read_register_field(bar['base_reg'], bar['base_addr'], bus=_bus)
            start <<= int(bar['base_align'])
            base <<= int(bar['align_bits'])
            limit <<= int(bar['align_bits'])
            base += start
            limit += ((0x1 << int(bar['align_bits'])) - 1)
            limit += start
            size = limit - base
        else:
            size = bar['size'] if ('size' in bar) else DEFAULT_MMIO_BAR_SIZE

        self.logger.log_hal(f'[mmio] {bar_name}: 0x{base:016X} (size = 0x{size:X})')
        if base == 0:
            self.logger.log_hal('[mmio] Base address was determined to be 0.')
            raise CSReadError('[mmio] Base address was determined to be 0')

        if self.cache_bar_addresses_resolution:
            self.cached_bar_addresses[(bar_name, bus)] = (base, size)
        return base, size

    #
    # Check if MMIO range is enabled by MMIO BAR name
    #
    def is_MMIO_BAR_enabled(self, bar_name: str, bus: Optional[int] = None) -> bool:
        if not self.is_MMIO_BAR_defined(bar_name):
            return False
        bar = self.cs.Cfg.MMIO_BARS[bar_name]
        is_enabled = True
        if 'register' in bar:
            bar_reg = bar['register']
            if 'enable_field' in bar:
                bar_en_field = bar['enable_field']
                is_enabled = (1 == self.cs.read_register_field(bar_reg, bar_en_field, bus=bus))
        else:
            # this method is not preferred (less flexible)
            if bus is not None:
                b = bus
            else:
                b = bar['bus']
            d = bar['dev']
            f = bar['fun']
            r = bar['reg']
            width = bar['width']
            if not self.cs.pci.is_enabled(b, d, f):
                return False
            if 8 == width:
                base_lo = self.cs.pci.read_dword(b, d, f, r)
                base_hi = self.cs.pci.read_dword(b, d, f, r + 4)
                base = (base_hi << 32) | base_lo
            else:
                base = self.cs.pci.read_dword(b, d, f, r)

            if 'enable_bit' in bar:
                en_mask = 1 << int(bar['enable_bit'])
                is_enabled = (0 != base & en_mask)

        return is_enabled

    #
    # Check if MMIO range is programmed by MMIO BAR name
    #
    def is_MMIO_BAR_programmed(self, bar_name: str) -> bool:
        bar = self.cs.Cfg.MMIO_BARS[bar_name]

        if 'register' in bar:
            bar_reg = bar['register']
            if 'base_field' in bar:
                base_field = bar['base_field']
                base = self.cs.read_register_field(bar_reg, base_field, preserve_field_position=True)
            else:
                base = self.cs.read_register(bar_reg)
        else:
            # this method is not preferred (less flexible)
            b = bar['bus']
            d = bar['dev']
            f = bar['fun']
            r = bar['reg']
            width = bar['width']
            if 8 == width:
                base_lo = self.cs.pci.read_dword(b, d, f, r)
                base_hi = self.cs.pci.read_dword(b, d, f, r + 4)
                base = (base_hi << 32) | base_lo
            else:
                base = self.cs.pci.read_dword(b, d, f, r)

        #if 'mask' in bar: base &= bar['mask']
        return (0 != base)

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
        self.logger.log('--------------------------------------------------------------------------------------')
        self.logger.log(' MMIO Range   | BUS | BAR Register   | Base             | Size     | En? | Description')
        self.logger.log('--------------------------------------------------------------------------------------')
        for _bar_name in self.cs.Cfg.MMIO_BARS:
            if not self.is_MMIO_BAR_defined(_bar_name):
                continue
            _bar = self.cs.Cfg.MMIO_BARS[_bar_name]
            bus_data = []
            if 'register' in _bar:
                bus_data = self.cs.get_register_bus(_bar['register'])
                if not bus_data:
                    if 'bus' in self.cs.get_register_def(_bar['register']):
                        bus_data = [int(self.cs.get_register_def(_bar['register'])['bus'], 16)]
            elif 'bus' in _bar:
                bus_data = [_bar['bus']]
            else:
                continue
            for bus in bus_data:
                try:
                    (_base, _size) = self.get_MMIO_BAR_base_address(_bar_name, bus)
                except:
                    self.logger.log_hal(f'Unable to find MMIO BAR {_bar}')
                    continue
                _en = self.is_MMIO_BAR_enabled(_bar_name)

                if 'register' in _bar:
                    _s = _bar['register']
                    if 'offset' in _bar:
                        _s += (f' + 0x{_bar["offset"]:X}')
                else:
                    bus_value = _bar["bus"]
                    dev_value = _bar["dev"]
                    fun_value = _bar["fun"]
                    _s = f'{bus_value:02X}:{dev_value:02X}.{fun_value:01X} + {_bar["reg"]}'

                self.logger.log(f' {_bar_name:12} |  {bus or 0:02X} | {_s:14} | {_base:016X} | {_size:08X} | {_en:d}   | {_bar["desc"]}')

    ##################################################################################
    # Access to Memory Mapped PCIe Configuration Space
    ##################################################################################

    def get_MMCFG_base_address(self) -> Tuple[int, int]:
        (bar_base, bar_size) = self.get_MMIO_BAR_base_address('MMCFG')
        if self.cs.register_has_field("PCI0.0.0_PCIEXBAR", "LENGTH") and not self.cs.is_server():
            len = self.cs.read_register_field("PCI0.0.0_PCIEXBAR", "LENGTH")
            if len == PCI_PCIEXBAR_REG_LENGTH_256MB:
                bar_base &= (PCI_PCIEBAR_REG_MASK << 2)
            elif len == PCI_PCIEXBAR_REG_LENGTH_128MB:
                bar_base &= (PCI_PCIEBAR_REG_MASK << 1)
            if len == PCI_PCIEXBAR_REG_LENGTH_64MB:
                bar_base &= (PCI_PCIEBAR_REG_MASK << 0)
            if len == PCI_PCIEXBAR_REG_LENGTH_512MB:
                bar_base &= (PCI_PCIEBAR_REG_MASK << 3)
            if len == PCI_PCIEXBAR_REG_LENGTH_1024MB:
                bar_base &= (PCI_PCIEBAR_REG_MASK << 4)
            if len == PCI_PCIEXBAR_REG_LENGTH_2048MB:
                bar_base &= (PCI_PCIEBAR_REG_MASK << 5)
            if len == PCI_PCIEXBAR_REG_LENGTH_4096MB:
                bar_base &= (PCI_PCIEBAR_REG_MASK << 6)
        if self.cs.register_has_field("MmioCfgBaseAddr", "BusRange"):
            num_buses = self.cs.read_register_field("MmioCfgBaseAddr", "BusRange")
            if num_buses <= 8:
                bar_size = 2**20 * 2**num_buses
            else:
                self.logger.log_hal(f'[mmcfg] Unexpected MmioCfgBaseAddr bus range: 0x{num_buses:01X}')
        self.logger.log_hal(f'[mmcfg] Memory Mapped CFG Base: 0x{bar_base:016X}')
        return bar_base, bar_size

    def read_mmcfg_reg(self, bus: int, dev: int, fun: int, off: int, size: int) -> int:
        pciexbar, _ = self.get_MMCFG_base_address()
        pciexbar_off = (bus * 32 * 8 + dev * 8 + fun) * 0x1000 + off
        value = self.read_MMIO_reg(pciexbar, pciexbar_off, size)
        self.logger.log_hal(f'[mmcfg] reading {bus:02d}:{dev:02d}.{fun:d} + 0x{off:02X} (MMCFG + 0x{pciexbar_off:08X}): 0x{value:08X}')
        if 1 == size:
            return (value & 0xFF)
        elif 2 == size:
            return (value & 0xFFFF)
        return value

    def write_mmcfg_reg(self, bus: int, dev: int, fun: int, off: int, size: int, value: int) -> bool:
        pciexbar, _ = self.get_MMCFG_base_address()
        pciexbar_off = (bus * 32 * 8 + dev * 8 + fun) * 0x1000 + off
        if size == 1:
            mask = 0xFF
        elif size == 2:
            mask = 0xFFFF
        else:
            mask = 0xFFFFFFFF
        self.write_MMIO_reg(pciexbar, pciexbar_off, (value & mask), size)
        self.logger.log_hal(f'[mmcfg] writing {bus:02d}:{dev:02d}.{fun:d} + 0x{off:02X} (MMCFG + 0x{pciexbar_off:08X}): 0x{value:08X}')
        return True
