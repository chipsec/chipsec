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
    >>> get_MMIO_BAR_base_address('MCHBAR')
    >>> is_MMIO_BAR_enabled('MCHBAR')
    >>> is_MMIO_BAR_programmed('MCHBAR')
    >>> dump_MMIO_BAR('MCHBAR')
    >>> list_MMIO_BARs()

    Access Memory Mapped Config Space:

    >>> get_MMCFG_base_address()
    >>> read_mmcfg_reg(0, 0, 0, 0x10, 4)
    >>> read_mmcfg_reg(0, 0, 0, 0x10, 4, 0xFFFFFFFF)
"""
from typing import List, Optional, Tuple
from chipsec.hal import hal_base
from chipsec.library.exceptions import CSReadError
from chipsec.library.logger import logger
from chipsec.library.defines import get_bits, is_all_ones

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
                    is_bar_defined = self.cs.register.is_defined(_bar['register'])
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

        is_ba_invalid = False
        if 'register' in bar:
            preserve = True
            bar_reg = bar['register']
            if _bus is None:
                _buses = self.cs.register.get_bus(bar_reg)
                _bus = _buses[0] if _buses else None
            if 'align_bits' in bar:
                preserve = False
            if 'base_field' in bar:
                base_field = bar['base_field']
                try:
                    base = self.cs.register.read_field(bar_reg, base_field, preserve, bus=_bus)
                except CSReadError:
                    base = 0
                    self.logger.log_hal(f'[mmio] Unable to determine MMIO Base.  Using Base = 0x{base:X}')
                is_ba_invalid = base == 0 or self.cs.register.is_field_all_ones(bar_reg, base_field, base)
                try:
                    reg_mask = self.cs.register.get_field_mask(bar_reg, base_field, preserve)
                except CSReadError:
                    reg_mask = 0xFFFF
                    self.logger.log_hal(f'[mmio] Unable to determine MMIO Mask.  Using Mask = 0x{reg_mask:X}')
            else:
                base = self.cs.register.read(bar_reg, bus=_bus)
                reg_mask = self.cs.register.get_field_mask(bar_reg, preserve_field_position=preserve)
            if 'limit_field' in bar:
                limit_field = bar['limit_field']
                limit = self.cs.register.read_field(bar_reg, limit_field, bus=_bus)
            else:
                if self.logger.HAL:
                    self.logger.log_warning(f"[mmio] 'limit_field' field not defined for bar, using limit = 0x{limit:X}")
        else:
            # this method is not preferred (less flexible)
            if _bus is not None:
                b = _bus
            else:
                b = self.cs.device.get_first_bus(bar)
            d = bar['dev']
            f = bar['fun']
            r = bar['reg']
            width = bar['width']
            reg_mask = (1 << (width * 8)) - 1
            size = 4 if width != 8 else 8
            if 8 == width:
                base_lo = self.cs.pci.read_dword(b, d, f, r)
                base_hi = self.cs.pci.read_dword(b, d, f, r + 4)
                base = (base_hi << 32) | base_lo
            else:
                base = self.cs.pci.read_dword(b, d, f, r)
            is_ba_invalid = base == 0 or is_all_ones(base, size)

        if 'fixed_address' in bar and (base == reg_mask or base == 0):
            base = bar['fixed_address']
            self.logger.log_hal(f'[mmio] Using fixed address for {bar_name}: 0x{base:016X}')
        if 'mask' in bar:
            base &= bar['mask']
        if 'offset' in bar:
            base = base + bar['offset']
        if 'align_bits' in bar:
            _buses = self.cs.register.get_bus(bar['base_reg'])
            _bus = _buses[0] if _buses else None
            start = self.cs.register.read_field(bar['base_reg'], bar['base_addr'], bus=_bus)
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
        if is_ba_invalid:
            self.logger.log_hal('[mmio] Base address was determined to be invalid.')
            raise CSReadError(f'[mmio] Base address was determined to be invalid: 0x{base:016X}')

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
                is_enabled = (1 == self.cs.register.read_field(bar_reg, bar_en_field, bus=bus))
        else:
            # this method is not preferred (less flexible)
            if bus is not None:
                b = bus
            else:
                b = self.cs.device.get_first_bus(bar)
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
                base = self.cs.register.read_field(bar_reg, base_field, preserve_field_position=True)
            else:
                base = self.cs.register.read(bar_reg)
        else:
            # this method is not preferred (less flexible)
            b = self.cs.device.get_first_bus(bar)
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
                bus_data = self.cs.register.get_bus(_bar['register'])
                if not bus_data:
                    if 'bus' in self.cs.register.get_def(_bar['register']):
                        bus_data = [self.cs.register.get_def(_bar['register'])['bus']]
            elif 'bus' in _bar:
                bus_data.extend(_bar['bus'])
            else:
                continue
            for bus in bus_data:
                bus = self.cs.device.get_first(bus)
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
                    bus_value = self.cs.device.get_first(_bar["bus"])
                    dev_value = _bar["dev"]
                    fun_value = _bar["fun"]
                    _s = f'{bus_value:02X}:{dev_value:02X}.{fun_value:01X} + {_bar["reg"]}'

                self.logger.log(f' {_bar_name:12} |  {bus or 0:02X} | {_s:14} | {_base:016X} | {_size:08X} | {_en:d}   | {_bar["desc"]}')

    ##################################################################################
    # Access to Memory Mapped PCIe Configuration Space
    ##################################################################################
    def get_MMCFG_base_addresses(self) -> List[Tuple[int, int]]:
        mmcfg_base_address_list = []
        for bus in self.cs.Cfg.CONFIG_PCI['MemMap_VTd']['bus']:
            mmcfg_base_address_list.append(self.get_MMCFG_base_address(bus))
        return mmcfg_base_address_list

    def get_MMCFG_base_address(self, bus: Optional[int] = None) -> Tuple[int, int]:
        (bar_base, bar_size) = self.get_MMIO_BAR_base_address('MMCFG', bus)
        if self.cs.register.has_field("PCI0.0.0_PCIEXBAR", "LENGTH") and not self.cs.is_server():
            len = self.cs.register.read_field("PCI0.0.0_PCIEXBAR", "LENGTH")
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
        if self.cs.register.has_field("MmioCfgBaseAddr", "BusRange"):
            num_buses = self.cs.register.read_field("MmioCfgBaseAddr", "BusRange")
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

    def get_extended_capabilities(self, bus: int, dev: int, fun: int) -> List['ECEntry']:
        retcap = []
        off = 0x100
        while off and off != 0xFFF:
            cap = self.read_mmcfg_reg(bus, dev, fun, off, 4)
            retcap.append(ECEntry(bus, dev, fun, off, cap))
            off = get_bits(cap, 20, 12)
        return retcap

    def get_vsec(self, bus: int, dev: int, fun: int, ecoff: int) -> 'VSECEntry':
        off = ecoff + 4
        vsec = self.read_mmcfg_reg(bus, dev, fun, off, 4)
        return VSECEntry(vsec)


class ECEntry:
    def __init__(self, bus: int, dev: int, fun: int, off: int, value: int):
        self.bus = bus
        self.dev = dev
        self.fun = fun
        self.off = off
        self.next = get_bits(value, 20, 12)
        self.ver = get_bits(value, 16, 4)
        self.id = get_bits(value, 0, 16)

    def __str__(self) -> str:
        ret = f'\tNext Capability Offset: {self.next:03X}'
        ret += f'\tCapability Version: {self.ver:01X}'
        ret += f'\tCapability ID: {self.id:04X} - {ecIDs.get(self.id, "Reserved")}'
        return ret


class VSECEntry:
    def __init__(self, value: int):
        self.size = get_bits(value, 20, 12)
        self.rev = get_bits(value, 16, 4)
        self.id = get_bits(value, 0, 16)

    def __str__(self) -> str:
        ret = f'\tVSEC Size: {self.size:03X}'
        ret += f'\tVSEC Revision: {self.rev:01X}'
        ret += f'\tVSEC ID: {self.id:04X}'
        return ret


def print_pci_extended_capability(ecentries: List[ECEntry]) -> None:
    currentbdf = (None, None, None)
    for ecentry in ecentries:
        if currentbdf != (ecentry.bus, ecentry.dev, ecentry.fun):
            currentbdf = (ecentry.bus, ecentry.dev, ecentry.fun)
            logger().log(f'Extended Capbilities for 0x{ecentry.bus:02X}:{ecentry.dev:02X}.{ecentry.fun:X}:')
        logger().log(f'\tNext Capability Offset: {ecentry.next:03X}')
        logger().log(f'\tCapability Version: {ecentry.ver:01X}')
        logger().log(f'\tCapability ID: {ecentry.id:04X} - {ecIDs.get(ecentry.id, "Reserved")}')


# pci extended capability IDs
ecIDs = {
    0x0: 'Null Capability',
    0x1: 'Advanced Error Reporting (AER)',
    0x2: 'Virtual Channel (VC)',
    0x3: 'Device Serial Number',
    0x4: 'Power Budgeting',
    0x5: 'Root Complex Link Declaration',
    0x6: 'Root Complex Internal Link Control',
    0x7: 'Root Complex Event Collector Endpoint Association',
    0x8: 'Multi-Function Virtual Channel (MFVC)',
    0x9: 'Virtual Channel (VC)',
    0xA: 'Root Complex Register Block (RCRB) Header',
    0xB: 'Vendor-Specific Extended Capability (VSEC)',
    0xC: 'Configuration Access Correlation (CAC)',
    0xD: 'Access Control Services (ACS)',
    0xE: 'Alternative Routing-ID Interpretation (ARI)',
    0xF: 'Address Translation Services (ATS)',
    0x10: 'Single Root I/O Virtualizaiton (SR-IOV)',
    0x11: 'Multi-Root I/O Virtualization (MR-IOV)',
    0x12: 'Multicast',
    0x13: 'Page Request Interface (PRI)',
    0x14: 'Reserved for AMD',
    0x15: 'Resizable BAR',
    0x16: 'Dynamic Power Allocation (DPA)',
    0x17: 'TPH Requester',
    0x18: 'Latency Tolerance Reporting (LTR)',
    0x19: 'Secondary PCI Express',
    0x1A: 'Protocol Multiplexing (PMUX)',
    0x1B: 'Process Address Space ID (PASID)',
    0x1C: 'LN Requester (LNR)',
    0x1D: 'Downstream Port Containment (DPC)',
    0x1E: 'L1 PM Substates',
    0x1F: 'Precision Time Measurement (PTM)',
    0x20: 'PCI Express over M-PHY (M-PCIe)',
    0x21: 'FRS Queueing',
    0x22: 'Readiness Time Reporting',
    0x23: 'Designanated Vendor-Specific Extended Capability',
    0x24: 'VF Resizable BAR',
    0x25: 'Data Link Feature',
    0x26: 'Physical Layer 16.0 GT/s',
    0x27: 'Lane Margining at the Receiver',
    0x28: 'Hiearchy ID',
    0x29: 'Native PCIe Enclosure Management (NPEM)',
    0x2A: 'Physical Layer 32.0 GT/s',
    0x2B: 'Alternative Protocol',
    0x2C: 'System Firmware Intermediary (SFI)',
    0x2D: 'Shadow Functions',
    0x2E: 'Data Object Exchange'
}