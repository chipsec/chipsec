#!/usr/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2021, Intel Corporation
#
#This program is free software; you can redistribute it and/or
#modify it under the terms of the GNU General Public License
#as published by the Free Software Foundation; Version 2.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with this program; if not, write to the Free Software
#Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
#Contact information:
#chipsec@intel.com
#

"""
Access to MMIO (Memory Mapped IO) BARs and Memory-Mapped PCI Configuration Space (MMCFG)

usage:
    >>> read_MMIO_reg(cs, bar_base, 0x0, 4 )
    >>> write_MMIO_reg(cs, bar_base, 0x0, 0xFFFFFFFF, 4 )
    >>> read_MMIO( cs, bar_base, 0x1000 )
    >>> dump_MMIO( cs, bar_base, 0x1000 )

    Access MMIO by BAR name:

    >>> read_MMIO_BAR_reg( cs, 'MCHBAR', 0x0, 4 )
    >>> write_MMIO_BAR_reg( cs, 'MCHBAR', 0x0, 0xFFFFFFFF, 4 )
    >>> get_MMIO_BAR_base_address( cs, 'MCHBAR' )
    >>> is_MMIO_BAR_enabled( cs, 'MCHBAR' )
    >>> is_MMIO_BAR_programmed( cs, 'MCHBAR' )
    >>> dump_MMIO_BAR( cs, 'MCHBAR' )
    >>> list_MMIO_BARs( cs )

    Access Memory Mapped Config Space:

    >>> get_MMCFG_base_address(cs)
    >>> read_mmcfg_reg( cs, 0, 0, 0, 0x10, 4 )
    >>> read_mmcfg_reg( cs, 0, 0, 0, 0x10, 4, 0xFFFFFFFF )
"""

from chipsec.hal import hal_base

DEFAULT_MMIO_BAR_SIZE = 0x1000

PCI_PCIEXBAR_REG_LENGTH_256MB  = 0x0
PCI_PCIEXBAR_REG_LENGTH_128MB  = 0x1
PCI_PCIEXBAR_REG_LENGTH_64MB   = 0x2
PCI_PCIEXBAR_REG_LENGTH_512MB  = 0x3
PCI_PCIEXBAR_REG_LENGTH_1024MB = 0x4
PCI_PCIEXBAR_REG_LENGTH_2048MB = 0x5
PCI_PCIEXBAR_REG_LENGTH_4096MB = 0x6
PCI_PCIEBAR_REG_MASK = 0x7FFC000000

class MMIO(hal_base.HALBase):

    def __init__(self, cs):
        super(MMIO, self).__init__(cs)

    ###########################################################################
    # Access to MMIO BAR defined by configuration files (chipsec/cfg/*.py)
    ###########################################################################
    #
    # To add your own MMIO bar:
    #   1. Add new MMIO BAR id (any)
    #   2. Write a function get_yourBAR_base_address() with no args that
    #      returns base addres of new bar
    #   3. Add a pointer to this function to MMIO_BAR_base map
    #   4. Don't touch read/write_MMIO_reg functions ;)
    #
    ###########################################################################




    #
    # Read MMIO register as an offset off of MMIO range base address
    #
    def read_MMIO_reg(self, bar_base, offset, size=4, bar_size=None ):
        if size > 8:
            if self.logger.HAL: self.logger.warn("MMIO read cannot exceed 8")
        reg_value = self.cs.helper.read_mmio_reg( bar_base, size, offset, bar_size )
        if self.logger.HAL: self.logger.log( '[mmio] 0x{:08X} + 0x{:08X} = 0x{:08X}'.format(bar_base, offset, reg_value) )
        return reg_value

    def read_MMIO_reg_byte(self, bar_base, offset ):
        reg_value = self.cs.helper.read_mmio_reg( bar_base, 1, offset )
        if self.logger.HAL: self.logger.log( '[mmio] 0x{:08X} + 0x{:08X} = 0x{:08X}'.format(bar_base, offset, reg_value) )
        return reg_value

    def read_MMIO_reg_word(self, bar_base, offset ):
        reg_value = self.cs.helper.read_mmio_reg( bar_base, 2, offset )
        if self.logger.HAL: self.logger.log( '[mmio] 0x{:08X} + 0x{:08X} = 0x{:08X}'.format(bar_base, offset, reg_value) )
        return reg_value

    def read_MMIO_reg_dword(self, bar_base, offset ):
        reg_value = self.cs.helper.read_mmio_reg( bar_base, 4, offset )
        if self.logger.HAL: self.logger.log( '[mmio] 0x{:08X} + 0x{:08X} = 0x{:08X}'.format(bar_base, offset, reg_value) )
        return reg_value

    #
    # Write MMIO register as an offset off of MMIO range base address
    #
    def write_MMIO_reg(self, bar_base, offset, value, size=4, bar_size=None ):
        if self.logger.HAL: self.logger.log( '[mmio] write 0x{:08X} + 0x{:08X} = 0x{:08X}'.format(bar_base, offset, value) )
        self.cs.helper.write_mmio_reg( bar_base, size, value, offset, bar_size )

    def write_MMIO_reg_byte(self, bar_base, offset, value ):
        if self.logger.HAL: self.logger.log( '[mmio] write 0x{:08X} + 0x{:08X} = 0x{:08X}'.format(bar_base, offset, value) )
        self.cs.helper.write_mmio_reg( bar_base, 1, value, offset )

    def write_MMIO_reg_word(self, bar_base, offset, value ):
        if self.logger.HAL: self.logger.log( '[mmio] write 0x{:08X} + 0x{:08X} = 0x{:08X}'.format(bar_base, offset, value) )
        self.cs.helper.write_mmio_reg( bar_base, 2, value, offset )

    def write_MMIO_reg_dword(self, bar_base, offset, value ):
        if self.logger.HAL: self.logger.log( '[mmio] write 0x{:08X} + 0x{:08X} = 0x{:08X}'.format(bar_base, offset, value) )
        self.cs.helper.write_mmio_reg( bar_base, 4, value, offset )

    #
    # Read MMIO registers as offsets off of MMIO range base address
    #
    def read_MMIO(self, bar_base, size):
        regs = []
        size -= size % 4
        for offset in range(0, size, 4):
            regs.append(self.read_MMIO_reg(bar_base, offset))
        return regs

    #
    # Dump MMIO range
    #
    def dump_MMIO(self, bar_base, size ):
        self.logger.log("[mmio] MMIO register range [0x{:016X}:0x{:016X}+{:08X}]:".format(bar_base, bar_base, size))
        size -= size % 4
        for offset in range(0, size, 4):
            self.logger.log( '+{:08X}: {:08X}'.format(offset, self.read_MMIO_reg(bar_base, offset)) )


    ###############################################################################
    # Access to MMIO BAR defined by XML configuration files (chipsec/cfg/*.xml)
    ###############################################################################

    #
    # Check if MMIO BAR with bar_name has been defined in XML config
    # Use this function to fall-back to hardcoded config in case XML config is not available
    #
    def is_MMIO_BAR_defined(self, bar_name):
        is_bar_defined = False
        try:
            _bar = self.cs.Cfg.MMIO_BARS[ bar_name ]
            if _bar is not None:
                if 'register' in _bar:
                    is_bar_defined = self.cs.is_register_defined(_bar['register'])
                elif ('bus' in _bar) and ('dev' in _bar) and ('fun' in _bar) and ('reg' in _bar):
                    # old definition
                    is_bar_defined = True
        except KeyError:
            pass

        if not is_bar_defined:
            if self.logger.HAL: self.logger.warn( "'{}' MMIO BAR definition not found/correct in XML config".format(bar_name) )
        return is_bar_defined

    #
    # Get base address of MMIO range by MMIO BAR name
    #
    def get_MMIO_BAR_base_address(self, bar_name):
        bar = self.cs.Cfg.MMIO_BARS[ bar_name ]
        if bar is None or bar == {}: return -1, -1

        if 'register' in bar:
            preserve = True
            bar_reg = bar['register']
            if 'base_field' in bar:
                base_field = bar['base_field']
                try:
                    base = self.cs.read_register_field(bar_reg, base_field, preserve)
                except Exception:
                    base = 0
                try:
                    reg_mask = self.cs.get_register_field_mask(bar_reg, base_field, preserve)
                except:
                    reg_mask = 0xFFFF
            else:
                base = self.cs.read_register(bar_reg)
                reg_mask = self.cs.get_register_field_mask(bar_reg, preserve)
        else:
            # this method is not preferred (less flexible)
            b = int(bar['bus'], 16)
            d = int(bar['dev'], 16)
            f = int(bar['fun'], 16)
            r = int(bar['reg'], 16)
            width = int(bar['width'], 16)
            reg_mask = (1 << (width * 8)) - 1
            if 8 == width:
                base_lo = self.cs.pci.read_dword( b, d, f, r )
                base_hi = self.cs.pci.read_dword( b, d, f, r + 4 )
                base = (base_hi << 32) | base_lo
            else:
                base = self.cs.pci.read_dword( b, d, f, r )

        if 'fixed_address' in bar and (base == reg_mask or base == 0):
            base = int(bar['fixed_address'], 16)
            if self.logger.HAL: self.logger.log('[mmio] Using fixed address for {}: 0x{:016X}'.format(bar_name, base))
        if 'mask' in bar: base &= int(bar['mask'], 16)
        if 'offset' in bar: base = base + int(bar['offset'], 16)
        size = int(bar['size'], 16) if ('size' in bar) else DEFAULT_MMIO_BAR_SIZE

        if self.logger.HAL: self.logger.log( '[mmio] {}: 0x{:016X} (size = 0x{:X})'.format(bar_name, base, size) )
        if base == 0:
            raise Exception
        return base, size

    #
    # Check if MMIO range is enabled by MMIO BAR name
    #
    def is_MMIO_BAR_enabled(self, bar_name):
        if not self.is_MMIO_BAR_defined( bar_name ):
            return False
        bar = self.cs.Cfg.MMIO_BARS[ bar_name ]
        is_enabled = True
        if 'register' in bar:
            bar_reg   = bar['register']
            if 'enable_field' in bar:
                bar_en_field = bar['enable_field']
                is_enabled = (1 == self.cs.read_register_field(bar_reg, bar_en_field))
        else:
            # this method is not preferred (less flexible)
            b = int(bar['bus'], 16)
            d = int(bar['dev'], 16)
            f = int(bar['fun'], 16)
            r = int(bar['reg'], 16)
            width = int(bar['width'], 16)
            if 8 == width:
                base_lo = self.cs.pci.read_dword( b, d, f, r )
                base_hi = self.cs.pci.read_dword( b, d, f, r + 4 )
                base = (base_hi << 32) | base_lo
            else:
                base = self.cs.pci.read_dword( b, d, f, r )

            if 'enable_bit' in bar:
                en_mask = 1 << int(bar['enable_bit'])
                is_enabled = (0 != base & en_mask)

        return is_enabled

    #
    # Check if MMIO range is programmed by MMIO BAR name
    #
    def is_MMIO_BAR_programmed(self, bar_name):
        bar = self.cs.Cfg.MMIO_BARS[bar_name]

        if 'register' in bar:
            bar_reg   = bar['register']
            if 'base_field' in bar:
                base_field = bar['base_field']
                base = self.cs.read_register_field(bar_reg, base_field, preserve_field_position=True)
            else:
                base = self.cs.read_register(bar_reg)
        else:
            # this method is not preferred (less flexible)
            b = int(bar['bus'], 16)
            d = int(bar['dev'], 16)
            f = int(bar['fun'], 16)
            r = int(bar['reg'], 16)
            width = int(bar['width'], 16)
            if 8 == width:
                base_lo = self.cs.pci.read_dword( b, d, f, r )
                base_hi = self.cs.pci.read_dword( b, d, f, r + 4 )
                base = (base_hi << 32) | base_lo
            else:
                base = self.cs.pci.read_dword( b, d, f, r )

        #if 'mask' in bar: base &= int(bar['mask'],16)
        return (0 != base)

    #
    # Read MMIO register from MMIO range defined by MMIO BAR name
    #
    def read_MMIO_BAR_reg(self, bar_name, offset, size=4 ):
        (bar_base, bar_size) = self.get_MMIO_BAR_base_address(bar_name)
        # @TODO: check offset exceeds BAR size
        return self.read_MMIO_reg(bar_base, offset, size, bar_size)

    #
    # Write MMIO register from MMIO range defined by MMIO BAR name
    #
    def write_MMIO_BAR_reg(self, bar_name, offset, value, size=4 ):
        (bar_base, bar_size) = self.get_MMIO_BAR_base_address(bar_name)
        # @TODO: check offset exceeds BAR size
        return self.write_MMIO_reg(bar_base, offset, value, size, bar_size)

    def read_MMIO_BAR(self, bar_name):
        (bar_base, bar_size) = self.get_MMIO_BAR_base_address(bar_name)
        return self.read_MMIO(bar_base, bar_size)

    #
    # Dump MMIO range by MMIO BAR name
    #
    def dump_MMIO_BAR(self, bar_name):
        (bar_base, bar_size) = self.get_MMIO_BAR_base_address(bar_name)
        self.dump_MMIO(bar_base, bar_size)

    def list_MMIO_BARs(self):
        self.logger.log('')
        self.logger.log( '--------------------------------------------------------------------------------' )
        self.logger.log( ' MMIO Range   | BAR Register   | Base             | Size     | En? | Description' )
        self.logger.log( '--------------------------------------------------------------------------------' )
        for _bar_name in self.cs.Cfg.MMIO_BARS:
            if not self.is_MMIO_BAR_defined( _bar_name ): continue
            _bar = self.cs.Cfg.MMIO_BARS[_bar_name]
            try:
                (_base, _size) = self.get_MMIO_BAR_base_address(_bar_name)
            except:
                if self.logger.HAL: self.logger.log("Unable to find MMIO BAR {}".format(_bar))
                continue
            _en = self.is_MMIO_BAR_enabled( _bar_name)

            if 'register' in _bar:
                _s = _bar['register']
                if 'offset' in _bar: _s += (' + 0x{:X}'.format(int(_bar['offset'], 16)))
            else:
                _s = '{:02X}:{:02X}.{:01X} + {}'.format( int(_bar['bus'], 16), int(_bar['dev'], 16), int(_bar['fun'], 16), _bar['reg'] )

            self.logger.log( ' {:12} | {:14} | {:016X} | {:08X} | {:d}   | {}'.format(_bar_name, _s, _base, _size, _en, _bar['desc']) )


    ##################################################################################
    # Access to Memory Mapped PCIe Configuration Space
    ##################################################################################

    def get_MMCFG_base_address(self):
        (bar_base, bar_size)  = self.get_MMIO_BAR_base_address('MMCFG')
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
        if self.logger.HAL: self.logger.log( '[mmcfg] Memory Mapped CFG Base: 0x{:016X}'.format(bar_base) )
        return bar_base, bar_size

    def read_mmcfg_reg(self, bus, dev, fun, off, size):
        pciexbar, pciexbar_sz = self.get_MMCFG_base_address()
        pciexbar_off = (bus * 32 * 8 + dev * 8 + fun) * 0x1000 + off
        value = self.read_MMIO_reg(pciexbar, pciexbar_off, size, pciexbar_sz)
        if self.logger.HAL: self.logger.log( "[mmcfg] reading {:02d}:{:02d}.{:d} + 0x{:02X} (MMCFG + 0x{:08X}): 0x{:08X}".format(bus, dev, fun, off, pciexbar_off, value))
        if 1 == size:
            return (value & 0xFF)
        elif 2 == size:
            return (value & 0xFFFF)
        return value

    def write_mmcfg_reg(self, bus, dev, fun, off, size, value):
        pciexbar, pciexbar_sz = self.get_MMCFG_base_address()
        pciexbar_off = (bus * 32 * 8 + dev * 8 + fun) * 0x1000 + off
        if size == 1:
            mask = 0xFF
        elif size == 2:
            mask = 0xFFFF
        else:
            mask = 0xFFFFFFFF
        self.write_MMIO_reg(pciexbar, pciexbar_off, (value & mask), size, pciexbar_sz)
        if self.logger.HAL: self.logger.log( "[mmcfg] writing {:02d}:{:02d}.{:d} + 0x{:02X} (MMCFG + 0x{:08X}): 0x{:08X}".format(bus, dev, fun, off, pciexbar_off, value))
        return True
