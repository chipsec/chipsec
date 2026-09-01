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
Access to message bus (IOSF sideband) interface registers on Intel SoCs

References:

- Intel(R) Atom(TM) Processor D2000 and N2000 Series Datasheet, Volume 2, July 2012, Revision 003
  http://www.intel.com/content/dam/doc/datasheet/atom-d2000-n2000-vol-2-datasheet.pdf (section 1.10.2)

usage:
    >>> get_sbreg_base_address( )
    >>> read( port, register )
    >>> write( port, register, data )
"""

from typing import Any, Optional, Tuple
from chipsec.hal import hal_base
from chipsec.library.defines import is_all_ones
from chipsec.library.exceptions import MMIOBarConfigError, RegisterNotFoundError, CSReadError

# BIOS hides P2SB before OS handoff, so it is absent from enumeration and its bus is never resolved.
P2SB_DEFAULT_BUS = 0


class MMMsgBus(hal_base.HALBase):

    def __init__(self, cs):
        super(MMMsgBus, self).__init__(cs)
        self.p2sbHide = None

    def __get_unfiltered_register(self, reg_name: str) -> Any:
        """
        Get a register definition without filtering on device enablement.

        The normal register lookup applies filter_enabled(), which drops every P2SB
        register because the hidden device never gets a bus assigned during enumeration.

        Arguments:
            reg_name (str): Full scoped register name.
        Returns:
            Any: The register definition object.
        Raises:
            RegisterNotFoundError: If the register is not defined.
        """
        for reg in self.cs.Cfg.get_reglist(reg_name):
            return reg
        raise RegisterNotFoundError(f'RegisterNotFound: {reg_name}')

    def __get_p2sb_bdf(self, reg: Any) -> Tuple[int, int, int]:
        """
        Get the B/D/F to use for direct config access to a P2SB register.

        Arguments:
            reg: A P2SB register definition object.
        Returns:
            Tuple[int, int, int]: (bus, device, function)
        Raises:
            RegisterNotFoundError: If the device or function is not defined.
        """
        bus = reg.pci.bus if reg.pci.bus is not None else P2SB_DEFAULT_BUS
        if reg.pci.dev is None or reg.pci.fun is None:
            raise RegisterNotFoundError(f'RegisterNotFound: no B/D/F defined for {reg.name}')
        return bus, reg.pci.dev, reg.pci.fun

    def __get_hide_register(self) -> Any:
        """
        Get the register definition holding the P2SB HIDE field.

        Returns:
            Any: The register definition object.
        Raises:
            RegisterNotFoundError: If neither hide register variant is defined.
        """
        if not self.p2sbHide:
            for reg_name in ('8086.P2SBC.P2SBC', '8086.P2SBC.P2SB_HIDE'):
                try:
                    reg = self.__get_unfiltered_register(reg_name)
                except RegisterNotFoundError:
                    continue
                if reg.has_field('HIDE'):
                    self.p2sbHide = {'reg': reg_name, 'field': 'HIDE'}
                    break
            else:
                raise RegisterNotFoundError('RegisterNotFound: 8086.P2SBC.P2SBC')
        return self.__get_unfiltered_register(self.p2sbHide['reg'])

    def __unhide_p2sb(self) -> None:
        """
        Unhide the P2SB device by clearing the HIDE field.

        The hidden device reads back all-ones, so the new value is seeded at 0 rather than
        read-modify-written, to avoid writing the all-ones pattern into the other bits.
        """
        reg = self.__get_hide_register()
        bus, dev, fun = self.__get_p2sb_bdf(reg)
        reg.set_value(0)
        value = reg.set_field(self.p2sbHide['field'], 0)
        self.logger.log_hal(f'[mm_msgbus] Unhiding P2SB at {bus:02X}:{dev:02X}.{fun:X}')
        self.cs.hals.pci.write(bus, dev, fun, reg.offset, reg.size, value)

    def __hide_p2sb(self) -> None:
        """
        Hide the P2SB device by setting the HIDE field.
        """
        reg = self.__get_hide_register()
        bus, dev, fun = self.__get_p2sb_bdf(reg)
        current = self.cs.hals.pci.read(bus, dev, fun, reg.offset, reg.size)
        if is_all_ones(current, reg.size):
            self.logger.log_hal('[mm_msgbus] P2SB is already hidden; skipping re-hide')
            return
        reg.set_value(current)
        value = reg.set_field(self.p2sbHide['field'], 1)
        self.logger.log_hal(f'[mm_msgbus] Re-hiding P2SB at {bus:02X}:{dev:02X}.{fun:X}')
        self.cs.hals.pci.write(bus, dev, fun, reg.offset, reg.size, value)

    def __read_sbreg_bar_direct(self) -> int:
        """
        Read SBREG_BAR straight from PCI config space using the configured B/D/F.

        Returns:
            int: The base address decoded from the BAR.
        Raises:
            CSReadError: If the BAR still reads back as all-ones or zero.
        """
        reg = self.__get_unfiltered_register('8086.P2SBC.SBREG_BAR')
        bus, dev, fun = self.__get_p2sb_bdf(reg)
        raw = self.cs.hals.pci.read(bus, dev, fun, reg.offset, reg.size)
        if is_all_ones(raw, reg.size):
            raise CSReadError('[mm_msgbus] SBREG_BAR reads all ones; P2SB is still hidden')
        bar = self.cs.register.mmio.get_def('8086.P2SBC.SBREGBAR')
        base_field = bar.base_field if bar and bar.base_field else 'RBA'
        preserve = not (bar and bar.reg_align)
        reg.set_value(raw)
        base = reg.get_field(base_field, preserve)
        if not preserve:
            base <<= bar.reg_align
        if base == 0:
            raise CSReadError('[mm_msgbus] SBREG_BAR base address was determined to be 0')
        return base

    def get_sbreg_base_address(self) -> int:
        """
        Get the base address of the SBREG MMIO BAR.
        Returns:
            int: The base address of the SBREG MMIO BAR, or None if it cannot be determined.
        """
        try:
            mmio_addr = self.cs.hals.mmio.get_MMIO_BAR_base_address('8086.P2SBC.SBREGBAR')[0]
            return mmio_addr
        except (MMIOBarConfigError, CSReadError):
            self.logger.log_hal('Failed to read MMIO BAR base address for 8086.P2SBC.SBREGBAR')
        try:
            hobs = self.cs.hals.hob.get_list_by_name('8086.HOB.P2SB_HOB')
            if hobs:
                mmio_addr = hobs[0].get_field_value('PCI')
                return mmio_addr
        except Exception:
            self.logger.log_hal('Failed to read SBREG_BAR from HOBs')
        self.logger.log_hal('Attempting to unhide and read MMIO BAR base address for 8086.P2SBC.SBREGBAR')
        self.__unhide_p2sb()
        try:
            return self.__read_sbreg_bar_direct()
        finally:
            self.__hide_p2sb()

    def read(self, port: int, register: int) -> int:
        """
        Read a register from the MMMsgBus.
        Arguments:
            port (int): The port number to read from.
            register (int): The register number to read.
        Returns:
            int: The value read from the register.
        """
        mmio_addr = self.get_sbreg_base_address()
        reg_val = self.cs.hals.mmio.read_MMIO_reg_dword(mmio_addr, ((port & 0xFF) << 16) | (register & 0xFFFF))
        return reg_val

    def write(self, port: int, register: int, data: int) -> Optional[int]:
        """
        Write a value to a register in the MMMsgBus.
        Arguments:
            port (int): The port number to write to.
            register (int): The register number to write to.
            data (int): The data to write to the register.
        Returns:
            Optional[int]: The value written to the register, or None if the write operation fails.
        """
        mmio_addr = self.get_sbreg_base_address()
        reg_val = self.cs.hals.mmio.write_MMIO_reg_dword(mmio_addr, ((port & 0xFF) << 16) | (register & 0xFFFF), data)
        return reg_val


haldata = {"arch": [hal_base.HALBase.MfgIds.Intel], 'name': {'mmmsgbus': "MMMsgBus"}}
