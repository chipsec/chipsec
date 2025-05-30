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
    >>> msgbus_reg_read( port, register )
    >>> msgbus_reg_write( port, register, data )
    >>> msgbus_read_message( port, register, opcode )
    >>> msgbus_write_message( port, register, opcode, data )
    >>> msgbus_send_message( port, register, opcode, data )
"""

from typing import Optional
from chipsec.hal import hal_base
from chipsec.library.exceptions import CSReadError, RegisterNotFoundError


class MMMsgBus(hal_base.HALBase):

    def __init__(self, cs):
        super(MMMsgBus, self).__init__(cs)
        self.p2sbHide = None

    def __hide_p2sb(self, hide: bool) -> bool:
        """
        Hide or unhide the P2SB device by writing to the HIDE field in the P2SBC register.
        Arguments:
            hide (bool): If True, hide the P2SB device; if False, unhide it.
        Returns:
            bool: True if the P2SB device was hidden, False if it was not.
        """
        if not self.p2sbHide:
            if self.cs.register.has_field("8086.P2SBC.P2SBC", "HIDE"):
                self.p2sbHide = {'reg': '8086.P2SBC.P2SBC', 'field': 'HIDE'}
            elif self.cs.register.has_field("8086.P2SBC.P2SB_HIDE", "HIDE"):
                self.p2sbHide = {'reg': '8086.P2SBC.P2SB_HIDE', 'field': 'HIDE'}
            else:
                raise RegisterNotFoundError('RegisterNotFound: 8086.P2SBC.P2SBC')

        hidden = all(dev is None for dev in self.cs.device.get_bus('8086.P2SBC'))

        p2sbc_reg = self.cs.register.get_list_by_name(self.p2sbHide['reg'])

        if hide:
            p2sbc_reg.write_field(self.p2sbHide['field'], 1)
        else:
            p2sbc_reg.write_field(self.p2sbHide['field'], 0)
        return hidden

    def get_sbreg_base_address(self) -> int:
        """
        Get the base address of the SBREG MMIO BAR.
        Returns:
            None if the base address cannot be determined.
        """
        try:
            mmio_addr = self.cs.hals.MMIO.get_MMIO_BAR_base_address('8086.P2SBC.SBREGBAR')[0]
            return mmio_addr
        except CSReadError:
            self.logger.log_hal('Failed to read MMIO BAR base address for 8086.P2SBC.SBREGBAR')
        self.logger.log_hal('Attempting to unhide and read MMIO BAR base address for 8086.P2SBC.SBREGBAR')
        self.__hide_p2sb(False)
        mmio_addr = self.cs.hals.MMIO.get_MMIO_BAR_base_address('8086.P2SBC.SBREGBAR')[0]
        self.__hide_p2sb(True)
        return mmio_addr

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
        reg_val = self.cs.hals.MMIO.read_MMIO_reg_dword(mmio_addr, ((port & 0xFF) << 16) | (register & 0xFFFF))
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
        reg_val = self.cs.hals.MMIO.write_MMIO_reg_dword(mmio_addr, ((port & 0xFF) << 16) | (register & 0xFFFF), data)
        return reg_val


haldata = {"arch": [hal_base.HALBase.MfgIds.Intel], 'name': ['MMMsgBus']}
