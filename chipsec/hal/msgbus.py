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
from chipsec.library.exceptions import RegisterNotFoundError


#
# IOSF Message bus message opcodes
# Reference: http://lxr.free-electrons.com/source/arch/x86/include/asm/iosf_mbi.h
#
class MessageBusOpcode:
    MB_OPCODE_MMIO_READ = 0x00
    MB_OPCODE_MMIO_WRITE = 0x01
    MB_OPCODE_IO_READ = 0x02
    MB_OPCODE_IO_WRITE = 0x03
    MB_OPCODE_CFG_READ = 0x04
    MB_OPCODE_CFG_WRITE = 0x05
    MB_OPCODE_CR_READ = 0x06
    MB_OPCODE_CR_WRITE = 0x07
    MB_OPCODE_REG_READ = 0x10
    MB_OPCODE_REG_WRITE = 0x11
    MB_OPCODE_ESRAM_READ = 0x12
    MB_OPCODE_ESRAM_WRITE = 0x13

#
# IOSF Message bus unit ports
# Reference: http://lxr.free-electrons.com/source/arch/x86/include/asm/iosf_mbi.h
# @TODO: move these to per-platform XML config?
#


class MessageBusPort_Atom:
    UNIT_AUNIT = 0x00
    UNIT_SMC = 0x01
    UNIT_CPU = 0x02
    UNIT_BUNIT = 0x03
    UNIT_PMC = 0x04
    UNIT_GFX = 0x06
    UNIT_SMI = 0x0C
    UNIT_USB = 0x43
    UNIT_SATA = 0xA3
    UNIT_PCIE = 0xA6


class MessageBusPort_Quark:
    UNIT_HBA = 0x00
    UNIT_HB = 0x03
    UNIT_RMU = 0x04
    UNIT_MM = 0x05
    UNIT_SOC = 0x31


class MsgBus(hal_base.HALBase):

    def __init__(self, cs):
        super(MsgBus, self).__init__(cs)
        self.helper = cs.helper
        self.p2sbHide = None

    def __MB_MESSAGE_MCR(self, port: int, reg: int, opcode: int) -> int:
        mcr = 0x0
        mcr = self.cs.register.set_field('MSG_CTRL_REG', mcr, 'MESSAGE_WR_BYTE_ENABLES', 0xF)
        mcr = self.cs.register.set_field('MSG_CTRL_REG', mcr, 'MESSAGE_ADDRESS_OFFSET', reg)
        mcr = self.cs.register.set_field('MSG_CTRL_REG', mcr, 'MESSAGE_PORT', port)
        mcr = self.cs.register.set_field('MSG_CTRL_REG', mcr, 'MESSAGE_OPCODE', opcode)
        return mcr

    def __MB_MESSAGE_MCRX(self, reg: int) -> int:
        mcrx = 0x0
        mcrx = self.cs.register.set_field('MSG_CTRL_REG_EXT', mcrx, 'MESSAGE_ADDRESS_OFFSET_EXT', (reg >> 8), preserve_field_position=True)
        return mcrx

    def __MB_MESSAGE_MDR(self, data: int) -> int:
        mdr = 0x0
        mdr = self.cs.register.set_field('MSG_DATA_REG', mdr, 'MESSAGE_DATA', data)
        return mdr

    def __hide_p2sb(self, hide: bool) -> bool:
        if not self.p2sbHide:
            if self.cs.register.has_field("P2SBC", "HIDE"):
                self.p2sbHide = {'reg': 'P2SBC', 'field': 'HIDE'}
            elif self.cs.register.has_field("P2SB_HIDE", "HIDE"):
                self.p2sbHide = {'reg': 'P2SB_HIDE', 'field': 'HIDE'}
            else:
                raise RegisterNotFoundError('RegisterNotFound: P2SBC')

        hidden = not self.cs.device.is_enabled('P2SBC')
        if hide:
            self.cs.register.write_field(self.p2sbHide['reg'], self.p2sbHide['field'], 1)
        else:
            self.cs.register.write_field(self.p2sbHide['reg'], self.p2sbHide['field'], 0)
        return hidden

    #
    # Issues read message on the message bus
    #
    def msgbus_read_message(self, port: int, register: int, opcode: int) -> Optional[int]:
        mcr = self.__MB_MESSAGE_MCR(port, register, opcode)
        mcrx = self.__MB_MESSAGE_MCRX(register)

        self.logger.log_hal(f'[msgbus] Read: port 0x{port:02X} + 0x{register:08X} (op = 0x{opcode:02X})')
        self.logger.log_hal(f'[msgbus]       MCR = 0x{mcr:08X}, MCRX = 0x{mcrx:08X}')

        mdr_out = self.helper.msgbus_send_read_message(mcr, mcrx)

        self.logger.log_hal(f'[msgbus]       < 0x{mdr_out:08X}')

        return mdr_out

    #
    # Issues write message on the message bus
    #
    def msgbus_write_message(self, port: int, register: int, opcode: int, data: int) -> None:
        mcr = self.__MB_MESSAGE_MCR(port, register, opcode)
        mcrx = self.__MB_MESSAGE_MCRX(register)
        mdr = self.__MB_MESSAGE_MDR(data)

        self.logger.log_hal(f'[msgbus] Write: port 0x{port:02X} + 0x{register:08X} (op = 0x{opcode:02X}) < data = 0x{data:08X}')
        self.logger.log_hal(f'[msgbus]        MCR = 0x{mcr:08X}, MCRX = 0x{mcrx:08X}, MDR = 0x{mdr:08X}')

        return self.helper.msgbus_send_write_message(mcr, mcrx, mdr)

    #
    # Issues generic message on the message bus
    #
    def msgbus_send_message(self, port: int, register: int, opcode: int, data: Optional[int] = None) -> Optional[int]:
        mcr = self.__MB_MESSAGE_MCR(port, register, opcode)
        mcrx = self.__MB_MESSAGE_MCRX(register)
        mdr = None if data is None else self.__MB_MESSAGE_MDR(data)

        self.logger.log_hal(f'[msgbus] message: port 0x{port:02X} + 0x{register:08X} (op = 0x{opcode:02X})')
        if data is not None:
            self.logger.log_hal(f'[msgbus]          data = 0x{data:08X}')
        self.logger.log_hal(f'[msgbus]          MCR = 0x{mcr:08X}, MCRX = 0x{mcrx:08X}, MDR = 0x{mdr:08X}')

        mdr_out = self.helper.msgbus_send_message(mcr, mcrx, mdr)

        self.logger.log_hal(f'[msgbus]          < 0x{mdr_out:08X}')

        return mdr_out

    #
    # Message bus register read/write
    #

    def msgbus_reg_read(self, port: int, register: int) -> Optional[int]:
        return self.msgbus_read_message(port, register, MessageBusOpcode.MB_OPCODE_REG_READ)

    def msgbus_reg_write(self, port: int, register: int, data: int) -> None:
        return self.msgbus_write_message(port, register, MessageBusOpcode.MB_OPCODE_REG_WRITE, data)

    def mm_msgbus_reg_read(self, port: int, register: int) -> int:
        was_hidden = False
        if self.cs.register.is_defined('P2SBC'):
            was_hidden = self.__hide_p2sb(False)
        mmio_addr = self.cs.mmio.get_MMIO_BAR_base_address('SBREGBAR')[0]
        reg_val = self.cs.mmio.read_MMIO_reg_dword(mmio_addr, ((port & 0xFF) << 16) | (register & 0xFFFF))
        if self.cs.register.is_defined('P2SBC') and was_hidden:
            self.__hide_p2sb(True)
        return reg_val

    def mm_msgbus_reg_write(self, port: int, register: int, data: int) -> Optional[int]:
        was_hidden = False
        if self.cs.register.is_defined('P2SBC'):
            was_hidden = self.__hide_p2sb(False)
        mmio_addr = self.cs.mmio.get_MMIO_BAR_base_address('SBREGBAR')[0]
        reg_val = self.cs.mmio.write_MMIO_reg_dword(mmio_addr, ((port & 0xFF) << 16) | (register & 0xFFFF), data)
        if self.cs.register.is_defined('P2SBC') and was_hidden:
            self.__hide_p2sb(True)
        return reg_val
