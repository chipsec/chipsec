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
        self.instance = 0
        self.p2sbHide = None
        self.get_registers()

    def get_registers(self):
        self.msg_ctl_reg = self.cs.register.get_instance_by_name('8086.P2SBC.MSG_CTRL_REG', self.instance)
        self.msg_ctl_reg_ext = self.cs.register.get_instance_by_name('8086.P2SBC.MSG_CTRL_REG_EXT', self.instance)
        self.msg_data_reg = self.cs.register.get_instance_by_name('8086.P2SBC.MSG_DATA_REG', self.instance)

    def __MB_MESSAGE_MCR(self, port: int, reg: int, opcode: int) -> int:

        self.msg_ctl_reg.set_value(0x0)
        self.msg_ctl_reg.set_field('MESSAGE_WR_BYTE_ENABLES', 0xF)
        self.msg_ctl_reg.set_field('MESSAGE_ADDRESS_OFFSET', reg)
        self.msg_ctl_reg.set_field('MESSAGE_PORT', port)
        self.msg_ctl_reg.set_field('MESSAGE_OPCODE', opcode)
        return self.msg_ctl_reg.value

    def __MB_MESSAGE_MCRX(self, reg: int) -> int:
        self.msg_ctl_reg_ext.set_value(0x0)
        mcrx = self.msg_ctl_reg_ext.set_field('MESSAGE_ADDRESS_OFFSET_EXT', reg >> 8)
        return mcrx

    def __MB_MESSAGE_MDR(self, data: int) -> int:
        self.msg_data_reg.set_value(0x0)
        mdr = self.msg_data_reg.set_field('MESSAGE_DATA', data)
        return mdr

    #
    # Issues read message on the message bus
    #
    def msgbus_read_message(self, port: int, register: int, opcode: int) -> Optional[int]:
        mcr = self.__MB_MESSAGE_MCR(port, register, opcode)
        mcrx = self.__MB_MESSAGE_MCRX(register)

        self.logger.log_hal(f'[msgbus] Read: port 0x{port:02X} + 0x{register:08X} (op = 0x{opcode:02X})')
        self.logger.log_hal(f'[msgbus]       MCR = 0x{mcr:08X}, MCRX = 0x{mcrx:08X}')

        mdr_out = self.cs.helper.msgbus_send_read_message(mcr, mcrx)

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

        return self.cs.helper.msgbus_send_write_message(mcr, mcrx, mdr)

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

        mdr_out = self.cs.helper.msgbus_send_message(mcr, mcrx, mdr)

        self.logger.log_hal(f'[msgbus]          < 0x{mdr_out:08X}')

        return mdr_out

    #
    # Message bus register read/write
    #

    def msgbus_reg_read(self, port: int, register: int) -> Optional[int]:
        return self.msgbus_read_message(port, register, MessageBusOpcode.MB_OPCODE_REG_READ)

    def msgbus_reg_write(self, port: int, register: int, data: int) -> None:
        return self.msgbus_write_message(port, register, MessageBusOpcode.MB_OPCODE_REG_WRITE, data)


haldata = {"arch": [hal_base.HALBase.MfgIds.Intel], 'name': ['MsgBus']}
