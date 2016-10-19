#!/usr/local/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2016, Intel Corporation
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



# -------------------------------------------------------------------------------
#
# CHIPSEC: Platform Hardware Security Assessment Framework
# (c) 2010-2016 Intel Corporation
#
# -------------------------------------------------------------------------------

"""
Access to message bus (IOSF sideband) interface registers on Intel SoCs

References:
- Intel(R) Atom(TM) Processor E3800 Product Family Datasheet, May 2016, Revision 4.0
  http://www.intel.com/content/www/us/en/embedded/products/bay-trail/atom-e3800-family-datasheet.html (sections 3.6 and 13.4.6 - 13.4.8)
- Intel(R) Atom(TM) Processor D2000 and N2000 Series Datasheet, Volume 2, July 2012, Revision 003
  http://www.intel.com/content/dam/doc/datasheet/atom-d2000-n2000-vol-2-datasheet.pdf (section 1.10.2)

usage:
    >>> msgbus_reg_read( port, register )
    >>> msgbus_reg_write( port, register, data )

    >>> msgbus_read_message( port, register, opcode )
    >>> msgbus_write_message( port, register, opcode, data )
    >>> msgbus_send_message( port, register, opcode, data )
"""

__version__ = '1.0'

import struct
import sys
import os.path
import chipsec.chipset
from chipsec.logger import logger

#
# IOSF Message bus message opcodes
# Reference: http://lxr.free-electrons.com/source/arch/x86/include/asm/iosf_mbi.h
#
class MessageBusOpcode:
  MB_OPCODE_MMIO_READ   = 0x00
  MB_OPCODE_MMIO_WRITE  = 0x01
  MB_OPCODE_IO_READ     = 0x02
  MB_OPCODE_IO_WRITE    = 0x03
  MB_OPCODE_CFG_READ    = 0x04
  MB_OPCODE_CFG_WRITE   = 0x05
  MB_OPCODE_CR_READ     = 0x06
  MB_OPCODE_CR_WRITE    = 0x07
  MB_OPCODE_REG_READ    = 0x10
  MB_OPCODE_REG_WRITE   = 0x11
  MB_OPCODE_ESRAM_READ  = 0x12
  MB_OPCODE_ESRAM_WRITE = 0x13

#
# IOSF Message bus unit ports
# Reference: http://lxr.free-electrons.com/source/arch/x86/include/asm/iosf_mbi.h
# @TODO: move these to per-platform XML config?
#
class MessageBusPort_Atom:
  UNIT_AUNIT = 0x00
  UNIT_SMC   = 0x01
  UNIT_CPU   = 0x02
  UNIT_BUNIT = 0x03
  UNIT_PMC   = 0x04
  UNIT_GFX   = 0x06
  UNIT_SMI   = 0x0C
  UNIT_USB   = 0x43
  UNIT_SATA  = 0xA3
  UNIT_PCIE  = 0xA6

class MessageBusPort_Quark:
  UNIT_HBA   = 0x00
  UNIT_HB    = 0x03
  UNIT_RMU   = 0x04
  UNIT_MM    = 0x05
  UNIT_SOC   = 0x31


def MB_MESSAGE_MCR( _cs, port, reg, opcode ):
    mcr = 0x0
    mcr = chipsec.chipset.set_register_field( _cs, 'MSG_CTRL_REG', mcr, 'MESSAGE_WR_BYTE_ENABLES', 0xF )
    mcr = chipsec.chipset.set_register_field( _cs, 'MSG_CTRL_REG', mcr, 'MESSAGE_ADDRESS_OFFSET', reg )
    mcr = chipsec.chipset.set_register_field( _cs, 'MSG_CTRL_REG', mcr, 'MESSAGE_PORT', port )
    mcr = chipsec.chipset.set_register_field( _cs, 'MSG_CTRL_REG', mcr, 'MESSAGE_OPCODE', opcode )
    return mcr

def MB_MESSAGE_MCRX( _cs, reg ):
    mcrx = 0x0
    mcrx = chipsec.chipset.set_register_field( _cs, 'MSG_CTRL_REG_EXT', mcrx, 'MESSAGE_ADDRESS_OFFSET_EXT', reg, preserve_field_position=True )
    return mcrx

def MB_MESSAGE_MDR( _cs, data ):
    mdr = 0x0
    mdr = chipsec.chipset.set_register_field( _cs, 'MSG_DATA_REG', mdr, 'MESSAGE_DATA', data )
    return mdr


class MsgBusRuntimeError (RuntimeError):
    pass

class MsgBus:

    def __init__( self, cs ):
        self.helper = cs.helper
        self.cs     = cs


    #
    # Issues read message on the message bus
    #
    def msgbus_read_message( self, port, register, opcode ):
        mcr  = MB_MESSAGE_MCR (self.cs, port, register, opcode)
        mcrx = MB_MESSAGE_MCRX(self.cs, register)

        if logger().HAL: logger().log( "[msgbus] read: port 0x%02X + 0x%08X (op = 0x%02X)" % (port, register, opcode) )
        if logger().VERBOSE: logger().log( "[msgbus]       MCR = 0x%08X, MCRX = 0x%08X" % (mcr, mcrx) )

        mdr_out = self.helper.msgbus_send_read_message( mcr, mcrx )

        if logger().HAL: logger().log( "[msgbus]       < 0x%08X" % mdr_out )

        return mdr_out

    #
    # Issues write message on the message bus
    #
    def msgbus_write_message( self, port, register, opcode, data ):
        mcr  = MB_MESSAGE_MCR (self.cs, port, register, opcode)
        mcrx = MB_MESSAGE_MCRX(self.cs, register)
        mdr  = MB_MESSAGE_MDR (self.cs, data)

        if logger().HAL: logger().log( "[msgbus] write: port 0x%02X + 0x%08X (op = 0x%02X) < data = 0x%08X" % (port, register, opcode, data) )
        if logger().VERBOSE: logger().log( "[msgbus]        MCR = 0x%08X, MCRX = 0x%08X, MDR = 0x%08X" % (mcr, mcrx, mdr) )

        return self.helper.msgbus_send_write_message( mcr, mcrx, mdr )

    #
    # Issues generic message on the message bus
    #
    def msgbus_send_message( self, port, register, opcode, data=None ):
        mcr  = MB_MESSAGE_MCR(self.cs, port, register, opcode)
        mcrx = MB_MESSAGE_MCRX(self.cs, register)
        mdr  = None if data is None else MB_MESSAGE_MDR(self.cs, data)

        if logger().HAL:
            logger().log( "[msgbus] message: port 0x%02X + 0x%08X (op = 0x%02X)" % (port, register, opcode) )
            if data is not None: logger().log( "[msgbus]          data = 0x%08X" % data )
        if logger().VERBOSE: logger().log( "[msgbus]          MCR = 0x%08X, MCRX = 0x%08X, MDR = 0x%08X" % (mcr, mcrx, mdr) )

        mdr_out = self.helper.msgbus_send_message( mcr, mcrx, mdr )

        if logger().HAL: logger().log( "[msgbus]          < 0x%08X" % mdr_out )

        return mdr_out

    #
    # Message bus register read/write
    #

    def msgbus_reg_read( self, port, register ):
        return self.msgbus_read_message( port, register, MessageBusOpcode.MB_OPCODE_REG_READ )

    def msgbus_reg_write( self, port, register, data ):
        return self.msgbus_write_message( port, register, MessageBusOpcode.MB_OPCODE_REG_WRITE, data )

    """
    # py implementation of msgbus -- doesn't seem to work properly becaise it's not atomic
    def msgbus_send_message( self, port, register, opcode, data=None ):
        if logger().HAL:
            logger().log( "[msgbus] message - port: 0x%02X, reg: 0x%08X (op: 0x%02X)" % (port, register, opcode) )
            if data is not None: logger().log( "[msgbus] message - data: 0x%08X" % data )
        if (register & 0xFFFFFF00):
            # write extended register address (bits [31:08]) to Message Control Register Extension (MCRX)
            chipsec.chipset.write_register_field( self.cs, 'MSG_CTRL_REG_EXT', 'MESSAGE_ADDRESS_OFFSET_EXT', register, preserve_field_position=True )
        res = None
        # write data to Message Data Register (MDR) for writes
        if data is not None: chipsec.chipset.write_register( self.cs, 'MSG_DATA_REG', data )
        # write message (byte enables, address bits [08:00], port and opcode) to Message Control Register (MCR)
        chipsec.chipset.write_register( self.cs, 'MSG_CTRL_REG', MB_MESSAGE(self.cs, port, register, opcode) )
        # read the data from Message Data Register (MDR) for reads
        if data is None: res = chipsec.chipset.read_register( self.cs, 'MSG_DATA_REG' )
        return res
    """
