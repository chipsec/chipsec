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
#
# -------------------------------------------------------------------------------

"""
Access to SMBus Controller
"""

from chipsec.logger import *

import chipsec.hal.iobar

SMBUS_COMMAND_QUICK         = 0
SMBUS_COMMAND_BYTE          = 1
SMBUS_COMMAND_BYTE_DATA     = 2
SMBUS_COMMAND_WORD_DATA     = 3
SMBUS_COMMAND_PROCESS_CALL  = 4
SMBUS_COMMAND_BLOCK         = 5
SMBUS_COMMAND_I2C_READ      = 6
SMBUS_COMMAND_BLOCK_PROCESS = 7

SMBUS_POLL_COUNT = 1000

SMBUS_COMMAND_WRITE = 0
SMBUS_COMMAND_READ  = 1

class SMBus:
    def __init__( self, cs ):
        self.cs = cs
        self.iobar = chipsec.hal.iobar.iobar( self.cs )
        self.smb_reg_status  = 'SMBUS_HST_STS'
        self.smb_reg_command = 'SMBUS_HST_CMD'
        self.smb_reg_address = 'SMBUS_HST_SLVA'
        self.smb_reg_control = 'SMBUS_HST_CNT'
        self.smb_reg_data0   = 'SMBUS_HST_D0'
        self.smb_reg_data1   = 'SMBUS_HST_D1'

    def get_SMBus_Base_Address( self ):
        if self.iobar.is_IO_BAR_defined( 'SMBUS_BASE' ):
            (sba_base, sba_size) = self.iobar.get_IO_BAR_base_address( 'SMBUS_BASE' )
            return sba_base
        else:
            raise chipsec.hal.iobar.IOBARNotFoundError, ('IOBARAccessError: SMBUS_BASE')

    def get_SMBus_HCFG( self ):
        if chipsec.chipset.is_register_defined( self.cs, 'SMBUS_HCFG' ):
            reg_value = chipsec.chipset.read_register( self.cs, 'SMBUS_HCFG' )
            if logger().HAL: chipsec.chipset.print_register( self.cs, 'SMBUS_HCFG', reg_value )
            return reg_value
        else:
            raise chipsec.chipset.RegisterNotFoundError, ('RegisterNotFound: SMBUS_HCFG')

    def display_SMBus_info( self ):
        if logger().HAL: logger().log( "[smbus] SMBus Base Address: 0x%04X" % self.get_SMBus_Base_Address() )
        self.get_SMBus_HCFG()

    def is_SMBus_enabled( self ):
        return self.cs.is_device_enabled( 'SMBUS' )

    def is_SMBus_supported( self ):
        (did,vid) = self.cs.get_DeviceVendorID( 'SMBUS' )
        if logger().VERBOSE: logger().log( "[smbus] SMBus Controller (DID,VID) = (0x%04X,0x%04X)" % (did,vid) )
        if (0x8086 == vid): return True
        else:
            logger().error( "Unknown SMBus Controller (DID,VID) = (0x%04X,0x%04X)" % (did,vid) )
            return False

    def is_SMBus_host_controller_enabled( self ):
        hcfg = self.get_SMBus_HCFG()
        return hcfg.CFG_REG_PCH_SMB_HCFG_HST_EN

    def enable_SMBus_host_controller( self ):
        # Enable SMBus Host Controller Interface in HCFG
        reg_value = chipsec.chipset.read_register( self.cs, 'SMBUS_HCFG' )
        if 0 == (reg_value & 0x1): chipsec.chipset.write_register( self.cs, 'SMBUS_HCFG', (reg_value|0x1) )
        # @TODO: check SBA is programmed
        sba = self.get_SMBus_Base_Address()
        # Enable SMBus I/O Space
        cmd = chipsec.chipset.read_register( self.cs, 'SMBUS_CMD' )
        if 0 == (cmd & 0x1): chipsec.chipset.write_register( self.cs, 'SMBUS_CMD', (cmd|0x1) )


    #
    # SMBus commands
    # 

    # waits for SMBus to become ready
    def _is_smbus_ready( self ):
        for i in range(SMBUS_POLL_COUNT):
            #time.sleep( SMBUS_POLL_SLEEP_INTERVAL )
            busy = chipsec.chipset.read_register_field( self.cs, self.smb_reg_status, 'BUSY' )
            if 0 == busy: return True
        return (0 == busy)

    # waits for SMBus transaction to complete
    def _wait_for_cycle( self ):
        for i in range(SMBUS_POLL_COUNT):
            #time.sleep( SMBUS_POLL_SLEEP_INTERVAL )
            sts    = chipsec.chipset.read_register( self.cs, self.smb_reg_status )
            busy   = chipsec.chipset.get_register_field( self.cs, self.smb_reg_status, sts, 'BUSY' )
            failed = chipsec.chipset.get_register_field( self.cs, self.smb_reg_status, sts, 'FAILED' )
            if 0 == busy:
                #if logger().VERBOSE:
                #    intr = chipsec.chipset.get_register_field( self.cs, self.smb_reg_status, sts, 'INTR' )
                #    logger().log( "[smbus]: INTR = %d" % intr )
                break
            elif 1 == failed:
                #kill = 0
                #if chipsec.chipset.register_has_field( self.cs, self.smb_reg_control, 'KILL' ):
                #    kill = chipsec.chipset.read_register_field( self.cs, self.smb_reg_control, 'KILL' )
                if logger().HAL: logger().error( "SMBus transaction failed (FAILED/ERROR bit = 1)" )
                return False
            else:
                if chipsec.chipset.register_has_field( self.cs, self.smb_reg_status, 'DEV_ERR' ):
                    if 1 == chipsec.chipset.get_register_field( self.cs, self.smb_reg_status, sts, 'DEV_ERR' ): 
                        if logger().HAL: logger().error( "SMBus device error (invalid cmd, unclaimed cycle or time-out error)" )
                        return False
                if chipsec.chipset.register_has_field( self.cs, self.smb_reg_status, 'BUS_ERR' ):
                    if 1 == chipsec.chipset.get_register_field( self.cs, self.smb_reg_status, sts, 'BUS_ERR' ):
                        if logger().HAL: logger().error( "SMBus bus error" )
                        return False
        return (0 == busy)

    def read_byte( self, target_address, offset ):
        # clear status bits
        chipsec.chipset.write_register( self.cs, self.smb_reg_status, 0xFF )

        # SMBus txn RW direction = Read, SMBus slave address = target_address
        hst_sa = 0x0
        hst_sa = chipsec.chipset.set_register_field( self.cs, self.smb_reg_address, hst_sa, 'RW', SMBUS_COMMAND_READ )
        hst_sa = chipsec.chipset.set_register_field( self.cs, self.smb_reg_address, hst_sa, 'Address', target_address, True )
        chipsec.chipset.write_register( self.cs, self.smb_reg_address, hst_sa )
        # command data = byte offset (bus txn address)
        chipsec.chipset.write_register_field( self.cs, self.smb_reg_command, 'DataOffset', offset )
        # command = Byte Data
        #if chipsec.chipset.register_has_field( self.cs, self.smb_reg_control, 'SMB_CMD' ):
        chipsec.chipset.write_register_field( self.cs, self.smb_reg_control, 'SMB_CMD', SMBUS_COMMAND_BYTE_DATA )
        # send SMBus txn
        chipsec.chipset.write_register_field( self.cs, self.smb_reg_control, 'START', 1 )

        # wait for cycle to complete
        if not self._wait_for_cycle(): return 0xFF
        # read the data
        value = chipsec.chipset.read_register_field( self.cs, self.smb_reg_data0, 'Data' )
        # clear status bits
        chipsec.chipset.write_register( self.cs, self.smb_reg_status, 0xFF )
        # clear address/offset registers
        #chipsec.chipset.write_register( self.cs, self.smb_reg_address, 0x0 )
        #chipsec.chipset.write_register( self.cs, self.smb_reg_command, 0x0 )
        if logger().VERBOSE: logger().log( "[smbus] read device %X off %X = %X" % (target_address, offset, value) )
        return value

    def write_byte( self, target_address, offset, value ):
        # clear status bits
        chipsec.chipset.write_register( self.cs, self.smb_reg_status, 0xFF )

        # SMBus txn RW direction = Write, SMBus slave address = target_address
        hst_sa = 0x0
        hst_sa = chipsec.chipset.set_register_field( self.cs, self.smb_reg_address, hst_sa, 'RW', SMBUS_COMMAND_WRITE )
        hst_sa = chipsec.chipset.set_register_field( self.cs, self.smb_reg_address, hst_sa, 'Address', target_address, True )
        chipsec.chipset.write_register( self.cs, self.smb_reg_address, hst_sa )
        # command data = byte offset (bus txn address)
        chipsec.chipset.write_register_field( self.cs, self.smb_reg_command, 'DataOffset', offset )
        # write the data
        chipsec.chipset.write_register_field( self.cs, self.smb_reg_data0, 'Data', value )
        # command = Byte Data
        #if chipsec.chipset.register_has_field( self.cs, self.smb_reg_control, 'SMB_CMD' ):
        chipsec.chipset.write_register_field( self.cs, self.smb_reg_control, 'SMB_CMD', SMBUS_COMMAND_BYTE_DATA )
        # send SMBus txn
        chipsec.chipset.write_register_field( self.cs, self.smb_reg_control, 'START', 1 )

        # wait for cycle to complete
        if not self._wait_for_cycle(): return False
        # clear status bits
        chipsec.chipset.write_register( self.cs, self.smb_reg_status, 0xFF )
        # clear address/offset registers
        #chipsec.chipset.write_register( self.cs, self.smb_reg_address, 0x0 )
        #chipsec.chipset.write_register( self.cs, self.smb_reg_command, 0x0 )
        if logger().VERBOSE: logger().log( "[smbus] write to device %X off %X = %X" % (target_address, offset, value) )
        return True


    def read_range( self, target_address, start_offset, size ):
        buffer = [chr(0xFF)]*size
        for i in range (size):
            buffer[i] = chr( self.read_byte( target_address, start_offset + i ) )
        if logger().HAL:
            logger().log( "[smbus] reading %u bytes from device 0x%X at offset %X" % (size, target_address, start_offset) )
            #print_buffer( buffer )
        return buffer

    def write_range( self, target_address, start_offset, buffer ):
        size = len(buffer)
        for i in range(size):
            self.write_byte( target_address, start_offset + i, ord(buffer[i]) )
        if logger().HAL:
            logger().log( "[smbus] writing %u bytes to device 0x%X at offset %X" % (size, target_address, start_offset) )
            #print_buffer( buffer )
        return True
