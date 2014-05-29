#!/usr/local/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2014, Intel Corporation
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
# (c) 2010-2012 Intel Corporation
#
# -------------------------------------------------------------------------------
## \addtogroup hal
# chipsec/hal/smbus.py
# ================================
# Access to SMBus Controller
#
#
#



from chipsec.logger import *
from chipsec.cfg.common import *

class SMBus:
    def __init__( self, cs ):
        self.cs = cs

    def get_SMBus_Base_Address( self ):
        #
        # B0:D31:F3 + 0x20 SMBus Base Address (SBA)
        #
        reg_value = self.cs.pci.read_byte( 0, Cfg.PCI_B0D31F3_SMBUS_CTRLR_DEV, Cfg.PCI_B0D31F3_SMBUS_CTRLR_FUN, Cfg.CFG_REG_PCH_SMB_SBA )
        return (reg_value & Cfg.CFG_REG_PCH_SMB_SBA_BASE_ADDRESS_MASK) 

    def get_SMBus_HCFG( self ):
        #
        # B0:D31:F3 + 0x40 SMBus Host Configuration (HCFG)
        #
        reg_value = self.cs.pci.read_byte( 0, Cfg.PCI_B0D31F3_SMBUS_CTRLR_DEV, Cfg.PCI_B0D31F3_SMBUS_CTRLR_FUN, Cfg.CFG_REG_PCH_SMB_HCFG )
        hcfg = Cfg.SMB_HCFG_REG( reg_value, (reg_value&Cfg.CFG_REG_PCH_SMB_HCFG_SPD_WD > 0), (reg_value&Cfg.CFG_REG_PCH_SMB_HCFG_SSRESET > 0), (reg_value&Cfg.CFG_REG_PCH_SMB_HCFG_I2C_EN > 0), (reg_value&Cfg.CFG_REG_PCH_SMB_HCFG_SMB_SMI_EN > 0), (reg_value&Cfg.CFG_REG_PCH_SMB_HCFG_HST_EN > 0) )
        return hcfg

    def display_SMBus_info( self ):
        logger().log( "[smbus] SMBus Base Address: 0x%04X" % self.get_SMBus_Base_Address() )
        logger().log( self.get_SMBus_HCFG() )

    def is_SMBus_enabled( self ):
        return self.cs.pci.is_enabled( 0, Cfg.PCI_B0D31F3_SMBUS_CTRLR_DEV, Cfg.PCI_B0D31F3_SMBUS_CTRLR_FUN )

    def is_SMBus_supported( self ):
        (did,vid) = self.cs.pci.get_DIDVID( 0, Cfg.PCI_B0D31F3_SMBUS_CTRLR_DEV, Cfg.PCI_B0D31F3_SMBUS_CTRLR_FUN )
        if logger().VERBOSE:
           logger().log( "[*] SMBus Controller (DID,VID) = (0x%04X,0x%04X)" % (did,vid) )

        # @TODO: check correct DIDs
        #if (0x8086 == vid and Cfg.PCI_B0D31F3_SMBUS_CTRLR_DID == did):
        if (0x8086 == vid):
          return True
        else:
          logger().error( "Unknown SMBus Controller (DID,VID) = (0x%04X,0x%04X)" % (did,vid) )
          return False

    def is_SMBus_host_controller_enabled( self ):
        hcfg = self.get_SMBus_HCFG()
        return hcfg.CFG_REG_PCH_SMB_HCFG_HST_EN

    def enable_SMBus_host_controller( self ):
        # Enable SMBus Host Controller Interface in HCFG
        hcfg = self.get_SMBus_HCFG()
        if 0 == hcfg.HST_EN:
            hcfg.HST_EN = 1
            self.cs.pci.write_byte( 0, Cfg.PCI_B0D31F3_SMBUS_CTRLR_DEV, Cfg.PCI_B0D31F3_SMBUS_CTRLR_FUN, Cfg.CFG_REG_PCH_SMB_HCFG, hcfg )

        # @TODO: check SBA is programmed
        sba = self.get_SMBus_Base_Address()

        # Enable I/O Space in CMD
        cmd = self.cs.pci.read_word( 0, Cfg.PCI_B0D31F3_SMBUS_CTRLR_DEV, Cfg.PCI_B0D31F3_SMBUS_CTRLR_FUN, Cfg.CFG_REG_PCH_SMB_CMD )
        if (cmd & 0x1): self.cs.pci.write_byte( 0, Cfg.PCI_B0D31F3_SMBUS_CTRLR_DEV, Cfg.PCI_B0D31F3_SMBUS_CTRLR_FUN, Cfg.CFG_REG_PCH_SMB_CMD, 0x1 )


    def _wait_for_cycle( self, smbus_io_base ):
        # wait for cycle to complete
        #while True:
        for i in range(10):
            sts = self.cs.io.read_port_byte( smbus_io_base )
            if   (sts & 0x02): break
            elif (sts & 0x04): logger().error( "SMBus cycle failed: Device error" )
            elif (sts & 0x08): logger().error( "SMBus cycle failed: Bus Error" )
            elif (sts & 0x10): logger().error( "SMBus cycle failed: Unknown Error" )
        if (0x02 == sts): return True
        else: return False

    def _read_byte( self, smbus_io_base, target_address, offset ):
        self.cs.io.write_port_byte( smbus_io_base + 0x0, 0xFF )                   # Clear status bits
        ##self.cs.io.write_port_byte( smbus_io_base + 0x1, 0x1F )
        #for i in range(100):
        #    self.cs.io.write_port_byte( smbus_io_base + 0x0, 0xFF )                   # Clear status bits
        #    sts = self.cs.io.read_port_byte( smbus_io_base )
        #    if (0 == (sts & 0x9F)): break
        #if (sts & 0x9F):
        #    logger().error( "SMBus is not ready for whatever reason" ) 
        #    return 0xFF

        self.cs.io.write_port_byte( smbus_io_base + 0x4, (target_address | 0x1) ) # Byte Read from SMBus device at target_address
        self.cs.io.write_port_byte( smbus_io_base + 0x3, offset )                 # Byte offset
        self.cs.io.write_port_byte( smbus_io_base + 0x2, 0x48 )                   # Send command
        # wait for cycle to complete
        if not self._wait_for_cycle( smbus_io_base ): return 0xFF
        # read the data
        value = self.cs.io.read_port_byte( smbus_io_base + 0x5 )
        # Clear status bits
        self.cs.io.write_port_byte( smbus_io_base + 0x0, 0xFF )
        return value

    def _write_byte( self, smbus_io_base, target_address, offset, value ):
        self.cs.io.write_port_byte( smbus_io_base + 0x0, 0xFF )            # Clear status bits
        self.cs.io.write_port_byte( smbus_io_base + 0x4, target_address )  # Byte Write to SMBus device at target_address
        self.cs.io.write_port_byte( smbus_io_base + 0x3, offset )          # Byte offset
        self.cs.io.write_port_byte( smbus_io_base + 0x5, value )           # Byte data to write
        self.cs.io.write_port_byte( smbus_io_base + 0x2, 0x48 )            # Send command
        # wait for cycle to complete
        if not self._wait_for_cycle( smbus_io_base ): return False
        # Clear status bits
        self.cs.io.write_port_byte( smbus_io_base + 0x0, 0xFF )
        return True

    def read_byte( self, target_address, offset ):
        smbus_io_base = self.cs.pci.read_word( 0, Cfg.PCI_B0D31F3_SMBUS_CTRLR_DEV, Cfg.PCI_B0D31F3_SMBUS_CTRLR_FUN, 0x20 ) & 0xFFFE
        value = self._read_byte( smbus_io_base, target_address, offset )
        if logger().VERBOSE: logger().log( "[smbus] read device %X off %X = %X" % (target_address, offset, value) )
        return value

    def write_byte( self, target_address, offset, value ):
        smbus_io_base = self.cs.pci.read_word( 0, Cfg.PCI_B0D31F3_SMBUS_CTRLR_DEV, Cfg.PCI_B0D31F3_SMBUS_CTRLR_FUN, 0x20 ) & 0xFFFE
        sts = self._write_byte( smbus_io_base, target_address, offset, value )
        if logger().VERBOSE: logger().log( "[smbus] write to device %X off %X = %X" % (target_address, offset, value) )
        return sts

    def read_range( self, target_address, start_offset, size ):
        buffer = [chr(0xFF)]*size
        smbus_io_base = self.cs.pci.read_word( 0, Cfg.PCI_B0D31F3_SMBUS_CTRLR_DEV, Cfg.PCI_B0D31F3_SMBUS_CTRLR_FUN, 0x20 ) & 0xFFFE
        for i in range (size):
            buffer[i] = chr( self._read_byte( smbus_io_base, target_address, start_offset + i ) )
        if logger().VERBOSE:
            logger().log( "[smbus] read device %X from offset %X size %X:" % (target_address, start_offset, size) )
            print_buffer( buffer )
        return buffer

    def write_range( self, target_address, start_offset, buffer ):
        size = len(buffer)
        smbus_io_base = self.cs.pci.read_word( 0, Cfg.PCI_B0D31F3_SMBUS_CTRLR_DEV, Cfg.PCI_B0D31F3_SMBUS_CTRLR_FUN, 0x20 ) & 0xFFFE
        for i in range(size):
            self._write_byte( smbus_io_base, target_address, start_offset + i, ord(buffer[i]) )
        if logger().VERBOSE:
            logger().log( "[smbus] write device %X to offset %X size %X:" % (target_address, start_offset, size) )
            print_buffer( buffer )
        return True
