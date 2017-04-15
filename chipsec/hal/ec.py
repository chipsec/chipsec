#!/usr/bin/python
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
Access to Embedded Controller (EC)

Usage:

    >>> write_command( command )
    >>> write_data( data )
    >>> read_data()
    >>> read_memory( offset )
    >>> write_memory( offset, data )
    >>> read_memory_extended( word_offset )
    >>> write_memory_extended( word_offset, data )
    >>> read_range( start_offset, size )
    >>> write_range( start_offset, buffer )

"""

from chipsec.hal import hal_base
from chipsec.logger import *
from chipsec.cfg.common import *

#
# Embedded Controller ACPI ports
#
IO_PORT_EC_DATA        = 0x62
IO_PORT_EC_COMMAND     = 0x66
IO_PORT_EC_STATUS      = 0x66

IO_PORT_EC_INDEX       = 0x380
IO_PORT_EC_INDEX_ADDRH = (IO_PORT_EC_INDEX + 0x1)
IO_PORT_EC_INDEX_ADDRL = (IO_PORT_EC_INDEX + 0x2)
IO_PORT_EC_INDEX_DATA  = (IO_PORT_EC_INDEX + 0x3)


EC_STS_OBF         = 0x01 # EC Output buffer full
EC_STS_IBF         = 0x02 # EC Input buffer empty


#
# Embedded Controller ACPI commands
# These commands should be submitted to EC ACPI I/O ports
#
EC_COMMAND_ACPI_READ        = 0x080  # Read EC ACPI memory
EC_COMMAND_ACPI_WRITE       = 0x081  # Write EC ACPI memory
EC_COMMAND_ACPI_LOCK        = 0x082  # Lock EC for burst use
EC_COMMAND_ACPI_UNLOCK      = 0x083  # Unlock EC from burst use
EC_COMMAND_ACPI_QUERY       = 0x084  # Query EC event
EC_COMMAND_ACPI_READ_EXT    = 0x0F0  # Read EC ACPI extended memory
EC_COMMAND_ACPI_WRITE_EXT   = 0x0F1  # Write EC ACPI extended memory

class EC(hal_base.HALBase):

    #
    # EC ACPI memory access
    #

    # Wait for EC input buffer empty
    def _wait_ec_inbuf_empty( self ):
        to = 1000
        while (self.cs.io.read_port_byte(IO_PORT_EC_STATUS) & EC_STS_IBF) and to: to = to - 1
        return True

    # Wait for EC output buffer full
    def _wait_ec_outbuf_full( self ):
        to = 1000
        while not ( self.cs.io.read_port_byte(IO_PORT_EC_STATUS) & EC_STS_OBF ) and to: to = to - 1
        return True

    def write_command( self, command ):
        self._wait_ec_inbuf_empty()
        return self.cs.io.write_port_byte( IO_PORT_EC_COMMAND, command )

    def write_data( self, data ):
        self._wait_ec_inbuf_empty()
        return self.cs.io.write_port_byte( IO_PORT_EC_DATA, data )

    def read_data( self ):
        if not self._wait_ec_outbuf_full(): return None
        return self.cs.io.read_port_byte( IO_PORT_EC_DATA )

    def read_memory( self, offset ):
        self.write_command( EC_COMMAND_ACPI_READ )
        self.write_data( offset )
        return self.read_data()

    def write_memory( self, offset, data ):
        self.write_command( EC_COMMAND_ACPI_WRITE )
        self.write_data( offset )
        return self.write_data( data )

    def read_memory_extended( self, word_offset ):
        self.write_command( EC_COMMAND_ACPI_READ )
        self.write_data( 0x2 )
        self.write_data( word_offset & 0xFF )
        self.write_command( EC_COMMAND_ACPI_READ_EXT )
        self.write_data( word_offset >> 8 )
        return self.read_data()

    def write_memory_extended( self, word_offset, data ):
        self.write_command( EC_COMMAND_ACPI_WRITE )
        self.write_data( 0x2 )
        self.write_data( word_offset & 0xFF )
        self.write_command( EC_COMMAND_ACPI_WRITE_EXT )
        self.write_data( word_offset >> 8 )
        return self.write_data( data )

    def read_range( self, start_offset, size ):
        buffer = [chr(0xFF)]*size
        #self.write_command( EC_COMMAND_ACPI_READ )
        for i in range (size):
            #self.write_data( start_offset + i )
            #buffer[i] = chr( self.read_data() )
            if start_offset + i < 0x100:
                buffer[i] = chr( self.read_memory( start_offset + i ) )
            else:
                buffer[i] = chr( self.read_memory_extended( start_offset + i ) )

        if logger().VERBOSE:
            logger().log( "[ec] read EC memory from offset %X size %X:" % (start_offset, size) )
            print_buffer( buffer )
        return buffer

    def write_range( self, start_offset, buffer ):
        size = len(buffer)
        for i in range(size):
            self.write_memory( start_offset + i, ord(buffer[i]) )
        if logger().VERBOSE:
            logger().log( "[ec] write EC memory to offset %X size %X:" % (start_offset, size) )
            print_buffer( buffer )
        return True

    #
    # EC Intex I/O access
    #
    def read_idx( self, offset ):
        self.cs.io.write_port_byte( IO_PORT_EC_INDEX_ADDRL, offset & 0xFF )
        self.cs.io.write_port_byte( IO_PORT_EC_INDEX_ADDRH, (offset>>8) & 0xFF )
        value = self.cs.io.read_port_byte( IO_PORT_EC_INDEX_DATA )
        if logger().HAL: logger().log( "[ec] index read: offset 0x%02X > 0x%02X:" % (offset, value) )
        return value

    def write_idx( self, offset, value ):
        if logger().HAL: logger().log( "[ec] index write: offset 0x%02X < 0x%02X:" % (offset, value) )
        self.cs.io.write_port_byte( IO_PORT_EC_INDEX_ADDRL, offset & 0xFF )
        self.cs.io.write_port_byte( IO_PORT_EC_INDEX_ADDRH, (offset>>8) & 0xFF )
        self.cs.io.write_port_byte( IO_PORT_EC_INDEX_DATA, value & 0xFF )
        return True
