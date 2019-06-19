#!/usr/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2018, Intel Corporation
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
CHIPSEC includes functionality for reading and writing the SPI flash. When an image file is created from reading the SPI flash, this image can be parsed to reveal sections, files, variables, etc.

.. warning:: Particular care must be taken when using the spi write and spi erase functions. These could make your system unbootable.

A basic forensic operation might be to dump the entire SPI flash to a file. This is accomplished as follows:

``# python chipsec_util.py spi dump rom.bin``

The file rom.bin will contain the full binary of the SPI flash. It can then be parsed using the decode util command.
"""

import time

from chipsec.command    import BaseCommand
from chipsec.hal.spi    import *


# SPI Flash Controller
class SPICommand(BaseCommand):
    """
    >>> chipsec_util spi info|dump|read|write|erase|disable-wp [flash_address] [length] [file]

    Examples:

    >>> chipsec_util spi info
    >>> chipsec_util spi dump rom.bin
    >>> chipsec_util spi read 0x700000 0x100000 bios.bin
    >>> chipsec_util spi write 0x0 flash_descriptor.bin
    >>> chipsec_util spi disable-wp
    >>> chipsec_util spi jedec
    >>> chipsec_util spi jedec decode
    """
    def requires_driver(self):
        # No driver required when printing the util documentation
        if len(self.argv) < 3:
            return False
        return True

    def run(self):
        if len(self.argv) < 3:
            print (SPICommand.__doc__)
            return

        try:
            _spi = SPI( self.cs )
        except SpiRuntimeError as msg:
            print (msg)
            return

        spi_op = self.argv[2]

        t = time.time()

        _msg = "it may take a few minutes (use DEBUG or VERBOSE logger options to see progress)"
        if ( 'erase' == spi_op ):
            spi_fla = int(self.argv[3],16)
            self.logger.log( "[CHIPSEC] erasing SPI flash memory block at FLA = 0x{:X}".format(spi_fla) )

            ok = _spi.erase_spi_block( spi_fla )
            if ok: self.logger.log_result( "completed SPI flash memory erase" )
            else:  self.logger.warn( "SPI flash erase returned error (turn on VERBOSE)" )
        elif ( 'write' == spi_op and 5 == len(self.argv) ):
            spi_fla = int(self.argv[3],16)
            filename = self.argv[4]
            self.logger.log( "[CHIPSEC] writing to SPI flash memory at FLA = 0x{:X} from '{:64}'".format(spi_fla, filename) )

            ok = _spi.write_spi_from_file( spi_fla, filename )
            if ok: self.logger.log( "[CHIPSEC] completed SPI flash memory write" )
            else:  self.logger.warn( "SPI flash write returned error (turn on VERBOSE)" )
        elif ( 'read' == spi_op ):
            spi_fla = int(self.argv[3],16)
            length = int(self.argv[4],16)
            self.logger.log( "[CHIPSEC] reading 0x{:X} bytes from SPI Flash starting at FLA = 0x{:X}".format(length, spi_fla) )
            self.logger.log( "[CHIPSEC] {}".format(_msg) )
            out_file = None
            if 6 == len(self.argv):
                out_file = self.argv[5]
            buf = _spi.read_spi_to_file( spi_fla, length, out_file )
            if (buf is None): self.logger.error( "SPI flash read didn't return any data (turn on VERBOSE)" )
            else: self.logger.log( "[CHIPSEC] completed SPI flash memory read" )
        elif ( 'info' == spi_op ):
            self.logger.log( "[CHIPSEC] SPI flash memory information\n" )
            _spi.display_SPI_map()
        elif ( 'dump' == spi_op ):
            out_file = 'rom.bin'
            if 4 == len(self.argv):
                out_file = self.argv[3]
            self.logger.log( "[CHIPSEC] dumping entire SPI flash memory to '{}'".format(out_file) )
            self.logger.log( "[CHIPSEC] {}".format(_msg) )
            # @TODO: don't assume SPI Flash always ends with BIOS region
            (base,limit,freg) = _spi.get_SPI_region( BIOS )
            spi_size = limit + 1
            self.logger.log( "[CHIPSEC] BIOS region: base = 0x{:08X}, limit = 0x{:08X}".format(base,limit) )
            self.logger.log( "[CHIPSEC] dumping 0x{:08X} bytes (to the end of BIOS region)".format(spi_size) )
            buf = _spi.read_spi_to_file( 0, spi_size, out_file )
            if (buf is None): self.logger.error( "dumping SPI Flash didn't return any data (turn on VERBOSE)" )
            else: self.logger.log( "[CHIPSEC] completed SPI flash dump to '{}'".format(out_file) )

        elif ( 'disable-wp' == spi_op ):
            self.logger.log( "[CHIPSEC] trying to disable BIOS write protection.." )
            #
            # This write protection only matters for BIOS range in SPI flash memory
            #
            if _spi.disable_BIOS_write_protection():
                self.logger.log_good( "BIOS region write protection is disabled in SPI flash" )
            else:
                self.logger.log_bad( "couldn't disable BIOS region write protection in SPI flash" )
        elif ( 'jedec' == spi_op ):
            if ( len(self.argv) < 4 ):
                self.logger.log( '    JEDEC ID: 0x{:06X}'.format(_spi.get_SPI_JEDEC_ID()) )
                self.logger.log( '' )
            else:
                (jedec, man, part) = _spi.get_SPI_JEDEC_ID_decoded()
                self.logger.log( '    JEDEC ID     : 0x{:06X}'.format(jedec) )
                self.logger.log( '    Manufacturer : 0x{:02X}     - {}'.format( (jedec >> 16) & 0xFF , man) )
                self.logger.log( '    Device       : 0x{:04X}   - {}'.format(jedec & 0xFFFF, part) )
                self.logger.log( '' )
        else:
            print (SPICommand.__doc__)
            return

        self.logger.log( "[CHIPSEC] (spi {}) time elapsed {:.3f}".format(spi_op, time.time()-t) )

commands = { 'spi': SPICommand }
