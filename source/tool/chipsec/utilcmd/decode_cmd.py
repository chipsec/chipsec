#!/usr/local/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2015, Intel Corporation
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
CHIPSEC can parse an image file containing data from the SPI flash (such as the result of chipsec_util spi dump). This can be critical in forensic analysis.

Examples:

chipsec_util decode spi.bin vss

This will create multiple log files, binaries, and directories that correspond to the sections, firmware volumes, files, variables, etc. stored in the SPI flash.

.. note: It may be necessary to try various options for fw_type in order to correctly parse NVRAM variables. Currently, CHIPSEC does not autodetect the correct format. If the nvram directory does not appear and the list of nvram variables is empty, try again with another type.
"""

__version__ = '1.0'

import os
import time

from chipsec.file import read_file, write_file
from chipsec.command import BaseCommand

import chipsec.hal.spi            as spi
import chipsec.hal.spi_descriptor as spi_descriptor
import chipsec.hal.spi_uefi       as spi_uefi
import chipsec.hal.uefi           as uefi


class DecodeCommand(BaseCommand):
    """
    >>> chipsec_util decode <rom> [fw_type]

    For a list of fw types run:

    >>> chipsec_util decode types

    Examples:

    >>> chipsec_util decode spi.bin vss
    """

    def requires_driver(self):
        return False

    def run(self):
        if len(self.argv) < 3:
            print DecodeCommand.__doc__
            return
        
        _uefi = uefi.UEFI( self.cs )
        if self.argv[2] == "types":
            print "\n<fw_type> should be in [ %s ]\n" % ( " | ".join( ["%s" % t for t in uefi.fw_types] ) )
            return
            
        rom_file = self.argv[2]
        fwtype   = self.argv[3] if len(self.argv) == 4 else None      

        self.logger.log( "[CHIPSEC] Decoding SPI ROM image from a file '%s'" % rom_file )
        t = time.time()

        f = read_file( rom_file )
        (fd_off, fd) = spi_descriptor.get_spi_flash_descriptor( f )
        if (-1 == fd_off) or (fd is None):
            self.logger.error( "Could not find SPI Flash descriptor in the binary '%s'" % rom_file )
            return False

        self.logger.log( "[CHIPSEC] Found SPI Flash descriptor at offset 0x%x in the binary '%s'" % (fd_off, rom_file) )
        rom = f[fd_off:]
        # Decoding Flash Descriptor
        #self.logger.LOG_COMPLETE_FILE_NAME = os.path.join( pth, 'flash_descriptor.log' )
        #parse_spi_flash_descriptor( fd )

        # Decoding SPI Flash Regions
        # flregs[r] = (r,SPI_REGION_NAMES[r],flreg,base,limit,notused)
        flregs = spi_descriptor.get_spi_regions( fd )
        if flregs is None:
            self.logger.error( "SPI Flash descriptor region is not valid" )
            return False

        _orig_logname = self.logger.LOG_FILE_NAME

        pth = os.path.join( self.cs.helper.getcwd(), rom_file + ".dir" )
        if not os.path.exists( pth ):
            os.makedirs( pth )

        for r in flregs:
            idx     = r[0]
            name    = r[1]
            base    = r[3]
            limit   = r[4]
            notused = r[5]
            if not notused:
                region_data = rom[base:limit+1]
                fname = os.path.join( pth, '%d_%04X-%04X_%s.bin' % (idx, base, limit, name) )
                write_file( fname, region_data )
                if spi.FLASH_DESCRIPTOR == idx:
                    # Decoding Flash Descriptor
                    self.logger.set_log_file( os.path.join( pth, fname + '.log' ) )
                    spi_descriptor.parse_spi_flash_descriptor( region_data )
                elif spi.BIOS == idx:
                    # Decoding EFI Firmware Volumes
                    self.logger.set_log_file( os.path.join( pth, fname + '.log' ) )
                    spi_uefi.decode_uefi_region(_uefi, pth, fname, fwtype)

        self.logger.set_log_file( _orig_logname )
        self.logger.log( "[CHIPSEC] (decode) time elapsed %.3f" % (time.time()-t) )

commands = { "decode": DecodeCommand }
