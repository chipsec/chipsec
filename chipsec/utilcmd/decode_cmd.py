#!/usr/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2019, Intel Corporation
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

import os
from time import time
from argparse import ArgumentParser

from chipsec.file import read_file, write_file
from chipsec.command import BaseCommand

from chipsec.hal.spi import FLASH_DESCRIPTOR, BIOS
from chipsec.hal.spi_descriptor import get_spi_flash_descriptor, get_spi_regions, parse_spi_flash_descriptor
from chipsec.hal.spi_uefi import decode_uefi_region
from chipsec.hal.uefi import UEFI, uefi_platform

class DecodeCommand(BaseCommand):
    """
    >>> chipsec_util decode <rom> [fw_type]

    For a list of fw types run:

    >>> chipsec_util decode types

    Examples:

    >>> chipsec_util decode spi.bin vss
    """

    def requires_driver(self):
        parser = ArgumentParser(usage=DecodeCommand.__doc__)
        subparsers = parser.add_subparsers()
        parser_types = subparsers.add_parser('types')
        parser_types.set_defaults(func=self.decode_types)
        parser_decode = subparsers.add_parser('decode')
        parser_decode.add_argument('_rom', metavar='<rom>', nargs=1, help='file to decode')
        parser_decode.add_argument('_fwtype', metavar='fw_type', nargs='?', help='firmware type')
        parser_decode.set_defaults(func=self.decode_rom)
        parser.parse_args(self.argv[2:], namespace=self)
        return False

    def decode_types(self):
        self.logger.log("\n<fw_type> should be in [ {} ]\n".format( " | ".join( ["{}".format (t) for t in uefi_platform.fw_types] ) ))

    def decode_rom(self):
        _uefi = UEFI( self.cs )
        self.logger.log( "[CHIPSEC] Decoding SPI ROM image from a file '{}'".format(self._rom) )
        f = read_file( self._rom )
        (fd_off, fd) = get_spi_flash_descriptor( f )
        if (-1 == fd_off) or (fd is None):
            self.logger.error( "Could not find SPI Flash descriptor in the binary '{}'".format(self._rom) )
            self.logger.log_information( "To decode an image without a flash decriptor try chipsec_util uefi decode" )
            return False

        self.logger.log( "[CHIPSEC] Found SPI Flash descriptor at offset 0x{:X} in the binary '{}'".format(fd_off, self._rom) )
        rom = f[fd_off:]

        # Decoding SPI Flash Regions
        flregs = get_spi_regions( fd )
        if flregs is None:
            self.logger.error( "SPI Flash descriptor region is not valid" )
            self.logger.log_information( "To decode an image with an invalid flash decriptor try chipsec_util uefi decode" )
            return False

        _orig_logname = self.logger.LOG_FILE_NAME

        pth = os.path.join( self.cs.helper.getcwd(), self._rom + ".dir" )
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
                fname = os.path.join( pth, '{:d}_{:04X}-{:04X}_{}.bin'.format(idx, base, limit, name) )
                write_file( fname, region_data )
                if FLASH_DESCRIPTOR == idx:
                    # Decoding Flash Descriptor
                    self.logger.set_log_file( os.path.join( pth, fname + '.log' ) )
                    parse_spi_flash_descriptor( self.cs, region_data )
                elif BIOS == idx:
                    # Decoding EFI Firmware Volumes
                    self.logger.set_log_file( os.path.join( pth, fname + '.log' ) )
                    decode_uefi_region(_uefi, pth, fname, self._fwtype)

        self.logger.set_log_file( _orig_logname )


    def run(self):
        t = time()
        self.func()
        self.logger.log( "[CHIPSEC] (decode) time elapsed {:.3f}".format(time()-t) )

commands = { "decode": DecodeCommand }
