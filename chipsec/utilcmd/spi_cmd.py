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
CHIPSEC includes functionality for reading and writing the SPI flash. When an image file is created from reading the SPI flash, this image can be parsed to reveal sections, files, variables, etc.

.. warning:: Particular care must be taken when using the SPI write and SPI erase functions. These could make your system unbootable.

A basic forensic operation might be to dump the entire SPI flash to a file. This is accomplished as follows:

``# python chipsec_util.py spi dump rom.bin``

The file rom.bin will contain the full binary of the SPI flash. It can then be parsed using the decode util command.

>>> chipsec_util spi info|dump|read|write|erase|disable-wp [flash_address] [length] [file]

Examples:

>>> chipsec_util spi info
>>> chipsec_util spi dump rom.bin
>>> chipsec_util spi read 0x700000 0x100000 bios.bin
>>> chipsec_util spi write 0x0 flash_descriptor.bin
>>> chipsec_util spi disable-wp
>>> chipsec_util spi sfdp
>>> chipsec_util spi jedec
>>> chipsec_util spi jedec decode
"""

import os
from chipsec.command import BaseCommand, toLoad
from chipsec.hal.spi import SPI, BIOS
from argparse import ArgumentParser


# SPI Flash Controller
class SPICommand(BaseCommand):

    def requirements(self) -> toLoad:
        return toLoad.All

    def parse_arguments(self) -> None:
        parser = ArgumentParser(prog='chipsec_util spi', usage=__doc__)
        subparsers = parser.add_subparsers()
        parser_info = subparsers.add_parser('info')
        parser_info.set_defaults(func=self.spi_info)

        parser_dump = subparsers.add_parser('dump')
        parser_dump.add_argument('out_file', type=str, nargs='?', default='rom.bin', help='Output file name [default=rom.bin]')
        parser_dump.set_defaults(func=self.spi_dump)

        parser_read = subparsers.add_parser('read')
        parser_read.add_argument('spi_fla', type=lambda x: int(x, 16), help='Start Address (hex)')
        parser_read.add_argument('length', type=lambda x: int(x, 16), nargs='?', default=0x4, help='Length [default=0x4] (hex)')
        parser_read.add_argument('out_file', type=str, nargs='?', default='read.bin', help='Output file [default=read.bin')
        parser_read.set_defaults(func=self.spi_read)

        parser_write = subparsers.add_parser('write')
        parser_write.add_argument('spi_fla', type=lambda x: int(x, 16), help='Start Address (hex)')
        parser_write.add_argument('filename', type=str, help='File name (hex)')
        parser_write.set_defaults(func=self.spi_write)

        parser_erase = subparsers.add_parser('erase')
        parser_erase.add_argument('spi_fla', type=lambda x: int(x, 16), help='Start Address (hex)')
        parser_erase.set_defaults(func=self.spi_erase)

        parser_disable_wp = subparsers.add_parser('disable-wp')
        parser_disable_wp.set_defaults(func=self.spi_disable_wp)

        parser_sfdp = subparsers.add_parser('sfdp')
        parser_sfdp.set_defaults(func=self.spi_sfdp)

        parser_jedec = subparsers.add_parser('jedec')
        parser_jedec.add_argument('option', type=str, nargs='?', default='', help='Optional decode')
        parser_jedec.set_defaults(func=self.spi_jedec)

        parser.parse_args(self.argv, namespace=self)

    def set_up(self) -> None:
        self._spi = SPI(self.cs)
        self._msg = "it may take a few minutes (use DEBUG or VERBOSE logger options to see progress)"

    def spi_info(self):
        self.logger.log("[CHIPSEC] SPI flash memory information\n")
        self._spi.display_SPI_map()

    def spi_dump(self):
        self.logger.log("[CHIPSEC] Dumping entire SPI flash memory to '{}'".format(self.out_file))
        self.logger.log("[CHIPSEC] {}".format(self._msg))
        # @TODO: don't assume SPI Flash always ends with BIOS region
        (base, limit, _) = self._spi.get_SPI_region(BIOS)
        spi_size = limit + 1
        self.logger.log("[CHIPSEC] BIOS region: base = 0x{:08X}, limit = 0x{:08X}".format(base, limit))
        self.logger.log("[CHIPSEC] Dumping 0x{:08X} bytes (to the end of BIOS region)".format(spi_size))
        buf = self._spi.read_spi_to_file(0, spi_size, self.out_file)
        if buf is None:
            self.logger.log_error("Dumping SPI Flash didn't return any data (turn on VERBOSE)")
        else:
            self.logger.log("[CHIPSEC] Completed SPI flash dump to '{}'".format(self.out_file))

    def spi_read(self):
        self.logger.log("[CHIPSEC] Reading 0x{:x} bytes from SPI Flash starting at FLA = 0x{:X}".format(self.length, self.spi_fla))
        self.logger.log("[CHIPSEC] {}".format(self._msg))
        buf = self._spi.read_spi_to_file(self.spi_fla, self.length, self.out_file)
        if buf is None:
            self.logger.log_error("SPI flash read didn't return any data (turn on VERBOSE)")
        else:
            self.logger.log("[CHIPSEC] Completed SPI flash memory read")

    def spi_write(self):
        if not os.path.exists(self.filename):
            self.logger.log_error("File '{}' doesn't exist".format(self.filename))
            return
        self.logger.log("[CHIPSEC] Writing to SPI flash memory at FLA = 0x{:X} from '{:64s}'".format(self.spi_fla, self.filename))

        if self._spi.write_spi_from_file(self.spi_fla, self.filename):
            self.logger.log("[CHIPSEC] Completed SPI flash memory write")
        else:
            self.logger.log_warning("SPI flash write returned error (turn on VERBOSE)")

    def spi_erase(self):
        self.logger.log("[CHIPSEC] Erasing SPI flash memory block at FLA = 0x{:X}".format(self.spi_fla))

        if self._spi.erase_spi_block(self.spi_fla):
            self.logger.log_good("Completed SPI flash memory erase")
        else:
            self.logger.log_warning("SPI flash erase returned error (turn on VERBOSE)")

    def spi_disable_wp(self):
        self.logger.log("[CHIPSEC] Trying to disable BIOS write protection..")
        #
        # This write protection only matters for BIOS range in SPI flash memory
        #
        if self._spi.disable_BIOS_write_protection():
            self.logger.log_good("BIOS region write protection is disabled in SPI flash")
        else:
            self.logger.log_bad("Couldn't disable BIOS region write protection in SPI flash")

    def spi_sfdp(self):
        self._spi.get_SPI_SFDP()

    def spi_jedec(self):
        if self.option.lower() == 'decode':
            (jedec, man, part) = self._spi.get_SPI_JEDEC_ID_decoded()
            if jedec is not False:
                self.logger.log('    JEDEC ID     : 0x{:06X}'.format(jedec))
                self.logger.log('    Manufacturer : 0x{:02X}     - {}'.format((jedec >> 16) & 0xFF, man))
                self.logger.log('    Device       : 0x{:04X}   - {}'.format(jedec & 0xFFFF, part))
                self.logger.log('')
            else:
                self.logger.log(' JEDEC ID command is not supported')
        else:
            jedec_id = self._spi.get_SPI_JEDEC_ID()
            if jedec_id is not False:
                self.logger.log('    JEDEC ID: 0x{:06X}'.format(jedec_id))
                self.logger.log('')
            else:
                self.logger.log(' JEDEC ID command is not supported')

commands = {'spi': SPICommand}
