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
>>> chipsec_util spidesc <rom>

Examples:

>>> chipsec_util spidesc spi.bin
"""

from chipsec.command import BaseCommand, toLoad
from chipsec.library.file import read_file
from chipsec.hal.spi_descriptor import parse_spi_flash_descriptor
from argparse import ArgumentParser


class SPIDescCommand(BaseCommand):

    def requirements(self) -> toLoad:
        return toLoad.Config

    def parse_arguments(self) -> None:
        parser = ArgumentParser(prog='chipsec_util spidesc', usage=__doc__)
        parser.add_argument('fd_file', type=str, help='File name')
        parser.set_defaults()
        parser.parse_args(self.argv, namespace=self)

    def run(self):

        self.logger.log("[CHIPSEC] Parsing SPI Flash Descriptor from file '{}'\n".format(self.fd_file))
        fd = read_file(self.fd_file)
        if fd:
            parse_spi_flash_descriptor(self.cs, fd)


commands = {'spidesc': SPIDescCommand}
