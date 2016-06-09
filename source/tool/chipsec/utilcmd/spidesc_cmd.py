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



__version__ = '1.0'

import time

from chipsec.command            import BaseCommand
from chipsec.file               import read_file
from chipsec.hal.spi_descriptor import *

class SPIDescCommand(BaseCommand):
    """
    >>> chipsec_util spidesc [rom]

    Examples:

    >>> chipsec_util spidesc spi.bin
    """
    def requires_driver(self):
        return False

    def run(self):
        if len(self.argv) < 3:
            print SPIDescCommand.__doc__
            return

        fd_file = self.argv[2]
        self.logger.log( "[CHIPSEC] Parsing SPI Flash Descriptor from file '%s'\n" % fd_file )

        t = time.time()
        fd = read_file( fd_file )
        if type(fd) == str: parse_spi_flash_descriptor( fd )
        self.logger.log( "\n[CHIPSEC] (spidesc) time elapsed %.3f" % (time.time()-t) )

commands = { 'spidesc': SPIDescCommand }
