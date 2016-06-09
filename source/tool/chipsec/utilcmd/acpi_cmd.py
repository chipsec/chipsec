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
Command-line utility providing access to ACPI tables 
"""

__version__ = '1.0'

import os
import time

from chipsec.hal.acpi   import *
from chipsec.command    import BaseCommand

# ###################################################################
#
# Advanced Configuration and Power Interface (ACPI)
#
# ###################################################################

class ACPICommand(BaseCommand):
    """
    >>> chipsec_util acpi list
    >>> chipsec_util acpi table <name>|<file_path>

    Examples:

    >>> chipsec_util acpi list
    >>> chipsec_util acpi table XSDT
    >>> chipsec_util acpi table acpi_table.bin
    """

    def requires_driver(self):
        # No driver required when printing the util documentation
        if len(self.argv) < 3:
            return False
        return True

    def run(self):
        if len(self.argv) < 3:
            print ACPICommand.__doc__
            return
        op = self.argv[2]
        t = time.time()

        try:
            _acpi = ACPI(self.cs)
        except AcpiRuntimeError, msg:
            print msg
            return

        if ( 'list' == op ):
            self.logger.log( "[CHIPSEC] Enumerating ACPI tables.." )
            _acpi.print_ACPI_table_list()
        elif ( 'table' == op ):
            if len(self.argv) < 4:
                print ACPICommand.__doc__
                return
            name = self.argv[ 3 ]
            if name in ACPI_TABLES:
                if _acpi.is_ACPI_table_present( name ):
                    self.logger.log( "[CHIPSEC] reading ACPI table '%s'" % name )
                    _acpi.dump_ACPI_table( name )
                else:
                    self.logger.log( "[CHIPSEC] ACPI table '%s' wasn't found" % name )
            elif os.path.exists( name ):
                self.logger.log( "[CHIPSEC] reading ACPI table from file '%s'" % name )
                _acpi.dump_ACPI_table( name, True )
            else:
                self.logger.error( "Please specify table name or path to a file.\nTable name must be in %s" % ACPI_TABLES.keys() )
                print ACPICommand.__doc__
                return
        else:
            print ACPICommand.__doc__
            return

        self.logger.log( "[CHIPSEC] (acpi) time elapsed %.3f" % (time.time()-t) )

commands = { 'acpi': ACPICommand }
