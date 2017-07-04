#!/usr/bin/python
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
Command-line utility providing access to IOMMU engines
"""

import time

import chipsec_util

from chipsec.logger     import *
from chipsec.file       import *
from chipsec.hal import acpi, iommu
from chipsec.command    import BaseCommand


# I/O Memory Management Unit (IOMMU), e.g. Intel VT-d
class IOMMUCommand(BaseCommand):
    """
    >>> chipsec_util iommu list
    >>> chipsec_util iommu config [iommu_engine]
    >>> chipsec_util iommu status [iommu_engine]
    >>> chipsec_util iommu enable|disable <iommu_engine>
    >>> chipsec_util iommu pt

    Examples:

    >>> chipsec_util iommu list
    >>> chipsec_util iommu config VTD
    >>> chipsec_util iommu status GFXVTD
    >>> chipsec_util iommu enable VTD
    >>> chipsec_util iommu pt
    """

    def requires_driver(self):
        # No driver required when printing the util documentation
        if len(self.argv) < 3:
            return False
        return True

    def run(self):
        if len(self.argv) < 3:
            print IOMMUCommand.__doc__
            return
        op = self.argv[2]
        t = time.time()

        try:
            _iommu = iommu.IOMMU(self.cs)
        except IOMMUError, msg:
            print msg
            return

        if ( 'list' == op ):
            self.logger.log( "[CHIPSEC] Enumerating supported IOMMU engines.." )
            self.logger.log( iommu.IOMMU_ENGINES.keys() )
        elif ( 'config' == op or 'status' == op or 'enable' == op or 'disable' == op ):
            if len(self.argv) > 3:
                if self.argv[3] in iommu.IOMMU_ENGINES.keys():
                    _iommu_engines = [ self.argv[3] ]
                else:
                    self.logger.error( "IOMMU name %s not recognized. Run 'iommu list' command for supported IOMMU names" % self.argv[3] )
                    return
            else:
                _iommu_engines = iommu.IOMMU_ENGINES.keys()

            if 'config' == op:

                try:
                    _acpi  = acpi.ACPI( self.cs )
                except acpi.AcpiRuntimeError, msg:
                    print msg
                    return

                if _acpi.is_ACPI_table_present(acpi.ACPI_TABLE_SIG_DMAR):
                    self.logger.log( "[CHIPSEC] Dumping contents of DMAR ACPI table..\n" )
                    _acpi.dump_ACPI_table(acpi.ACPI_TABLE_SIG_DMAR)
                else:
                    self.logger.log( "[CHIPSEC] Couldn't find DMAR ACPI table\n" )

            for e in _iommu_engines:
               if   'config'  == op: _iommu.dump_IOMMU_configuration( e )
               elif 'pt'      == op: _iommu.dump_IOMMU_page_tables( e )
               elif 'status'  == op: _iommu.dump_IOMMU_status( e )
               elif 'enable'  == op: _iommu.set_IOMMU_Translation( e, 1 )
               elif 'disable' == op: _iommu.set_IOMMU_Translation( e, 0 )
        else:
            print IOMMUCommand.__doc__
            return

        self.logger.log( "[CHIPSEC] (iommu) time elapsed %.3f" % (time.time()-t) )


commands = { 'iommu': IOMMUCommand }
