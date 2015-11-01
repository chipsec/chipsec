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

from chipsec.command import BaseCommand

# ###################################################################
#
# CPUid
#
# ###################################################################
class CPUIDCommand(BaseCommand):
    """
    >>> chipsec_util cpuid <eax> [ecx]

    Examples:

    >>> chipsec_util cpuid 40000000
    """

    def requires_driver(self):
        # No driver required when printing the util documentation
        if len(self.argv) < 3:
            return False
        return True

    def run(self):
        if len(self.argv) < 3:
            print CPUIDCommand.__doc__
            return

        eax = int(self.argv[2],16)
        ecx = int(self.argv[3],16) if 4 == len(self.argv) else 0

        self.logger.log( "[CHIPSEC] CPUID < EAX: 0x%08X" % eax)
        self.logger.log( "[CHIPSEC]         ECX: 0x%08X" % ecx)

        val = self.cs.cpuid.cpuid( eax, ecx )

        self.logger.log( "[CHIPSEC] CPUID > EAX: 0x%08X" % (val[0]) )
        self.logger.log( "[CHIPSEC]         EBX: 0x%08X" % (val[1]) )
        self.logger.log( "[CHIPSEC]         ECX: 0x%08X" % (val[2]) )
        self.logger.log( "[CHIPSEC]         EDX: 0x%08X" % (val[3]) )

commands = { 'cpuid': CPUIDCommand }
