#!/usr/bin/python
# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2017, Google Inc
# Copyright (c) 2010-2015, Intel Corporation
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
#You should have received a copy of the GNU General Public License
#along with this program; if not, write to the Free Software
#Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
#Contact information:
#chipsec@intel.com
#

from chipsec.command import BaseCommand
from chipsec.hal import tpm_eventlog
from chipsec.hal import tpm

class TPMCommand(BaseCommand):
        """
        >>> chipsec_util tpm parse_log <file>
        >>> chipsec_util tpm state <locality>
        >>> chipsec_util tpm command <commandName> <locality> <command_parameters>

        locality: 0 | 1 | 2 | 3 | 4
        commands - parameters:
        pccrread - pcr number ( 0 - 23 )
        nvread - Index, Offset, Size
        startup - startup type ( 1 - 3 )
        continueselftest
        getcap - Capabilities Area, Size of Sub-capabilities, Sub-capabilities
        forceclear
        
        Examples:
                        
        >>> chipsec_util tpm parse_log binary_bios_measurements
        >>> chipsec_util tpm state 0
        >>> chipsec_util tpm command pcrread 0 17
        >>> chipsec_util tpm command continueselftest 0
        """
        def requires_driver(self):
            return False

        def run(self):
            if len(self.argv) < 4:
                print TPMCommand.__doc__
                return
            op = argv[2]
            if ( 'parse_log' == op ):
                log = open(self.argv[3])
                tpm_eventlog.parse(log)
            elif ('command' == op ):
                if len(argv) < 5:
                    print TPMCommand.__doc__
                    return
                tpm.command( argv[3], argv[4], argv[5:] )
            elif ('state' == op ):
                tpm.dump_access ( argv[3] )
                tpm.dump_status ( argv[3] )
                tpm.didvid ( argv[3] )
                tpm.dump_rid ( argv[3] )
                tpm.dump_intcap ( argv[3] )
                tpm.dump_intenable( argv[3] )
            else:
                print TPMCommand.__doc__
                return

commands = { 'tpm': TPMCommand }
