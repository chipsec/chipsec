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
    no_driver_cmd = ['parse_log']

    def requires_driver(self):
        if len(self.argv) < 4:
            return False
        if self.argv[2] in self.no_driver_cmd:
            return False
        return True

    def run(self):
        try:
            _tpm = tpm.TPM(self.cs)
        except tpm.TpmRuntimeError as msg:
            print(msg)
            return

        if len(self.argv) < 4:
            print (TPMCommand.__doc__)
            return
        op = self.argv[2]
        if ( 'parse_log' == op ):
            log = open(self.argv[3],'rb')
            tpm_eventlog.parse(log)
        elif ('command' == op ):
            if len(self.argv) < 5:
                print (TPMCommand.__doc__)
                return
            _tpm.command( self.argv[3], self.argv[4], self.argv[5:] )
        elif ('state' == op ):
            _tpm.dump_access ( self.argv[3] )
            _tpm.dump_status ( self.argv[3] )
            _tpm.dump_didvid ( self.argv[3] )
            _tpm.dump_rid ( self.argv[3] )
            _tpm.dump_intcap ( self.argv[3] )
            _tpm.dump_intenable( self.argv[3] )
        else:
            print (TPMCommand.__doc__)
            return

commands = { 'tpm': TPMCommand }
