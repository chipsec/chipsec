# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2017, Google Inc
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

from chipsec.command import BaseCommand, toLoad
from chipsec.hal import tpm_eventlog
from chipsec.hal import tpm
from chipsec.library.exceptions import TpmRuntimeError
from chipsec.testcase import ExitCode
from argparse import ArgumentParser


class TPMCommand(BaseCommand):

    no_driver_cmd = ['parse_log']

    def requirements(self) -> toLoad:
        return toLoad.All

    def parse_arguments(self) -> None:
        parser = ArgumentParser(usage=__doc__)
        subparsers = parser.add_subparsers()
        parser_parse = subparsers.add_parser('parse_log')
        parser_parse.add_argument('file', type=str, help='File name')
        parser_parse.set_defaults(func=self.tpm_parse)

        parser_command = subparsers.add_parser('command')
        parser_command.add_argument('command_name', type=str, help='Command')
        parser_command.add_argument('locality', type=str, choices=['0', '1', '2', '3', '4'], help='Locality')
        parser_command.add_argument('command_parameters', nargs='*', type=int, help='Command Parameters')
        parser_command.set_defaults(func=self.tpm_command)

        parser_state = subparsers.add_parser('state')
        parser_state.add_argument('locality', type=str, choices=['0', '1', '2', '3', '4'], help='Locality')
        parser_state.set_defaults(func=self.tpm_state)
        parser.parse_args(self.argv, namespace=self)

    def tpm_parse(self):
        with open(self.file, 'rb') as log:
            tpm_eventlog.parse(log)

    def tpm_command(self):
        self._tpm.command(self.command_name, self.locality, self.command_parameters)

    def tpm_state(self):
        self._tpm.dump_access(self.locality)
        self._tpm.dump_status(self.locality)
        self._tpm.dump_didvid(self.locality)
        self._tpm.dump_rid(self.locality)
        self._tpm.dump_intcap(self.locality)
        self._tpm.dump_intenable(self.locality)

    def set_up(self):
        if self.func != self.tpm_parse:
            try:
                self._tpm = tpm.TPM(self.cs)
            except TpmRuntimeError as msg:
                self.logger.log(msg)
                return

    def run(self):
        try:
            self.func()
        except Exception:
            self.ExitCode = ExitCode.ERROR

commands = {'tpm': TPMCommand}
