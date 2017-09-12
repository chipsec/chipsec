#!/usr/bin/python
# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2017, Google Inc
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

from chipsec.command import BaseCommand
from chipsec.hal import tpm_eventlog

class TPMCommand(BaseCommand):
    """
    >>> chipsec_util tpm parse_log <file>

    Examples:

    >>> chipsec_util tpm parse_log binary_bios_measurements
    """
    def requires_driver(self):
        return False

    def run(self):
        if len(self.argv) < 4:
            print TPMCommand.__doc__
            return
        log = open(self.argv[3])
        tpm_eventlog.parse(log)


commands = { 'tpm': TPMCommand }
