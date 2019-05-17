#!/usr/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2016, Google
#Copyright (c) 2019, Intel Corporation
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


import chipsec.logger
from chipsec.testcase import ExitCode

class BaseCommand:

    def __init__(self, argv, cs=None):
        self.argv = argv
        self.logger = chipsec.logger.logger()
        self.cs = cs
        self.ExitCode = ExitCode.OK

    def run(self):
        raise NotImplementedError('sub class should overwrite the run() method')

    def requires_driver(self):
        raise NotImplementedError('sub class should overwrite the requires_driver() method')
