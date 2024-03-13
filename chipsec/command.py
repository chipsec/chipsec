# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2016, Google
# Copyright (c) 2019-2021, Intel Corporation
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


from enum import Enum
import traceback

from chipsec.library.logger import logger
from chipsec.testcase import ExitCode

class BaseCommand:

    def __init__(self, argv, cs=None):
        self.argv = argv
        self.logger = logger()
        self.cs = cs
        self.ExitCode = ExitCode.OK

    def run(self) -> None:
        try:
            self.func()
        except Exception:
            self.logger.log_error('An error occured during the execution of the command!')
            self.logger.log_error('Please run with the debug option for further details')
            if logger().DEBUG:
                traceback.print_exc()

    def set_up(self) -> None:
        pass
    
    def tear_down(self) -> None:
        pass

    def parse_arguments(self) -> None:
        raise NotImplementedError('sub class should overwrite the parse_arguments() method')
    
    def requirements(self) -> 'toLoad':
        raise NotImplementedError('sub class should overwrite the requirements() method')
    
class toLoad(Enum):
    Nil = 0
    Config = 1
    Driver = 2
    All = 3

    def load_config(self) -> bool:
        if self in [self.Config, self.All]:
            return True
        return False

    def load_driver(self) -> bool:
        if self in [self.Driver, self.All]:
            return True
        return False
