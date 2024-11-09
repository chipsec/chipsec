# CHIPSEC: Platform Security Assessment Framework
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
Requires the Driver. Lists all available HALs (Hardware Abstraction Layers). 
>>> chipsec_util hals list
>>> chipsec_util hals funcs <hal_name>

Examples:

>>> chipsec_util hals list
>>> chipsec_util hals funcs Pci
"""

from argparse import ArgumentParser

from chipsec.command import BaseCommand, toLoad
from types import FunctionType as function

# ###################################################################
#
# CPU utility
#
# ###################################################################


class HALsCommand(BaseCommand):
    
    def requirements(self) -> toLoad:
        return toLoad.Driver

    def parse_arguments(self) -> None:
        parser = ArgumentParser(usage=__doc__)
        subparsers = parser.add_subparsers()
        parser_list = subparsers.add_parser('list')
        parser_list.set_defaults(func=self.hals_list)
        parser_halfuncs = subparsers.add_parser('funcs')
        parser_halfuncs.add_argument('hal_name', help='Name of the helper you want to get the function list from', choices=sorted(self.cs.hals.available_hals()))
        parser_halfuncs.set_defaults(func=self.list_hal_functions)

        parser.parse_args(self.argv, namespace=HALsCommand)

    def hals_list(self) -> None:
        self.logger.log("[CHIPSEC] List of HALs:")
        self.logger.log_heading(', '.join(sorted(self.cs.hals.available_hals())))

    def list_hal_functions(self) -> None:
        self.logger.log(f'[CHIPSEC] List of functions in {self.hal_name}:')
        hal = self.cs.hals.find_best_hal_by_name(self.hal_name)
        hal_class = getattr(hal['mod'], self.hal_name)
        hal_class_elements = dir(hal_class)
        hal_functions = []
        for element in hal_class_elements:
            if element.startswith('_'):
                continue
            if type(getattr(hal_class, element)) is function:
                hal_functions.append(element)
        self.logger.log_heading(', '.join(hal_functions))
            



commands = {'hals': HALsCommand}
