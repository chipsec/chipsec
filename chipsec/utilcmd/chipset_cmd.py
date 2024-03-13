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
usage as a standalone utility:
    >>> chipsec_util platform
"""

from chipsec.command import BaseCommand, toLoad
from chipsec.library.exceptions import UnknownChipsetError

# ###################################################################
#
# Chipset/CPU Detection
#
# ###################################################################


class PlatformCommand(BaseCommand):
    """
    chipsec_util platform
    """

    def requirements(self) -> toLoad:
        return toLoad.All
    
    def parse_arguments(self) -> None:
        pass

    def run(self):
        try:
            self.cs.Cfg.print_supported_chipsets()
            self.logger.log("")
            self.cs.Cfg.print_platform_info()
            self.cs.Cfg.print_pch_info()
        except UnknownChipsetError as msg:
            self.logger.log_error(msg)


commands = {'platform': PlatformCommand}
