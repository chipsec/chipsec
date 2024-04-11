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
Abstracts support for various OS/environments, wrapper around platform specific code that invokes kernel driver
"""

import os
import errno
import importlib
import platform
import traceback
import sys
from typing import Tuple, List, Dict, Optional, AnyStr, Any, TYPE_CHECKING
if TYPE_CHECKING:
    from chipsec.library.types import EfiVariableType
from chipsec.library.file import get_main_dir, TOOLS_DIR
from chipsec.library.logger import logger
from chipsec.helper.basehelper import Helper
from chipsec.helper.nonehelper import NoneHelper
from chipsec.library.exceptions import OsHelperError


def get_tools_path() -> str:
    return os.path.normpath(os.path.join(get_main_dir(), TOOLS_DIR))


# OS Helper
#
# Abstracts support for various OS/environments, wrapper around platform specific code that invokes kernel driver


class OsHelper:
    def __init__(self):
        self.avail_helpers = {}
        self.load_helpers()
        self.filecmds = None
        self.helper = self.get_default_helper()
        if (not self.helper):
            os_system = platform.system()
            raise OsHelperError("Could not load any helpers for '{}' environment (unsupported environment?)".format(os_system), errno.ENODEV)
        else:
            if sys.version[0] == "2":
                logger().log_warning("*****************************************************************************")
                logger().log_warning("* !! Python 2 is deprecated and not supported. Please update to Python 3 !! *")
                logger().log_warning("* !!                           Exiting CHIPSEC                           !! *")
                logger().log_warning("*****************************************************************************")
                sys.exit(0)
            self.os_system = self.helper.os_system
            self.os_release = self.helper.os_release
            self.os_version = self.helper.os_version
            self.os_machine = self.helper.os_machine

    def load_helpers(self) -> None:
        helper_dir = os.path.join(get_main_dir(), "chipsec", "helper")
        helpers = [os.path.basename(f) for f in os.listdir(helper_dir)
                    if os.path.isdir(os.path.join(helper_dir, f)) and not os.path.basename(f).startswith("__")]

        for helper in helpers:
            helper_path = ''
            try:
                helper_path = f'chipsec.helper.{helper}.{helper}helper'
                hlpr = importlib.import_module(helper_path)
                self.avail_helpers[f'{helper}helper'] = hlpr
            except ImportError as msg:
                logger().log_debug(f"Unable to load helper: {helper}")

    def get_helper(self, name: str) -> Any:
        ret = None
        if name in self.avail_helpers:
            ret = self.avail_helpers[name].get_helper()
        return ret
    
    def get_available_helpers(self) -> List[str]:
        return sorted(self.avail_helpers.keys())

    def get_base_helper(self):
        return NoneHelper()
    
    def get_default_helper(self):
        ret = None
        if self.is_linux():
            ret = self.get_helper("linuxhelper")
        elif self.is_windows():
            ret = self.get_helper("windowshelper")
        elif self.is_efi():
            ret = self.get_helper("efihelper")
        elif self.is_dal():
            ret = self.get_helper("dalhelper")
        if ret is None:
            ret = self.get_base_helper()
        return ret

 

    def is_dal(self) -> bool:
        return 'itpii' in sys.modules

    def is_efi(self) -> bool:
        return platform.system().lower().startswith('efi') or platform.system().lower().startswith('uefi')

    def is_linux(self) -> bool:
        return 'linux' == platform.system().lower()

    def is_windows(self) -> bool:
        return 'windows' == platform.system().lower()

    def is_win8_or_greater(self) -> bool:
        win8_or_greater = self.is_windows() and (self.os_release.startswith('8') or ('2008Server' in self.os_release) or ('2012Server' in self.os_release))
        return win8_or_greater

    def is_macos(self) -> bool:
        return 'darwin' == platform.system().lower()
    
    def getcwd(self) -> str:
        return os.getcwd()


   


_helper = None


def helper():
    global _helper
    if _helper is None:
        try:
            _helper = OsHelper()
        except BaseException as msg:
            if logger().DEBUG:
                logger().log_error(str(msg))
                logger().log_bad(traceback.format_exc())
            raise
    return _helper
