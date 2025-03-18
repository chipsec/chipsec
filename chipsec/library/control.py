# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2024, Intel Corporation
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

from chipsec.library.logger import logger
from chipsec.library.register import ObjList
from typing import Any


class Control:

    def __init__(self, cs) -> None:
        self.cs = cs

    def get_list_by_name(self, control_name: str):
        """Gets list of control objects (by name)"""
        controls = ObjList()
        if control_name in self.cs.Cfg.CONTROLS.keys():
            controls.extend(self.cs.Cfg.CONTROLS[control_name])
        return controls
    
    def get_instance_by_name(self, control_name: str, instance: Any):
        if control_name in self.cs.Cfg.CONTROLS.keys():
            for ctrl in self.cs.Cfg.CONTROLS[control_name]:
                if instance == ctrl.instance:
                    return ctrl
        return None

    def get_def(self, control_name: str):
        """Gets control definition (by name)"""
        return self.cs.Cfg.CONTROLS[control_name]

    def is_defined(self, control_name: str) -> bool:
        """Returns True if control_name Control is defined."""
        return True if control_name in self.cs.Cfg.CONTROLS else False

