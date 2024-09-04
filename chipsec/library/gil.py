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

import sysconfig
from typing import Optional


def gil_macro() -> Optional[int]:
    return sysconfig.get_config_vars().get("Py_GIL_DISABLED")


def gil_enabled() -> bool:
    return gil_macro() in [None, 0]


def gil_disabled() -> bool:
    return gil_macro() in [1]


def gil_status() -> str:
    return 'Enabled' if gil_enabled() else 'Disabled'
