# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2016, Google
# Copyright (c) 2018-2019, Intel Corporation
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

import platform
from chipsec.helper.oshelper import avail_helpers
if 'darwin' == platform.system().lower():
    __all__ = [ "osxhelper" ]
    avail_helpers.append("osxhelper")
else:
    __all__ = [ ]
