# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2016, Google
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
if 'darwin' == platform.system().lower():
    __all__ = [ "helper" ]
else:
    __all__ = [ ]
