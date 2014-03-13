#!/usr/local/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2014, Intel Corporation
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
#Contact information:
#chipsec@intel.com
#




#
# usage as a standalone utility:
#
## \addtogroup standalone chipsec util
#  Chipsec Standalone utility\n
#
# chipsec_util platform
# -----------------------------
# ~~~
# chipsec_util platform 
# ~~~
#
#
#
#

__version__ = '1.0'

import os
import sys
import time

import chipsec_util
#from chipsec_util import global_usage, chipsec_util_commands, _cs
from chipsec_util import chipsec_util_commands, _cs

from chipsec.logger     import *
from chipsec.file       import *

from chipsec.chipset    import UnknownChipsetError, print_supported_chipsets
#_cs = cs()

usage = "chipsec_util platform\n\n"

chipsec_util.global_usage += usage


# ###################################################################
#
# Chipset/CPU Detection
#
# ###################################################################
def platform(argv):

    try:
        print_supported_chipsets()
        logger().log("")
        _cs.print_chipset()
    except UnknownChipsetError, msg:
        logger().error( msg )

chipsec_util_commands['platform'] = {'func' : platform, 'start_driver' : True  }

