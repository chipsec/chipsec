#!/usr/local/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2015, Intel Corporation
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



# -------------------------------------------------------------------------------
#
# CHIPSEC: Platform Hardware Security Assessment Framework
# (c) 2010-2012 Intel Corporation
#
# -------------------------------------------------------------------------------

"""
Access to CR registers

usage:
    >>> read_cr( 0 )
    >>> write_cr( 4, 0 )
"""

__version__ = '1.0'

import struct
import sys
import os.path

from chipsec.logger import logger

class CrRegs:

    def __init__( self, cs ):
        self.helper = cs.helper
        self.cs = cs

    def read_cr(self, cpu_thread_id, cr_number ):
        value = self.helper.read_cr( cpu_thread_id, cr_number )
        if logger().VERBOSE: logger().log( "[cr] IN CPU: %d 0x%04X: value = 0x%08X" % (cpu_thread_id, cr_number, value) )
        return value

    def write_cr(self, cpu_thread_id, cr_number, value ):
        if logger().VERBOSE: logger().log( "[cr] OUT CPU: %d 0x%04X: value = 0x%08X" % (cpu_thread_id, cr_number, value) )
        status = self.helper.write_cr( cpu_thread_id, cr_number, value )
        return status
