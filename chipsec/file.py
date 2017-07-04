#!/usr/bin/python
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



#
# -------------------------------------------------------------------------------
#
# CHIPSEC: Platform Hardware Security Assessment Framework
# (c) 2010-2012 Intel Corporation
#
# -------------------------------------------------------------------------------

"""
Reading from/writing to files

usage:
    >>> read_file( filename )
    >>> write_file( filename, buffer )
"""

import struct
import sys
import os

from chipsec.logger import logger

TOOLS_DIR = 'chipsec_tools'

def read_file( filename, size=0 ):
    #with open( filename, 'rb' ) as f:
    #  _file = f.read()
    #f.closed

    try:
        f = open(filename, 'rb')
    except:
        logger().error( "Unable to open file '%.256s' for read access" % filename )
        return 0

    if size:
        _file = f.read( size )
    else:
        _file = f.read()
    f.close()

    if logger().VERBOSE: logger().log( "[file] read %d bytes from '%.256s'" % ( len(_file), filename ) )
    return _file

def write_file( filename, buffer, append=False ):
    #with open( filename, 'wb' ) as f:
    #  f.write( buffer )
    #f.closed
    perm = 'ab' if append else 'wb'
    try:
        f = open(filename, perm)
    except:
        logger().error( "Unable to open file '%.256s' for write access" % filename )
        return 0
    f.write( buffer )
    f.close()

    if logger().VERBOSE: logger().log( "[file] wrote %d bytes to '%.256s'" % ( len(buffer), filename ) )
    return True


# determine if CHIPSEC is loaded as chipsec.exe or in python
def main_is_frozen():
    return (hasattr(sys, "frozen") or  # new py2exe
            hasattr(sys, "importers")) # old py2exe

def get_main_dir():
    path = os.path.abspath( os.path.join( os.path.dirname( __file__ ), os.path.pardir ) )
    if main_is_frozen():
        path = os.path.dirname(sys.executable)
    #elif len( os.path.dirname(sys.argv[0]) ) > 0:
    #    path = os.path.dirname(sys.argv[0])
    return  path
