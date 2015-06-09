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
Microcode update specific functionality (for each CPU thread)

usage:
    >>> ucode_update_id( 0 )
    >>> load_ucode_update( 0, ucode_buf )
    >>> update_ucode_all_cpus( 'ucode.pdb' )
    >>> dump_ucode_update_header( 'ucode.pdb' )
"""

__version__ = '1.0'

import struct
import sys

from chipsec.logger import *
from chipsec.hal.physmem import *
from chipsec.hal.msr import *
from chipsec.file import *

IA32_MSR_BIOS_UPDT_TRIG      = 0x79
IA32_MSR_BIOS_SIGN_ID        = 0x8B
IA32_MSR_BIOS_SIGN_ID_STATUS = 0x1


from collections import namedtuple
class UcodeUpdateHeader( namedtuple('UcodeUpdateHeader', 'header_version update_revision date processor_signature checksum loader_revision processor_flags data_size total_size reserved1 reserved2 reserved3') ):
    __slots__ = ()
    def __str__(self):
        return """
Microcode Update Header
--------------------------------
Header Version      : 0x%08X
Update Revision     : 0x%08X
Date                : 0x%08X
Processor Signature : 0x%08X
Checksum            : 0x%08X
Loader Revision     : 0x%08X
Processor Flags     : 0x%08X
Update Data Size    : 0x%08X
Total Size          : 0x%08X
Reserved1           : 0x%08X
Reserved2           : 0x%08X
Reserved3           : 0x%08X
""" % ( self.header_version, self.update_revision, self.date, self.processor_signature, self.checksum, self.loader_revision, self.processor_flags, self.data_size, self.total_size, self.reserved1, self.reserved2, self.reserved3 )

UCODE_HEADER_SIZE = 0x30
def dump_ucode_update_header( pdb_ucode_buffer ):
    ucode_header = UcodeUpdateHeader( *struct.unpack_from( '12I', pdb_ucode_buffer ) )
    print ucode_header
    return ucode_header

def read_ucode_file( ucode_filename ):
    ucode_buf = read_file( ucode_filename )
    if (ucode_filename.endswith('.pdb')):
        if logger().VERBOSE:
            logger().log( "[ucode] PDB file '%.256s' has ucode update header (size = 0x%X)" % (ucode_filename, UCODE_HEADER_SIZE) )
        dump_ucode_update_header( ucode_buf )
        return ucode_buf[UCODE_HEADER_SIZE:]
    else:
        return ucode_buf


class Ucode:
    def __init__( self, cs ):
        self.helper = cs.helper
        self.cs = cs

    # @TODO remove later/replace with msr.get_cpu_thread_count()
    def get_cpu_thread_count( self ):
        (core_thread_count, dummy) = self.helper.read_msr( 0, Cfg.IA32_MSR_CORE_THREAD_COUNT )
        return (core_thread_count & Cfg.IA32_MSR_CORE_THREAD_COUNT_THREADCOUNT_MASK)

    def ucode_update_id(self, cpu_thread_id):
        #self.helper.write_msr( cpu_thread_id, IA32_MSR_BIOS_SIGN_ID, 0, 0 )
        #self.helper.cpuid( cpu_thread_id, 0 )
        (bios_sign_id_lo, bios_sign_id_hi) = self.helper.read_msr( cpu_thread_id, IA32_MSR_BIOS_SIGN_ID )
        ucode_update_id = bios_sign_id_hi

        if (bios_sign_id_lo & IA32_MSR_BIOS_SIGN_ID_STATUS):
            if logger().VERBOSE: logger().log( "[ucode] CPU%d: last Microcode update failed (current microcode id = 0x%08X)" % (cpu_thread_id, ucode_update_id) )
        else:
            if logger().VERBOSE: logger().log( "[ucode] CPU%d: Microcode update ID = 0x%08X" % (cpu_thread_id, ucode_update_id) )

        return ucode_update_id

    def update_ucode_all_cpus(self, ucode_file ):
        if not ( os.path.exists(ucode_file) and os.path.isfile(ucode_file) ):
            logger().error( "Ucode file not found: '%.256s'" % ucode_file )
            return False
        ucode_buf = read_ucode_file( ucode_file )
        if (ucode_buf is not None) and (len(ucode_buf) > 0):
            for tid in range(self.get_cpu_thread_count()):
                self.load_ucode_update( tid, ucode_buf )
        return True

    def update_ucode(self, cpu_thread_id, ucode_file ):
        if not ( os.path.exists(ucode_file) and os.path.isfile(ucode_file) ):
            logger().error( "Ucode file not found: '%.256s'" % ucode_file )
            return False
        _ucode_buf = read_ucode_file( ucode_file )
        return self.load_ucode_update( cpu_thread_id, _ucode_buf )

    def load_ucode_update(self, cpu_thread_id, ucode_buf ):
        if logger().HAL: logger().log( "[ucode] loading microcode update on CPU%d" % cpu_thread_id )
        self.helper.load_ucode_update( cpu_thread_id, ucode_buf )
        return self.ucode_update_id( cpu_thread_id )
