#!/usr/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2018, Jason Meltzer <jmeltzer@strangeresearch.com>
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
#Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
#02110-1301, USA.
#

"""
Intel DFx Abstraction Layer (DAL) / In-Target Probe  (ITP) Helper
"""

import struct
import sys, os
import time
from ctypes import *

DAL_DIR = r"c:\Intel\DAL"   # default location
if "DALINSTALLDIR" in os.environ:
    DAL_DIR = os.environ["DALINSTALLDIR"]
if DAL_DIR not in sys.path:
   sys.path.append(DAL_DIR)
import itpii

from chipsec import defines
from chipsec.helper.oshelper import Helper, OsHelperError, HWAccessViolationError, UnimplementedAPIError, UnimplementedNativeAPIError, get_tools_path
from chipsec.logger import logger, print_buffer
import chipsec.file


class PCI_BDF(Structure):
    _fields_ = [("BUS",  c_ushort, 16),  # Bus
                ("DEV",  c_ushort, 16),  # Device
                ("FUNC", c_ushort, 16),  # Function
                ("OFF",  c_ushort, 16)]  # Offset

    def cfg_address(self):
        addr = (self.BUS << 16) | (self.DEV << 11) | (self.FUNC << 8) | (self.OFF & 0xFC) | 0x80000000
        return addr

class DALHelperError(RuntimeError):
    pass

class DALHelper(Helper):
 
    def __init__(self):
        super(DALHelper, self).__init__()
        self.os_system  = "Intel DAL/ITP"
        self.os_release = "0.0"
        self.os_version = "0.0"
        self.os_machine = "dal"
        self.os_uname = "Intel DAL/ITP"
  
    def __del__(self):
        try:
            destroy()
        except NameError:
            pass

######################################################################
# Driver/service management functions
######################################################################

    def create( self, start_driver ):
        if logger().VERBOSE:
            logger().log("[helper] DAL Helper created")
        return True

    def start( self, start_driver, silly):
	self.base = itpii.baseaccess()
        self.driver_loaded = True
        # Put all the threads in probe mode
        if self.base.cv.isrunning:
            self.base.halt()
            time.sleep(1)

        if logger().VERBOSE:
            logger().log("[helper] DAL Helper started/loaded")
        return True

    def stop( self, start_driver=True ):
        self.base.go()
        self.driver_loaded = False
        if logger().VERBOSE:
            logger().log("[helper] DAL Helper stopped/unloaded")
        return True

    def delete( self, start_driver=True ):
        if logger().VERBOSE:
            logger().log("[helper] DAL Helper deleted")
        return True

    def destroy( self ):
        self.stop()
        self.delete()
        return True

############################################################
# Functions to get information about the attached target
############################################################


    def target_machine( self ):
        return self.base.threads[0].devicetype + "-" + self.base.threads[0].stepping

############################################################
# API functions to access HW resources of the remote target
############################################################

    def read_physical_mem( self, phys_address, length, thread_id=0 ):
        struct_format = {1: 'B', 2: 'H', 4: 'I', 8:'Q'}
        ret = ''
        addr = itpii.Address((phys_address), itpii.AddressType.physical)
        mem_array = self.base.threads[thread_id].memblock(addr, length, 0)
        if length in struct_format:
            ret = struct.pack(struct_format[length], mem_array)
        else:
            for i in list(mem_array.Data):
                ret += struct.pack( 'I', i )
        return ret

    # Callers expect to be returned a string representation of the memory read
    
    def read_phys_mem( self, phys_address_hi, phys_address_lo, length ) :
        return self.read_physical_mem((phys_address_hi << 32) | phys_address_lo, length)

    
    def write_physical_mem( self, phys_address, length, buf, thread_id=0 ):
        struct_format = {1: 'B', 2: 'H', 4: 'I', 8:'Q'}
        width = 8
        ptr = 0
        while width >= 1 :
            while (length - ptr) >= width :
                val = struct.unpack_from(struct_format[width], buf, ptr)
                addr = itpii.Address((phys_address + ptr),itpii.AddressType.physical)
                #print "Writing", width, "bytes (", hex(v[0]), ") to", hex(phys_address + ptr)
                self.base.threads[thread_id].mem(addr, width, val[0])
                ptr += width
            width = width / 2
        return

    def write_phys_mem( self, phys_address_hi, phys_address_lo, length, buf ) :
        self.write_physical_mem((phys_address_hi << 32) | phys_address_lo, length, buf)
        return

    def read_msr( self, thread_id, msr_addr ):
        val = self.base.threads[thread_id].msr( msr_addr )
        edx = ( val.ToUInt64() >> 32 )
        eax = val.ToUInt64() & 0xffffffff
        return ( eax, edx )

    def write_msr( self, thread_id, msr_addr, eax, edx ):
        val = ( edx << 32 ) | eax
        self.base.threads[thread_id].msr( msr_addr, val )
        return

    def read_io_port( self, io_port, size ):
        if size == 1 :
            val = self.base.threads[0].port(io_port)
        elif size == 2 :
            val = self.base.threads[0].wport(io_port)
        elif size == 4 :
            val = self.base.threads[0].dport(io_port)
        else :
            raise DALHelperError(size, "is not a valid IO port size.")
        return val.ToUInt32()

    def write_io_port( self, io_port, value, size ):
        if size == 1 :
            self.base.threads[0].port(io_port, value)
        elif size == 2 :
            self.base.threads[0].wport(io_port, value)
        elif size == 4 :
            self.base.threads[0].dport(io_port, value)
        else :
            raise DALHelperError(size, "is not a valid IO port size.")
        return

    def read_pci_reg( self, bus, device, function, offset, size=4 ):
        if (bus >= 256) or (device >= 32) or (function >= 8) or (offset >= 256):
            logger().log("[WARNING] PCI register access out of range. Access through MMIO via PCIEXBAR instead.")
        value = 0xFFFFFFFF
        bdf = PCI_BDF( bus&0xFFFF, device&0xFFFF, function&0xFFFF, offset&0xFFFF )
        cfg_addr = bdf.cfg_address()
        byte_off = offset & 0x03
        self.write_io_port(0xCF8, cfg_addr, 4)
        value = self.read_io_port(0xCFC + byte_off, size)
        return value

    def write_pci_reg( self, bus, device, function, offset, value, size=4 ):
        if (bus >= 256) or (device >= 32) or (function >= 8) or (offset >= 256):
            logger().log("[WARNING] PCI register access out of range. Access through MMIO via PCIEXBAR instead.")
        bdf = PCI_BDF( bus&0xFFFF, device&0xFFFF, function&0xFFFF, offset&0xFFFF )
        cfg_addr = bdf.cfg_address()
        byte_off = offset & 0x03
        self.write_io_port(0xCF8, cfg_addr, 4)
        self.write_io_port(0xCFC + byte_off, value, size)
        return True

    def read_mmio_reg(self, phys_address, size):
        struct_format = {1: 'B', 2: 'H', 4: 'I', 8:'Q'}
        out_buf = self.read_physical_mem( phys_address, size )
        if size in [ 1, 2, 4, 8]:
            value = struct.unpack( struct_format[size], out_buf[:size] )[0]
        else: value = 0
        return value

    def write_mmio_reg(self, phys_address, size, value):
        self.write_physical_mem( phys_address, size, value )

    def get_threads_count( self ):
        return len( self.base.threads )

    def cpuid( self, eax, ecx ):
        ret_eax = self.base.threads[0].cpuid_eax( eax, ecx )
        ret_ebx = self.base.threads[0].cpuid_ebx( eax, ecx )
        ret_ecx = self.base.threads[0].cpuid_ecx( eax, ecx )
        ret_edx = self.base.threads[0].cpuid_edx( eax, ecx )
        return ret_eax, ret_ebx, ret_ecx, ret_edx

    def EFI_supported( self ):
        return False
    
#    def read_cr(self, cpu_thread_id, cr_number):

#    def write_cr(self, cpu_thread_id, cr_number):

#
# Get an instance of this helper
#
    def get_helper():
        return DALHelper()
