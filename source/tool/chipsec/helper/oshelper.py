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
Abstracts support for various OS/environments, wrapper around platform specific code that invokes kernel driver
"""

import os
import fnmatch
import re
import errno
import shutil

import chipsec.file
from chipsec.logger import *
import traceback

_importlib = True
try:
    import importlib

except ImportError:
    _importlib = False


ZIP_HELPER_RE = re.compile("^chipsec\/helper\/\w+\/\w+\.pyc$", re.IGNORECASE)
def f_mod_zip(x):
    return ( x.find('__init__') == -1 and ZIP_HELPER_RE.match(x) )
def map_modname_zip(x):
    return (x.rpartition('.')[0]).replace('/','.')

class OsHelperError (RuntimeError):
    def __init__(self,msg,errorcode):
        super(OsHelperError,self).__init__(msg)
        self.errorcode = errorcode

class HWAccessViolationError (OsHelperError):
    pass

# Base class for the helpers
class Helper(object):
    class __metaclass__(type):
        def __init__(cls, name, bases, attrs):
            if not hasattr(cls, 'registry'):
                cls.registry = []
            else:
                cls.registry.append((name, cls))

    def __init__(self):
        self.driver_loaded = False

import chipsec.helper.helpers

## OS Helper
#
# Abstracts support for various OS/environments, wrapper around platform specific code that invokes kernel driver
class OsHelper:
    def __init__(self):
        self.helper = None
        self.loadHelpers()
        #print "Operating System: %s %s %s %s" % (self.os_system, self.os_release, self.os_version, self.os_machine)
        #print self.os_uname
        if(not self.helper):
            import platform
            os_system  = platform.system()
            #raise OsHelperError("Unsupported platform '%s'" % os_system,errno.ENODEV)
            raise OsHelperError( "Could not load helper for '%s' environment (unsupported environment?)" % os_system, errno.ENODEV )
        else:
            self.os_system  = self.helper.os_system
            self.os_release = self.helper.os_release
            self.os_version = self.helper.os_version
            self.os_machine = self.helper.os_machine

    def loadHelpers(self):
        for name, cls in Helper.registry:
            try:
                self.helper = cls()
                break
            except OsHelperError:
                raise
            except:
                pass

    def __del__(self):
        try:
            destroy()
        except NameError:
            pass

    def start(self, start_driver):
        try:
            self.helper.create(start_driver)
            self.helper.start(start_driver)
        except (None,Exception) , msg:
            if logger().VERBOSE: logger().log_bad(traceback.format_exc())
            error_no = errno.ENXIO
            if hasattr(msg,'errorcode'):
                error_no = msg.errorcode
            raise OsHelperError("Could not start the OS Helper, are you running as Admin/root?\n           Message: \"%s\"" % msg,error_no)

    def stop( self ):
        self.helper.stop()

    def destroy( self ):
        self.helper.delete()

    def is_driver_loaded(self):
        return self.helper.driver_loaded

    def is_efi( self ):
        return self.os_system.lower().startswith('efi')
    def is_linux( self ):
        return ('linux' == self.os_system.lower())
    def is_windows( self ):
        return ('windows' == self.os_system.lower())
    def is_win8_or_greater( self ):
        win8_or_greater = self.is_windows() and ( self.os_release.startswith('8') or ('2008Server' in self.os_release) or ('2012Server' in self.os_release) )
        return win8_or_greater


    #################################################################################################
    # Actual OS helper functionality accessible to HAL components

    #
    # Read/Write PCI configuration registers via legacy CF8/CFC ports
    #
    def read_pci_reg( self, bus, device, function, address, size ):
        """Read PCI configuration registers via legacy CF8/CFC ports"""
        if ( 0 != (address & (size - 1)) ):
            logger().warn( "Config register address is not naturally aligned" )
        return self.helper.read_pci_reg( bus, device, function, address, size )

    def write_pci_reg( self, bus, device, function, address, value, size ):
        """Write PCI configuration registers via legacy CF8/CFC ports"""
        if ( 0 != (address & (size - 1)) ):
            logger().warn( "Config register address is not naturally aligned" )
        return self.helper.write_pci_reg( bus, device, function, address, value, size )

    #
    # physical_address_hi/physical_address_lo are 32 bit integers
    #
    def read_phys_mem( self, phys_address_hi, phys_address_lo, length ):
        return self.helper.read_phys_mem( phys_address_hi, phys_address_lo, length )
    def write_phys_mem( self, phys_address_hi, phys_address_lo, length, buf ):
        return self.helper.write_phys_mem( phys_address_hi, phys_address_lo, length, buf )
    def alloc_phys_mem( self, length, max_pa_hi, max_pa_lo ):
        return self.helper.alloc_phys_mem( length, (max_pa_hi<<32|max_pa_lo) )
    def va2pa( self, va ):
        return self.helper.va2pa( va )
    def map_io_space(self, physical_address, length, cache_type):
        return self.helper.map_io_space(physical_address, length, cache_type)
    def free_physical_mem(self, physical_address):
        return self.helper.free_phys_mem(physical_address)

    #
    # read/write mmio
    #
    def read_mmio_reg( self, phys_address, size ):
        return self.helper.read_mmio_reg( phys_address, size )
        
    def write_mmio_reg( self, phys_address, size, value ):
        return self.helper.write_mmio_reg( phys_address, size, value )
        
    #
    # physical_address is 64 bit integer
    #
    def read_physical_mem( self, phys_address, length ):
        return self.helper.read_phys_mem( (phys_address>>32)&0xFFFFFFFF, phys_address&0xFFFFFFFF, length )

    def write_physical_mem( self, phys_address, length, buf ):
        return self.helper.write_phys_mem( (phys_address>>32)&0xFFFFFFFF, phys_address&0xFFFFFFFF, length, buf )

    def alloc_physical_mem( self, length, max_phys_address ):
        return self.helper.alloc_phys_mem( length, max_phys_address )

    #
    # Read/Write I/O port
    #
    def read_io_port( self, io_port, size ):
        return self.helper.read_io_port( io_port, size )

    def write_io_port( self, io_port, value, size ):
        return self.helper.write_io_port( io_port, value, size )

    #
    # Read/Write CR registers
    #
    def read_cr(self, cpu_thread_id, cr_number):
        return self.helper.read_cr( cpu_thread_id, cr_number )

    def write_cr(self, cpu_thread_id, cr_number, value):
        return self.helper.write_cr( cpu_thread_id, cr_number, value )

    #
    # Read/Write MSR on a specific CPU thread
    #
    def read_msr( self, cpu_thread_id, msr_addr ):
        return self.helper.read_msr( cpu_thread_id, msr_addr )

    def write_msr( self, cpu_thread_id, msr_addr, eax, edx ):
        return self.helper.write_msr( cpu_thread_id, msr_addr, eax, edx )

    #
    # Load CPU microcode update on a specific CPU thread
    #
    def load_ucode_update( self, cpu_thread_id, ucode_update_buf ):
        return self.helper.load_ucode_update( cpu_thread_id, ucode_update_buf )

    #
    # Read IDTR/GDTR/LDTR on a specific CPU thread
    #
    def get_descriptor_table( self, cpu_thread_id, desc_table_code ):
        return self.helper.get_descriptor_table( cpu_thread_id, desc_table_code )

    #
    # EFI Variable API
    #
    def EFI_supported(self):
        return self.helper.EFI_supported()

    def get_EFI_variable( self, name, guid ):
        return self.helper.get_EFI_variable( name, guid )

    def set_EFI_variable( self, name, guid, data, datasize=None, attrs=None ):
        return self.helper.set_EFI_variable( name, guid, data, datasize, attrs )

    def delete_EFI_variable( self, name, guid ):
        return self.helper.delete_EFI_variable( name, guid )

    def list_EFI_variables( self ):
        return self.helper.list_EFI_variables()
    
    #
    # ACPI
    #
    def get_ACPI_SDT(self):
        return self.helper.get_ACPI_SDT()
        
    def get_ACPI_table_list(self):
        return self.helper.get_ACPI_table_list()
    
    #
    # CPUID
    #
    def cpuid( self, eax, ecx ):
        return self.helper.cpuid( eax, ecx )
        
    #
    # IOSF Message Bus access
    #

    def msgbus_send_read_message( self, mcr, mcrx ):
        return self.helper.msgbus_send_read_message( mcr, mcrx )

    def msgbus_send_write_message( self, mcr, mcrx, mdr ):
        return self.helper.msgbus_send_write_message( mcr, mcrx, mdr )

    def msgbus_send_message( self, mcr, mcrx, mdr ):
        return self.helper.msgbus_send_message( mcr, mcrx, mdr )

    #
    # Affinity
    #
    def get_affinity( self ):
        return self.helper.get_affinity()
        
    def set_affinity( self, value ):
        return self.helper.set_affinity( value )
        
    #
    # Logical CPU count
    #
    def get_threads_count( self ):
        return self.helper.get_threads_count()

    #
    # Send SW SMI
    #
    def send_sw_smi( self, cpu_thread_id, SMI_code_data, _rax, _rbx, _rcx, _rdx, _rsi, _rdi ):
        return self.helper.send_sw_smi( cpu_thread_id, SMI_code_data, _rax, _rbx, _rcx, _rdx, _rsi, _rdi )

    #
    # Hypercall
    #
    def hypercall( self, rcx=0, rdx=0, r8=0, r9=0, r10=0, r11=0, rax=0, rbx=0, rdi=0, rsi=0, xmm_buffer=0 ):
        return self.helper.hypercall( rcx, rdx, r8, r9, r10, r11, rax, rbx, rdi, rsi, xmm_buffer )

    #
    # File system
    #
    def getcwd( self ):
        return self.helper.getcwd()

    #
    # Decompress binary with OS specific tools
    #
    def decompress_file( self, CompressedFileName, OutputFileName, CompressionType ):
        import subprocess
        if (CompressionType == 0): # not compressed
          shutil.copyfile(CompressedFileName, OutputFileName)
        else:
          exe = self.helper.get_compression_tool_path( CompressionType )
          if exe is None: return None 
          try:
            subprocess.call( '%s -d -o %s %s' % (exe,OutputFileName,CompressedFileName), stdout=open(os.devnull, 'wb') )
          except BaseException, msg:
            logger().error( str(msg) )
            if logger().DEBUG: logger().log_bad( traceback.format_exc() )
            return None

        return chipsec.file.read_file( OutputFileName )

    #
    # Compress binary with OS specific tools
    #
    def compress_file( self, FileName, OutputFileName, CompressionType ):
        import subprocess
        if (CompressionType == 0): # not compressed
          shutil.copyfile(FileName, OutputFileName)
        else:
          exe = self.helper.get_compression_tool_path( CompressionType )
          if exe is None: return None 
          try:
            subprocess.call( '%s -e -o %s %s' % (exe,OutputFileName,FileName), stdout=open(os.devnull, 'wb') )
          except BaseException, msg:
            logger().error( str(msg) )
            if logger().DEBUG: logger().log_bad( traceback.format_exc() )
            return None

        return chipsec.file.read_file( OutputFileName )

_helper = None

def helper():
    global _helper
    if _helper == None:
        try:
            _helper  = OsHelper()
        except BaseException, msg:
            logger().error( str(msg) )
            if logger().DEBUG: logger().log_bad(traceback.format_exc())
            raise
    return _helper
