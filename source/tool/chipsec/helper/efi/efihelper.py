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
# (c) 2010-2015 Intel Corporation
#
# -------------------------------------------------------------------------------

"""
On UEFI use the efi package functions
"""

__version__ = '1.0'

import struct
import sys
import uuid

try:
    import edk2        # for Python 2.7 on UEFI
except ImportError:
    import efi as edk2 # for Python 2.4 on EFI 1.10

from chipsec.logger import logger

class EfiHelperError (RuntimeError):
    pass

status_dict = { 0:"EFI_SUCCESS", 1:"EFI_LOAD_ERROR", 2:"EFI_INVALID_PARAMETER", 3:"EFI_UNSUPPORTED", 4:"EFI_BAD_BUFFER_SIZE", 5:"EFI_BUFFER_TOO_SMALL", 6:"EFI_NOT_READY", 7:"EFI_DEVICE_ERROR", 8:"EFI_WRITE_PROTECTED", 9:"EFI_OUT_OF_RESOURCES", 14:"EFI_NOT_FOUND", 26:"EFI_SECURITY_VIOLATION" }


class EfiHelper:

    def __init__(self):
        if sys.platform.startswith('EFI'):
            self.os_system = sys.platform
            self.os_release = "0.0"
            self.os_version = "0.0"
            self.os_machine = "i386"
        else:
            import platform
            self.os_system  = platform.system()
            self.os_release = platform.release()
            self.os_version = platform.version()
            self.os_machine = platform.machine()
            self.os_uname   = platform.uname()

    def __del__(self):
        try:
            destroy()
        except NameError:
            pass

###############################################################################################
# Driver/service management functions
###############################################################################################

    def create( self ):
        if logger().VERBOSE:
            logger().log("[helper] UEFI Helper created")

    def start( self ):
        if logger().VERBOSE:
            logger().log("[helper] UEFI Helper started/loaded")

    def stop( self ):
        if logger().VERBOSE:
            logger().log("[helper] UEFI Helper stopped/unloaded")

    def delete( self ):
        if logger().VERBOSE:
            logger().log("[helper] UEFI Helper deleted")

    def destroy( self ):
        self.stop()
        self.delete()

###############################################################################################
# Actual API functions to access HW resources
###############################################################################################

    def read_phys_mem( self, phys_address_hi, phys_address_lo, length ):
        if logger().VERBOSE:
            logger().log( '[efi] helper does not support 64b PA' )
        return self._read_phys_mem( phys_address_lo, length )
    
    def read_mmio_reg(self, phys_address, size):
        if logger().VERBOSE:
            logger().log( '[efi] helper does not support 64b PA' )
        out_buf = self._read_phys_mem( phys_address, size )
        if size == 4:
            value = struct.unpack( '=I', out_buf[:size] )[0]
        elif size == 2:
            value = struct.unpack( '=H', out_buf[:size] )[0]
        elif size == 1:
            value = struct.unpack( '=B', out_buf[:size] )[0]
        else: value = 0
        return value
        
# def _read_phys_mem( self, phys_address, length ):
#  out_buf = (c_char * length)()
#  s_buf = edk2.readmem( phys_address, length )
#  # warning: this is hackish...
#  for j in range(len(s_buf)):
#   out_buf[j] = list(s_buf)[j]
#  return out_buf
    def _read_phys_mem( self, phys_address, length ):
        return edk2.readmem( phys_address, length )

    def write_phys_mem( self, phys_address_hi, phys_address_lo, length, buf ):
        if logger().VERBOSE:
            logger().log( '[efi] helper does not support 64b PA' )
        return self._write_phys_mem( phys_address_lo, length, buf )

    def write_mmio_reg(self, phys_address, size, value):
        if logger().VERBOSE:
            logger().log( '[efi] helper does not support 64b PA' )
        return self._write_phys_mem( phys_address, size, value )
        
    def _write_phys_mem( self, phys_address, length, buf ):
        # temp hack
        if 4 == length:
            dword_value = struct.unpack( 'I', buf )[0]
            edk2.writemem_dword( phys_address, dword_value )
        else:
            edk2.writemem( phys_address, buf, length )

    def read_msr( self, cpu_thread_id, msr_addr ):
        (eax, edx) = edk2.rdmsr( msr_addr )
        eax = eax % 2**32
        edx = edx % 2**32
        return ( eax, edx )

    def write_msr( self, cpu_thread_id, msr_addr, eax, edx ):
        edk2.wrmsr( msr_addr, eax, edx )

    def read_pci_reg( self, bus, device, function, address, size ):
        if   (1 == size):
            return ( edk2.readpci( bus, device, function, address, size ) & 0xFF )
        elif (2 == size):
            return ( edk2.readpci( bus, device, function, address, size ) & 0xFFFF )
        else:
            return edk2.readpci( bus, device, function, address, size )

    def write_pci_reg( self, bus, device, function, address, value, size ):
        return edk2.writepci( bus, device, function, address, value, size )

    def read_io_port( self, io_port, size ):
        if   (1 == size):
            return ( edk2.readio( io_port, size ) & 0xFF )
        elif (2 == size):
            return ( edk2.readio( io_port, size ) & 0xFFFF )
        else:
            return edk2.readio( io_port, size )

    def write_io_port( self, io_port, value, size ):
        return edk2.writeio( io_port, size, value )

    def send_sw_smi( self, cpu_thread_id, SMI_code_data, _rax, _rbx, _rcx, _rdx, _rsi, _rdi ):
        return edk2.swsmi(SMI_code_data, _rax, _rbx, _rcx, _rdx, _rsi, _rdi)

    def read_cr(self, cpu_thread_id, cr_number):
        return 0

    def write_cr(self, cpu_thread_id, cr_number, value):
        return False

    def load_ucode_update( self, cpu_thread_id, ucode_update_buf ):
        logger().error( "[efi] load_ucode_update is not supported yet" )
        return 0

    def getcwd( self ):
        return os.getcwd()

    def EFI_supported( self ):
        return True

        

    def get_EFI_variable_full(self, name, guidstr):
        guid = uuid.UUID(guidstr)
        
        size = 100
        (Status, Attributes, newdata, DataSize) = edk2.GetVariable(unicode(name), guid.bytes, size)
        status_dict = { 0:"EFI_SUCCESS", 1:"EFI_LOAD_ERROR", 2:"EFI_INVALID_PARAMETER", 3:"EFI_UNSUPPORTED", 4:"EFI_BAD_BUFFER_SIZE", 5:"EFI_BUFFER_TOO_SMALL", 6:"EFI_NOT_READY", 7:"EFI_DEVICE_ERROR", 8:"EFI_WRITE_PROTECTED", 9:"EFI_OUT_OF_RESOURCES", 14:"EFI_NOT_FOUND", 26:"EFI_SECURITY_VIOLATION" }
        
        if Status == 5:
            size = DataSize+1
            (Status, Attributes, newdata, DataSize) = edk2.GetVariable(unicode(name), guid.bytes, size) 
        
        return (Status, newdata, Attributes)
        

    def get_EFI_variable(self, name, guidstr):
        (status, data, attrs) = self.get_EFI_variable_full(name, guidstr)
        return data
        
    def set_EFI_variable(self, name, guidstr, data, attrs=0x7):
        
        guid = uuid.UUID(guidstr)
        
        if not attrs: attrs = int(7)        
        if not data: 
            size = 0
            data = '\0'*4
        else: size = len(data)

        (Status, DataSize, guidbytes) = edk2.SetVariable(unicode(name),  guid.bytes, int(attrs), data, size)
        
        return Status
        
    def delete_EFI_variable(self, name, guid):
        return self.set_EFI_variable(name, guid, "")
    
    def list_EFI_variables(self):   
                
        off = 0
        buf = list()
        hdr = 0
        attr = 0
        variables = dict()

        status_dict = { 0:"EFI_SUCCESS", 1:"EFI_LOAD_ERROR", 2:"EFI_INVALID_PARAMETER", 3:"EFI_UNSUPPORTED", 4:"EFI_BAD_BUFFER_SIZE", 5:"EFI_BUFFER_TOO_SMALL", 6:"EFI_NOT_READY", 7:"EFI_DEVICE_ERROR", 8:"EFI_WRITE_PROTECTED", 9:"EFI_OUT_OF_RESOURCES", 14:"EFI_NOT_FOUND", 26:"EFI_SECURITY_VIOLATION" }
        
        name = '\0'*200
        
        randguid = uuid.uuid4()
        
        (status, name, size, guidbytes) = edk2.GetNextVariableName(200, unicode(name), randguid.bytes)     
        
        if status == 5:
            if logger().VERBOSE: logger().log("size was too small increasing to %d" % size)
            name = '\0'*size
            (status, name, size, guidbytes) = edk2.GetNextVariableName(size, unicode(name), randguid.bytes)

        
#        while status != 14:
        while status == 0:
            guid =  uuid.UUID(bytes=guidbytes)  
            name = name.encode('ascii','ignore')
            (status, data, attr) = self.get_EFI_variable_full(name, guid.hex)
            
            if logger().VERBOSE: logger().log("%d: Found variable %s" % (len(variables), name))

            var = (off, buf, hdr, data, guid, attr)
            if name in variables: 
                if logger().VERBOSE: logger().log("WARNING: found a second instance of name %s." % name)

            else: variables[name] = []
            if data != "" or guid != 0 or attr != 0:
                variables[name].append(var)

            (status, name, size, guidbytes) = edk2.GetNextVariableName(200, unicode(name), guid.bytes)
            if logger().VERBOSE: logger().log("returned %s. status is %s" % (name, status_dict[status]))

            if status == 5:
                if logger().VERBOSE: logger().log("size was too small increasing to %d" % size)
                (status, name, size, guidbytes) = edk2.GetNextVariableName(size, unicode(name), guid.bytes)
        return variables        
        
    def get_ACPI_SDT( self ):
        logger().error( "[efi] ACPI is not supported yet" )
        return 0        

    def get_threads_count ( self ):
        logger().log_warning( "EFI helper hasn't implemented get_threads_count yet" )
        #print "OsHelper for %s does not support get_threads_count from OS API"%self.os_system.lower()
        return 0
        
    def cpuid(self, eax, ecx):
        (reax, rebx, recx, redx)=edk2.cpuid(eax,ecx)
        return (reax, rebx, recx, redx)
    
    def alloc_phys_mem( length, max_pa ):
        logger().log_warning("EFI helper has not implemented alloc_phys_mem yet")
        return 0

    def get_descriptor_table( cpu_thread_id, desc_table_code ):
        logger().log_warning("EFI helper has not implemented get_descriptor_table yet")
        return 0

    def va2pa( self, va ):
        pa = va # UEFI shell has identity mapping
        if logger().VERBOSE: logger().log( "[helper] VA (0X%016x) -> PA (0X%016x)" % (va,pa) )
        return pa
        
def get_helper():
    return EfiHelper( )
