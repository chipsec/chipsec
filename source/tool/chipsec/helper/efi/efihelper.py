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




# -------------------------------------------------------------------------------
#
# CHIPSEC: Platform Hardware Security Assessment Framework
# (c) 2010-2012 Intel Corporation
#
# -------------------------------------------------------------------------------
## \addtogroup helpers
# __chipsec/helper/efi/efihelper.py__ -- On UEFI use the efi package functions
#
#
__version__ = '1.0'

import struct
import sys
try:
  import edk2        # for Python 2.7 on UEFI
except ImportError:
  import efi as edk2 # for Python 2.4 on EFI 1.10

from chipsec.logger import logger

class EfiHelperError (RuntimeError):
    pass

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


 def load_ucode_update( self, cpu_thread_id, ucode_update_buf ):
     logger().error( "[efi] load_ucode_update is not supported yet" )
     return 0


 def getcwd( self ):
     return os.getcwd()


def get_threads_count ( self ):
    logger().log_warning( "EFI helper hasn't implemented get_threads_count yet" )
    #print "OsHelper for %s does not support get_threads_count from OS API"%self.os_system.lower()
    return 0

def get_helper():
    return EfiHelper( )

