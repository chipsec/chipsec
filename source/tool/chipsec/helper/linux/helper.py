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
Linux helper
"""

__version__ = '1.0'

import struct
import sys
import os
import fcntl
import platform
import ctypes
import fnmatch
from chipsec.helper.oshelper import OsHelperError
from chipsec.logger import logger, print_buffer
import errno
import array
import chipsec.file

from ctypes import *

_IOCTL_BASE = 0
def IOCTL_BASE():       return 0x0
def IOCTL_RDIO():       return _IOCTL_BASE + 0x1
def IOCTL_WRIO():       return _IOCTL_BASE + 0x2
def IOCTL_RDPCI():      return _IOCTL_BASE + 0x3
def IOCTL_WRPCI():      return _IOCTL_BASE + 0x4
def IOCTL_RDMSR():      return _IOCTL_BASE + 0x5
def IOCTL_WRMSR():      return _IOCTL_BASE + 0x6
def IOCTL_CPUID():      return _IOCTL_BASE + 0x7
def IOCTL_GET_CPU_DESCRIPTOR_TABLE():   return _IOCTL_BASE + 0x8
def IOCTL_HYPERCALL():  return _IOCTL_BASE + 0x9
def IOCTL_SWSMI():      return _IOCTL_BASE + 0xA
def IOCTL_LOAD_UCODE_PATCH():   return _IOCTL_BASE + 0xB
def IOCTL_ALLOC_PHYSMEM(): return _IOCTL_BASE + 0xC
def IOCTL_GET_EFIVAR(): return _IOCTL_BASE + 0xD
def IOCTL_SET_EFIVAR(): return _IOCTL_BASE + 0xE
def IOCTL_RDCR():	return _IOCTL_BASE + 0x10
def IOCTL_WRCR():	return _IOCTL_BASE + 0x11
def IOCTL_RDMMIO():       return _IOCTL_BASE + 0x12
def IOCTL_WRMMIO():       return _IOCTL_BASE + 0x13
def IOCTL_VA2PA():      return _IOCTL_BASE + 0x14

class LinuxHelper:

    def __init__(self):
        import platform
        self.os_system  = platform.system()
        self.os_release = platform.release()
        self.os_version = platform.version()
        self.os_machine = platform.machine()
        self.os_uname   = platform.uname()

        self.init()

    def __del__(self):
        try:
            destroy()
        except NameError:
            pass

###############################################################################################
# Driver/service management functions
###############################################################################################

    def create( self ):
        self.init()
        if logger().VERBOSE:
            logger().log("[helper] Linux Helper created")

    def start( self ):
        if logger().VERBOSE:
            logger().log("[helper] Linux Helper started/loaded")

    def stop( self ):
        if logger().VERBOSE:
            logger().log("[helper] Linux Helper stopped/unloaded")

    def delete( self ):
        if logger().VERBOSE:
            logger().log("[helper] Linux Helper deleted")

    def destroy( self ):
        self.stop()
        self.delete()

    def init( self ):
        x64 = True if sys.maxsize > 2**32 else False
        global DEVICE_NAME
        global _DEV_FH
        _DEV_FH = None

        #already initialized?
        if(_DEV_FH != None): return

        logger().log("\n****** Chipsec Linux Kernel module is licensed under GPL 2.0\n")
        DEVICE_NAME="/dev/chipsec"

        try:
            _DEV_FH = open(DEVICE_NAME, "r+")
        except IOError as e:
            raise OsHelperError("Unable to open chipsec device. %s"%str(e),e.errno)
        except BaseException as be:
            raise OsHelperError("Unable to open chipsec device. %s"%str(be),errno.ENXIO)

        #decode the arg size
        global _PACK
        _PACK = 'Q' if x64 else 'I'

        global _IOCTL_BASE
        _IOCTL_BASE = fcntl.ioctl(_DEV_FH, IOCTL_BASE()) << 4

        global CPU_MASK_LEN
        CPU_MASK_LEN = 8 if x64 else 4


    def close():
        global _DEV_FH
        close(_DEV_FH)
        _DEV_FH = None

###############################################################################################
# Actual API functions to access HW resources
###############################################################################################
    def __mem_block(self, sz, newval = None):
        if(newval == None):
            return _DEV_FH.read(sz)
        else:
            _DEV_FH.write(newval)
            _DEV_FH.flush()
        return 1

    def mem_read_block(self, addr, sz):
        if(addr != None): _DEV_FH.seek(addr)
        return self.__mem_block(sz)

    def mem_write_block(self, addr, sz, newval):
        if(addr != None): _DEV_FH.seek(addr)
        return self.__mem_block(sz, newval)

    def write_phys_mem(self, phys_address_hi, phys_address_lo, sz, newval):
        if(newval == None): return None
        return self.mem_write_block((phys_address_hi << 32) | phys_address_lo, sz, newval)

    def read_phys_mem(self, phys_address_hi, phys_address_lo, length):
        ret = self.mem_read_block((phys_address_hi << 32) | phys_address_lo, length)
        if(ret == None): return None
        return ret

    def va2pa( self, va ):
        error_code = 0

        in_buf = struct.pack( _PACK, va )
        out_buf = fcntl.ioctl( _DEV_FH, IOCTL_VA2PA(), in_buf )
        pa = struct.unpack( _PACK, out_buf )[0]

        #Check if PA > max physical address
        max_pa = self.cpuid( 0x80000008 , 0x0 )[0] & 0xFF
        if pa > 1<<max_pa:
            print "[helper] Error in va2pa: PA higher that max physical address: VA (0x%016X) -> PA (0x%016X)"% (va, pa) 
            error_code = 1
        return (pa,error_code)

    #DEPRECATED: Pass-through
    def read_pci( self, bus, device, function, address ):
        return self.read_pci_reg(bus, device, function, address)

    def read_pci_reg( self, bus, device, function, offset, size = 4 ):
        _PCI_DOM = 0 #Change PCI domain, if there is more than one.
        d = struct.pack("5"+_PACK, ((_PCI_DOM << 16) | bus), ((device << 16) | function), offset, size, 0)
        try:
            ret = fcntl.ioctl(_DEV_FH, IOCTL_RDPCI(), d)
        except IOError:
            print "IOError\n"
            return None
        x = struct.unpack("5"+_PACK, ret)
        return x[4]

    def write_pci_reg( self, bus, device, function, offset, value, size = 4 ):
        _PCI_DOM = 0 #Change PCI domain, if there is more than one.
        d = struct.pack("5"+_PACK, ((_PCI_DOM << 16) | bus), ((device << 16) | function), offset, size, value)
        try:
            ret = fcntl.ioctl(_DEV_FH, IOCTL_WRPCI(), d)
        except IOError:
            print "IOError\n"
            return None
        x = struct.unpack("5"+_PACK, ret)
        return x[4]

    def load_ucode_update( self, cpu_thread_id, ucode_update_buf):
        cpu_ucode_thread_id = ctypes.c_int(cpu_thread_id)

        in_buf = struct.pack('=BH', cpu_thread_id, len(ucode_update_buf)) + ucode_update_buf
        in_buf_final = array.array("c", in_buf)
        #print_buffer(in_buf)
        out_length=0
        out_buf=(c_char * out_length)()
        try:
            out_buf = fcntl.ioctl(_DEV_FH, IOCTL_LOAD_UCODE_PATCH(), in_buf_final, True)
        except IOError:
            print "IOError IOCTL Load Patch\n"
            return None

        return True


    def read_io_port(self, io_port, size):
        in_buf = struct.pack( "3"+_PACK, io_port, size, 0 )
        out_buf = fcntl.ioctl( _DEV_FH, IOCTL_RDIO(), in_buf )
        try:
            #print_buffer(out_buf)
            if 1 == size:
                value = struct.unpack("3"+_PACK, out_buf)[2] & 0xff
            elif 2 == size:
                value = struct.unpack("3"+_PACK, out_buf)[2] & 0xffff
            else:
                value = struct.unpack("3"+_PACK, out_buf)[2] & 0xffffffff
        except:
            logger().error( "DeviceIoControl did not return value of proper size %x (value = '%s')" % (size, out_buf) )

        return value

    def write_io_port( self, io_port, value, size ):
        in_buf = struct.pack( "3"+_PACK, io_port, size, value )
        return fcntl.ioctl( _DEV_FH, IOCTL_WRIO(), in_buf)

    def read_cr(self, cpu_thread_id, cr_number):
        self.set_affinity(cpu_thread_id)
        cr = 0
        in_buf = struct.pack( "3"+_PACK, cpu_thread_id, cr_number, cr)
        unbuf = struct.unpack("3"+_PACK, fcntl.ioctl( _DEV_FH, IOCTL_RDCR(), in_buf ))
        return (unbuf[2])

    def write_cr(self, cpu_thread_id, cr_number, value):
        self.set_affinity(cpu_thread_id)
        print "Writing CR 0x%x with value = 0x%x" % (cr_number, value)
        in_buf = struct.pack( "3"+_PACK, cpu_thread_id, cr_number, value )
        fcntl.ioctl( _DEV_FH, IOCTL_WRCR(), in_buf )
        return

    def read_msr(self, thread_id, msr_addr):
        self.set_affinity(thread_id)
        edx = eax = 0
        in_buf = struct.pack( "4"+_PACK, thread_id, msr_addr, edx, eax)
        unbuf = struct.unpack("4"+_PACK, fcntl.ioctl( _DEV_FH, IOCTL_RDMSR(), in_buf ))
        return (unbuf[3], unbuf[2])

    def write_msr(self, thread_id, msr_addr, eax, edx):
        self.set_affinity(thread_id)
        print "Writing msr 0x%x with eax = 0x%x, edx = 0x%x" % (msr_addr, eax, edx)
        in_buf = struct.pack( "4"+_PACK, thread_id, msr_addr, edx, eax )
        fcntl.ioctl( _DEV_FH, IOCTL_WRMSR(), in_buf )
        return

    def get_descriptor_table(self, cpu_thread_id, desc_table_code  ):
        self.set_affinity(cpu_thread_id)
        in_buf = struct.pack( "5"+_PACK, cpu_thread_id, desc_table_code, 0 , 0, 0)
        out_buf = fcntl.ioctl( _DEV_FH, IOCTL_GET_CPU_DESCRIPTOR_TABLE(), in_buf)
        (limit,base_hi,base_lo,pa_hi,pa_lo) = struct.unpack( "5"+_PACK, out_buf )
        pa = (pa_hi << 32) + pa_lo
        base = (base_hi << 32) + base_lo
        return (limit,base,pa)

    def do_hypercall(self, vector, arg1, arg2, arg3, arg4, arg5, use_peach):
        in_buf = struct.pack( "7"+_PACK, vector, arg1, arg2, arg3, arg4, arg5, use_peach)
        out_buf = fcntl.ioctl( _DEV_FH, IOCTL_HYPERCALL(), in_buf)
        regs = struct.unpack( "7"+_PACK, out_buf )
        return regs

    def cpuid(self, eax, ecx):
        # add ecx
        in_buf = struct.pack( "4"+_PACK, eax, 0, ecx, 0)
        out_buf = fcntl.ioctl( _DEV_FH, IOCTL_CPUID(), in_buf)
        return struct.unpack( "4"+_PACK, out_buf )

    def alloc_phys_mem(self, num_bytes, max_addr):
        in_buf = struct.pack( "2"+_PACK, num_bytes, max_addr)
        out_buf = fcntl.ioctl( _DEV_FH, IOCTL_ALLOC_PHYSMEM(), in_buf)
        return struct.unpack( "2"+_PACK, out_buf )

    def read_mmio_reg(self, phys_address, size):
        in_buf = struct.pack( "2"+_PACK, phys_address, size)
        out_buf = fcntl.ioctl( _DEV_FH, IOCTL_RDMMIO(), in_buf)
        if size == 8:
            value = struct.unpack( '=Q', out_buf[:size] )[0]
        elif size == 4:
            value = struct.unpack( '=I', out_buf[:size] )[0]
        elif size == 2:
            value = struct.unpack( '=H', out_buf[:size] )[0]
        elif size == 1:
            value = struct.unpack( '=B', out_buf[:size] )[0]
        else: value = 0
        return value

    def write_mmio_reg(self, phys_address, size, value):
        in_buf = struct.pack( "3"+_PACK, phys_address, size, value )
        out_buf = fcntl.ioctl( _DEV_FH, IOCTL_WRMMIO(), in_buf )
        return
        
    def kern_get_EFI_variable_full(self, name, guid):
        status_dict = { 0:"EFI_SUCCESS", 1:"EFI_LOAD_ERROR", 2:"EFI_INVALID_PARAMETER", 3:"EFI_UNSUPPORTED", 4:"EFI_BAD_BUFFER_SIZE", 5:"EFI_BUFFER_TOO_SMALL", 6:"EFI_NOT_READY", 7:"EFI_DEVICE_ERROR", 8:"EFI_WRITE_PROTECTED", 9:"EFI_OUT_OF_RESOURCES", 14:"EFI_NOT_FOUND", 26:"EFI_SECURITY_VIOLATION" }
        off = 0
        data = ""
        attr = 0
        buf = list()
        hdr = 0
        base = 12
        namelen = len(name)
        header_size = 52
        data_size = header_size + namelen
        guid0 = int(guid[:8] , 16)
        guid1 = int(guid[9:13], 16)
        guid2 = int(guid[14:18], 16)
        guid3 = int(guid[19:21], 16)
        guid4 = int(guid[21:23], 16)
        guid5 = int(guid[24:26], 16)
        guid6 = int(guid[26:28], 16)
        guid7 = int(guid[28:30], 16)
        guid8 = int(guid[30:32], 16)
        guid9 = int(guid[32:34], 16)
        guid10 = int(guid[34:], 16)
        
        in_buf = struct.pack('13I'+str(namelen)+'s', data_size, guid0, guid1, guid2, guid3, guid4, guid5, guid6, guid7, guid8, guid9, guid10, namelen, name)
        buffer = array.array("c", in_buf)
        stat = fcntl.ioctl(_DEV_FH, IOCTL_GET_EFIVAR(), buffer, True)
        new_size, status = struct.unpack( "2I", buffer[:8])

        if (status == 0x5):
            data_size = new_size + header_size + namelen # size sent by driver + size of header (size + guid) + size of name
            in_buf = struct.pack('13I'+str(namelen+new_size)+'s', data_size, guid0, guid1, guid2, guid3, guid4, guid5, guid6, guid7, guid8, guid9, guid10, namelen, name)
            buffer = array.array("c", in_buf)
            try:
                stat = fcntl.ioctl(_DEV_FH, IOCTL_GET_EFIVAR(), buffer, True)
            except IOError:
                logger().error("IOError IOCTL GetUEFIvar\n")
                return (off, buf, hdr, None, guid, attr)                    
            new_size, status = struct.unpack( "2I", buffer[:8])
            
        if (new_size > data_size):
            logger().error( "Incorrect size returned from driver" )
            return (off, buf, hdr, None, guid, attr)
            
        if (status > 0):
            logger().error( "Reading variable (GET_EFIVAR) did not succeed: %s" % status_dict[status])
            data = ""
            guid = 0
            attr = 0
        else:
            data = buffer[base:base+new_size].tostring()
            attr = struct.unpack( "I", buffer[8:12])[0]
        return (off, buf, hdr, data, guid, attr)

        
    def kern_get_EFI_variable(self, name, guid):
        (off, buf, hdr, data, guid, attr) = self.kern_get_EFI_variable_full(name, guid)
        return data

    def kern_delete_EFI_variable(self, name, guid):
        return self.kern_set_EFI_variable(name, guid, "")
    
    def kern_list_EFI_variables(self, infcls):
        varlist = []
        off = 0
        buf = list()
        hdr = 0
        attr = 0
        try:
            if os.path.isdir('/sys/firmware/efi/efivars'):
                varlist = os.listdir('/sys/firmware/efi/efivars')
            elif os.path.isdir('/sys/firmware/efi/vars'):
                varlist = os.listdir('/sys/firmware/efi/vars')
            else:
                return None
        except Exception:
            logger().error('Failed to read /sys/firmware/efi/[vars|efivars]. Folder does not exist')
            return None
        variables = dict()
        for v in varlist:
            name = v[:-37]
            guid = v[len(name)+1:]
            if name and name is not None:
                variables[name] = []
                var = self.kern_get_EFI_variable_full(name, guid)
                (off, buf, hdr, data, guid, attr) = var
                variables[name].append(var)
        return variables
    
    def kern_set_EFI_variable(self, name, guid, value, attr=0x7):
        status_dict = { 0:"EFI_SUCCESS", 1:"EFI_LOAD_ERROR", 2:"EFI_INVALID_PARAMETER", 3:"EFI_UNSUPPORTED", 4:"EFI_BAD_BUFFER_SIZE", 5:"EFI_BUFFER_TOO_SMALL", 6:"EFI_NOT_READY", 7:"EFI_DEVICE_ERROR", 8:"EFI_WRITE_PROTECTED", 9:"EFI_OUT_OF_RESOURCES", 14:"EFI_NOT_FOUND", 26:"EFI_SECURITY_VIOLATION" }
        
        header_size = 60 # 4*15
        namelen = len(name)
        if value: datalen = len(value)
        else: 
            datalen = 0
            value = '\0'
        data_size = header_size + namelen + datalen
        guid0 = int(guid[:8] , 16)
        guid1 = int(guid[9:13], 16)
        guid2 = int(guid[14:18], 16)
        guid3 = int(guid[19:21], 16)
        guid4 = int(guid[21:23], 16)
        guid5 = int(guid[24:26], 16)
        guid6 = int(guid[26:28], 16)
        guid7 = int(guid[28:30], 16)
        guid8 = int(guid[30:32], 16)
        guid9 = int(guid[32:34], 16)
        guid10 = int(guid[34:], 16)
        
        in_buf = struct.pack('15I'+str(namelen)+'s'+str(datalen)+'s', data_size, guid0, guid1, guid2, guid3, guid4, guid5, guid6, guid7, guid8, guid9, guid10, attr, namelen, datalen, name, value)
        buffer = array.array("c", in_buf)        
        stat = fcntl.ioctl(_DEV_FH, IOCTL_SET_EFIVAR(), buffer, True)
        size, status = struct.unpack( "2I", buffer[:8])

        if (status != 0):
            logger().error( "Setting EFI (SET_EFIVAR) variable did not succeed: %s" % status_dict[status] )
        else:
            os.system('umount /sys/firmware/efi/efivars; mount -t efivarfs efivarfs /sys/firmware/efi/efivars')
        return status
        
    def get_ACPI_SDT( self ):
        logger().error( "ACPI is not supported yet" )
        return 0  
        
    def get_affinity(self):
        CORES = ctypes.cdll.LoadLibrary( os.path.join(chipsec.file.get_main_dir( ), 'chipsec/helper/linux/cores.so' ) )
        CORES.getaffinity.argtypes = [ ctypes.c_int, POINTER( ( ctypes.c_long * 128 ) ),POINTER( ctypes.c_int ) ]
        CORES.getaffinity.restype = ctypes.c_int
        mask = ( ctypes.c_long * 128 )( )
        try:
            numCpus = 0
            f = open('/proc/cpuinfo', 'r')
            for line in f:
                if "processor" in line:
                    numCpus += 1
            f.close()
        except:
            numCpus = 1;
            pass
        errno = ctypes.c_int( 0 )
        if 0 == CORES.getaffinity( numCpus,byref( mask ),byref( errno ) ):
            AffinityString = " GetAffinity: "
            for i in range( 0, numCpus ):
                if mask[i] == 1:
                    AffinityString += "%s " % i
            logger().log( AffinityString )
            return 1
        else:
            AffinityString = " Get_affinity errno::%s"%( errno.value )
            logger().log( AffinityString )
            return None

    def set_affinity(self, thread_id):
        CORES = ctypes.cdll.LoadLibrary(os.path.join(chipsec.file.get_main_dir(),'chipsec/helper/linux/cores.so'))
        CORES.setaffinity.argtypes=[ctypes.c_int,POINTER(ctypes.c_int)]
        CORES.setaffinity.restype=ctypes.c_int
        errno= ctypes.c_int(0)
        if 0 == CORES.setaffinity(ctypes.c_int(thread_id),byref(errno)) :
            return thread_id
        else:
            AffinityString= " Set_affinity errno::%s"%(errno.value)
            logger().log( AffinityString )
            return None

##############
    # UEFI Variable API
##############

    def use_efivars(self):
#        rel = platform.release()
#        ind = rel.find('.')
#        major = rel[:ind]
#        minor = rel[ind+1:rel.find('.', ind+1)]
#        return (int(major) >= 3) and (int(minor) >= 10)
        return os.path.exists("/sys/firmware/efi/efivars/")
 
    def use_kernvars(self):
        return True

    def EFI_supported( self):
        return os.path.exists("/sys/firmware/efi/vars/") or os.path.exists("/sys/firmware/efi/efivars/")

    #
    # Legacy /efi/vars methods
    #

    def VARS_get_efivar_from_sys( self, filename ):
        off = 0
        buf = list()
        hdr = 0
        try:
            f =open('/sys/firmware/efi/vars/'+filename+'/data', 'r')
            data = f.read()
            f.close()

            f = open('/sys/firmware/efi/vars/'+filename+'/guid', 'r')
            guid = (f.read()).strip()
            f.close()

            f = open('/sys/firmware/efi/vars/'+filename+'/attributes', 'r')
            attrstring = f.read()
            attr = 0
            if fnmatch.fnmatch(attrstring, '*NON_VOLATILE*'):
                attr |= EFI_VARIABLE_NON_VOLATILE
            if fnmatch.fnmatch(attrstring, '*BOOTSERVICE*'):
                attr |= EFI_VARIABLE_BOOTSERVICE_ACCESS
            if fnmatch.fnmatch(attrstring, '*RUNTIME*'):
                attr |= EFI_VARIABLE_RUNTIME_ACCESS
            if fnmatch.fnmatch(attrstring, '*ERROR*'):
                attr |= EFI_VARIABLE_HARDWARE_ERROR_RECORD
            if fnmatch.fnmatch(attrstring, 'EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS'):
                attr |= EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS
            if fnmatch.fnmatch(attrstring, '*TIME_BASED_AUTHENTICATED*'):
                attr |= EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS
            if fnmatch.fnmatch(attrstring, '*APPEND_WRITE*'):
                attr |= EFI_VARIABLE_APPEND_WRITE
            f.close()

        except Exception, err:
            logger().error('Failed to read files under /sys/firmware/efi/vars/'+filename)
            data = ""
            guid = 0
            attr = 0

        finally:
            return (off, buf, hdr, data, guid, attr)

    def VARS_list_EFI_variables ( self, infcls=2 ):
        varlist = []
        try:
            varlist = os.listdir('/sys/firmware/efi/vars')
        except Exception:
            logger().error('Failed to read /sys/firmware/efi/vars. Folder does not exist')
        variables = dict()
        for v in varlist:
            name = v[:-37]
            if name and name is not None:
                variables[name] = []
                var = self.VARS_get_efivar_from_sys(v)
                # did we get something real back?
                (off, buf, hdr, data, guid, attr) = var
                if data != "" or guid != 0 or attr != 0:
                    variables[name].append(var)
        return variables

    def VARS_get_EFI_variable( self, name, guid ):
        if not name:
            name = '*'
        if not guid:
            guid = '*'
        for var in os.listdir('/sys/firmware/efi/vars'):
            if fnmatch.fnmatch(var, '%s-%s' % (name,guid)):
                (off,buf,hdr,data,guid,attr) = self.VARS_get_efivar_from_sys(var)
                return data

    def VARS_set_EFI_variable(self,  name, guid, value ):
        ret = True
        if not name:
            name = '*'
        if not guid:
            guid = '*'
        for var in os.listdir('/sys/firmware/efi/vars'):
            if fnmatch.fnmatch(var, '%s-%s' % (name,guid)):
                try:
                    f = open('/sys/firmware/efi/vars/'+var+'/data', 'w')
                    f.write(value)
                except Exception, err:
                    logger().error('Failed to write EFI variable. %s' % err)
                    ret = False
                finally:
                    pass
        return ret



#
# New (kernel 3.10+) /efi/efivars methods
#
    def EFIVARS_get_efivar_from_sys( self, filename ):
        guid = filename[filename.find('-')+1:]
        off = 0
        buf = list()
        hdr = 0
        try:
            f = open('/sys/firmware/efi/efivars/'+filename, 'r')
            data = f.read()
            attr = struct.unpack_from("<I",data)[0]
            data = data[4:]
            f.close()

        except Exception, err:
            logger().error('Failed to read /sys/firmware/efi/efivars/'+filename)
            data = ""
            guid = 0
            attr = 0

        finally:
            return (off, buf, hdr, data, guid, attr)


    def EFIVARS_list_EFI_variables ( self, infcls=2 ):
        varlist = []
        try:
            varlist = os.listdir('/sys/firmware/efi/efivars')
        except Exception:
            logger().error('Failed to read /sys/firmware/efi/efivars. Folder does not exist')
            return None
        variables = dict()
        for v in varlist:
            name = v[:-37]
            if name and name is not None:
                variables[name] = []
                var = self.EFIVARS_get_efivar_from_sys(v)
                # did we get something real back?
                (off, buf, hdr, data, guid, attr) = var
                if data != "" or guid != 0 or attr != 0:
                    variables[name].append(var)
        return variables

    def EFIVARS_get_EFI_variable( self, name, guid ):
        filename = name + "-" + guid
        try:
            f = open('/sys/firmware/efi/efivars/'+filename, 'r')
            data = f.read()
            attr = struct.unpack_from("<I",data)[0]
            data = data[4:]
            f.close()

        except Exception, err:
            logger().error('Failed to read /sys/firmware/efi/efivars/'+filename)
            data = ""

        finally:
            return data


    def EFIVARS_set_EFI_variable(self, name, guid, value, attrs=None):
        if not name:
            name = '*'
        if not guid:
            guid = '*'

        path = '/sys/firmware/efi/efivars/%s-%s' % (name, guid)
        if value != None:
            try:
                if os.path.isfile(path):
                    #Variable already exists
                    if attrs is not None: logger().warn("Changing attributes on an existing variable is not supported. Keeping old attributes...")
                    f = open(path, 'r')
                    sattrs = f.read(4)
                else:
                    #Create new variable with attributes NV+BS+RT if attrs were not passed in
                    sattrs = struct.pack("I", 0x7) if attrs is None else struct.pack("I",attrs)
                f = open(path, 'w')
                f.write(sattrs + value)
                f.close()
                return True
            except Exception, err:
                logger().error('Failed to write EFI variable. %s' % err)
                return False
        else:
            try:
                os.remove(path)
                return True
            except Exception, err:
                logger().error('Failed to delete EFI variable. %s' % err)

#
# UEFI API entry points
#


    def delete_EFI_variable(self, name, guid):
        if self.use_kernvars(): return self.kern_delete_EFI_variable(name, guid)
        elif self.use_efivars(): return self.EFIVARS_set_EFI_variable(name, guid, None)

    def list_EFI_variables (self, infcls=2):
        if      self.use_kernvars(): return self.kern_list_EFI_variables(infcls)
        elif self.use_efivars():  return self.EFIVARS_list_EFI_variables(infcls)
        else:                        return self.VARS_list_EFI_variables(infcls)

    def get_EFI_variable(self, name, guid, attrs=None):
        if self.use_kernvars():    return self.kern_get_EFI_variable(name, guid)
        elif self.use_efivars():  return self.EFIVARS_get_EFI_variable(name, guid)
        else:                      return self.VARS_get_EFI_variable(name, guid)

    def set_EFI_variable(self, name, guid, value, attrs=None):
        if self.use_kernvars(): return self.kern_set_EFI_variable(name, guid, value)
        if self.use_efivars():  return self.EFIVARS_set_EFI_variable(name, guid, value, attrs)
        else:                      return self.VARS_set_EFI_variable(name, guid, value)


##############
    # End UEFI Variable API
##############

    #
    # Interrupts
    #
    def send_sw_smi( self, cpu_thread_id, SMI_code_data, _rax, _rbx, _rcx, _rdx, _rsi, _rdi ):
        self.set_affinity(cpu_thread_id)
        #print "Sending SW SMI 0x%x with rax = 0x%x, rbx = 0x%x, rcx = 0x%x, rdx = 0x%x, rsi = 0x%x, rdi = 0x%x" % (SMI_code_data, _rax, _rbx, _rcx, _rdx, _rsi, _rdi)
        in_buf = struct.pack( "7"+_PACK, SMI_code_data, _rax, _rbx, _rcx, _rdx, _rsi, _rdi )
        fcntl.ioctl( _DEV_FH, IOCTL_SWSMI(), in_buf )
        return


    #
    # File system
    #
    def get_tools_path( self ):
        return os.path.join('..','..','tools','edk2','linux')

    def get_compression_tool_path( self, compression_type ):
        tool = None
        if   1 == compression_type:
             tool = os.path.join( self.get_tools_path(), 'TianoCompress.bin')
        elif 2 == compression_type:
             tool = os.path.join( self.get_tools_path(), 'LzmaCompress.bin' )
        else:
             logger().error( "Don't have a tool for compression type 0x%X" % compression_type )
             return None

        if not os.path.exists( tool ):
           err = "Couldn't find compression tool '%s'" % tool
           logger().error( err )
           #raise OsHelperError(err, 0)
           return None

        return tool
  
    def getcwd( self ):
        return os.getcwd()


    #
    # Logical CPU count
    #
    def get_threads_count ( self ):
        import subprocess
        return int(subprocess.check_output("grep -c process /proc/cpuinfo", shell=True))

def get_helper():
    return LinuxHelper()
