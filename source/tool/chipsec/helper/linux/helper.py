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
#@{
# __chipsec/helper/linux/helper.py__ -- Linux helper
#@}
#

__version__ = '1.0'

import struct
import sys
import os
import fcntl
import platform
import ctypes
import fnmatch
from chipsec.helper.oshelper import OsHelperError
from chipsec.logger import logger
from chipsec.hal.uefi_common import *
import errno

from ctypes import *

_IOCTL_BASE = 0
def IOCTL_BASE(): 	return 0x0
def IOCTL_RDIO():	return _IOCTL_BASE + 0x1
def IOCTL_WRIO():	return _IOCTL_BASE + 0x2  
def IOCTL_RDPCI():	return _IOCTL_BASE + 0x3   
def IOCTL_WRPCI():	return _IOCTL_BASE + 0x4
def IOCTL_RDMSR():	return _IOCTL_BASE + 0x5
def IOCTL_WRMSR():	return _IOCTL_BASE + 0x6
def IOCTL_CPUID():	return _IOCTL_BASE + 0x7
def IOCTL_GET_CPU_DESCRIPTOR_TABLE():	return _IOCTL_BASE + 0x8
def IOCTL_HYPERCALL():	return _IOCTL_BASE + 0x9
def IOCTL_SWSMI():	return _IOCTL_BASE + 0xA
def IOCTL_LOAD_UCODE_PATCH():	return _IOCTL_BASE + 0xB


class LinuxHelper:

    def __init__(self):
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
        global _DEV_FH
        _DEV_FH = None
        
        #already initialized?
        if(_DEV_FH != None): return
        
        logger().log("\n****** Chipsec Linux Kernel module is licensed under GPL 2.0\n")

        try: 
            _DEV_FH = open("/dev/chipsec", "r+")
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

    def read_io_port(self, io_port, size):
        in_buf = struct.pack( "3"+_PACK, io_port, size, 0 )
        out_buf = fcntl.ioctl( _DEV_FH, IOCTL_RDIO(), in_buf )
        try:
            if 1 == size:
                value = struct.unpack_from( 'B', out_buf, 2)
            elif 2 == size:
                value = struct.unpack_from( 'H', out_buf, 2)
            else:
                value = struct.unpack_from( 'I', out_buf, 2)
        except:
            logger().error( "DeviceIoControl did not return value of proper size %x (value = '%s')" % (size, out_buf) )

        return value[0]

    def write_io_port( self, io_port, value, size ):
        in_buf = struct.pack( 'HIB', io_port, value, size )
        return fcntl.ioctl( _DEV_FH, IOCTL_WRIO(), in_buf)

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

    def cpuid(self, eax):
        in_buf = struct.pack( "4"+_PACK, eax, 0, 0, 0) 
        out_buf = fcntl.ioctl( _DEV_FH, IOCTL_CPUID(), in_buf)
        return struct.unpack( "4"+_PACK, out_buf )


    def get_affinity(self):
        CORES = ctypes.cdll.LoadLibrary('./chipsec/helper/linux/cores.so')
        CORES.sched_getaffinity.argtypes = [ctypes.c_int, ctypes.c_int, POINTER(ctypes.c_int)]
        CORES.sched_getaffinity.restype = ctypes.c_int
        pid = ctypes.c_int(0)
        leng = ctypes.c_int(CPU_MASK_LEN) 
        cpu_mask = ctypes.c_int(0)
        if (CORES.sched_getaffinity(pid, leng, byref(cpu_mask)) == 0):
            return cpu_mask.value
        else:
            return None
        
  
    def set_affinity(self, thread_id):
        CORES = ctypes.cdll.LoadLibrary('./chipsec/helper/linux/cores.so')
        pid = ctypes.c_int(0)
        leng = ctypes.c_int(CPU_MASK_LEN) 
        cpu_mask = ctypes.c_int(thread_id)
        ret = CORES.setaffinity(thread_id)
        if(ret == 0):
            return thread_id
        else: 
            #CORES.geterror.restype = ctypes.c_int
            print "set_affinity error: %s" % os.strerror(ret)
            return None
        
##############
    # UEFI Variable API
##############

    def use_efivars(self):
        rel = platform.release()
        ind = rel.find('.')
	major = rel[:ind]
	minor = rel[ind+1:rel.find('.', ind+1)]
	return (int(major) >= 3) and (int(minor) >= 10)
	

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
        varlist = os.listdir('/sys/firmware/efi/vars')
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
        varlist = os.listdir('/sys/firmware/efi/efivars')
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
        if self.use_efivars(): return self.EFIVARS_set_EFI_variable(name, guid, None)

    def list_EFI_variables (self, infcls=2):
        if self.use_efivars():  return self.EFIVARS_list_EFI_variables(infcls)
        else:  		            return self.VARS_list_EFI_variables(infcls)
		
    def get_EFI_variable(self, name, guid, attrs=None):
        if self.use_efivars():  return self.EFIVARS_get_EFI_variable(name, guid)
        else:                       return self.VARS_get_EFI_variable(name, guid)		
	
    def set_EFI_variable(self, name, guid, value, attrs=None):
        if self.use_efivars():  return self.EFIVARS_set_EFI_variable(name, guid, value, attrs)
        else:                       return self.VARS_set_EFI_variable(name, guid, value)
        
	
##############
    # End UEFI Variable API
##############
		
		
    #
    # Interrupts
    #
    def send_sw_smi( self, SMI_code_data, _rax, _rbx, _rcx, _rdx, _rsi, _rdi ):
        print "Sending SW SMI 0x%x with rax = 0x%x, rbx = 0x%x, rcx = 0x%x, rdx = 0x%x, rsi = 0x%x, rdi = 0x%x" % (SMI_code_data, _rax, _rbx, _rcx, _rdx, _rsi, _rdi)
        in_buf = struct.pack( "7"+_PACK, SMI_code_data, _rax, _rbx, _rcx, _rdx, _rsi, _rdi )
        print "NOT IMPLEMENTED IN LINUX HELPER YET ;("
        #fcntl.ioctl( _DEV_FH, IOCTL_SWSMI(), in_buf )	
        return 

    #########


    def getcwd( self ):
        return os.getcwd()
    
    def get_threads_count ( self ):
        import subprocess
        return int(subprocess.check_output("grep -c process /proc/cpuinfo", shell=True))

def get_helper():
    return LinuxHelper()




