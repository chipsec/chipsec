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
from chipsec.helper.oshelper import OsHelperError, Helper
from chipsec.logger import logger, print_buffer
import errno
import array
import subprocess
import os.path
import chipsec.file

from ctypes import *

MSGBUS_MDR_IN_MASK  = 0x1
MSGBUS_MDR_OUT_MASK = 0x2

IOCTL_BASE                     = 0x0
IOCTL_RDIO                     = 0x1
IOCTL_WRIO                     = 0x2
IOCTL_RDPCI                    = 0x3
IOCTL_WRPCI                    = 0x4
IOCTL_RDMSR                    = 0x5
IOCTL_WRMSR                    = 0x6
IOCTL_CPUID                    = 0x7
IOCTL_GET_CPU_DESCRIPTOR_TABLE = 0x8
IOCTL_HYPERCALL                = 0x9
IOCTL_SWSMI                    = 0xA
IOCTL_LOAD_UCODE_PATCH         = 0xB
IOCTL_ALLOC_PHYSMEM            = 0xC
IOCTL_GET_EFIVAR               = 0xD
IOCTL_SET_EFIVAR               = 0xE
IOCTL_RDCR                     = 0x10
IOCTL_WRCR                     = 0x11
IOCTL_RDMMIO                   = 0x12
IOCTL_WRMMIO                   = 0x13
IOCTL_VA2PA                    = 0x14
IOCTL_MSGBUS_SEND_MESSAGE      = 0x15

class LinuxHelper(Helper):

    DEVICE_NAME = "/dev/chipsec"
    DEV_MEM = "/dev/mem"
    MODULE_NAME = "chipsec"
    SUPPORT_KERNEL26_GET_PAGE_IS_RAM = False

    def __init__(self):
        super(LinuxHelper, self).__init__()
        import platform
        self.os_system  = platform.system()
        self.os_release = platform.release()
        self.os_version = platform.version()
        self.os_machine = platform.machine()
        self.os_uname   = platform.uname()
        self.dev_fh = None
        self.dev_mem = None

    def __del__(self):
        try:
            destroy()
        except NameError:
            pass

###############################################################################################
# Driver/service management functions
###############################################################################################

    # This function load CHIPSEC driver. (implement functionality from run.sh)
    def load_chipsec_module(self):
        page_is_ram = ""
        a1 = ""
        if self.SUPPORT_KERNEL26_GET_PAGE_IS_RAM:
            page_is_ram = self.get_page_is_ram()
            if not page_is_ram:
                if logger().VERBOSE:
                    logger().log("Cannot find symbol 'page_is_ram'")
            else:
                a1 = "a1=0x%s" % page_is_ram 
        driver_path = os.path.join(chipsec.file.get_main_dir(), ".." , "drivers" ,"linux", "chipsec.ko" )
        subprocess.check_output( [ "insmod", driver_path, a1 ] )
        uid = gid = 0
        os.chown(self.DEVICE_NAME, uid, gid)
        os.chmod(self.DEVICE_NAME, 600)
        if os.path.exists(self.DEVICE_NAME):
            if logger().VERBOSE:
                logger().log("Module %s loaded successfully"%self.DEVICE_NAME)
        else:
            logger().error( "Fail to load module: %s" % driver_path )


    def create(self, start_driver):
        if logger().VERBOSE:
            logger().log("[helper] Linux Helper created")

    def start(self, start_driver):
        if start_driver:
            if os.path.exists(self.DEVICE_NAME):
                subprocess.call(["rmmod", self.MODULE_NAME])
            self.load_chipsec_module()
        self.init(start_driver)
        if logger().VERBOSE:
            logger().log("[helper] Linux Helper started/loaded")

    def stop( self ):
        self.close()
        if self.driver_loaded:
            subprocess.call(["rmmod", self.MODULE_NAME])
        if logger().VERBOSE:
            logger().log("[helper] Linux Helper stopped/unloaded")

    def delete( self ):
        if logger().VERBOSE:
            logger().log("[helper] Linux Helper deleted")

    def destroy( self ):
        self.stop()
        self.delete()

    def init(self, start_driver):
        x64 = True if sys.maxsize > 2**32 else False
        self._pack = 'Q' if x64 else 'I'

        if start_driver:
            logger().log("****** Chipsec Linux Kernel module is licensed under GPL 2.0")

            try:
                self.dev_fh = open(self.DEVICE_NAME, "r+")
                self.driver_loaded = True
            except IOError as e:
                raise OsHelperError("Unable to open chipsec device. Did you run as root/sudo and load the driver?\n %s"%str(e),e.errno)
            except BaseException as be:
                raise OsHelperError("Unable to open chipsec device. Did you run as root/sudo and load the driver?\n %s"%str(be),errno.ENXIO)

            self._ioctl_base = fcntl.ioctl(self.dev_fh, IOCTL_BASE) << 4

    def devmem_available(self):
        """Check if /dev/mem is usable.

           In case the driver is not loaded, we might be able to perform the
           requested operation via /dev/mem. Returns True if /dev/mem is
           accessible.
        """
        if self.dev_mem:
            return True
        if not self.driver_loaded:
            logger().log("[helper] Trying /dev/mem instead of the Chipsec driver.")
            try:
                self.dev_mem = os.open(self.DEV_MEM, os.O_RDWR)
                return True
            except IOError as err:
                raise OsHelperError("Unable to open /dev/mem.\n"
                                    "This command requires either the Chipsec"
                                    "driver or access to /dev/mem.\n"
                                    "Are you running this command as root?\n"
                                    "%s" % str(err), err.errno)
        return False

    def close(self):
        if self.dev_fh:
            self.dev_fh.close()
        self.dev_fh = None
        if self.dev_mem:
            os.close(self.dev_mem)
        self.dev_mem = None


    def ioctl(self, nr, args, *mutate_flag):
        return fcntl.ioctl(self.dev_fh, self._ioctl_base + nr, args)

###############################################################################################
# Actual API functions to access HW resources
###############################################################################################
    def __mem_block(self, sz, newval = None):
        if(newval == None):
            return self.dev_fh.read(sz)
        else:
            self.dev_fh.write(newval)
            self.dev_fh.flush()
        return 1

    def mem_read_block(self, addr, sz):
        if self.driver_loaded:
            if(addr != None): self.dev_fh.seek(addr)
            return self.__mem_block(sz)
        elif self.devmem_available():
            os.lseek(self.dev_mem, addr, os.SEEK_SET)
            return os.read(self.dev_mem, sz)

    def mem_write_block(self, addr, sz, newval):
        if self.driver_loaded:
            if(addr != None): self.dev_fh.seek(addr)
            return self.__mem_block(sz, newval)
        elif self.devmem_available():
            os.lseek(self.dev_mem, addr, os.SEEK_SET)
            written = os.write(self.dev_mem, newval)
            if written != sz:
                logger().error("Cannot write %s to memory %016x (wrote %d of %d)" % (newval, addr, written, sz))

    def write_phys_mem(self, phys_address_hi, phys_address_lo, sz, newval):
        if(newval == None): return None
        return self.mem_write_block((phys_address_hi << 32) | phys_address_lo, sz, newval)

    def read_phys_mem(self, phys_address_hi, phys_address_lo, length):
        ret = self.mem_read_block((phys_address_hi << 32) | phys_address_lo, length)
        if(ret == None): return None
        return ret

    def va2pa( self, va ):
        error_code = 0

        in_buf = struct.pack( self._pack, va )
        out_buf = self.ioctl(IOCTL_VA2PA, in_buf)
        pa = struct.unpack( self._pack, out_buf )[0]

        #Check if PA > max physical address
        max_pa = self.cpuid( 0x80000008 , 0x0 )[0] & 0xFF
        if pa > 1<<max_pa:
            print "[helper] Error in va2pa: PA higher that max physical address: VA (0x%016X) -> PA (0x%016X)"% (va, pa) 
            error_code = 1
        return (pa,error_code)

    #DEPRECATED: Pass-through
    def read_pci( self, bus, device, function, address ):
        return self.read_pci_reg(bus, device, function, address)

    def read_pci_reg_from_sys(self, bus, device, function, offset, size, domain=0):
        device_name = "{domain:04x}:{bus:02x}:{device:02x}.{function}".format(
                      domain=domain, bus=bus, device=device, function=function)
        device_path = "/sys/bus/pci/devices/{}/config".format(device_name)
        try:
            config = open(device_path, "rb")
        except IOError as err:
            raise OsHelperError("Unable to open {}".format(device_path), err.errno)
        config.seek(offset)
        reg = config.read(size)
        config.close()
        if size == 4:
          reg = struct.unpack("=I", reg)[0]
        elif size == 2:
          reg = struct.unpack("=H", reg)[0]
        elif size == 1:
          reg = struct.unpack("=B", reg)[0]
        return reg

    def read_pci_reg( self, bus, device, function, offset, size = 4 ):
        _PCI_DOM = 0 #Change PCI domain, if there is more than one.
        if not self.driver_loaded:
            return self.read_pci_reg_from_sys(bus, device, function, offset, size, domain=_PCI_DOM)
        d = struct.pack("5"+self._pack, ((_PCI_DOM << 16) | bus), ((device << 16) | function), offset, size, 0)
        try:
            ret = self.ioctl(IOCTL_RDPCI, d)
        except IOError:
            print "IOError\n"
            return None
        x = struct.unpack("5"+self._pack, ret)
        return x[4]

    def write_pci_reg( self, bus, device, function, offset, value, size = 4 ):
        _PCI_DOM = 0 #Change PCI domain, if there is more than one.
        d = struct.pack("5"+self._pack, ((_PCI_DOM << 16) | bus), ((device << 16) | function), offset, size, value)
        try:
            ret = self.ioctl(IOCTL_WRPCI, d)
        except IOError:
            print "IOError\n"
            return None
        x = struct.unpack("5"+self._pack, ret)
        return x[4]

    def load_ucode_update( self, cpu_thread_id, ucode_update_buf):
        cpu_ucode_thread_id = ctypes.c_int(cpu_thread_id)

        in_buf = struct.pack('=BH', cpu_thread_id, len(ucode_update_buf)) + ucode_update_buf
        in_buf_final = array.array("c", in_buf)
        #print_buffer(in_buf)
        out_length=0
        out_buf=(c_char * out_length)()
        try:
            out_buf = self.ioctl(IOCTL_LOAD_UCODE_PATCH, in_buf_final)
        except IOError:
            print "IOError IOCTL Load Patch\n"
            return None

        return True


    def read_io_port(self, io_port, size):
        in_buf = struct.pack( "3"+self._pack, io_port, size, 0 )
        out_buf = self.ioctl(IOCTL_RDIO, in_buf)
        try:
            #print_buffer(out_buf)
            if 1 == size:
                value = struct.unpack("3"+self._pack, out_buf)[2] & 0xff
            elif 2 == size:
                value = struct.unpack("3"+self._pack, out_buf)[2] & 0xffff
            else:
                value = struct.unpack("3"+self._pack, out_buf)[2] & 0xffffffff
        except:
            logger().error( "DeviceIoControl did not return value of proper size %x (value = '%s')" % (size, out_buf) )

        return value

    def write_io_port( self, io_port, value, size ):
        in_buf = struct.pack( "3"+self._pack, io_port, size, value )
        return self.ioctl(IOCTL_WRIO, in_buf)

    def read_cr(self, cpu_thread_id, cr_number):
        self.set_affinity(cpu_thread_id)
        cr = 0
        in_buf = struct.pack( "3"+self._pack, cpu_thread_id, cr_number, cr)
        unbuf = struct.unpack("3"+self._pack, self.ioctl(IOCTL_RDCR, in_buf))
        return (unbuf[2])

    def write_cr(self, cpu_thread_id, cr_number, value):
        self.set_affinity(cpu_thread_id)
        in_buf = struct.pack( "3"+self._pack, cpu_thread_id, cr_number, value )
        self.ioctl(IOCTL_WRCR, in_buf)
        return

    def read_msr(self, thread_id, msr_addr):
        self.set_affinity(thread_id)
        edx = eax = 0
        in_buf = struct.pack( "4"+self._pack, thread_id, msr_addr, edx, eax)
        unbuf = struct.unpack("4"+self._pack, self.ioctl(IOCTL_RDMSR, in_buf))
        return (unbuf[3], unbuf[2])

    def write_msr(self, thread_id, msr_addr, eax, edx):
        self.set_affinity(thread_id)
        in_buf = struct.pack( "4"+self._pack, thread_id, msr_addr, edx, eax )
        self.ioctl(IOCTL_WRMSR, in_buf)
        return

    def get_descriptor_table(self, cpu_thread_id, desc_table_code  ):
        self.set_affinity(cpu_thread_id)
        in_buf = struct.pack( "5"+self._pack, cpu_thread_id, desc_table_code, 0 , 0, 0)
        out_buf = self.ioctl(IOCTL_GET_CPU_DESCRIPTOR_TABLE, in_buf)
        (limit,base_hi,base_lo,pa_hi,pa_lo) = struct.unpack( "5"+self._pack, out_buf )
        pa = (pa_hi << 32) + pa_lo
        base = (base_hi << 32) + base_lo
        return (limit,base,pa)

    def do_hypercall(self, vector, arg1, arg2, arg3, arg4, arg5, use_peach):
        in_buf = struct.pack( "7"+self._pack, vector, arg1, arg2, arg3, arg4, arg5, use_peach)
        out_buf = self.ioctl(IOCTL_HYPERCALL, in_buf)
        regs = struct.unpack( "7"+self._pack, out_buf )
        return regs

    def cpuid(self, eax, ecx):
        # add ecx
        in_buf = struct.pack( "4"+self._pack, eax, 0, ecx, 0)
        out_buf = self.ioctl(IOCTL_CPUID, in_buf)
        return struct.unpack( "4"+self._pack, out_buf )

    def alloc_phys_mem(self, num_bytes, max_addr):
        in_buf = struct.pack( "2"+self._pack, num_bytes, max_addr)
        out_buf = self.ioctl(IOCTL_ALLOC_PHYSMEM, in_buf)
        return struct.unpack( "2"+self._pack, out_buf )

    def read_mmio_reg(self, phys_address, size):
        if self.driver_loaded:
            in_buf = struct.pack( "2"+self._pack, phys_address, size)
            out_buf = self.ioctl(IOCTL_RDMMIO, in_buf)
            reg = out_buf[:size]
        elif self.devmem_available():
            os.lseek(self.dev_mem, phys_address, os.SEEK_SET)
            reg = os.read(self.dev_mem, size)

        if size == 8:
            value = struct.unpack( '=Q', reg)[0]
        elif size == 4:
            value = struct.unpack( '=I', reg)[0]
        elif size == 2:
            value = struct.unpack( '=H', reg)[0]
        elif size == 1:
            value = struct.unpack( '=B', reg)[0]
        else:
            value = 0
        return value

    def write_mmio_reg(self, phys_address, size, value):
        if self.driver_loaded:
            in_buf = struct.pack( "3"+self._pack, phys_address, size, value )
            out_buf = self.ioctl(IOCTL_WRMMIO, in_buf)
        elif self.devmem_available():
            if size == 4:
                reg = struct.pack("=I", value)
            elif size == 2:
                reg = struct.pack("=H", value)
            elif size == 1:
                reg = struct.pack("=B", value)
            os.lseek(self.dev_mem, phys_address, os.SEEK_SET)
            written = os.write(self.dev_mem, reg)
            if written != size:
                logger().error("Unable to write all data to MMIO (wrote %d of %d)" % (written, size))

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
        stat = self.ioctl(IOCTL_GET_EFIVAR, buffer)
        new_size, status = struct.unpack( "2I", buffer[:8])

        if (status == 0x5):
            data_size = new_size + header_size + namelen # size sent by driver + size of header (size + guid) + size of name
            in_buf = struct.pack('13I'+str(namelen+new_size)+'s', data_size, guid0, guid1, guid2, guid3, guid4, guid5, guid6, guid7, guid8, guid9, guid10, namelen, name)
            buffer = array.array("c", in_buf)
            try:
                stat = self.ioctl(IOCTL_GET_EFIVAR, buffer)
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
        stat = self.ioctl(IOCTL_SET_EFIVAR, buffer)
        size, status = struct.unpack( "2I", buffer[:8])

        if (status != 0):
            logger().error( "Setting EFI (SET_EFIVAR) variable did not succeed: %s" % status_dict[status] )
        else:
            os.system('umount /sys/firmware/efi/efivars; mount -t efivarfs efivarfs /sys/firmware/efi/efivars')
        return status
        
    def get_ACPI_SDT( self ):
        logger().error( "ACPI is not supported yet" )
        return 0  
        
    #
    # IOSF Message Bus access
    #
    def msgbus_send_read_message( self, mcr, mcrx ):
        mdr_out = 0
        in_buf  = struct.pack( "5"+self._pack, MSGBUS_MDR_OUT_MASK, mcr, mcrx, 0, mdr_out )
        out_buf = self.ioctl( IOCTL_MSGBUS_SEND_MESSAGE, in_buf )
        mdr_out = struct.unpack( "5"+self._pack, out_buf )[4]
        return mdr_out

    def msgbus_send_write_message( self, mcr, mcrx, mdr ):
        in_buf  = struct.pack( "5"+self._pack, MSGBUS_MDR_IN_MASK, mcr, mcrx, mdr, 0 )
        out_buf = self.ioctl( IOCTL_MSGBUS_SEND_MESSAGE, in_buf )
        return

    def msgbus_send_message( self, mcr, mcrx, mdr=None ):
        mdr_out = 0
        if mdr is None: in_buf = struct.pack( "5"+self._pack, MSGBUS_MDR_OUT_MASK, mcr, mcrx, 0, mdr_out )
        else:           in_buf = struct.pack( "5"+self._pack, (MSGBUS_MDR_IN_MASK | MSGBUS_MDR_OUT_MASK), mcr, mcrx, mdr, mdr_out )
        out_buf = self.ioctl( IOCTL_MSGBUS_SEND_MESSAGE, in_buf )
        mdr_out = struct.unpack( "5"+self._pack, out_buf )[4]
        return mdr_out

    #
    # Affinity functions
    #

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
        in_buf = struct.pack( "7"+self._pack, SMI_code_data, _rax, _rbx, _rcx, _rdx, _rsi, _rdi )
        self.ioctl(IOCTL_SWSMI, in_buf)
        return


    #
    # File system
    #
    def get_tools_path( self ):
        p = os.path.join(chipsec.file.get_main_dir(), "..", "..", 'tools','edk2','linux')
        return os.path.normpath(p)

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

    def get_page_is_ram( self ):
        PROC_KALLSYMS = "/proc/kallsyms"
        symarr = chipsec.file.read_file(PROC_KALLSYMS).splitlines()
        for line in symarr:
            if "page_is_ram" in line:
               return line.split(" ")[0]
    #
    # Logical CPU count
    #
    def get_threads_count ( self ):
        import subprocess
        return int(subprocess.check_output("grep -c process /proc/cpuinfo", shell=True))

def get_helper():
    return LinuxHelper()
