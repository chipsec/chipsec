# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2016, Google
#
# Copyright (c) 2010-2019, Intel Corporation
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; Version 2.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#

"""
OSX helper
"""

import errno
import fcntl
import os
import platform
import struct
import subprocess
import sys
import shutil

import chipsec
import chipsec.defines
from chipsec.helper.oshelper import OsHelperError, HWAccessViolationError, UnimplementedAPIError, UnimplementedNativeAPIError
from chipsec.helper.basehelper import Helper
from chipsec.logger import logger, print_buffer

MSGBUS_MDR_IN_MASK          = 0x1
MSGBUS_MDR_OUT_MASK         = 0x2

IOCTL_RDPCI                 = 0xc00c7001
IOCTL_WRPCI                 = 0xc00c7002
IOCTL_RDMMIO                = 0xc0187003
IOCTL_WRMMIO                = 0xc0187004
IOCTL_RDCR                  = 0xc0107005
IOCTL_WRCR                  = 0xc0107006
IOCTL_RDIO                  = 0xc0187007
IOCTL_WRIO                  = 0xc0187008
IOCTL_CPUID                 = 0xc0207009
IOCTL_RDMSR                 = 0xc018700a
IOCTL_WRMSR                 = 0xc018700b
IOCTL_SWSMI                 = 0xc038700c
IOCTL_HYPERCALL             = 0xc060700d
IOCTL_MSGBUS_SEND_MESSAGE   = 0xc028700e
IOCTL_CPU_DESCRIPTOR_TABLE  = 0xc038700f
IOCTL_ALLOC_PHYSMEM         = 0xc0207010
#IOCTL_LOAD_UCODE_PATCH      = 0xc0067011

# Format for the IOCTL structures. See chipsec_ioctl.h for the complete
# definition.
_pci_msg_t_fmt       = "BBBHBI"
_mmio_msg_t_fmt      = "QQB"
_io_msg_t_fmt        = "QQQ"
_cr_msg_t_fmt        = "IQ"
_msr_msg_t_fmt       = "QQQ"
_cpuid_msg_t_fmt     = "QQQQ"
_smi_msg_t_fmt       = "QQQQQQQ"
_hypercall_msg_t_fmt = "QQQQQQQQQQQQ"
_msgbus_msg_t_fmt    = "QQQQQ"
_cpudes_msg_t_fmt    = "QQQQQQQ"
#_ucodeh_msg_t_fmt    = "BH"
_alloc_mem_msg_t_fmt = "QQQQ"


LZMA  = os.path.join(chipsec.file.TOOLS_DIR,"compression","bin","LzmaCompress")
TIANO = os.path.join(chipsec.file.TOOLS_DIR,"compression","bin","TianoCompress")
EFI   = os.path.join(chipsec.file.TOOLS_DIR,"compression","bin","TianoCompress")
BROTLI = os.path.join(chipsec.file.TOOLS_DIR,"compression","bin","Brotli")

class OSXHelper(Helper):

    DEVICE_NAME = "/dev/chipsec"
    DRIVER_NAME = "chipsec.kext"

    def __init__(self):
        super(OSXHelper, self).__init__()
        self.os_system  = platform.system()
        self.os_release = platform.release()
        self.os_version = platform.version()
        self.os_machine = platform.machine()
        self.os_uname   = platform.uname()
        self.dev_fh = None
        self.name = "OSXHelper"

    decompression_oder_type1 = [chipsec.defines.COMPRESSION_TYPE_TIANO,chipsec.defines.COMPRESSION_TYPE_UEFI]
    decompression_oder_type2 = [chipsec.defines.COMPRESSION_TYPE_TIANO,chipsec.defines.COMPRESSION_TYPE_UEFI,chipsec.defines.COMPRESSION_TYPE_LZMA,chipsec.defines.COMPRESSION_TYPE_BROTLI]

    def load_driver(self):
        driver_path = os.path.join(chipsec.file.get_main_dir(), "chipsec",
                                   "helper", "osx", self.DRIVER_NAME)
        # Make sure the driver image and its subdirectories are owned by root.
        s = os.stat(driver_path)
        if s.st_uid != 0 or s.st_gid != 0:
            os.chown(driver_path, 0, 0)
            for root, dirs, files in os.walk(driver_path):
                for f in dirs + files:
                    os.chown(os.path.join(root, f), 0, 0)
        subprocess.check_call(["kextload", driver_path])
        if os.path.exists(self.DEVICE_NAME):
            if logger().DEBUG:
                logger().log("Module {} loaded successfully".format(self.DRIVER_NAME))
        else:
            logger().error("Failed to load the module {}".format(self.DRIVER_NAME))
        self.driverpath = driver_path

    def create(self, start_driver):
        #self.init(start_driver)
        if logger().DEBUG:
            logger().log("[helper] OSX Helper created")
        return True

    def start(self, start_driver, driver_exists=False):
        if start_driver:
            if os.path.exists(self.DEVICE_NAME):
                driver_path = os.path.join(chipsec.file.get_main_dir(), "chipsec",
                                           "helper", "osx", self.DRIVER_NAME)
                subprocess.check_call(["kextunload", driver_path])
            self.load_driver()
        self.init(start_driver)
        if logger().DEBUG:
            logger().log("[helper] OSX Helper started/loaded")
        return True

    def stop(self, start_driver):
        self.close()
        if self.driver_loaded:
            driver_path = os.path.join(chipsec.file.get_main_dir(), "chipsec",
                                       "helper", "osx", self.DRIVER_NAME)
            subprocess.check_call(["kextunload", driver_path])
        if logger().DEBUG:
            logger().log("[helper] OSX Helper stopped/unloaded")
        return True

    def delete(self, start_driver):
        if logger().DEBUG:
            logger().log("[helper] OSX Helper deleted")
        return True

    def init(self, start_driver):
        if start_driver:
            try:
                self.dev_fh = open(self.DEVICE_NAME, "rb+")
                self.driver_loaded = True
            except IOError as e:
                raise OsHelperError("Unable to open the Chipsec device.\n"
                                    "{}".format(str(e)), e.errno)

    def close(self):
        if self.dev_fh:
            self.dev_fh.close()
        self.dev_fh = None

    def ioctl(self, ioctl_name, args):
        return fcntl.ioctl(self.dev_fh, ioctl_name, args)

    def mem_read_block(self, addr, sz):
        if(addr is not None):
            self.dev_fh.seek(addr)
        return self.dev_fh.read(sz)

    def mem_write_block(self, addr, sz, newval):
        if(addr is not None):
            self.dev_fh.seek(addr)
        self.dev_fh.write(newval)
        self.dev_fh.flush()

    def write_phys_mem(self, addr_hi, addr_lo, size, value):
        if(value is not None):
            self.mem_write_block((addr_hi << 32) | addr_lo, size, value)

    def read_phys_mem(self, addr_hi, addr_lo, size):
        ret = self.mem_read_block((addr_hi << 32) | addr_lo, size)
        return ret

    def read_pci_reg( self, bus, device, function, offset, size = 4 ):
        data = struct.pack(_pci_msg_t_fmt, bus, device, function, offset,
                           size, 0)
        try:
            ret = self.ioctl(IOCTL_RDPCI, data)
        except IOError:
            if logger().DEBUG: logger().error("IOError")
            return None
        x = struct.unpack(_pci_msg_t_fmt, ret)
        return x[5]

    def write_pci_reg( self, bus, device, function, offset, value, size = 4 ):
        data = struct.pack(_pci_msg_t_fmt, bus, device, function, offset,
                           size, value)
        try:
            ret = self.ioctl(IOCTL_WRPCI, data)
        except IOError:
            if logger().DEBUG: logger().error("IOError")

    def read_mmio_reg(self, phys_address, size):
        data = struct.pack(_mmio_msg_t_fmt, phys_address, 0, size)
        ret = self.ioctl(IOCTL_RDMMIO, data)
        x = struct.unpack(_mmio_msg_t_fmt, ret)
        return x[1]

    def write_mmio_reg(self, phys_address, size, value):
        data = struct.pack(_mmio_msg_t_fmt, phys_address, value, size)
        ret = self.ioctl(IOCTL_WRMMIO, data)

    def getcwd(self):
        return os.getcwd()

    def rotate_list(self, list, n):
        return list[n:] + list[:n]

    def unknown_decompress(self,CompressedFileName,OutputFileName):
        failed_times = 0
        for CompressionType in self.decompression_oder_type2:
            res = self.decompress_file(CompressedFileName,OutputFileName,CompressionType)
            if res == True:
                self.rotate_list(self.decompression_oder_type2,failed_times)
                break
            else:
                failed_times += 1
        return res
        
    def unknown_efi_decompress(self,CompressedFileName,OutputFileName):
        failed_times = 0
        for CompressionType in self.decompression_oder_type1:
            res = self.decompress_file(CompressedFileName,OutputFileName,CompressionType)
            if res == True:
                self.rotate_list(self.decompression_oder_type1,failed_times)
                break
            else:
                failed_times += 1
        return res

    #
    # Compress binary file
    #
    def compress_file( self, FileName, OutputFileName, CompressionType ):
        if not CompressionType in [i for i in chipsec.defines.COMPRESSION_TYPES]:
            return False
        encode_str = " -e -o {} ".format(OutputFileName)
        if CompressionType == chipsec.defines.COMPRESSION_TYPE_NONE:
            shutil.copyfile(FileName,OutputFileName)
            return True
        elif CompressionType == chipsec.defines.COMPRESSION_TYPE_TIANO:
            encode_str = TIANO + encode_str
        elif CompressionType == chipsec.defines.COMPRESSION_TYPE_UEFI:
            encode_str = EFI + encode_str + "--uefi "
        elif CompressionType == chipsec.defines.COMPRESSION_TYPE_LZMA:
            encode_str = LZMA + encode_str
        elif CompressionType == chipsec.defines.COMPRESSION_TYPE_BROTLI:
            encode_str = BROTLI + encode_str
        encode_str += FileName
        data = subprocess.call(encode_str,shell=True)
        if not data == 0 and logger().VERBOSE:
            logger().error("Cannot decompress file({})".format(FileName))
            return False
        return True
        
    #
    # Decompress binary
    #
    def decompress_file( self, CompressedFileName, OutputFileName, CompressionType ):
        if not CompressionType in [i for i in chipsec.defines.COMPRESSION_TYPES]:
            return False
        if CompressionType == chipsec.defines.COMPRESSION_TYPE_UNKNOWN:
            data = self.unknown_decompress(CompressedFileName,OutputFileName)
            return data
        elif CompressionType == chipsec.defines.COMPRESSION_TYPE_EFI_STANDARD:
            data = self.unknown_efi_decompress(CompressedFileName,OutputFileName)
            return data
        decode_str = " -d -o {} ".format(OutputFileName)
        if CompressionType == chipsec.defines.COMPRESSION_TYPE_NONE:
            shutil.copyfile(CompressedFileName,OutputFileName)
            return True
        elif CompressionType == chipsec.defines.COMPRESSION_TYPE_TIANO:
            decode_str = TIANO + decode_str
        elif CompressionType == chipsec.defines.COMPRESSION_TYPE_UEFI:
            decode_str = EFI + decode_str + "--uefi "
        elif CompressionType == chipsec.defines.COMPRESSION_TYPE_LZMA:
            decode_str = LZMA + decode_str
        elif CompressionType == chipsec.defines.COMPRESSION_TYPE_BROTLI:
            decode_str = BROTLI + decode_str
        decode_str += CompressedFileName
        data = subprocess.call(decode_str,shell=True)
        if not data == 0 and logger().VERBOSE:
            logger().error("Cannot decompress file({})".format(CompressedFileName))
            return False
        return True


    def get_tool_info( self, tool_type ):
        raise NotImplementedError()
    
    #
    # Logical CPU count
    #
    def get_threads_count (self):
        import subprocess
        return int(subprocess.check_output("sysctl -n hw.ncpu", shell=True))
    
    #########################################################
    # EFI Runtime API
    #########################################################

    # @TODO: macOS helper doesn't support EFI runtime API yet
    def EFI_supported(self):
        return False

    # Placeholders for EFI Variable API

    def delete_EFI_variable(self, name, guid):
        raise NotImplementedError()
    def native_delete_EFI_variable(self, name, guid):
        raise NotImplementedError()

    def list_EFI_variables(self):
        raise NotImplementedError()
    def native_list_EFI_variables(self):
        raise NotImplementedError()

    def get_EFI_variable(self, name, guid, attrs=None):
        raise NotImplementedError()
    def native_get_EFI_variable(self, name, guid, attrs=None):
        raise NotImplementedError()

    def set_EFI_variable(self, name, guid, data, datasize, attrs=None):
        raise NotImplementedError()
    def native_set_EFI_variable(self, name, guid, data, datasize, attrs=None):
        raise NotImplementedError()


    #########################################################
    # Port I/O
    #########################################################

    def read_io_port(self, io_port, size):
        in_buf = struct.pack(_io_msg_t_fmt, io_port, size, 0)
        out_buf = self.ioctl(IOCTL_RDIO,in_buf)
        try:
            if 1 == size:
                value = struct.unpack(_io_msg_t_fmt,out_buf)[2] & 0xff
            elif 2 == size:
                value = struct.unpack(_io_msg_t_fmt,out_buf)[2] & 0xffff
            else:
                value = struct.unpack(_io_msg_t_fmt,out_buf)[2] & 0xffffffff
        except:
            if logger().DEBUG: logger().error("DeviceIoControl did not return value of proper size {:x} (value = '{}')".format(size,out_buf))
        return value

    def write_io_port(self, io_port, value, size):
        in_buf = struct.pack(_io_msg_t_fmt, io_port, size, value)
        return self.ioctl(IOCTL_WRIO,in_buf)

    def read_cr(self, cpu_thread_id, cr_number):
        #self.set_affinity(cpu_thread_id)
        in_buf = struct.pack(_cr_msg_t_fmt,cr_number,0)
        out_buf = self.ioctl(IOCTL_RDCR,in_buf)
        value = struct.unpack(_cr_msg_t_fmt,out_buf)[1]
        return value

    def write_cr(self, cpu_thread_id, cr_number, value):
        #self.set_affinity(cpu_thread_id)
        in_buf = struct.pack(_cr_msg_t_fmt,cr_number,value)
        return self.ioctl(IOCTL_WRCR,in_buf)

    def read_msr(self, thread_id, msr_addr):
        #self.set_affinity(cpu_thread_id)
        in_buf = struct.pack(_msr_msg_t_fmt,msr_addr,0,0)
        out_buf = self.ioctl(IOCTL_RDMSR,in_buf)
        value = struct.unpack(_msr_msg_t_fmt,out_buf)
        return (value[1],value[2])

    def write_msr(self, thread_id, msr_addr, eax, edx):
        #self.set_affinity(cpu_thread_id)
        in_buf = struct.pack(_msr_msg_t_fmt,msr_addr,0,0)
        return self.ioctl(IOCTL_WRMSR,in_buf)

    def get_descriptor_table(self, cpu_thread_id, desc_table_code):
        #self.set_affinity(cpu_thread_id)
        in_buf = struct.pack(_cpudes_msg_t_fmt,cpu_thread_id, desc_table_code, 0, 0, 0,0,0)
        out_buf = self.ioctl(IOCTL_CPU_DESCRIPTOR_TABLE, in_buf)
        (limit,base_hi,base_lo,pa_hi,pa_lo) = struct.unpack(_cpudes_msg_t_fmt,out_buf)[2:]
        pa = (pa_hi << 32) + pa_lo
        base = (base_hi << 32) + base_lo
        return (limit,base,pa)
    
    def hypercall(self, rcx, rdx, r8, r9, r10, r11, rax, rbx, rdi, rsi, xmm_buffer ):
        in_buf = struct.pack(_hypercall_msg_t_fmt,rcx,rdx,r8,r9,r10,r11,rax,rbx,rdi,rsi,xmm_buffer,0)
        out_buf = self.ioctl(IOCTL_HYPERCALL,in_buf)
        return struct.unpack(_hypercall_msg_t_fmt,out_buf)[11]

    def cpuid(self, eax, ecx):
        in_buf = struct.pack(_cpuid_msg_t_fmt,eax,0,ecx,0)
        out_buf = self.ioctl(IOCTL_CPUID,in_buf)
        return struct.unpack(_cpuid_msg_t_fmt,out_buf)

    def alloc_phys_mem(self, num_bytes, max_addr):
        in_buf = struct.pack(_alloc_mem_msg_t_fmt,num_bytes,max_addr,0,0)
        out_buf = self.ioctl(IOCTL_ALLOC_PHYSMEM, in_buf)
        return struct.unpack(_alloc_mem_msg_t_fmt, out_buf)[2:]

    def msgbus_send_read_message( self, mcr, mcrx ):
        mdr_out = 0
        in_buf  = struct.pack(_msgbus_msg_t_fmt, MSGBUS_MDR_OUT_MASK, mcr, mcrx, 0, mdr_out)
        out_buf = self.ioctl( IOCTL_MSGBUS_SEND_MESSAGE, in_buf)
        mdr_out = struct.unpack( _msgbus_msg_t_fmt, out_buf)[4]
        return mdr_out
    
    def msgbus_send_write_message( self, mcr, mcrx, mdr):
        mdr_out = 0
        in_buf  = struct.pack(_msgbus_msg_t_fmt, MSGBUS_MDR_IN_MASK, mcr, mcrx, mdr, mdr_out)
        out_buf = self.ioctl( IOCTL_MSGBUS_SEND_MESSAGE, in_buf)
        return

    def msgbus_send_message( self, mcr, mcrx, mdr=None):
        mdr_out = 0
        if mdr is None:
            in_buf = struct.pack(_msgbus_msg_t_fmt, MSGBUS_MDR_OUT_MASK, mcr, mcrx, 0, mdr_out)
        else:
            in_buf = struct.pack(_msgbus_msg_t_fmt, (MSGBUS_MDR_IN_MASK | MSGBUS_MDR_OUT_MASK), mcr, mcrx, mdr, mdr_out)
        out_buf = self.ioctl( IOCTL_MSGBUS_SEND_MESSAGE, in_buf)
        mdr_out = struct.unpack( _msgbus_msg_t_fmt, out_buf)[4]
        return mdr_out

    def get_affinity(self):
        raise NotImplementedError()

    def set_affinity(self, thread_id):
        raise NotImplementedError()

    def send_sw_smi( self, cpu_thread_id, SMI_code_data, _rax, _rbx, _rcx, _rdx, _rsi, _rdi):
        #self.set_affinity(cpu_thread_id)
        in_buf = struct.pack(_smi_msg_t_fmt, SMI_code_data, _rax, _rbx, _rcx, _rdx, _rsi, _rdi)
        out_buf = self.ioctl(IOCTL_SWSMI, in_buf)
        ret = struct.unpack(_smi_msg_t_fmt,out_buf)
        return ret

    def map_io_space(self, base, size, cache_type):
        raise NotImplementedError()

    def load_ucode_update(self, cpu_thread_id, ucode_update_buf):
        raise NotImplementedError()
        '''cpu_ucode_thread_id = ctypes.c_int(cpu_thread_id)
        in_buf = struct.pack(_ucodeh_msg_t_fmt, cpu_thread_id,len(ucode_update_buf))+ ucode_update_buf
        in_buf_final = array.array("c",in_buf)
        out_len = 0
        out_buf = (ctypes.c_char * out_length)()
        try:
            out_buf = self.ioctl(IOCTL_LOAD_UCODE_PATCH, in_buf_final)
        except IOError:
            if logger().DEBUG:
                logger().error("IOError IOCTL Load Patch\n")
            return None

        return True'''

def get_helper():
    return OSXHelper()
