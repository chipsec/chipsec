# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2016, Google
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
from chipsec.helper.oshelper import OsHelperError, Helper, HWAccessViolationError, UnimplementedAPIError, UnimplementedNativeAPIError
from chipsec.logger import logger, print_buffer

from chipsec_tools import efi_compressor

IOCTL_RDPCI   = 0xc00c7001
IOCTL_WRPCI   = 0xc00c7002
IOCTL_RDMMIO  = 0xc0187003
IOCTL_WRMMIO  = 0xc0187004

# Format for the IOCTL structures. See chipsec_ioctl.h for the complete
# definition.
_pci_msg_t_fmt = "BBBHBI"
_mmio_msg_t_fmt = "QQB"


LZMA  = efi_compressor.LzmaDecompress
Tiano = efi_compressor.TianoDecompress
EFI   = efi_compressor.EfiDecompress 

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
            if logger().VERBOSE:
                logger().log("Module %s loaded successfully" % self.DRIVER_NAME)
        else:
            logger().error("Failed to load the module %s" % self.DRIVER_NAME)

    def create(self, start_driver):
        #self.init(start_driver)
        if logger().VERBOSE:
            logger().log("[helper] OSX Helper created")
        return True

    def start(self, start_driver, driver_exists=False):
        if start_driver:
            self.load_driver()
        self.init(start_driver)
        if logger().VERBOSE:
            logger().log("[helper] OSX Helper started/loaded")
        return True

    def stop(self, start_driver):
        if self.driver_loaded:
            pass
        if logger().VERBOSE:
            logger().log("[helper] OSX Helper stopped/unloaded")
        return True

    def delete(self, start_driver):
        if logger().VERBOSE:
            logger().log("[helper] OSX Helper deleted")
        return True

    def init(self, start_driver):
        if start_driver:
            try:
                self.dev_fh = open(self.DEVICE_NAME, "r+")
                self.driver_loaded = True
            except IOError as e:
                raise OsHelperError("Unable to open the Chipsec device.\n"
                                    "%s" % str(e), e.errno)

    def close(self):
        if self.dev_fh:
            self.dev_fh.close()
        self.dev_fh = None

    def ioctl(self, ioctl_name, args):
        return fcntl.ioctl(self.dev_fh, ioctl_name, args)

    def mem_read_block(self, addr, sz):
        if(addr != None):
            self.dev_fh.seek(addr)
        return self.dev_fh.read(sz)

    def mem_write_block(self, addr, sz, newval):
        if(addr != None):
            self.dev_fh.seek(addr)
        self.dev_fh.write(newval)
        self.dev_fh.flush()

    def write_phys_mem(self, addr_hi, addr_lo, size, value):
        if(value != None):
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
            logger().error("IOError")
            return None
        x = struct.unpack(_pci_msg_t_fmt, ret)
        return x[5]

    def write_pci_reg( self, bus, device, function, offset, value, size = 4 ):
        data = struct.pack(_pci_msg_t_fmt, bus, device, function, offset,
                           size, value)
        try:
            ret = self.ioctl(IOCTL_WRPCI, data)
        except IOError:
            logger().error("IOError")

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

    def decompress_data(self, funcs, cdata):
        for func in funcs:
            try:
                data = func(cdata, len(cdata))
                return  data
            except Exception:
                continue
        return None
    #
    # Decompress binary with efi_compressor from https://github.com/theopolis/uefi-firmware-parser
    #
    def decompress_file( self, CompressedFileName, OutputFileName, CompressionType ):
        CompressedFileData = chipsec.file.read_file( CompressedFileName )
        if CompressionType == 0: # not compressed
            shutil.copyfile( CompressedFileName, OutputFileName )
        elif CompressionType == 0x01:
            data = self.decompress_data( [ EFI, Tiano ], CompressedFileData )
        elif CompressionType == 0x02:
            data = self.decompress_data( [ LZMA, Tiano, EFI ] , CompressedFileData )
        if CompressionType != 0x00:
            if data is not None:
                chipsec.file.write_file( OutputFileName, data )
            else:
                logger().error( "Cannot decompress file (%s)" % ( CompressedFileName ) )
                return None
        return chipsec.file.read_file( OutputFileName )


    def get_tool_info( self, tool_type ):
        raise NotImplementedError()

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
        raise NotImplementedError()

    def write_io_port(self, io_port, value, size):
        raise NotImplementedError()

    def read_cr(self, cpu_thread_id, cr_number):
        raise NotImplementedError()

    def write_cr(self, cpu_thread_id, cr_number, value):
        raise NotImplementedError()

    def read_msr(self, thread_id, msr_addr):
        raise NotImplementedError()

    def write_msr(self, thread_id, msr_addr, eax, edx):
        raise NotImplementedError()

    def get_descriptor_table(self, cpu_thread_id, desc_table_code):
        raise NotImplementedError()

    def do_hypercall(self, vector, arg1, arg2, arg3, arg4, arg5, use_peach):
        raise NotImplementedError()

    def cpuid(self, eax, ecx):
        raise NotImplementedError()

    def alloc_phys_mem(self, num_bytes, max_addr):
        raise NotImplementedError()

    def msgbus_send_read_message( self, mcr, mcrx ):
        raise NotImplementedError()

    def msgbus_send_write_message( self, mcr, mcrx, mdr):
        raise NotImplementedError()

    def msgbus_send_message( self, mcr, mcrx, mdr=None):
        raise NotImplementedError()

    def get_affinity(self):
        raise NotImplementedError()

    def set_affinity(self, thread_id):
        raise NotImplementedError()

    def send_sw_smi( self, cpu_thread_id, SMI_code_data, _rax, _rbx, _rcx, _rdx, _rsi, _rdi):
        raise NotImplementedError()

    def map_io_space(self, base, size, cache_type):
        raise NotImplementedError()

def get_helper():
    return OSXHelper()
