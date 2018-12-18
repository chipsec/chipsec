#!/usr/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2018, Intel Corporation
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

"""
msr-safe helper
"""

import os
import platform
import sys
from chipsec import defines

from chipsec.helper.oshelper import Helper, OsHelperError, HWAccessViolationError, UnimplementedAPIError, UnimplementedNativeAPIError
from chipsec.logger import logger, print_buffer

IOCTL_RDMSR_REGS    = 0xc02063a0
IOCTL_WRMSR_REGS    = 0xc02063a1
IOCTL_MSR_BATCH     = 0xc02063a2

MSR_struct          = "8I"

class MsrsafeHelper(Helper):

    def __init__(self):
        super(MsrsafeHelper, self).__init__()
        self.os_system  = platform.system()
        self.os_release = platform.release()
        self.os_version = platform.version()
        self.os_machine = platform.machine()
        self.os_uname   = platform.uname()
        self.dev_fh = {}
        
###############################################################################################
# Driver/service management functions
###############################################################################################

    def create(self, start_driver):
        if logger().VERBOSE:
            logger().log("[helper] Msr-safe Helper created")
        return True

    def start(self, start_driver, driver_exists=False):
        self.init(start_driver)
        if logger().VERBOSE:
            logger().log("[helper] Msr-safe Helper started/loaded")
        return True

    def stop(self, start_driver):
        self.close()
        if logger().VERBOSE:
            logger().log("[helper] Msr-safe Helper stopped/unloaded")
        return True

    def delete(self, start_driver):
        if logger().VERBOSE:
            logger().log("[helper] Msr-safe Helper deleted")
        return True
    
    def init(self, start_driver):
        x64 = True if sys.maxsize > 2**32 else False
        self._pack = 'Q' if x64 else 'I'

        if start_driver:
            if logger().VERBOSE: logger().log("****** Opening devices ******")
            oswalk = os.walk("/dev/cpu")
            for line in oswalk:
                if 'msr_safe' in line[2]:
                    try:
                        self.dev_fh[line[0].split('/')[-1]] = open("{}/msr_safe".format(line[0]), "r+")
                    except IOError as e:
                        raise OsHelperError("Unable to open chipsec device. Did you run as root/sudo and load the driver?\n {}".format(str(e)),e.errno)
                    except BaseException as be:
                        raise OsHelperError("Unable to open chipsec device. Did you run as root/sudo and load the driver?\n {}".format(str(be)),errno.ENXIO)
            return True

    def close(self):
        #change to cycle through all cpus
        for fh in self.dev_fh.keys():
            self.dev_fh[fh].close()
        self.dev_fh = None

    def msr_ioctl(self, nr, args, tid):
        if tid in self.dev_fh.keys():
            return fcntl.ioctl(self.dev_fh[str(tid)], nr, args)
        else:
            if logger().VERBOSE: logger().log("There is no msr_safe instance for cpu {}".format(tid))
            return None

###############################################################################################
# Actual API functions to access HW resources
###############################################################################################

    def map_io_space(self, base, size, cache_type):
        raise UnimplementedAPIError("map_io_space")

    def write_phys_mem(self, phys_address_hi, phys_address_lo, length, newval):
        raise UnimplementedAPIError("write_phys_mem")

    def read_phys_mem(self, phys_address_hi, phys_address_lo, length):
        raise UnimplementedAPIError("read_phys_mem")

    def read_pci_reg( self, bus, device, function, offset, size = 4 ):
        raise UnimplementedAPIError("read_pci_reg")

    def write_pci_reg( self, bus, device, function, offset, value, size = 4 ):
        raise UnimplementedAPIError("write_pci_reg")

    def load_ucode_update( self, cpu_thread_id, ucode_update_buf):
        raise UnimplementedAPIError("load_ucode_update")

    def read_io_port(self, io_port, size):
        raise UnimplementedAPIError("read_io_port")

    def write_io_port( self, io_port, value, size ):
        raise UnimplementedAPIError("write_io_port")

    def read_cr(self, cpu_thread_id, cr_number):
        raise UnimplementedAPIError("read_cr")

    def write_cr(self, cpu_thread_id, cr_number, value):
        raise UnimplementedAPIError("write_cr")

    def read_msr(self, thread_id, msr_addr):
        #reg layout: u32 gprs[eax,ecx,edx,ebx,esp,ebp,esi,edi]
        inbuf = struct.pack(MSR_struct,0,msr_addr,0,0,0,0,0,0)
        unbuf = struct.unpack(MSR_struct,self.msr_ioctl(IOCTL_RDMSR_REGS,inbuf,thread_id))
        return (unbuf[0],unbuf[2])

    def write_msr(self, thread_id, msr_addr, eax, edx):
        #reg layout: u32 gprs[eax,ecx,edx,ebx,esp,ebp,esi,edi]
        inbuf = struct.pack(MSR_struct,eax,msr_addr,edx,0,0,0,0,0)
        self.msr_ioctl(IOCTL_WRMSR_REGS,inbuf,thread_id)
        return

    def get_descriptor_table(self, cpu_thread_id, desc_table_code  ):
        raise UnimplementedAPIError("get_descriptor_table")

    def cpuid(self, eax, ecx):
        raise UnimplementedAPIError("cpuid")

    def alloc_phys_mem(self, num_bytes, max_addr):
        raise UnimplementedAPIError("alloc_phys_mem")

    def free_phys_mem(self, physmem):
        raise UnimplementedAPIError("free_phys_mem")

    def read_mmio_reg(self, phys_address, size):
        raise UnimplementedAPIError("read_mmio_reg")

    def write_mmio_reg(self, phys_address, size, value):
        raise UnimplementedAPIError("write_mmio_reg")

    def get_ACPI_SDT( self ):
        raise UnimplementedAPIError( "get_ACPI_SDT" )

    def get_ACPI_table( self ):
        raise UnimplementedAPIError( "get_ACPI_table" )

    def msgbus_send_read_message( self, mcr, mcrx ):
        raise UnimplementedAPIError("msgbus_send_read_message")

    def msgbus_send_write_message( self, mcr, mcrx, mdr ):
        raise UnimplementedAPIError("msgbus_send_write_message")

    def msgbus_send_message( self, mcr, mcrx, mdr=None ):
        raise UnimplementedAPIError("msgbus_send_message")

    def get_affinity(self):
        raise UnimplementedAPIError("get_affinity")

    def set_affinity(self, thread_id):
        raise UnimplementedAPIError("set_affinity")

    def delete_EFI_variable(self, name, guid):
        raise UnimplementedAPIError("delete_EFI_variable")

    def list_EFI_variables(self):
        raise UnimplementedAPIError("list_EFI_variables")

    def get_EFI_variable(self, name, guid, attrs=None):
        raise UnimplementedAPIError("get_EFI_variable")

    def set_EFI_variable(self, name, guid, data, datasize, attrs=None):
        raise UnimplementedAPIError("set_EFI_variable")

    def hypercall( self, rcx, rdx, r8, r9, r10, r11, rax, rbx, rdi, rsi, xmm_buffer ):
        raise UnimplementedAPIError("hypercall")

    def send_sw_smi( self, cpu_thread_id, SMI_code_data, _rax, _rbx, _rcx, _rdx, _rsi, _rdi ):
        raise UnimplementedAPIError("send_sw_smi")

    def decompress_file( self, CompressedFileName, OutputFileName, CompressionType ):
        raise UnimplementedAPIError("decompress_file")

    def get_threads_count ( self ):
        raise UnimplementedAPIError("get_threads_count")

def get_helper():
    return MsrsafeHelper()




