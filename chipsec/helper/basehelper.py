#!/usr/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2019, Intel Corporation
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
from chipsec.logger import logger

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
        self.os_system = "basehelper"
        self.os_release = "0.0"
        self.os_version = "0.0"
        self.os_machine = "base"
        self.name = "Helper"
        self.driverpath = None

    def use_native_api(self):
        return (not self.driver_loaded)

    def create(self, start_driver):
        if logger().VERBOSE:
            logger().log("[helper] Helper created")
        raise NotImplementedError()

    def start(self, start_driver, from_file=None):
        if logger().VERBOSE:
            logger().log("[helper] Helper started/loaded")
        raise NotImplementedError()

    def stop( self, start_driver ):
        if logger().VERBOSE:
            logger().log("[helper] Helper stopped/unloaded")
        raise NotImplementedError()

    def delete(self, start_driver):
        if logger().VERBOSE:
            logger().log("[helper] Helper deleted")
        raise NotImplementedError()

    def get_info(self):
        return self.name, self.driverpath

    #################################################################################################
    # Actual OS helper functionality accessible to HAL components
    
    #
    # Read/Write PCI configuration registers via legacy CF8/CFC ports
    #
    def read_pci_reg( self, bus, device, function, address, size ):
        """Read PCI configuration registers via legacy CF8/CFC ports"""
        raise NotImplementedError()


    def write_pci_reg( self, bus, device, function, address, value, size ):
        """Write PCI configuration registers via legacy CF8/CFC ports"""
        raise NotImplementedError()


    #
    # read/write mmio
    #
    def read_mmio_reg( self, phys_address, size ):
        raise NotImplementedError()

    def write_mmio_reg( self, phys_address, size, value ):
        raise NotImplementedError()

    #
    # physical_address is 64 bit integer
    #
    def read_phys_mem( self, phys_address_hi, phys_address_lo, length ):
        raise NotImplementedError()

    def write_phys_mem( self, phys_address_hi, phys_address_lo, length, buf ):
        raise NotImplementedError()

    def alloc_phys_mem( self, length, max_phys_address ):
        raise NotImplementedError()

    def free_phys_mem(self, physical_address):
        raise NotImplementedError()

    def va2pa( self, va ):
        raise NotImplementedError()

    def map_io_space(self, physical_address, length, cache_type):
        raise NotImplementedError()

    #
    # Read/Write I/O portline 462, 
    #
    def read_io_port( self, io_port, size ):
        raise NotImplementedError()

    def write_io_port( self, io_port, value, size ):
        raise NotImplementedError()

    #
    # Read/Write CR registers
    #
    def read_cr(self, cpu_thread_id, cr_number):
        raise NotImplementedError()

    def write_cr(self, cpu_thread_id, cr_number, value):
        raise NotImplementedError()

    #
    # Read/Write MSR on a specific CPU thread
    #
    def read_msr( self, cpu_thread_id, msr_addr ):
        raise NotImplementedError()

    def write_msr( self, cpu_thread_id, msr_addr, eax, edx ):
        raise NotImplementedError()

    #
    # Load CPU microcode update on a specific CPU thread
    #
    def load_ucode_update( self, cpu_thread_id, ucode_update_buf ):
        raise NotImplementedError()

    #
    # Read IDTR/GDTR/LDTR on a specific CPU thread
    #
    def get_descriptor_table( self, cpu_thread_id, desc_table_code ):
        raise NotImplementedError()

    #
    # EFI Variable API
    #
    def EFI_supported(self):
        raise NotImplementedError()

    def get_EFI_variable( self, name, guid ):
        raise NotImplementedError()

    def set_EFI_variable( self, name, guid, data, datasize=None, attrs=None ):
        raise NotImplementedError()

    def delete_EFI_variable( self, name, guid ):
        raise NotImplementedError()

    def list_EFI_variables( self ):
        raise NotImplementedError()

    #
    # ACPI
    #
    def get_ACPI_SDT(self):
        raise NotImplementedError()

    def get_ACPI_table( self, table_name ):
        raise NotImplementedError()

    #
    # CPUID
    #
    def cpuid( self, eax, ecx ):
        raise NotImplementedError()

    #
    # IOSF Message Bus access
    #
    def msgbus_send_read_message( self, mcr, mcrx ):
        raise NotImplementedError()

    def msgbus_send_write_message( self, mcr, mcrx, mdr ):
        raise NotImplementedError()

    def msgbus_send_message( self, mcr, mcrx, mdr ):
        raise NotImplementedError()

    #
    # Affinity
    #
    def get_affinity( self ):
        raise NotImplementedError()

    def set_affinity( self, value ):
        raise NotImplementedError()

    #
    # Logical CPU count
    #
    def get_threads_count( self ):
        raise NotImplementedError()

    #
    # Send SW SMI
    #
    def send_sw_smi( self, cpu_thread_id, SMI_code_data, _rax, _rbx, _rcx, _rdx, _rsi, _rdi ):
        raise NotImplementedError()

    #
    # Hypercall
    #
    def hypercall( self, rcx=0, rdx=0, r8=0, r9=0, r10=0, r11=0, rax=0, rbx=0, rdi=0, rsi=0, xmm_buffer=0 ):
        raise NotImplementedError()

    #
    # File system
    #
    def getcwd( self ):
        raise NotImplementedError()

    #
    # Decompress binary with OS specific tools
    #
    def decompress_file( self, CompressedFileName, OutputFileName, CompressionType ):
        raise NotImplementedError()

    #
    # Compress binary with OS specific tools
    #
    def compress_file( self, FileName, OutputFileName, CompressionType ):
        raise NotImplementedError()
