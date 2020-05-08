#!/usr/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2018-2019, Intel Corporation
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
Use results from a json file
"""
import json
from sys import version

import chipsec.file
from chipsec.logger import logger
from chipsec.helper.oshelper import OsHelperError, UnimplementedAPIError
from chipsec.helper.basehelper import Helper
from chipsec.defines import bytestostring


class FileCmds:
    def __init__(self, filename):
        self.data = {}
        if filename == "":
            self.filename = "replay.json"
        else:
            self.filename = filename

    def AddElement(self,cmd,args,ret):
        try:
            margs = '({})'.format(','.join(str(i) for i in args))
        except:
            margs = str(args)
        if isinstance(ret, bytes):
            ret = bytestostring(ret)
        if str(cmd) in self.data:
            if margs in self.data[str(cmd)]:
                #using insert opposed to append so that it creates last in first out when using pop command within getElement
                self.data[str(cmd)][margs].insert(0,str(ret))
            else:
                self.data[str(cmd)][margs] = [str(ret)] 
        else:
            self.data[str(cmd)] = {margs:[str(ret)]}

    def Save(self):
        if version[0] == "3":
            js = json.dumps(self.data, sort_keys=False, indent=2, separators=(',', ': '))
        else:
            js = json.dumps(self.data, sort_keys=False, indent=2, separators=(',', ': '), encoding='latin_1')
        chipsec.file.write_file(self.filename,js)

    def Load(self):
        file_data = chipsec.file.read_file(self.filename)
        if file_data == 0:
            logger().error("Unable to open JSON file: {}".format(self.filename))
            raise OsHelperError("Unable to open JSON file: {}".format(self.filename),1)
        try:
            self.data = json.loads(file_data)
        except:
            logger().error("Unable to load JSON file: {}".format(self.filename))
            raise OsHelperError("Unable to open JSON file: {}".format(self.filename),1)

    def getElement(self,cmd,args):
        try:
            targs = '({})'.format(','.join(str(i) for i in args))
        except:
            targs = str(args)
        margs = targs.encode('latin_1')
        if str(cmd) in self.data:
            if margs in self.data[str(cmd)]:
                return self.data[cmd][margs].pop()
        logger().error("Missing entry for {} {}".format(str(cmd),margs))


class FileHelper(Helper):
    def __init__(self):
        super(FileHelper, self).__init__()
        self.os_system = "File"
        self.os_release = "0.0"
        self.os_version = "0.0"
        self.os_machine = "N/A"
        self.name = "FileHelper"

    def create(self, start_driver):
        if logger().VERBOSE:
            logger().log("[helper] File Helper created")
        return True

    def start(self, start_driver, from_file=None):
        self.filecmds = FileCmds(from_file)
        self.filecmds.Load()
        return True

    def stop( self, start_driver ):
        if logger().VERBOSE:
            logger().log("[helper] File Helper stopped/unloaded")
        return True

    def delete(self, start_driver):
        if logger().VERBOSE:
            logger().log("[helper] File Helper deleted")
        return True

    #################################################################################################
    # Actual OS helper functionality accessible to HAL components

    #
    # Read/Write PCI configuration registers via legacy CF8/CFC ports
    #
    def read_pci_reg( self, bus, device, function, address, size ):
        """Read PCI configuration registers via legacy CF8/CFC ports"""
        if ( 0 != (address & (size - 1)) ):
            logger().warn( "Config register address is not naturally aligned" )
        return self.filecmds.getElement("read_pci_reg",(bus,device,function,address,size))

    def write_pci_reg( self, bus, device, function, address, value, size ):
        """Write PCI configuration registers via legacy CF8/CFC ports"""
        if ( 0 != (address & (size - 1)) ):
            logger().warn( "Config register address is not naturally aligned" )

        return self.filecmds.getElement("write_pci_reg",(bus,device,function,address,size))

    #
    # read/write mmio
    #
    def read_mmio_reg( self, phys_address, size ):
        return self.filecmds.getElement("read_mmio_reg",(phys_address,size))

    def write_mmio_reg( self, phys_address, size, value ):
        return self.filecmds.getElement("write_mmio_reg",(phys_address, size, value))

    #
    # physical_address is 64 bit integer
    #
    def read_phys_mem( self, phys_address_hi, phys_address_lo, length ):
        ret = self.filecmds.getElement("read_physical_mem",(phys_address_hi, phys_address_lo,length))
        return ret.encode("latin_1")

    def write_phys_mem( self, phys_address_hi, phys_address_lo, length, buf ):
        return self.filecmds.getElement("write_physical_mem",(phys_address_hi, phys_address_lo,length,buf))

    def alloc_phys_mem( self, length, max_phys_address ):
        return self.filecmds.getElement("alloc_physical_mem",(length,max_phys_address))

    def free_phys_mem(self, physical_address):
        return self.filecmds.getElement("free_physical_mem",(physical_address))

    def va2pa( self, va ):
        return self.filecmds.getElement("va2pa",(va))

    def map_io_space(self, physical_address, length, cache_type):
        try:
            return self.filecmds.getElement("map_io_space",(physical_address, length, cache_type))
        except NotImplementedError:
            pass
        raise UnimplementedAPIError('map_io_space')

    #
    # Read/Write I/O portline 462, 
    #
    def read_io_port( self, io_port, size ):
        return self.filecmds.getElement("read_io_port",(io_port,size))

    def write_io_port( self, io_port, value, size ):
        return self.filecmds.getElement("write_io_port",(io_port,value,size))

    #
    # Read/Write CR registers
    #
    def read_cr(self, cpu_thread_id, cr_number):
        return self.filecmds.getElement("read_cr",(cpu_thread_id, cr_number))

    def write_cr(self, cpu_thread_id, cr_number, value):
        return self.filecmds.getElement("write_cr",(cpu_thread_id, cr_number,value))

    #
    # Read/Write MSR on a specific CPU thread
    #
    def read_msr( self, cpu_thread_id, msr_addr ):
        return self.filecmds.getElement("read_msr",(cpu_thread_id, msr_addr))

    def write_msr( self, cpu_thread_id, msr_addr, eax, edx ):
        return self.filecmds.getElement("write_msr",(cpu_thread_id, msr_addr, eax, edx))

    #
    # Load CPU microcode update on a specific CPU thread
    #
    def load_ucode_update( self, cpu_thread_id, ucode_update_buf ):
        return self.filecmds.getElement("load_ucode_update",(cpu_thread_id, ucode_update_buf))

    #
    # Read IDTR/GDTR/LDTR on a specific CPU thread
    #
    def get_descriptor_table( self, cpu_thread_id, desc_table_code ):
        return self.filecmds.getElement("get_descriptor_table",(cpu_thread_id, desc_table_code))

    #
    # EFI Variable API
    #
    def EFI_supported(self):
        return self.filecmds.getElement("EFI_supported",())

    def get_EFI_variable( self, name, guid ):
        return self.filecmds.getElement("get_EFI_variable",(name, guid))

    def set_EFI_variable( self, name, guid, data, datasize=None, attrs=None ):
        return self.filecmds.getElement("set_EFI_variable",(name, guid, data, datasize, attrs))

    def delete_EFI_variable( self, name, guid ):
        return self.filecmds.getElement("delete_EFI_variable",(name, guid))

    def list_EFI_variables( self ):
        return self.filecmds.getElement("list_EFI_variables",())

    #
    # ACPI
    #
    def get_ACPI_SDT(self):
        return self.filecmds.getElement("get_ACPI_SDT",())

    def get_ACPI_table( self, table_name ):
        return self.filecmds.getElement("get_ACPI_table",(table_name))


    #
    # CPUID
    #
    def cpuid( self, eax, ecx ):
        return self.filecmds.getElement("cpuid",(eax, ecx))

    #
    # IOSF Message Bus access
    #

    def msgbus_send_read_message( self, mcr, mcrx ):
        return self.filecmds.getElement("msgbus_send_read_message",(mcr, mcrx))

    def msgbus_send_write_message( self, mcr, mcrx, mdr ):
        return self.filecmds.getElement("msgbus_send_write_message",(mcr, mcrx, mdr))

    def msgbus_send_message( self, mcr, mcrx, mdr ):
        return self.filecmds.getElement("msgbus_send_message",(mcr, mcrx, mdr))

    #
    # Affinity
    #
    def get_affinity( self ):
        return self.filecmds.getElement("get_affinity",())

    def set_affinity( self, value ):
        return self.filecmds.getElement("set_affinity",(value))

    #
    # Logical CPU count
    #
    def get_threads_count( self ):
        return self.filecmds.getElement("get_threads_count",())

    #
    # Send SW SMI
    #
    def send_sw_smi( self, cpu_thread_id, SMI_code_data, _rax, _rbx, _rcx, _rdx, _rsi, _rdi ):
        return self.filecmds.getElement("send_sw_smi",(cpu_thread_id, SMI_code_data, _rax, _rbx, _rcx, _rdx, _rsi, _rdi))

    #
    # Hypercall
    #
    def hypercall( self, rcx=0, rdx=0, r8=0, r9=0, r10=0, r11=0, rax=0, rbx=0, rdi=0, rsi=0, xmm_buffer=0 ):
        return self.filecmds.getElement("hypercall",(rcx, rdx, r8, r9, r10, r11, rax, rbx, rdi, rsi, xmm_buffer))


    #
    # File system
    #
    def getcwd( self ):
        return self.filecmds.getElement("getcwd",())
    #
    # Decompress binary with OS specific tools
    #
    def decompress_file( self, CompressedFileName, OutputFileName, CompressionType ):
       return self.filecmds.getElement("decompress_file",(CompressedFileName, OutputFileName, CompressionType))

    #
    # Compress binary with OS specific tools
    #
    def compress_file( self, FileName, OutputFileName, CompressionType ):
        return self.filecmds.getElement("compress_file",(FileName, OutputFileName, CompressionType))

_helper = None

def get_helper():
    return FileHelper( )
