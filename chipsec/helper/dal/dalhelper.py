# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2021, Intel Corporation
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
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
# Contact information:
# chipsec@intel.com
#


"""
Intel DFx Abstraction Layer (DAL) helper

From the Intel(R) DFx Abstraction Layer Python* Command Line Interface User Guide

"""

import struct

from chipsec.library.logger import logger
try:
    import itpii
except:
    pass
from ctypes import c_char
from typing import Optional, Tuple, TYPE_CHECKING
if TYPE_CHECKING:
    from ctypes import Array
from chipsec.helper.basehelper import Helper
from chipsec.library.exceptions import DALHelperError, UnimplementedAPIError


class DALHelper(Helper):
    def __init__(self):
        super(DALHelper, self).__init__()
        self.base = itpii.baseaccess()
        self.is_system_halted = True
        logger().log_debug('[helper] DAL Helper')
        if not len(self.base.threads):
            logger().log('[helper] No threads detected!  DAL Helper will fail to load!')
        elif self.base.threads[self.find_thread()].cv.isrunning:
            self.is_system_halted = False
            self.base.halt()
        self.os_system = '(Via Intel DAL)'
        self.os_release = '(N/A)'
        self.os_version = self.dal_version()
        self.os_machine = self.target_machine()
        self.name = "DALHelper"

    def __del__(self):
        if not len(self.base.threads):
            logger().log('[helper] No threads detected!')
        elif not self.is_system_halted:
            logger().log('[helper] Threads are halted')
        else:
            self.base.go()
            logger().log('[helper] Threads are running')


###############################################################################################
# Driver/service management functions
###############################################################################################

    def create(self, start_driver: bool) -> bool:
        logger().log_debug('[helper] DAL Helper created')
        return True

    def start(self, start_driver: bool, driver_exhists: bool = False) -> bool:
        self.driver_loaded = True
        if self.base.threads[self.find_thread()].cv.isrunning:
            self.base.halt()
            self.is_system_halted = False
        logger().log_debug('[helper] DAL Helper started/loaded')
        return True

    def stop(self) -> bool:
        if not self.is_system_halted:
            self.base.go()
        logger().log_debug('[helper] DAL Helper stopped/unloaded')
        return True

    def delete(self) -> bool:
        logger().log_debug('[helper] DAL Helper deleted')
        return True


###############################################################################################
# Functions to get information about the remote target
###############################################################################################

    def target_machine(self) -> str:
        return f'{self.base.devicelist[0].devicetype}-{self.base.devicelist[0].stepping}'

    def dal_version(self) -> str:
        return self.base.cv.version

    # return first enabled thread
    def find_thread(self) -> int:
        for en_thread in range(len(self.base.threads)):
            if self.base.threads[en_thread].isenabled:
                return en_thread
        logger().log_debug('[WARNING] No enabled threads found.')
        return 0

###############################################################################################
# Actual API functions to access HW resources
###############################################################################################

    #
    # PCIe configuration access
    #

    def pci_addr(self, bus: int, device: int, function: int, offset: int) -> int:
        if (bus >= 256) or (device >= 32) or (function >= 8) or (offset >= 256):
            logger().log_debug('[WARNING] PCI access out of range. Use mmio functions to access PCIEXBAR.')
        config_addr = self.base.threads[self.find_thread()].dport(0xCF8)
        config_addr &= 0x7f000003
        config_addr |= 0x80000000
        config_addr |= (bus & 0xFF) << 16
        config_addr |= (device & 0x1F) << 11
        config_addr |= (function & 0x07) << 8
        config_addr |= (offset & 0xFF) << 0
        return config_addr

    def read_pci_reg(self, bus: int, device: int, function: int, address: int, size: int) -> int:
        ie_thread = self.find_thread()
        self.base.threads[ie_thread].dport(0xCF8, self.pci_addr(bus, device, function, address))
        value = (self.base.threads[ie_thread].dport(0xCFC) >> ((address % 4) * 8))
        if 1 == size:
            value &= 0xFF
        elif 2 == size:
            value &= 0xFFFF
        return value.ToUInt32()

    def write_pci_reg(self, bus: int, device: int, function: int, address: int, dword_value: int, size: int) -> int:
        ie_thread = self.find_thread()
        self.base.threads[ie_thread].dport(0xCF8, self.pci_addr(bus, device, function, address))
        old_value = self.base.threads[ie_thread].dport(0xCFC)
        self.base.threads[ie_thread].dport(0xCFC, dword_value)
        return old_value

    #
    # Physical memory access
    #

    def read_phys_mem(self, phys_address: int, length: int, bytewise: bool = False) -> bytes:
        if bytewise:
            width = 1
        else:
            width = 8
        out_buf = (c_char * length)()
        ptr = 0
        format = {1: 'B', 2: 'H', 4: 'L', 8: 'Q'}
        while width >= 1:
            while (length - ptr) >= width:
                v = self.base.threads[self.find_thread()].mem(itpii.Address((phys_address + ptr), itpii.AddressType.physical), width)
                struct.pack_into(format[width], out_buf, ptr, v.ToUInt64())
                ptr += width
            width = width // 2
        return b''.join(out_buf)

    def write_phys_mem(self, phys_address: int, length: int, buf: bytes, bytewise: bool = False) -> int:
        if bytewise:
            width = 1
        else:
            width = 8
        ptr = 0
        format = {1: 'B', 2: 'H', 4: 'L', 8: 'Q'}
        while width >= 1:
            while (length - ptr) >= width:
                v = struct.unpack_from(format[width], buf, ptr)
                self.base.threads[self.find_thread()].mem(itpii.Address((phys_address + ptr), itpii.AddressType.physical), width, v[0])
                ptr += width
            width = width // 2
        return 1

    def va2pa(self, va):
        raise UnimplementedAPIError('va2pa')

    def alloc_phys_mem(self, length, max_phys_address):
        raise UnimplementedAPIError('alloc_phys_mem')

    def free_phys_mem(self, physical_address):
        raise UnimplementedAPIError('free_phys_mem')

    #
    # CPU I/O port access
    #

    def read_io_port(self, io_port: int, size: int) -> int:
        if size == 1:
            val = self.base.threads[self.find_thread()].port(io_port)
        elif size == 2:
            val = self.base.threads[self.find_thread()].wport(io_port)
        elif size == 4:
            val = self.base.threads[self.find_thread()].dport(io_port)
        else:
            raise DALHelperError(size, 'is not a valid IO port size.')
        return val.ToUInt32()

    def write_io_port(self, io_port: int, value: int, size: int) -> int:
        if size == 1:
            ret = self.base.threads[self.find_thread()].port(io_port, value)
        elif size == 2:
            ret = self.base.threads[self.find_thread()].wport(io_port, value)
        elif size == 4:
            ret = self.base.threads[self.find_thread()].dport(io_port, value)
        else:
            raise DALHelperError(size, 'is not a valid IO port size.')
        return ret

    #
    # CPU related API
    #

    def read_msr(self, thread: int, msr_addr: int) -> Tuple[int, int]:
        if not self.base.threads[thread].isenabled:
            en_thread = self.find_thread()
            logger().log_debug(f'[WARNING] Selected thread [{thread:d}] was disabled, using [{en_thread:d}].')
            thread = en_thread
        val = self.base.threads[thread].msr(msr_addr)
        edx = (val.ToUInt64() >> 32)
        eax = val.ToUInt64() & 0xffffffff
        return (eax, edx)

    def write_msr(self, thread: int, msr_addr: int, eax: int, edx: int) -> int:
        if not self.base.threads[thread].isenabled:
            en_thread = self.find_thread()
            logger().log_debug(f'[WARNING] Selected thread [{thread:d}] was disabled, using [{en_thread:d}].')
            thread = en_thread
        val = (edx << 32) | eax
        self.base.threads[thread].msr(msr_addr, val)
        return True

    def read_cr(self, cpu_thread_id: int, cr_number: int) -> int:
        if not self.base.threads[cpu_thread_id].isenabled:
            en_thread = self.find_thread()
            logger().log_debug(f'[WARNING] Selected thread [{cpu_thread_id:d}] was disabled, using [{en_thread:d}].')
            cpu_thread_id = en_thread
        if cr_number == 0:
            val = self.base.threads[cpu_thread_id].state.regs.cr0.value
        elif cr_number == 2:
            val = self.base.threads[cpu_thread_id].state.regs.cr2.value
        elif cr_number == 3:
            val = self.base.threads[cpu_thread_id].state.regs.cr3.value
        elif cr_number == 4:
            val = self.base.threads[cpu_thread_id].state.regs.cr4.value
        elif cr_number == 8:
            val = self.base.threads[cpu_thread_id].state.regs.cr8.value
        else:
            logger().log_debug(f'[ERROR] Selected CR{cr_number:d} is not supported.')
            val = 0
        return val

    def write_cr(self, cpu_thread_id: int, cr_number: int, value: int) -> int:
        if not self.base.threads[cpu_thread_id].isenabled:
            en_thread = self.find_thread()
            logger().log_debug(f'[WARNING] Selected thread [{cpu_thread_id:d}] was disabled, using [{en_thread:d}].')
            cpu_thread_id = en_thread
        if cr_number == 0:
            self.base.threads[cpu_thread_id].state.regs.cr0 = value
        elif cr_number == 2:
            self.base.threads[cpu_thread_id].state.regs.cr2 = value
        elif cr_number == 3:
            self.base.threads[cpu_thread_id].state.regs.cr3 = value
        elif cr_number == 4:
            self.base.threads[cpu_thread_id].state.regs.cr4 = value
        elif cr_number == 8:
            self.base.threads[cpu_thread_id].state.regs.cr8 = value
        else:
            logger().log_debug(f'[ERROR] Selected CR{cr_number:d} is not supported.')
            return False
        return True

    def load_ucode_update(self, core_id, ucode_update_buf):
        raise UnimplementedAPIError('load_ucode_update')

    def get_threads_count(self) -> int:
        no_threads = len(self.base.threads)
        logger().log_debug(f'[helper] Threads discovered : 0x{no_threads:X} ({no_threads:d})')
        return no_threads

    def cpuid(self, eax: int, ecx: int) -> Tuple[int, int, int, int]:
        ie_thread = self.find_thread()
        reax = self.base.threads[ie_thread].cpuid_eax(eax, ecx)
        rebx = self.base.threads[ie_thread].cpuid_ebx(eax, ecx)
        recx = self.base.threads[ie_thread].cpuid_ecx(eax, ecx)
        redx = self.base.threads[ie_thread].cpuid_edx(eax, ecx)
        return (reax, rebx, recx, redx)

    def get_descriptor_table(self, cpu_thread_id, desc_table_code):
        raise UnimplementedAPIError('get_descriptor_table')

    def retpoline_enabled(self) -> bool:
        return False

    #
    # EFI Variable API
    #

    def EFI_supported(self) -> bool:
        return False

    def delete_EFI_variable(self, name, guid):
        raise UnimplementedAPIError('delete_EFI_variable')

    def list_EFI_variables(self):
        raise UnimplementedAPIError('list_EFI_variables')

    def get_EFI_variable(self, name, guid, attrs):
        raise UnimplementedAPIError('get_EFI_variable')

    def set_EFI_variable(self, name, guid, buffer, buffer_size, attrs):
        raise UnimplementedAPIError('set_EFI_variable')

    #
    # Memory-mapped I/O (MMIO) access
    #

    def map_io_space(self, physical_address: int, length: int, cache_type: int) -> int:
        return physical_address

    def read_mmio_reg(self, phys_address: int, size: int) -> int:
        out_buf = self.read_phys_mem(phys_address, size)
        if size == 8:
            value = struct.unpack('=Q', out_buf[:size])[0]
        elif size == 4:
            value = struct.unpack('=I', out_buf[:size])[0]
        elif size == 2:
            value = struct.unpack('=H', out_buf[:size])[0]
        elif size == 1:
            value = struct.unpack('=B', out_buf[:size])[0]
        else:
            value = 0
        return value

    def write_mmio_reg(self, phys_address: int, size: int, value: int) -> int:
        if size == 8:
            buf = struct.pack('=Q', value)
        elif size == 4:
            buf = struct.pack('=I', value & 0xFFFFFFFF)
        elif size == 2:
            buf = struct.pack('=H', value & 0xFFFF)
        elif size == 1:
            buf = struct.pack('=B', value & 0xFF)
        else:
            buf = bytes(1)
        return self.write_phys_mem(phys_address, size, buf)

    #
    # Interrupts
    #
    def send_sw_smi(self, cpu_thread_id, SMI_code_data, _rax, _rbx, _rcx, _rdx, _rsi, _rdi):
        raise UnimplementedAPIError('send_sw_smi')

    def set_affinity(self, value):
        raise UnimplementedAPIError('set_affinity')

    def get_affinity(self):
        raise UnimplementedAPIError('get_affinity')

    #
    # ACPI tables access
    #
    def get_ACPI_table(self, table_name: str) -> Optional['Array']:
        raise UnimplementedAPIError('get_ACPI_table')
    
    def enum_ACPI_tables(self) -> Optional['Array']:
        raise UnimplementedAPIError('enum_ACPI_table')

    #
    # IOSF Message Bus access
    #
    def msgbus_send_read_message(self, mcr, mcrx):
        raise UnimplementedAPIError('msgbus_send_read_message')

    def msgbus_send_write_message(self, mcr, mcrx, mdr):
        raise UnimplementedAPIError('msgbus_send_write_message')

    def msgbus_send_message(self, mcr, mcrx, mdr):
        raise UnimplementedAPIError('msgbus_send_message')

    #
    # File system
    #
    def get_tool_info(self, tool_type: str) -> Tuple[str, str]:
        return ('', '')


    def hypercall(self, rcx, rdx, r8, r9, r10, r11, rax, rbx, rdi, rsi, xmm_buffer):
        raise UnimplementedAPIError('hypercall')



def get_helper() -> DALHelper:
    return DALHelper()


if __name__ == '__main__':
    try:
        print('Not doing anything...')

    except DALHelperError as msg:
        if logger().DEBUG:
            logger().log_error(msg)
