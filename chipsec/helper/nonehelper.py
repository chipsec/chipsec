# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2023, Intel Corporation
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

from chipsec.library.exceptions import UnimplementedAPIError
from chipsec.helper.basehelper import Helper
from typing import Dict, List, Tuple, Optional, TYPE_CHECKING
if TYPE_CHECKING:
    from chipsec.library.types import EfiVariableType
    from ctypes import Array

# Base class for the helpers


class NoneHelper(Helper):

    def __init__(self):
        self.driver_loaded = False
        self.os_system = 'nonehelper'
        self.os_release = '0.0'
        self.os_version = '0.0'
        self.os_machine = 'base'
        self.name = 'NoneHelper'
        self.driverpath = ''

    def create(self) -> bool:
        raise UnimplementedAPIError('NoneHelper')

    def start(self) -> bool:
        raise UnimplementedAPIError('NoneHelper')

    def stop(self) -> bool:
        raise UnimplementedAPIError('NoneHelper')

    def delete(self) -> bool:
        raise UnimplementedAPIError('NoneHelper')

    def get_info(self) -> Tuple[str, str]:
        return self.name, self.driverpath

    #################################################################################################
    # Actual OS helper functionality accessible to HAL components

    #
    # Read/Write PCI configuration registers via legacy CF8/CFC ports
    #
    def read_pci_reg(self, bus: int, device: int, function: int, address: int, size: int) -> int:
        raise UnimplementedAPIError('NoneHelper')

    def write_pci_reg(self, bus: int, device: int, function: int, address: int, value: int, size: int) -> int:
        raise UnimplementedAPIError('NoneHelper')

    #
    # read/write mmio
    #
    def read_mmio_reg(self, phys_address: int, size: int) -> int:
        raise UnimplementedAPIError('NoneHelper')

    def write_mmio_reg(self, phys_address: int, size: int, value: int) -> int:
        raise UnimplementedAPIError('NoneHelper')

    #
    # physical_address is 64 bit integer
    #
    def read_phys_mem(self, phys_address: int, length: int) -> bytes:
        raise UnimplementedAPIError('NoneHelper')

    def write_phys_mem(self, phys_address: int, length: int, buf: bytes) -> int:
        raise UnimplementedAPIError('NoneHelper')

    def alloc_phys_mem(self, length: int, max_phys_address: int) -> Tuple[int, int]:
        raise UnimplementedAPIError('NoneHelper')

    def free_phys_mem(self, physical_address: int):
        raise UnimplementedAPIError('NoneHelper')

    def va2pa(self, va: int) -> Tuple[int, int]:
        raise UnimplementedAPIError('NoneHelper')

    def map_io_space(self, physical_address: int, length: int, cache_type: int) -> int:
        raise UnimplementedAPIError('NoneHelper')

    #
    # Read/Write I/O port
    #
    def read_io_port(self, io_port: int, size: int) -> int:
        raise UnimplementedAPIError('NoneHelper')

    def write_io_port(self, io_port: int, value: int, size: int) -> int:
        raise UnimplementedAPIError('NoneHelper')

    #
    # Read/Write CR registers
    #
    def read_cr(self, cpu_thread_id: int, cr_number: int) -> int:
        raise UnimplementedAPIError('NoneHelper')

    def write_cr(self, cpu_thread_id: int, cr_number: int, value: int) -> int:
        raise UnimplementedAPIError('NoneHelper')

    #
    # Read/Write MSR on a specific CPU thread
    #
    def read_msr(self, cpu_thread_id: int, msr_addr: int) -> Tuple[int, int]:
        raise UnimplementedAPIError('NoneHelper')

    def write_msr(self, cpu_thread_id: int, msr_addr: int, eax: int, edx: int) -> int:
        raise UnimplementedAPIError('NoneHelper')

    #
    # Load CPU microcode update on a specific CPU thread
    #
    def load_ucode_update(self, cpu_thread_id: int, ucode_update_buf: bytes) -> bool:
        raise UnimplementedAPIError('NoneHelper')

    #
    # Read IDTR/GDTR/LDTR on a specific CPU thread
    #
    def get_descriptor_table(self, cpu_thread_id: int, desc_table_code: int) -> Optional[Tuple[int, int, int]]:
        raise UnimplementedAPIError('NoneHelper')

    #
    # EFI Variable API
    #
    def EFI_supported(self) -> bool:
        raise UnimplementedAPIError('NoneHelper')

    def get_EFI_variable(self, name: str, guid: str) -> Optional[bytes]:
        raise UnimplementedAPIError('NoneHelper')

    def set_EFI_variable(self, name: str, guid: str, data: bytes, datasize: Optional[int], attrs: Optional[int]) -> Optional[int]:
        raise UnimplementedAPIError('NoneHelper')

    def delete_EFI_variable(self, name: str, guid: str) -> Optional[int]:
        raise UnimplementedAPIError('NoneHelper')

    def list_EFI_variables(self) -> Optional[Dict[str, List['EfiVariableType']]]:
        raise UnimplementedAPIError('NoneHelper')

    #
    # ACPI
    #

    def get_ACPI_table(self, table_name: str) -> Optional['Array']:
        raise UnimplementedAPIError('NoneHelper')
    
    def enum_ACPI_tables(self) -> Optional['Array']:
        raise UnimplementedAPIError('NoneHelper')

    #
    # CPUID
    #
    def cpuid(self, eax: int, ecx: int) -> Tuple[int, int, int, int]:
        raise UnimplementedAPIError('NoneHelper')

    #
    # IOSF Message Bus access
    #
    def msgbus_send_read_message(self, mcr: int, mcrx: int) -> Optional[int]:
        raise UnimplementedAPIError('NoneHelper')

    def msgbus_send_write_message(self, mcr: int, mcrx: int, mdr: int) -> None:
        raise UnimplementedAPIError('NoneHelper')

    def msgbus_send_message(self, mcr: int, mcrx: int, mdr: Optional[int]) -> Optional[int]:
        raise UnimplementedAPIError('NoneHelper')

    #
    # Affinity
    #
    def get_affinity(self) -> Optional[int]:
        raise UnimplementedAPIError('NoneHelper')

    def set_affinity(self, value: int) -> Optional[int]:
        raise UnimplementedAPIError('NoneHelper')

    #
    # Logical CPU count
    #
    def get_threads_count(self) -> int:
        raise UnimplementedAPIError('NoneHelper')

    #
    # Send SW SMI
    #
    def send_sw_smi(self, cpu_thread_id: int, SMI_code_data: int, _rax: int, _rbx: int, _rcx: int, _rdx: int, _rsi: int, _rdi: int) -> Optional[int]:
        raise UnimplementedAPIError('NoneHelper')

    #
    # Hypercall
    #
    def hypercall(self, rcx: int, rdx: int, r8: int, r9: int, r10: int, r11: int, rax: int, rbx: int, rdi: int, rsi: int, xmm_buffer: int) -> int:
        raise UnimplementedAPIError('NoneHelper')

    #
    # Speculation control
    #
    def retpoline_enabled(self) -> bool:
        raise UnimplementedAPIError('NoneHelper')
