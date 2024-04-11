# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2019-2021, Intel Corporation
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

from abc import ABC, abstractmethod
from typing import Dict, List, Tuple, Optional, TYPE_CHECKING
if TYPE_CHECKING:
    from chipsec.library.types import EfiVariableType
    from ctypes import Array

# Base class for the helpers


class Helper(ABC):
    class __metaclass__(type):
        def __init__(cls, name, bases, attrs):
            if not hasattr(cls, 'registry'):
                cls.registry = []
            else:
                cls.registry.append((name, cls))

    @abstractmethod
    def __init__(self):
        self.driver_loaded = False
        self.os_system = 'basehelper'
        self.os_release = '0.0'
        self.os_version = '0.0'
        self.os_machine = 'base'
        self.name = 'Helper'
        self.driverpath = ''

    @abstractmethod
    def create(self) -> bool:
        pass

    @abstractmethod
    def start(self) -> bool:
        pass

    @abstractmethod
    def stop(self) -> bool:
        pass

    @abstractmethod
    def delete(self) -> bool:
        pass

    def get_info(self) -> Tuple[str, str]:
        return self.name, self.driverpath

    #################################################################################################
    # Actual OS helper functionality accessible to HAL components

    #
    # Read/Write PCI configuration registers via legacy CF8/CFC ports
    #
    @abstractmethod
    def read_pci_reg(self, bus: int, device: int, function: int, address: int, size: int) -> int:
        pass

    @abstractmethod
    def write_pci_reg(self, bus: int, device: int, function: int, address: int, value: int, size: int) -> int:
        pass

    #
    # read/write mmio
    #
    @abstractmethod
    def read_mmio_reg(self, phys_address: int, size: int) -> int:
        pass

    @abstractmethod
    def write_mmio_reg(self, phys_address: int, size: int, value: int) -> int:
        pass

    #
    # physical_address is 64 bit integer
    #
    @abstractmethod
    def read_phys_mem(self, phys_address: int, size: int) -> bytes:
        pass

    @abstractmethod
    def write_phys_mem(self, phys_address: int, size: int, buffer: bytes) -> int:
        pass

    @abstractmethod
    def alloc_phys_mem(self, size: int, max_phys_address: int) -> Tuple[int, int]:
        pass

    @abstractmethod
    def free_phys_mem(self, phys_address: int):
        pass

    @abstractmethod
    def va2pa(self, virtual_address: int) -> Tuple[int, int]:
        pass

    @abstractmethod
    def map_io_space(self, phys_address: int, size: int, cache_type: int) -> int:
        pass

    #
    # Read/Write I/O port
    #
    @abstractmethod
    def read_io_port(self, io_port: int, size: int) -> int:
        pass

    @abstractmethod
    def write_io_port(self, io_port: int, value: int, size: int) -> int:
        pass

    #
    # Read/Write CR registers
    #
    @abstractmethod
    def read_cr(self, cpu_thread_id: int, cr_number: int) -> int:
        pass

    @abstractmethod
    def write_cr(self, cpu_thread_id: int, cr_number: int, value: int) -> int:
        pass

    #
    # Read/Write MSR on a specific CPU thread
    #
    @abstractmethod
    def read_msr(self, cpu_thread_id: int, msr_addr: int) -> Tuple[int, int]:
        pass

    @abstractmethod
    def write_msr(self, cpu_thread_id: int, msr_addr: int, eax: int, edx: int) -> int:
        pass

    #
    # Load CPU microcode update on a specific CPU thread
    #
    @abstractmethod
    def load_ucode_update(self, cpu_thread_id: int, ucode_update_buffer: bytes) -> bool:
        pass

    #
    # Read IDTR/GDTR/LDTR on a specific CPU thread
    #
    @abstractmethod
    def get_descriptor_table(self, cpu_thread_id: int, desc_table_code: int) -> Optional[Tuple[int, int, int]]:
        pass

    #
    # EFI Variable API
    #
    @abstractmethod
    def EFI_supported(self) -> bool:
        pass

    @abstractmethod
    def get_EFI_variable(self, name: str, guid: str) -> Optional[bytes]:
        pass

    @abstractmethod
    def set_EFI_variable(self, name: str, guid: str, buffer: bytes, buffer_size: Optional[int], attrs: Optional[int]) -> Optional[int]:
        pass

    @abstractmethod
    def delete_EFI_variable(self, name: str, guid: str) -> Optional[int]:
        pass

    @abstractmethod
    def list_EFI_variables(self) -> Optional[Dict[str, List['EfiVariableType']]]:
        pass

    #
    # ACPI
    #
    @abstractmethod
    def enum_ACPI_tables(self) -> Optional['Array']:
        pass

    @abstractmethod
    def get_ACPI_table(self, table_name: str) -> Optional['Array']:
        pass

    #
    # CPUID
    #
    @abstractmethod
    def cpuid(self, eax: int, ecx: int) -> Tuple[int, int, int, int]:
        pass

    #
    # IOSF Message Bus access
    #
    @abstractmethod
    def msgbus_send_read_message(self, mcr: int, mcrx: int) -> Optional[int]:
        pass

    @abstractmethod
    def msgbus_send_write_message(self, mcr: int, mcrx: int, mdr: int) -> None:
        pass

    @abstractmethod
    def msgbus_send_message(self, mcr: int, mcrx: int, mdr: Optional[int]) -> Optional[int]:
        pass

    #
    # Affinity
    #
    @abstractmethod
    def get_affinity(self) -> Optional[int]:
        pass

    @abstractmethod
    def set_affinity(self, value: int) -> Optional[int]:
        pass

    #
    # Logical CPU count
    #
    @abstractmethod
    def get_threads_count(self) -> int:
        pass

    #
    # Send SW SMI
    #
    @abstractmethod
    def send_sw_smi(self, cpu_thread_id: int, SMI_code_data: int, _rax: int, _rbx: int, _rcx: int, _rdx: int, _rsi: int, _rdi: int) -> Optional[int]:
        pass

    #
    # Hypercall
    #
    @abstractmethod
    def hypercall(self, rcx: int, rdx: int, r8: int, r9: int, r10: int, r11: int, rax: int, rbx: int, rdi: int, rsi: int, xmm_buffer: int) -> int:
        pass

    #
    # Speculation control
    #
    @abstractmethod
    def retpoline_enabled(self) -> bool:
        pass
