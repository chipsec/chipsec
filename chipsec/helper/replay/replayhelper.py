# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2023, Intel Corporation

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; Version 2.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

from json import loads
import os
from errno import EACCES, EFAULT
from glob import glob
import re
from importlib import import_module
from typing import Any, Dict, List, Optional, Tuple
from chipsec.library.defines import stringtobytes
from chipsec.library.exceptions import OsHelperError
from chipsec.library.file import read_file
from chipsec.library.logger import logger
from chipsec.helper.basehelper import Helper


class ReplayHelper(Helper):

    def __init__(self, filepath: str = ""):
        super(ReplayHelper, self).__init__()
        self.os_system = "test_helper"
        self.os_release = "0"
        self.os_version = "0"
        self.os_machine = "test"
        self.driver_loaded = True
        self.name = "ReplayHelper"
        if filepath and os.path.isfile(filepath):
            self.config_file = filepath
        else:
            files = glob(os.path.join("chipsec", "helper", "record", "*.json"))
            if files:
                self.config_file = max(files, key=os.path.getctime)
            else:
                raise FileNotFoundError("Cannot find a recorded file to load")
        self._data = {}

    def create(self) -> bool:
        return True

    def start(self) -> bool:
        self._load()
        return True

    def stop(self) -> bool:
        return True

    def delete(self) -> bool:
        return True

    def _get_element_eval(self, cmd: str, args: Tuple) -> Optional[Any]:
        element = self._get_element(cmd, args)
        if type(element) is str:
            ematch = re.match(r'^!! <class \'(.*)\'>: (.*)', element)
            if ematch:
                eimport = ematch[1].split('.')
                etype = getattr(import_module('.'.join(eimport[0:-1])), eimport[-1])
                raise etype(ematch[2])
        try:
            evaledobject = eval(element)
        except Exception:
            try:
                evaledobject = stringtobytes(element)
            except Exception:
                return None
        return evaledobject

    def _get_element(self, cmd: str, args: Tuple) -> Optional[Any]:
        try:
            targs = f"({','.join(str(i) for i in args)})"
        except Exception:
            targs = str(args)
        if str(cmd) in self._data:
            if targs in self._data[str(cmd)]:
                try:
                    return self._data[cmd][targs].pop()
                except IndexError as err:
                    logger().log_error(f'Ran out of entries for {str(cmd)} {targs}')
                    err.args = (err.args[0] + f': {str(cmd)} {targs}',)
                    raise err
        logger().log_error(f"Missing entry for {str(cmd)} {targs}")
        return None

    def _load(self) -> None:
        file_data = read_file(self.config_file)
        if file_data == 0:
            raise OsHelperError(f"Unable to open JSON File: {self.config_file}", EACCES)
        try:
            self._data = loads(file_data)
        except Exception:
            raise OsHelperError(f'Unable to load JSON File: {self.config_file}', EFAULT)

    def read_pci_reg(self, bus: int, device: int, function: int, offset: int, size: int) -> int:
        return self._get_element_eval("read_pci_reg", (bus, device, function, offset, size))

    def write_pci_reg(self, bus: int, device: int, function: int, offset: int, value: int, size: int) -> int:
        return self._get_element_eval("write_pci_reg", (bus, device, function, offset, value, size))

    def read_mmio_reg(self, phys_address: int, size: int) -> int:
        return self._get_element_eval("read_mmio_reg", (phys_address, size))

    def write_mmio_reg(self, phys_address: int, size: int, value: int) -> int:
        return self._get_element_eval("write_mmio_reg", (phys_address, size, value))

    #
    # physical_address is 64 bit integer
    #
    def read_phys_mem(self, phys_address: int, length: int) -> bytes:
        return stringtobytes(self._get_element("read_phys_mem", (phys_address, length)))

    def write_phys_mem(self, phys_address: int, length: int, buf: bytes) -> int:
        return self._get_element_eval("write_phys_mem", (phys_address, length, buf))

    def alloc_phys_mem(self, length: int, max_phys_address: int) -> Tuple[int, int]:
        return self._get_element_eval("alloc_phys_mem", (length, max_phys_address))

    def free_phys_mem(self, phys_address: int) -> Optional[int]:
        return self._get_element_eval("free_phys_mem", (phys_address, ))

    def va2pa(self, virtual_address: int) -> Tuple[int, int]:
        return self._get_element_eval("va2pa", (virtual_address, ))

    def map_io_space(self, phys_address: int, length: int, cache_type: int) -> int:
        return self._get_element_eval("map_io_space", (phys_address, length, cache_type))

    #
    # Read/Write I/O port
    #
    def read_io_port(self, io_port: int, size: int) -> int:
        return self._get_element_eval("read_io_port", (io_port, size))

    def write_io_port(self, io_port: int, value: int, size: int) -> int:
        return self._get_element_eval("write_io_port", (io_port, value, size))

    #
    # Read/Write CR registers
    #
    def read_cr(self, cpu_thread_id: int, cr_number: int) -> int:
        return self._get_element_eval("read_cr", (cpu_thread_id, cr_number))

    def write_cr(self, cpu_thread_id: int, cr_number: int, value: int) -> int:
        return self._get_element_eval("write_cr", (cpu_thread_id, cr_number, value))

    #
    # Read/Write MSR on a specific CPU thread
    #
    def read_msr(self, cpu_thread_id: int, msr_addr: int) -> Tuple[int, int]:
        return self._get_element_eval("read_msr", (cpu_thread_id, msr_addr))

    def write_msr(self, cpu_thread_id: int, msr_addr: int, eax: int, edx: int) -> int:
        return self._get_element_eval("write_msr", (cpu_thread_id, msr_addr, eax, edx))

    #
    # Load CPU microcode update on a specific CPU thread
    #
    def load_ucode_update(self, cpu_thread_id: int, ucode_update_buf: bytes) -> bool:
        return self._get_element_eval("load_ucode_update", (cpu_thread_id, ucode_update_buf))

    #
    # Read IDTR/GDTR/LDTR on a specific CPU thread
    #
    def get_descriptor_table(self, cpu_thread_id: int, desc_table_code: int) -> Optional[Tuple[int, int, int]]:
        return self._get_element_eval("get_descriptor_table", (cpu_thread_id, desc_table_code))

    #
    # EFI Variable API
    #
    def EFI_supported(self) -> bool:
        return self._get_element_eval("EFI_supported", ())

    def get_EFI_variable(self, name: str, guid: str) -> Optional[bytes]:
        return self._get_element_eval("get_EFI_variable", (name, guid))

    def set_EFI_variable(self, name: str, guid: str, data: bytes, datasize: Optional[int], attrs: Optional[int]) -> Optional[int]:
        return self._get_element_eval("set_EFI_variable", (name, guid, data, datasize, attrs))

    def delete_EFI_variable(self, name: str, guid: str) -> Optional[int]:
        return self._get_element_eval("delete_EFI_variable", (name, guid))

    def list_EFI_variables(self) -> Optional[Dict[str, List['EfiVariableType']]]:
        return self._get_element_eval("list_EFI_variables", ())

    #
    # ACPI
    #

    def get_ACPI_table(self, table_name: str) -> Optional['Array']:
        return self._get_element_eval("get_ACPI_table", (table_name, ))

    def enum_ACPI_tables(self) -> Optional['Array']:
        return self._get_element_eval("enum_ACPI_tables", ())

    #
    # CPUID
    #
    def cpuid(self, eax: int, ecx: int) -> Tuple[int, int, int, int]:
        return self._get_element_eval("cpuid", (eax, ecx))

    #
    # IOSF Message Bus access
    #
    def msgbus_send_read_message(self, mcr: int, mcrx: int) -> Optional[int]:
        return self._get_element_eval("msgbus_send_read_message", (mcr, mcrx))

    def msgbus_send_write_message(self, mcr: int, mcrx: int, mdr: int) -> None:
        return self._get_element_eval("msgbus_send_write_message", (mcr, mcrx, mdr))

    def msgbus_send_message(self, mcr: int, mcrx: int, mdr: Optional[int]) -> Optional[int]:
        return self._get_element_eval("msgbus_send_message", (mcr, mcrx, mdr))

    #
    # Affinity
    #
    def get_affinity(self) -> Optional[int]:
        return self._get_element_eval("get_affinity", ())

    def set_affinity(self, value: int) -> Optional[int]:
        return self._get_element_eval("set_affinity", (value, ))

    #
    # Logical CPU count
    #
    def get_threads_count(self) -> int:
        return self._get_element_eval("get_threads_count", ())

    #
    # Send SW SMI
    #
    def send_sw_smi(self, cpu_thread_id: int, SMI_code_data: int, _rax: int, _rbx: int, _rcx: int, _rdx: int, _rsi: int, _rdi: int) -> Optional[int]:
        return self._get_element_eval("send_sw_smi", (cpu_thread_id, SMI_code_data, _rax, _rbx, _rcx, _rdx, _rsi, _rdi))

    #
    # Hypercall
    #
    def hypercall(self, rcx: int, rdx: int, r8: int, r9: int, r10: int, r11: int, rax: int, rbx: int, rdi: int, rsi: int, xmm_buffer: int) -> int:
        return self._get_element_eval("hypercall", (rcx, rdx, r8, r9, r10, r11, rax, rbx, rdi, rsi, xmm_buffer))

    #
    # Speculation control
    #
    def retpoline_enabled(self) -> bool:
        return self._get_element_eval("retpoline_enabled", ())


def get_helper():
    return ReplayHelper()
