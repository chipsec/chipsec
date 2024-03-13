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

from json import dumps, loads
import os
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime

from chipsec.library.logger import logger
from chipsec.library.defines import bytestostring
from chipsec.helper.basehelper import Helper
from chipsec.helper.oshelper import helper
from chipsec.library.file import read_file, write_file


class RecordHelper(Helper):
    def __init__(self, filename: str = "", subhelper: str = ""):
        super(RecordHelper, self).__init__()
        self.os_system = "test_helper"
        self.os_release = "0"
        self.os_version = "0"
        self.os_machine = "test"
        self.driver_created = False
        self.driver_loaded = False
        self.name = "FileHelper"
        
        dtstr = datetime.now().strftime("%Y%m%d%H%M%S")
        self.default_file_name = f"recording{dtstr}.json"
        self.default_file_location = os.path.join("chipsec", "helper", "record")
        self._subhelper = helper().get_helper(subhelper) if subhelper else helper().get_default_helper()
        logger().log(f"Using subhelper: {self._subhelper.name}")
        self._filename = filename if filename else os.path.join(self.default_file_location, self.default_file_name)
        self._data = {}

    def switch_subhelper(self, newhelper: Helper) -> None:
        if self.driver_loaded:
            self._subhelper.stop()
        if self.driver_created:
            self._subhelper.delete()
        self._subhelper = newhelper
        logger().log(f"Switched subhelper to: {self._subhelper.name}")

    def _add_element(self, cmd: str, args: Tuple, ret: Any) -> None:
        try:
            margs = f"({','.join(str(i) for i in args)})"
        except Exception:
            margs = str(args)
        if isinstance(ret, bytes):
            ret = bytestostring(ret)
        if str(cmd) in self._data:
            if margs in self._data[str(cmd)]:
                # using insert opposed to append so that it creates last in first out when using pop command within getElement
                self._data[str(cmd)][margs].insert(0, str(ret))
            else:
                self._data[str(cmd)][margs] = [str(ret)]
        else:
            self._data[str(cmd)] = {margs: [str(ret)]}

    def _save(self) -> None:
        js = dumps(self._data, sort_keys=False, indent=2, separators=(',', ': '))
        write_file(self._filename, js)

    def _load(self) -> None:
        if os.path.isfile(self._filename):
            file_data = read_file(self._filename)
            if file_data == 0:
                self._data = {}
            try:
                self._data = loads(file_data)
            except Exception:
                self._data = {}

    def create(self) -> bool:
        self.driver_created = True
        return self._subhelper.create()

    def start(self) -> bool:
        self._load() # Load file if it exists
        self.driver_loaded = True
        return self._subhelper.start()

    def stop(self) -> bool:
        self._save()
        self.driver_loaded = False
        return self._subhelper.stop()

    def delete(self) -> bool:
        self.driver_created = False
        return self._subhelper.delete()

    

    def read_pci_reg(self, bus: int, device: int, function: int, offset: int, size: int) -> int:
        ret = self._subhelper.read_pci_reg(bus, device, function, offset, size)
        self._add_element("read_pci_reg", (bus, device, function, offset, size), ret)
        return ret

    def write_pci_reg(self, bus: int, device: int, function: int, offset: int, value: int, size: int) -> int:
        ret = self._subhelper.write_pci_reg(bus, device, function, offset, value, size)
        self._add_element("write_pci_reg", (bus, device, function, offset, value, size), ret)
        return ret

    def read_mmio_reg(self, phys_address: int, size: int) -> int:
        ret = self._subhelper.read_mmio_reg(phys_address, size)
        self._add_element("read_mmio_reg", (phys_address, size), ret)
        return ret
    
    def write_mmio_reg(self, phys_address: int, size: int, value: int) -> int:
        ret = self._subhelper.write_mmio_reg(phys_address, size, value)
        self._add_element("write_mmio_reg", (phys_address, size, value), ret)
        return ret
        
    #
    # physical_address is 64 bit integer
    #
    def read_phys_mem(self, phys_address:int, length:int) -> bytes:
        ret = self._subhelper.read_phys_mem(phys_address, length)
        self._add_element("read_phys_mem", (phys_address, length), ret)
        return ret

    def write_phys_mem(self, phys_address: int, length: int, buf: bytes) -> int:
        ret = self._subhelper.write_phys_mem(phys_address, length, buf)
        self._add_element("write_phys_mem", (phys_address, length, buf), ret)
        return ret

    def alloc_phys_mem(self, length: int, max_phys_address: int) -> Tuple[int, int]:
        ret = self._subhelper.alloc_phys_mem(length, max_phys_address)
        self._add_element("alloc_phys_mem", (length, max_phys_address), ret)
        return ret

    def free_phys_mem(self, physical_address: int) -> Optional[int]:
        ret = self._subhelper.free_phys_mem(physical_address)
        self._add_element("free_phys_mem", (physical_address), ret)
        return ret

    def va2pa(self, virtual_address: int) -> Tuple[int, int]:
        ret = self._subhelper.va2pa(virtual_address)
        self._add_element("va2pa", (virtual_address), ret)
        return ret

    def map_io_space(self, physical_address: int, length: int, cache_type: int) -> int:
        ret = self._subhelper.map_io_space(physical_address, length, cache_type)
        self._add_element("map_io_space", (physical_address, length, cache_type), ret)
        return ret

    #
    # Read/Write I/O port
    #
    def read_io_port(self, io_port: int, size: int) -> int:
        ret = self._subhelper.read_io_port(io_port, size)
        self._add_element("read_io_port", (io_port, size), ret)
        return ret

    def write_io_port(self, io_port: int, value: int, size: int) -> int:
        ret = self._subhelper.write_io_port(io_port, value, size)
        self._add_element("write_io_port", (io_port, value, size), ret)
        return ret

    #
    # Read/Write CR registers
    #
    def read_cr(self, cpu_thread_id: int, cr_number: int) -> int:
        ret = self._subhelper.read_cr(cpu_thread_id, cr_number)
        self._add_element("read_cr", (cpu_thread_id, cr_number), ret)
        return ret

    def write_cr(self, cpu_thread_id: int, cr_number: int, value: int) -> int:
        ret = self._subhelper.write_cr(cpu_thread_id, cr_number, value)
        self._add_element("write_cr", (cpu_thread_id, cr_number, value), ret)
        return ret

    #
    # Read/Write MSR on a specific CPU thread
    #
    def read_msr(self, cpu_thread_id: int, msr_addr: int) -> Tuple[int, int]:
        ret = self._subhelper.read_msr(cpu_thread_id, msr_addr)
        self._add_element("read_msr", (cpu_thread_id, msr_addr), ret)
        return ret

    def write_msr(self, cpu_thread_id: int, msr_addr: int, eax: int, edx: int) -> int:
        ret = self._subhelper.write_msr(cpu_thread_id, msr_addr, eax, edx)
        self._add_element("write_msr", (cpu_thread_id, msr_addr, eax, edx), ret)
        return ret

    #
    # Load CPU microcode update on a specific CPU thread
    #
    def load_ucode_update(self, cpu_thread_id: int, ucode_update_buf: bytes) -> bool:
        ret = self._subhelper.load_ucode_update(cpu_thread_id, ucode_update_buf)
        self._add_element("load_ucode_update", (cpu_thread_id, ucode_update_buf), ret)
        return ret

    #
    # Read IDTR/GDTR/LDTR on a specific CPU thread
    #
    def get_descriptor_table(self, cpu_thread_id: int, desc_table_code: int) -> Optional[Tuple[int, int, int]]:
        ret = self._subhelper.get_descriptor_table(cpu_thread_id, desc_table_code)
        self._add_element("get_descriptor_table", (cpu_thread_id, desc_table_code), ret)
        return ret

    #
    # EFI Variable API
    #
    def EFI_supported(self) -> bool:
        ret = self._subhelper.EFI_supported()
        self._add_element("EFI_supported", (), ret)
        return ret

    def get_EFI_variable(self, name: str, guid: str) -> Optional[bytes]:
        ret = self._subhelper.get_EFI_variable(name, guid)
        self._add_element("get_EFI_variable", (name, guid), ret)
        return ret

    def set_EFI_variable(self, name: str, guid: str, data: bytes, datasize: Optional[int], attrs: Optional[int]) -> Optional[int]:
        ret = self._subhelper.set_EFI_variable(name, guid, data, datasize, attrs)
        self._add_element("set_EFI_variable", (name, guid, data, datasize, attrs), ret)
        return ret

    def delete_EFI_variable(self, name: str, guid: str) -> Optional[int]:
        ret = self._subhelper.delete_EFI_variable(name, guid)
        self._add_element("delete_EFI_variable", (name, guid), ret)
        return ret

    def list_EFI_variables(self) -> Optional[Dict[str, List['EfiVariableType']]]:
        ret = self._subhelper.list_EFI_variables()
        self._add_element("list_EFI_variables", (), ret)
        return ret

    #
    # ACPI
    #
    def get_ACPI_SDT(self) -> Tuple[Optional['Array'], bool]:
        ret = self._subhelper.get_ACPI_SDT()
        self._add_element("get_ACPI_SDT", (), ret)
        return ret

    def get_ACPI_table(self, table_name: str) -> Optional['Array']:
        ret = self._subhelper.get_ACPI_table(table_name)
        self._add_element("get_ACPI_table", (table_name), ret)
        return ret

    #
    # CPUID
    #
    def cpuid(self, eax: int, ecx: int) -> Tuple[int, int, int, int]:
        ret = self._subhelper.cpuid(eax, ecx)
        self._add_element("cpuid", (eax, ecx), ret)
        return ret

    #
    # IOSF Message Bus access
    #
    def msgbus_send_read_message(self, mcr: int, mcrx: int) -> Optional[int]:
        ret = self._subhelper.msgbus_send_read_message(mcr, mcrx)
        self._add_element("msgbus_send_read_message", (mcr, mcrx), ret)
        return ret

    def msgbus_send_write_message(self, mcr: int, mcrx: int, mdr: int) -> None:
        ret = self._subhelper.msgbus_send_write_message(mcr, mcrx, mdr)
        self._add_element("msgbus_send_write_message", (mcr, mcrx, mdr), ret)
        return ret

    def msgbus_send_message(self, mcr: int, mcrx: int, mdr: Optional[int]) -> Optional[int]:
        ret = self._subhelper.msgbus_send_message(mcr, mcrx, mdr)
        self._add_element("msgbus_send_message", (mcr, mcrx, mdr), ret)
        return ret

    #
    # Affinity
    #
    def get_affinity(self) -> Optional[int]:
        ret = self._subhelper.get_affinity()
        self._add_element("get_affinity", (), ret)
        return ret

    def set_affinity(self, value: int) -> Optional[int]:
        ret = self._subhelper.set_affinity(value)
        self._add_element("set_affinity", (value), ret)
        return ret

    #
    # Logical CPU count
    #
    def get_threads_count(self) -> int:
        ret = self._subhelper.get_threads_count()
        self._add_element("get_threads_count", (), ret)
        return ret

    #
    # Send SW SMI
    #
    def send_sw_smi(self, cpu_thread_id: int, SMI_code_data: int, _rax: int, _rbx: int, _rcx: int, _rdx: int, _rsi: int, _rdi: int) -> Optional[int]:
        ret = self._subhelper.send_sw_smi(cpu_thread_id, SMI_code_data, _rax, _rbx, _rcx, _rdx, _rsi, _rdi)
        self._add_element("send_sw_smi", (cpu_thread_id, SMI_code_data, _rax, _rbx, _rcx, _rdx, _rsi, _rdi), ret)
        return ret

    #
    # Hypercall
    #
    def hypercall(self, rcx: int, rdx: int, r8: int, r9: int, r10: int, r11: int, rax: int, rbx: int, rdi: int, rsi: int, xmm_buffer: int) -> int:
        ret = self._subhelper.hypercall(rcx, rdx, r8, r9, r10, r11, rax, rbx, rdi, rsi, xmm_buffer)
        self._add_element("hypercall", (rcx, rdx, r8, r9, r10, r11, rax, rbx, rdi, rsi, xmm_buffer), ret)
        return ret

    #
    # Speculation control
    #
    def retpoline_enabled(self) -> bool:
        ret = self._subhelper.retpoline_enabled()
        self._add_element("retpoline_enabled", (), ret)
        return ret

def get_helper():
    return RecordHelper()

            