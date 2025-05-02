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

from inspect import stack
from json import dumps, loads
import os
from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING
if TYPE_CHECKING:
    from ctypes import Array
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

    def _call_subhelper(self, *myargs):
        fname= stack()[1][3]  # gets the name of the function that called _call_subhelper
        func = getattr(self._subhelper, fname)
        err = None
        try:
            ret = func(*myargs)
        except Exception as e:
            ret = f'!! {type(e)}: {e}'
            err = e
        self._add_element(fname, myargs, ret)
        if err is not None:
            raise err
        return ret

    def create(self) -> bool:
        self.driver_created = True
        return self._subhelper.create()

    def start(self) -> bool:
        self._load()  # Load file if it exists
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
        return self._call_subhelper(bus, device, function, offset, size)

    def write_pci_reg(self, bus: int, device: int, function: int, offset: int, value: int, size: int) -> int:
        return self._call_subhelper(bus, device, function, offset, value, size)

    def read_mmio_reg(self, phys_address: int, size: int) -> int:
        return self._call_subhelper(phys_address, size)

    def write_mmio_reg(self, phys_address: int, size: int, value: int) -> int:
        return self._call_subhelper(phys_address, size, value)

    #
    # physical_address is 64 bit integer
    #
    def read_phys_mem(self, phys_address: int, length: int) -> bytes:
        return self._call_subhelper(phys_address, length)

    def write_phys_mem(self, phys_address: int, length: int, buf: bytes) -> int:
        return self._call_subhelper(phys_address, length, buf)

    def alloc_phys_mem(self, length: int, max_phys_address: int) -> Tuple[int, int]:
        return self._call_subhelper(length, max_phys_address)

    def free_phys_mem(self, physical_address: int) -> Optional[int]:
        return self._call_subhelper(physical_address)

    def va2pa(self, virtual_address: int) -> Tuple[int, int]:
        return self._call_subhelper(virtual_address)

    def map_io_space(self, physical_address: int, length: int, cache_type: int) -> int:
        return self._call_subhelper(physical_address, length, cache_type)

    #
    # Read/Write I/O port
    #
    def read_io_port(self, io_port: int, size: int) -> int:
        return self._call_subhelper(io_port, size)

    def write_io_port(self, io_port: int, value: int, size: int) -> int:
        return self._call_subhelper(io_port, value, size)

    #
    # Read/Write CR registers
    #
    def read_cr(self, cpu_thread_id: int, cr_number: int) -> int:
        return self._call_subhelper(cpu_thread_id, cr_number)

    def write_cr(self, cpu_thread_id: int, cr_number: int, value: int) -> int:
        return self._call_subhelper(cpu_thread_id, cr_number, value)

    #
    # Read/Write MSR on a specific CPU thread
    #
    def read_msr(self, cpu_thread_id: int, msr_addr: int) -> Tuple[int, int]:
        return self._call_subhelper(cpu_thread_id, msr_addr)

    def write_msr(self, cpu_thread_id: int, msr_addr: int, eax: int, edx: int) -> int:
        return self._call_subhelper(cpu_thread_id, msr_addr, eax, edx)

    #
    # Load CPU microcode update on a specific CPU thread
    #
    def load_ucode_update(self, cpu_thread_id: int, ucode_update_buf: bytes) -> bool:
        return self._call_subhelper(cpu_thread_id, ucode_update_buf)

    #
    # Read IDTR/GDTR/LDTR on a specific CPU thread
    #
    def get_descriptor_table(self, cpu_thread_id: int, desc_table_code: int) -> Optional[Tuple[int, int, int]]:
        return self._call_subhelper(cpu_thread_id, desc_table_code)

    #
    # EFI Variable API
    #
    def EFI_supported(self) -> bool:
        return self._call_subhelper()

    def get_EFI_variable(self, name: str, guid: str) -> Optional[bytes]:
        return self._call_subhelper(name, guid)

    def set_EFI_variable(self, name: str, guid: str, data: bytes, datasize: Optional[int], attrs: Optional[int]) -> Optional[int]:
        return self._call_subhelper(name, guid, data, datasize, attrs)

    def delete_EFI_variable(self, name: str, guid: str) -> Optional[int]:
        return self._call_subhelper(name, guid)

    def list_EFI_variables(self) -> Optional[Dict[str, List['EfiVariableType']]]:
        return self._call_subhelper()

    #
    # ACPI
    #

    def get_ACPI_table(self, table_name: str) -> Optional['Array']:
        return self._call_subhelper(table_name)

    def enum_ACPI_tables(self) -> Optional['Array']:
        return self._call_subhelper()

    #
    # CPUID
    #
    def cpuid(self, eax: int, ecx: int) -> Tuple[int, int, int, int]:
        return self._call_subhelper(eax, ecx)

    #
    # IOSF Message Bus access
    #
    def msgbus_send_read_message(self, mcr: int, mcrx: int) -> Optional[int]:
        return self._call_subhelper(mcr, mcrx)

    def msgbus_send_write_message(self, mcr: int, mcrx: int, mdr: int) -> None:
        return self._call_subhelper(mcr, mcrx, mdr)

    def msgbus_send_message(self, mcr: int, mcrx: int, mdr: Optional[int]) -> Optional[int]:
        return self._call_subhelper(mcr, mcrx, mdr)

    #
    # Affinity
    #
    def get_affinity(self) -> Optional[int]:
        return self._call_subhelper()

    def set_affinity(self, value: int) -> Optional[int]:
        return self._call_subhelper(value)

    #
    # Logical CPU count
    #
    def get_threads_count(self) -> int:
        return self._call_subhelper()

    #
    # Send SW SMI
    #
    def send_sw_smi(self, cpu_thread_id: int, SMI_code_data: int, _rax: int, _rbx: int, _rcx: int, _rdx: int, _rsi: int, _rdi: int) -> Optional[int]:
        return self._call_subhelper(cpu_thread_id, SMI_code_data, _rax, _rbx, _rcx, _rdx, _rsi, _rdi)

    #
    # Hypercall
    #
    def hypercall(self, rcx: int, rdx: int, r8: int, r9: int, r10: int, r11: int, rax: int, rbx: int, rdi: int, rsi: int, xmm_buffer: int) -> int:
        return self._call_subhelper(rcx, rdx, r8, r9, r10, r11, rax, rbx, rdi, rsi, xmm_buffer)

    #
    # Speculation control
    #
    def retpoline_enabled(self) -> bool:
        return self._call_subhelper()


def get_helper():
    return RecordHelper()

