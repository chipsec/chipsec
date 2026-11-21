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

# -------------------------------------------------------------------------------
#
# CHIPSEC: Platform Hardware Security Assessment Framework
#
# -------------------------------------------------------------------------------

"""
On UEFI use the efi package functions
"""

import struct
import sys
import uuid
import os
import edk2   # Python 3.6.8 on UEFI

from typing import Dict, List, Optional, Tuple, TYPE_CHECKING
if TYPE_CHECKING:
    from ctypes import Array
    from chipsec.library.types import EfiVariableType
from chipsec.library.logger import logger
from chipsec.helper.oshelper import get_tools_path
from chipsec.helper.basehelper import Helper
from chipsec.library.exceptions import PhysicalMemoryAccessError, UnimplementedAPIError
from chipsec.library.uefi.common import StatusCode, EFI_MEMORY_RO, EFI_MEMORY_RP, EFI_PAGE_SIZE


_tools = {
}

# Only the first 1 MiB is checked against the UEFI memory map. Above it, MMIO is legitimately
# absent from the memory map, so page attributes are the only check applied.
LEGACY_REGION_END = 0x100000

class EfiHelper(Helper):

    def __init__(self):
        super(EfiHelper, self).__init__()
        self.name = "EfiHelper"
        self._memory_map: Optional[List[Tuple[int, int]]] = None
        if sys.platform.startswith('EFI'):
            self.os_system = sys.platform
            self.os_release = "0.0"
            self.os_version = "0.0"
            self.os_machine = "i386"
        else:
            import platform
            self.os_system = platform.system()
            self.os_release = platform.release()
            self.os_version = platform.version()
            self.os_machine = platform.machine()
            self.os_uname = platform.uname()

    def __del__(self):
        try:
            destroy()
        except NameError:
            pass

###############################################################################################
# Driver/service management functions
###############################################################################################

    def create(self) -> bool:
        logger().log_debug('[helper] UEFI Helper created')
        return True

    def start(self) -> bool:
        # The driver is part of the modified version of edk2.
        # It is always considered as loaded.
        self.driver_loaded = True
        logger().log_debug('[helper] UEFI Helper started/loaded')
        return True

    def stop(self) -> bool:
        logger().log_debug('[helper] UEFI Helper stopped/unloaded')
        return True

    def delete(self) -> bool:
        logger().log_debug('[helper] UEFI Helper deleted')
        return True


###############################################################################################
# Actual API functions to access HW resources
###############################################################################################

    #
    # Physical memory access
    #

    def split_address(self, pa: int) -> Tuple[int, int]:
        return (pa & 0xFFFFFFFF, (pa >> 32) & 0xFFFFFFFF)

    def _get_memory_map(self) -> List[Tuple[int, int]]:
        """
        Physical ranges described by the UEFI memory map, as merged, sorted (start, end) pairs.

        Empty if the interpreter has no edk2.GetMemoryMap() or the call fails.
        """
        if self._memory_map is None:
            self._memory_map = []
            if not hasattr(edk2, 'GetMemoryMap'):
                logger().log_debug('[helper] edk2.GetMemoryMap() unavailable; memory map not used to validate access')
                return self._memory_map
            (status, entries) = edk2.GetMemoryMap()
            if status != StatusCode.EFI_SUCCESS:
                logger().log_debug(f'[helper] GetMemoryMap() failed with status {status:d}')
                return self._memory_map
            ranges = sorted((start, start + pages * EFI_PAGE_SIZE) for (_, start, pages, _) in entries)
            for (start, end) in ranges:
                if self._memory_map and start <= self._memory_map[-1][1]:
                    self._memory_map[-1] = (self._memory_map[-1][0], max(self._memory_map[-1][1], end))
                else:
                    self._memory_map.append((start, end))
        return self._memory_map

    def _in_memory_map(self, start: int, end: int) -> bool:
        """
        Return False if the memory map is known and [start, end) is not entirely within it.

        Firmware such as Patina reports memory that does not exist (e.g. the 0xA0000-0x100000
        legacy hole) with no access attributes, so GetMemoryAttributes() alone cannot reject it.
        """
        memory_map = self._get_memory_map()
        if not memory_map:
            return True
        for (map_start, map_end) in memory_map:
            if map_start <= start and end <= map_end:
                return True
            if map_start >= end:
                break
        return False

    def _check_access(self, phys_address: int, length: int, write: bool = False) -> None:
        """
        Raise PhysicalMemoryAccessError if any page in the range would fault when accessed.

        In the UEFI shell edk2.readmem/writemem dereference the address directly, so an
        unmapped or read-protected page takes down the whole firmware. Any part of the range
        below LEGACY_REGION_END must lie within the UEFI memory map (when available), and page
        attributes come from EFI_MEMORY_ATTRIBUTE_PROTOCOL; if the interpreter or firmware
        cannot provide either, that check is skipped and the access is allowed as before.
        """
        if length <= 0:
            return
        access = 'write' if write else 'read'
        legacy_end = min(phys_address + length, LEGACY_REGION_END)
        if phys_address < legacy_end and not self._in_memory_map(phys_address, legacy_end):
            raise PhysicalMemoryAccessError(f'Physical address 0x{phys_address:016X} (0x{length:X} bytes) is not accessible for {access}: '
                                            'range is not in the UEFI memory map', StatusCode.EFI_NO_MAPPING)
        if not hasattr(edk2, 'GetMemoryAttributes'):
            return
        page_start = phys_address & ~(EFI_PAGE_SIZE - 1)
        page_end = (phys_address + length + EFI_PAGE_SIZE - 1) & ~(EFI_PAGE_SIZE - 1)
        denied = EFI_MEMORY_RP | (EFI_MEMORY_RO if write else 0)
        bad_page = self._find_inaccessible_page(page_start, page_end, denied)
        if bad_page is not None:
            raise PhysicalMemoryAccessError(f'Physical address 0x{phys_address:016X} (0x{length:X} bytes) is not accessible for {access}: '
                                            f'page 0x{bad_page:016X} is not mapped or is protected', StatusCode.EFI_NO_MAPPING)

    def _find_inaccessible_page(self, start: int, end: int, denied: int) -> Optional[int]:
        """
        Return the first page in [start, end) that is unmapped or has any of the denied attributes.

        GetMemoryAttributes() reports EFI_NO_MAPPING both for unmapped pages and for ranges
        whose attributes differ between pages, so such ranges are split in half until each
        part is uniform. A large read over uniform memory costs a single query.
        """
        (status, attributes) = edk2.GetMemoryAttributes(start, end - start)
        if status == StatusCode.EFI_SUCCESS:
            return start if attributes & denied else None
        if status != StatusCode.EFI_NO_MAPPING:
            logger().log_debug(f'[helper] GetMemoryAttributes(0x{start:016X}, 0x{end - start:X}) returned {status:d}; unable to validate access')
            return None
        if end - start <= EFI_PAGE_SIZE:
            return start
        mid = start + ((end - start) // (2 * EFI_PAGE_SIZE)) * EFI_PAGE_SIZE
        bad_page = self._find_inaccessible_page(start, mid, denied)
        if bad_page is None:
            bad_page = self._find_inaccessible_page(mid, end, denied)
        return bad_page

    def read_phys_mem(self, phys_address: int, length: int) -> bytes:
        self._check_access(phys_address, length)
        return self.read_phys_mem_unsafe(phys_address, length)

    def read_phys_mem_unsafe(self, phys_address: int, length: int) -> bytes:
        pa_lo, pa_hi = self.split_address(phys_address)
        return edk2.readmem(pa_lo, pa_hi, length)

    def write_phys_mem(self, phys_address: int, length: int, buf: bytes) -> int:
        self._check_access(phys_address, length, write=True)
        return self.write_phys_mem_unsafe(phys_address, length, buf)

    def write_phys_mem_unsafe(self, phys_address: int, length: int, buf: bytes) -> int:
        pa_lo, pa_hi = self.split_address(phys_address)
        # edk2.writemem writes the whole buffer, so never write more than the length requested
        # (and, in write_phys_mem, checked).
        if len(buf) > length:
            logger().log_debug(f'[helper] Buffer (0x{len(buf):X} bytes) is longer than the write length (0x{length:X}); '
                               f'only 0x{length:X} bytes are written to 0x{phys_address:016X}')
        buf = bytes(buf[:length])
        if 4 == length:
            dword_value = struct.unpack('I', buf)[0]
            res = edk2.writemem_dword(pa_lo, pa_hi, dword_value)
        else:
            res = edk2.writemem(pa_lo, pa_hi, buf)
        return res

    def alloc_phys_mem(self, length: int, max_pa: int) -> Tuple[int, int]:
        va = edk2.allocphysmem(length, max_pa)[0]
        (pa, _) = self.va2pa(va)
        return (va, pa)

    def va2pa(self, va: int) -> Tuple[int, int]:
        pa = va  # UEFI shell has identity mapping
        logger().log_debug(f'[helper] VA (0X{va:016X}) -> PA (0X{pa:016X})')
        return (pa, 0)

    def get_EFI_System_Table_address(self) -> Optional[int]:
        """Address of the EFI System Table, straight from the firmware.

        Avoids brute-force scanning memory for the 'IBI SYST' signature, which
        is slow and walks regions that newer firmware leaves unmapped.
        """
        try:
            address = edk2.GetSystemTable()
        except AttributeError:
            logger().log_debug('[helper] edk2.GetSystemTable() unavailable')
            return None
        logger().log_debug(f'[helper] EFI System Table @ 0x{address:016X}')
        return address or None

    def pa2va(self, pa: int) -> int:
        va = pa  # UEFI Shell has identity mapping
        logger().log_debug(f'[helper] PA (0X{pa:016X}) -> VA (0X{va:016X})')
        return va

    #
    # Memory-mapped I/O (MMIO) access
    #

    def map_io_space(self, physical_address: int, length: int, cache_type: int) -> int:
        return self.pa2va(physical_address)

    def read_mmio_reg(self, phys_address: int, size: int) -> int:
        phys_address_lo = phys_address & 0xFFFFFFFF
        phys_address_hi = (phys_address >> 32) & 0xFFFFFFFF
        out_buf = edk2.readmem(phys_address_lo, phys_address_hi, size)
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
        phys_address_lo = phys_address & 0xFFFFFFFF
        phys_address_hi = (phys_address >> 32) & 0xFFFFFFFF
        if size == 4:
            ret = edk2.writemem_dword(phys_address_lo, phys_address_hi, value)
        else:
            buf = value.to_bytes(size, 'little')
            ret = edk2.writemem(phys_address_lo, phys_address_hi, buf)
        return ret

    #
    # PCIe configuration access
    #

    def read_pci_reg(self, bus: int, device: int, function: int, address: int, size: int) -> int:
        if (1 == size):
            return (edk2.readpci(bus, device, function, address, size) & 0xFF)
        elif (2 == size):
            return (edk2.readpci(bus, device, function, address, size) & 0xFFFF)
        else:
            return edk2.readpci(bus, device, function, address, size)

    def write_pci_reg(self, bus: int, device: int, function: int, address:int, value: int, size: int) -> int:
        return edk2.writepci(bus, device, function, address, value, size)

    #
    # CPU I/O port access
    #

    def read_io_port(self, io_port: int, size: int) -> int:
        if (1 == size):
            return (edk2.readio(io_port, size) & 0xFF)
        elif (2 == size):
            return (edk2.readio(io_port, size) & 0xFFFF)
        else:
            return edk2.readio(io_port, size)

    def write_io_port(self, io_port: int, value: int, size: int) -> int:
        return edk2.writeio(io_port, size, value)

    #
    # SMI events
    #

    def send_sw_smi(self, cpu_thread_id: int, SMI_code_data: int, _rax: int, _rbx: int, _rcx: int, _rdx: int, _rsi: int, _rdi: int) -> None:
        return edk2.swsmi(SMI_code_data, _rax, _rbx, _rcx, _rdx, _rsi, _rdi)

    #
    # CPU related API
    #

    def read_msr(self, cpu_thread_id: int, msr_addr: int) -> Tuple[int, int]:
        (eax, edx) = edk2.rdmsr(msr_addr)
        eax = eax % 2**32
        edx = edx % 2**32
        return (eax, edx)

    def write_msr(self, cpu_thread_id: int, msr_addr: int, eax: int, edx: int) -> int:
        return edk2.wrmsr(msr_addr, eax, edx)

    def read_cr(self, cpu_thread_id: int, cr_number: int) -> int:
        raise UnimplementedAPIError('read_cr')

    def write_cr(self, cpu_thread_id: int, cr_number: int, value: int) -> int:
        raise UnimplementedAPIError('write_cr')

    def load_ucode_update(self, cpu_thread_id: int, ucode_update_buf: int) -> bool:
        raise UnimplementedAPIError('load_ucode_update')

    def get_threads_count(self) -> int:
        return 1

    def cpuid(self, eax: int, ecx: int) -> Tuple[int, int, int, int]:
        (reax, rebx, recx, redx) = edk2.cpuid(eax, ecx)
        return (reax, rebx, recx, redx)

    def get_descriptor_table(self, cpu_thread_id: int, desc_table_code: int)-> None:
        raise UnimplementedAPIError('get_descriptor_table')

    #
    # File system
    #

    def get_tool_info(self, tool_type: str) -> Tuple[str, str]:
        tool_name = _tools[tool_type] if tool_type in _tools else ''
        tool_path = os.path.join(get_tools_path(), self.os_system.lower())
        return (tool_name, tool_path)

    #
    # EFI Variable API
    #

    def EFI_supported(self) -> bool:
        return True

    def get_EFI_variable_full(self, name: str, guidstr: str) -> Tuple[int, Optional[bytes], int]:

        size = 100
        (Status, Attributes, newdata, DataSize) = edk2.GetVariable(name, guidstr, size)

        if Status == 5:
            size = DataSize + 1
            (Status, Attributes, newdata, DataSize) = edk2.GetVariable(name, guidstr, size)

        return (Status, newdata, Attributes)

    def get_EFI_variable(self, name: str, guidstr: str) -> Optional[bytes]:
        (_, data, _) = self.get_EFI_variable_full(name, guidstr)
        return data

    def set_EFI_variable(self, name: str, guidstr: str, buffer: bytes, buffer_size: Optional[int] = None, attrs: Optional[int] = 0x7) -> int:

        if buffer_size is None:
            buffer_size = len(buffer)
        if attrs is None:
            attrs = 0x07
            if logger().VERBOSE:
                logger().log_important(f'Setting attributes to: {attrs:04X}')
        elif isinstance(attrs, bytes):
            attrs =  struct.unpack("L", attrs)[0]

        (Status, buffer_size, guidstr) = edk2.SetVariable(name, guidstr, int(attrs), buffer, buffer_size)

        return Status

    def delete_EFI_variable(self, name: str, guid: str) -> int:
        return self.set_EFI_variable(name, guid, bytes(4), 0, 0)

    def list_EFI_variables(self) -> Optional[Dict[str, List['EfiVariableType']]]:

        off = 0
        buf = b''
        hdr = 0
        attr = 0
        var_list = list()
        variables = dict()

        status_dict = {0: "EFI_SUCCESS", 1: "EFI_LOAD_ERROR", 2: "EFI_INVALID_PARAMETER", 3: "EFI_UNSUPPORTED", 4: "EFI_BAD_BUFFER_SIZE", 5: "EFI_BUFFER_TOO_SMALL",
                       6: "EFI_NOT_READY", 7: "EFI_DEVICE_ERROR", 8: "EFI_WRITE_PROTECTED", 9: "EFI_OUT_OF_RESOURCES", 14: "EFI_NOT_FOUND", 26: "EFI_SECURITY_VIOLATION"}

        namestr = ''
        size = 200
        guidstr = str(uuid.uuid4())

        search_complete = False
        while not search_complete:
            namestr += '\x00'
            name = namestr.encode('utf-16-le')
            guid = uuid.UUID(guidstr).bytes_le
            (status, namestr, size, guidstr) = edk2.GetNextVariableName(size, name, guid)

            if status == 5:
                logger().log_debug(f'[helper] EFI Variable name size was too small increasing to {size:d}')
                (status, namestr, size, guidstr) = edk2.GetNextVariableName(size, name, guid)

            logger().log_debug(f'[helper] Returned {name}. Status is {status_dict[status]}')

            if status:
                search_complete = True
            else:
                if (namestr, guidstr) in var_list:
                    continue
                else:
                    var_list.append((namestr, guidstr))

                logger().log_debug(f"[helper] Found variable '{name}' - [{guidstr}]")

        for (name, guidstr) in var_list:
            (status, data, attr) = self.get_EFI_variable_full(name, guidstr)

            if status:
                logger().log_verbose(f'[helper] Error reading variable {name}.  Status = {status:d} - {status_dict[status]}')

            var_data = (off, buf, hdr, data, guidstr, attr)

            if name in variables:
                logger().log_verbose(f'[helper] Duplicate variable name {name} - {guidstr}')
                continue
            else:
                variables[name] = []

            if data != '' or guidstr != '' or attr != 0:
                variables[name].append(var_data)

        return variables

    #
    # ACPI tables access
    #

    #
    # IOSF Message Bus access
    #

    def msgbus_send_read_message(self, mcr: int, mcrx: int) -> None:
        raise UnimplementedAPIError('msgbus_send_read_message')

    def msgbus_send_write_message(self, mcr: int, mcrx: int, mdr: int) -> None:
        raise UnimplementedAPIError('msgbus_send_write_message')

    def msgbus_send_message(self, mcr: int, mcrx: int, mdr: Optional[int] = None) -> None:
        raise UnimplementedAPIError('msgbus_send_message')

    def set_affinity(self, value: int) -> None:
        raise UnimplementedAPIError('set_affinity')

    def free_phys_mem(self, physical_address):
        raise UnimplementedAPIError('free_phys_mem')

    def get_ACPI_table(self, table_name: str) -> Optional['Array']:
        raise UnimplementedAPIError('get_ACPI_table')

    def enum_ACPI_tables(self) -> Optional['Array']:
        raise UnimplementedAPIError('enum_ACPI_table')

    def get_affinity(self):
        raise UnimplementedAPIError('get_affinity')

    def hypercall(self, rcx, rdx, r8, r9, r10, r11, rax, rbx, rdi, rsi, xmm_buffer):
        raise UnimplementedAPIError('hypercall')

    def retpoline_enabled(self) -> bool:
        return False

def get_helper() -> EfiHelper:
    return EfiHelper()
