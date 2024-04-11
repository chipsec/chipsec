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

"""
Native Linux helper
"""

import mmap
import os
import platform
import resource
import struct
import sys
from typing import Optional, Tuple, TYPE_CHECKING
if TYPE_CHECKING:
    from ctypes import Array

from chipsec.library import defines
from chipsec.library.exceptions import OsHelperError
from chipsec.helper.basehelper import Helper
from chipsec.helper.linuxnative.cpuid import CPUID
from chipsec.helper.linuxnative.legacy_pci import LegacyPci
from chipsec.library.logger import logger


class MemoryMapping(mmap.mmap):
    """Memory mapping based on Python's mmap.
    This subclass keeps tracks of the start and end of the mapping.
    """

    def __init__(self, fileno, length, flags, prot, offset):
        self.start = offset
        self.end = offset + length
        super().__init__()


class LinuxNativeHelper(Helper):

    DEV_MEM = "/dev/mem"
    DEV_PORT = "/dev/port"

    def __init__(self):
        super(LinuxNativeHelper, self).__init__()
        self.os_system = platform.system()
        self.os_release = platform.release()
        self.os_version = platform.version()
        self.os_machine = platform.machine()
        self.os_uname = platform.uname()
        self.name = "LinuxNativeHelper"
        self.dev_fh = None
        self.dev_mem = None
        self.dev_port = None
        self.dev_msr = None

        # A list of all the mappings allocated via map_io_space. When using
        # read/write MMIO, if the region is already mapped in the process's
        # memory, simply read/write from there.
        self.mappings = []

###############################################################################################
# Driver/service management functions
###############################################################################################
    def create(self) -> bool:
        logger().log_debug("[helper] Linux Helper created")
        return True

    def start(self) -> bool:
        self.init()
        logger().log_debug("[helper] Linux Helper started/loaded")
        return True

    def stop(self) -> bool:
        self.close()
        logger().log_debug("[helper] Linux Helper stopped/unloaded")
        return True

    def delete(self) -> bool:
        logger().log_debug("[helper] Linux Helper deleted")
        return True

    def init(self):
        x64 = True if sys.maxsize > 2**32 else False
        self._pack = 'Q' if x64 else 'I'

    def devmem_available(self) -> bool:
        """Check if /dev/mem is usable.
           In case the driver is not loaded, we might be able to perform the
           requested operation via /dev/mem. Returns True if /dev/mem is
           accessible.
        """
        if self.dev_mem:
            return True

        try:
            self.dev_mem = os.open(self.DEV_MEM, os.O_RDWR)
            return True
        except IOError as err:
            raise OsHelperError("Unable to open /dev/mem.\n"
                                "This command requires access to /dev/mem.\n"
                                "Are you running this command as root?\n"
                                f"{str(err)}", err.errno)

    def devport_available(self) -> bool:
        """Check if /dev/port is usable.
           In case the driver is not loaded, we might be able to perform the
           requested operation via /dev/port. Returns True if /dev/port is
           accessible.
        """
        if self.dev_port:
            return True

        try:
            self.dev_port = os.open(self.DEV_PORT, os.O_RDWR)
            return True
        except IOError as err:
            raise OsHelperError("Unable to open /dev/port.\n"
                                "This command requires access to /dev/port.\n"
                                "Are you running this command as root?\n"
                                f"{str(err)}", err.errno)

    def devmsr_available(self) -> bool:
        """Check if /dev/cpu/CPUNUM/msr is usable.
           In case the driver is not loaded, we might be able to perform the
           requested operation via /dev/cpu/CPUNUM/msr. This requires loading
           the (more standard) msr driver. Returns True if /dev/cpu/CPUNUM/msr
           is accessible.
        """
        if self.dev_msr:
            return True

        try:
            self.dev_msr = {}
            if not os.path.exists("/dev/cpu/0/msr"):
                os.system("modprobe msr")
            for cpu in os.listdir("/dev/cpu"):
                logger().log_debug(f"found cpu = {str(cpu)}")
                if cpu.isdigit():
                    cpu = int(cpu)
                    self.dev_msr[cpu] = os.open(f"/dev/cpu/{str(cpu)}/msr", os.O_RDWR)
                    logger().log_debug(f"Added dev_msr {str(cpu)}")
            return True
        except IOError as err:
            raise OsHelperError("Unable to open /dev/cpu/CPUNUM/msr.\n"
                                "This command requires access to /dev/cpu/CPUNUM/msr.\n"
                                "Are you running this command as root?\n"
                                "Do you have the msr kernel module installed?\n"
                                f"{str(err)}", err.errno)

    def close(self):
        if self.dev_mem:
            os.close(self.dev_mem)
        self.dev_mem = None

###############################################################################################
# Actual API functions to access HW resources
###############################################################################################

    def read_pci_reg(self, bus: int, device: int, function: int, offset: int, size: int, domain: int = 0) -> int:
        device_name = f"{domain:04x}:{bus:02x}:{device:02x}.{function}"
        device_path = f"/sys/bus/pci/devices/{device_name}/config"
        if not os.path.exists(device_path):
            if offset < 256:
                value = LegacyPci.read_pci_config(bus, device, function, offset)
                if size == 1:
                    value = value & 0xFF
                elif size == 2:
                    value = value & 0xFFFF
                elif size == 4:
                    value = value & 0xFFFF_FFFF
                elif size == 8:
                    value = value & 0xFFFF_FFFF_FFFF_FFFF
                return value
            else:
                raise ValueError("Offset out of bounds")
        try:
            with open(device_path, "rb") as config:
                config.seek(offset)
                reg = config.read(size)
                reg = defines.unpack1(reg, size)
                return reg
        except IOError as err:
            raise OsHelperError(f"Unable to open {device_path}", err.errno)

    def write_pci_reg(self, bus: int, device: int, function: int, offset: int, value: int, size: int = 4, domain: int = 0) -> int:
        device_name = "{domain:04x}:{bus:02x}:{device:02x}.{function}".format(
                      domain=domain, bus=bus, device=device, function=function)
        device_path = f"/sys/bus/pci/devices/{device_name}/config"
        if not os.path.exists(device_path):
            if offset < 256:
                LegacyPci.write_pci_config(bus, device, function, offset, value)
                return -1
        try:
            with open(device_path, "wb") as config:
                config.seek(offset)
                config.write(defines.pack1(value, size))
        except IOError as err:
            raise OsHelperError(f"Unable to open {device_path}", err.errno)

        return 0

    # @TODO fix memory mapping and bar_size
    def read_mmio_reg(self, phys_address: int, size: int) -> int:
        if self.devmem_available():
            region = self.memory_mapping(phys_address, size)
            if not region:
                self.map_io_space(phys_address, size, 0)
                region = self.memory_mapping(phys_address, size)
                if not region:
                    logger().log_error(f"Unable to map region {phys_address:08x}")

            # Create memoryview into mmap'ed region
            region_mv = memoryview(region)
            offset_in_region = phys_address - region.start
            if size == 1:
                return region_mv[offset_in_region]

            if offset_in_region % size == 0:
                # Read aligned value
                region_casted = region_mv.cast(defines.SIZE2FORMAT[size])
                return region_casted[offset_in_region // size]

            # Read unaligned value
            return defines.unpack1(region_mv[offset_in_region:offset_in_region + size], size)
        return 0

    # @TODO fix memory mapping and bar_size
    def write_mmio_reg(self, phys_address: int, size: int, value: int) -> None:
        if self.devmem_available():
            reg = defines.pack1(value, size)
            region = self.memory_mapping(phys_address, size)
            if not region:
                self.map_io_space(phys_address, size, 0)
                region = self.memory_mapping(phys_address, size)
                if not region:
                    logger().log_error(f"Unable to map region {phys_address:08x}")

            # Create memoryview into mmap'ed region
            region_mv = memoryview(region)
            offset_in_region = phys_address - region.start
            if size == 1:
                region_mv[offset_in_region] = value
                return

            if offset_in_region % size == 0:
                # Write aligned value
                region_casted = region_mv.cast(defines.SIZE2FORMAT[size])
                region_casted[offset_in_region // size] = value
                return

            # Write unaligned value
            region_mv[offset_in_region:offset_in_region + size] = reg

    def memory_mapping(self, base: int, size: int) -> Optional[MemoryMapping]:
        """Returns the mmap region that fully encompasses this area.
        Returns None if no region matches.
        """
        for region in self.mappings:
            if region.start <= base and region.end >= base + size:
                return region
        return None

    def map_io_space(self, base: int, size: int, cache_type: int) -> None:
        """Map to memory a specific region."""
        if self.devmem_available() and not self.memory_mapping(base, size):
            logger().log_debug(f"[helper] Mapping 0x{base:x} to memory")
            length = max(size, resource.getpagesize())
            page_aligned_base = base - (base % resource.getpagesize())
            mapping = MemoryMapping(self.dev_mem, length, mmap.MAP_SHARED,
                                    mmap.PROT_READ | mmap.PROT_WRITE,
                                    offset=page_aligned_base)
            self.mappings.append(mapping)

    def read_phys_mem(self, phys_address, length: int) -> bytes:
        if self.devmem_available():
            os.lseek(self.dev_mem, phys_address, os.SEEK_SET)
            return os.read(self.dev_mem, length)
        return b'\x00'

    def write_phys_mem(self, phys_address, length: int, newval: bytes) -> int:
        if newval is None:
            return None
        if self.devmem_available():
            os.lseek(self.dev_mem, phys_address, os.SEEK_SET)
            written = os.write(self.dev_mem, newval)
            if written != length:
                logger().log_debug(f"Cannot write {newval} to memory {phys_address:016X} (wrote {written:d} of {length:d})")
            return written
        return -1

    def alloc_phys_mem(self, length, max_phys_address):
        raise NotImplementedError()

    def free_phys_mem(self, physical_address):
        raise NotImplementedError()

    def va2pa(self, va):
        raise NotImplementedError()

    def read_io_port(self, io_port: int, size: int) -> int:
        if self.devport_available():
            os.lseek(self.dev_port, io_port, os.SEEK_SET)

            value = os.read(self.dev_port, size)
            if 1 == size:
                return struct.unpack("B", value)[0]
            elif 2 == size:
                return struct.unpack("H", value)[0]
            elif 4 == size:
                return struct.unpack("I", value)[0]
            else:
                raise ValueError("Invalid size")
        return -1

    def write_io_port(self, io_port: int, value: int, size: int) -> bool:
        if self.devport_available():
            os.lseek(self.dev_port, io_port, os.SEEK_SET)
            if 1 == size:
                fmt = 'B'
            elif 2 == size:
                fmt = 'H'
            elif 4 == size:
                fmt = 'I'
            else:
                raise ValueError("Invalid size")
            written = os.write(self.dev_port, struct.pack(fmt, value))
            if written != size:
                logger().log_debug(f"Cannot write {value} to port {io_port:x} (wrote {written:d} of {size:d})")
                return False
            return True
        return False

    def read_cr(self, cpu_thread_id, cr_number):
        raise NotImplementedError()

    def write_cr(self, cpu_thread_id, cr_number, value):
        raise NotImplementedError()

    def read_msr(self, thread_id: int, msr_addr: int) -> Tuple[int, int]:
        if self.devmsr_available():
            os.lseek(self.dev_msr[thread_id], msr_addr, os.SEEK_SET)
            buf = os.read(self.dev_msr[thread_id], 8)
            unbuf = struct.unpack("2I", buf)
            return (unbuf[0], unbuf[1])
        return (-1, -1)

    def write_msr(self, thread_id: int, msr_addr: int, eax: int, edx: int) -> int:
        if self.devmsr_available():
            os.lseek(self.dev_msr[thread_id], msr_addr, os.SEEK_SET)
            buf = struct.pack("2I", eax, edx)
            written = os.write(self.dev_msr[thread_id], buf)
            if written != 8:
                logger().log_debug(f"Cannot write {buf.hex()} to MSR {msr_addr:x}")
            return written
        return False

    def load_ucode_update(self, cpu_thread_id, ucode_update_buf):
        raise NotImplementedError()

    def get_descriptor_table(self, cpu_thread_id, desc_table_code):
        raise NotImplementedError()

    def EFI_supported(self):
        raise NotImplementedError()

    def get_EFI_variable(self, name, guid):
        raise NotImplementedError()

    def set_EFI_variable(self, name, guid, buffer, buffer_size=None, attrs=None):
        raise NotImplementedError()

    def delete_EFI_variable(self, name, guid):
        raise NotImplementedError()

    def list_EFI_variables(self):
        raise NotImplementedError()

    def get_ACPI_table(self, table_name: str) -> Optional['Array']:
        raise NotImplementedError()
    
    def enum_ACPI_tables(self) -> Optional['Array']:
        raise NotImplementedError()

    def cpuid(self, eax: int, ecx: int) -> Tuple[int, int, int, int]:
        _cpuid = CPUID()
        return _cpuid(eax, ecx)

    def msgbus_send_read_message(self, mcr, mcrx):
        raise NotImplementedError()

    def msgbus_send_write_message(self, mcr, mcrx, mdr):
        raise NotImplementedError()

    def msgbus_send_message(self, mcr, mcrx, mdr):
        raise NotImplementedError()

    #
    # Affinity functions
    #
    def get_affinity(self) -> Optional[int]:
        try:
            affinity = os.sched_getaffinity(0)
            return list(affinity)[0]
        except Exception:
            return None

    def set_affinity(self, thread_id: int) -> Optional[int]:
        try:
            os.sched_setaffinity(os.getpid(), {thread_id})
            return thread_id
        except Exception:
            return None

    #
    # Logical CPU count
    #
    def get_threads_count(self) -> int:
        import multiprocessing
        return multiprocessing.cpu_count()

    #
    # Send SW SMI
    #
    def send_sw_smi(self, cpu_thread_id, SMI_code_data, _rax, _rbx, _rcx, _rdx, _rsi, _rdi):
        raise NotImplementedError()

    #
    # Hypercall
    #
    def hypercall(self, rcx=0, rdx=0, r8=0, r9=0, r10=0, r11=0, rax=0, rbx=0, rdi=0, rsi=0, xmm_buffer=0):
        raise NotImplementedError()

    #
    # Speculation control
    #
    def retpoline_enabled(self):
        raise NotImplementedError("retpoline_enabled")

    def get_bios_version(self) -> str:
        try:
            filename = "/sys/class/dmi/id/bios_version"
            with open(filename, 'r') as outfile:
                return outfile.read().strip()
        except FileNotFoundError:
            return 'Unable to read bios version'


def get_helper():
    return LinuxNativeHelper()
