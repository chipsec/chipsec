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
Linux helper
"""

import array
import ctypes
import errno
import fcntl
import fnmatch
import mmap
import os
import platform
import resource
import struct
import subprocess
import sys
from typing import Dict, List, Optional, Tuple, Iterable, TYPE_CHECKING
if TYPE_CHECKING:
    from chipsec.library.types import EfiVariableType
    from ctypes import Array
from chipsec.library import defines
from chipsec.helper.oshelper import get_tools_path
from chipsec.library.exceptions import OsHelperError, UnimplementedAPIError
from chipsec.helper.basehelper import Helper
from chipsec.library.logger import logger
import chipsec.library.file
from chipsec.hal.uefi_common import EFI_VARIABLE_NON_VOLATILE, EFI_VARIABLE_BOOTSERVICE_ACCESS, EFI_VARIABLE_RUNTIME_ACCESS
from chipsec.hal.uefi_common import EFI_VARIABLE_HARDWARE_ERROR_RECORD, EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS
from chipsec.hal.uefi_common import EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS, EFI_VARIABLE_APPEND_WRITE

MSGBUS_MDR_IN_MASK = 0x1
MSGBUS_MDR_OUT_MASK = 0x2

IOCTL_BASE = 0x0
IOCTL_RDIO = 0x1
IOCTL_WRIO = 0x2
IOCTL_RDPCI = 0x3
IOCTL_WRPCI = 0x4
IOCTL_RDMSR = 0x5
IOCTL_WRMSR = 0x6
IOCTL_CPUID = 0x7
IOCTL_GET_CPU_DESCRIPTOR_TABLE = 0x8
IOCTL_HYPERCALL = 0x9
IOCTL_SWSMI = 0xA
IOCTL_LOAD_UCODE_PATCH = 0xB
IOCTL_ALLOC_PHYSMEM = 0xC
IOCTL_GET_EFIVAR = 0xD
IOCTL_SET_EFIVAR = 0xE
IOCTL_RDCR = 0x10
IOCTL_WRCR = 0x11
IOCTL_RDMMIO = 0x12
IOCTL_WRMMIO = 0x13
IOCTL_VA2PA = 0x14
IOCTL_MSGBUS_SEND_MESSAGE = 0x15
IOCTL_FREE_PHYSMEM = 0x16
IOCTL_SWSMI_TIMED = 0x17

_tools = {}

class LinuxHelper(Helper):

    DEVICE_NAME = "/dev/chipsec"
    DEV_MEM = "/dev/mem"
    DEV_PORT = "/dev/port"
    MODULE_NAME = "chipsec"
    SUPPORT_KERNEL26_GET_PAGE_IS_RAM = False
    SUPPORT_KERNEL26_GET_PHYS_MEM_ACCESS_PROT = False
    DKMS_DIR = "/var/lib/dkms/"

    def __init__(self):
        super(LinuxHelper, self).__init__()
        self.os_system = platform.system()
        self.os_release = platform.release()
        self.os_version = platform.version()
        self.os_machine = platform.machine()
        self.os_uname = platform.uname()
        self.name = "LinuxHelper"
        self.dev_fh = None
        self.dev_mem = None
        self.dev_port = None
        self.dev_msr = None

###############################################################################################
# Driver/service management functions
###############################################################################################

    def get_dkms_module_location(self) -> str:
        version = defines.get_version()
        from os import listdir
        from os.path import isdir, join
        p = os.path.join(self.DKMS_DIR, self.MODULE_NAME, version, self.os_release)
        os_machine_dir_name = [f for f in listdir(p) if isdir(join(p, f))][0]
        return os.path.join(self.DKMS_DIR, self.MODULE_NAME, version, self.os_release, os_machine_dir_name, "module", "chipsec.ko")

    # This function load CHIPSEC driver

    def load_chipsec_module(self):
        page_is_ram = ""
        phys_mem_access_prot = ""
        a1 = ""
        a2 = ""
        if self.SUPPORT_KERNEL26_GET_PAGE_IS_RAM:
            page_is_ram = self.get_page_is_ram()
            if not page_is_ram:
                logger().log_debug("Cannot find symbol 'page_is_ram'")
            else:
                a1 = f"a1=0x{page_is_ram}"
        if self.SUPPORT_KERNEL26_GET_PHYS_MEM_ACCESS_PROT:
            phys_mem_access_prot = self.get_phys_mem_access_prot()
            if not phys_mem_access_prot:
                logger().log_debug("Cannot find symbol 'phys_mem_access_prot'")
            else:
                a2 = f'a2=0x{phys_mem_access_prot}'

        driver_path = os.path.join(chipsec.library.file.get_main_dir(), "chipsec", "helper", "linux", "chipsec.ko")
        if not os.path.exists(driver_path):
            driver_path += ".xz"
            if not os.path.exists(driver_path):
                # check DKMS modules location
                try:
                    driver_path = self.get_dkms_module_location()
                except Exception:
                    pass
                if not os.path.exists(driver_path):
                    driver_path += ".xz"
                    if not os.path.exists(driver_path):
                        raise Exception("Cannot find chipsec.ko module")
        try:
            subprocess.check_output(["insmod", driver_path, a1, a2])
        except Exception as err:
            raise Exception(f'Could not start Linux Helper, are you running as Admin/root?\n\t{err}')
        uid = gid = 0
        os.chown(self.DEVICE_NAME, uid, gid)
        os.chmod(self.DEVICE_NAME, 600)
        if os.path.exists(self.DEVICE_NAME):
            logger().log_debug(f'Module {self.DEVICE_NAME} loaded successfully')
        else:
            logger().log_error(f'Fail to load module: {driver_path}')
        self.driverpath = f'({driver_path})'

    def unload_chipsec_module(self) -> None:
        if self.driver_loaded or os.path.exists(self.DEVICE_NAME):
            subprocess.call(["rmmod", self.MODULE_NAME])
            logger().log_debug(f'Module for {self.DEVICE_NAME} unloaded successfully')

    def create(self):
        logger().log_debug("[helper] Linux Helper created")
        return True

    def start(self) -> bool:
        self.unload_chipsec_module()
        self.load_chipsec_module()
        self.init()
        logger().log_debug("[helper] Linux Helper started/loaded")
        return True

    def stop(self) -> bool:
        self.close()
        self.unload_chipsec_module()
        logger().log_debug("[helper] Linux Helper stopped/unloaded")
        return True

    def delete(self) -> bool:
        logger().log_debug("[helper] Linux Helper deleted")
        return True

    def init(self) -> None:
        x64 = True if sys.maxsize > 2**32 else False
        self._pack = 'Q' if x64 else 'I'

        estr = "Unable to open chipsec device. Did you run as root/sudo and load the driver?\n {}"
        try:
            # Do not buffer access to physical memory...
            self.dev_fh = open(self.DEVICE_NAME, "rb+", buffering=0)
            self.driver_loaded = True
        except IOError as e:
            raise OsHelperError(estr.format(str(e)), e.errno)
        except BaseException as be:
            raise OsHelperError(estr.format(str(be)), errno.ENXIO)
        self._ioctl_base = self.compute_ioctlbase()

    def close(self) -> None:
        if self.dev_fh:
            self.dev_fh.close()
        self.dev_fh = None
        if self.dev_mem:
            os.close(self.dev_mem)
        self.dev_mem = None

    # code taken from /include/uapi/asm-generic/ioctl.h
    # by default itype is 'C' see drivers/linux/include/chipsec.h
    # currently all chipsec ioctl functions are _IOWR
    # currently all size are pointer
    def compute_ioctlbase(self, itype: str = 'C') -> int:
        # define _IOWR(type,nr,size)	 _IOC(_IOC_READ|_IOC_WRITE,(type),(nr),(_IOC_TYPECHECK(size)))
        # define _IOC(dir,type,nr,size) \
        #    (((dir)  << _IOC_DIRSHIFT) | \
        #    ((type) << _IOC_TYPESHIFT) | \
        #    ((nr)   << _IOC_NRSHIFT) | \
        #    ((size) << _IOC_SIZESHIFT))
        # IOC_READ | _IOC_WRITE is 3
        # default _IOC_DIRSHIFT is 30
        # default _IOC_TYPESHIFT is 8
        # nr will be 0
        # _IOC_SIZESHIFT is 16
        return (3 << 30) | (ord(itype) << 8) | (struct.calcsize(self._pack) << 16)

    def ioctl(self, nr: int, args: Iterable, *mutate_flag: bool) -> bytes:
        return fcntl.ioctl(self.dev_fh, self._ioctl_base + nr, args)

###############################################################################################
# Actual API functions to access HW resources
###############################################################################################

    def map_io_space(self, base: int, size: int, cache_type: int) -> None:
        raise UnimplementedAPIError("map_io_space")

    def __mem_block(self, sz: int, newval: Optional[bytes] = None) -> bytes:
        if self.dev_fh is not None:
            if newval is None:
                return self.dev_fh.read(sz)
            else:
                res = self.dev_fh.write(newval)
                self.dev_fh.flush()
                return res.to_bytes(4, 'little')
        return b''

    def write_phys_mem(self, phys_address: int, length: int, newval: bytes) -> int:
        if (newval is None) or (self.dev_fh is None):
            return 0
        self.dev_fh.seek(phys_address)
        res = self.__mem_block(length, newval)
        return int.from_bytes(res, 'little')

    def read_phys_mem(self, phys_address: int, length: int) -> bytes:
        self.dev_fh.seek(phys_address)
        return self.__mem_block(length)

    def va2pa(self, va: int) -> Tuple[Optional[int], int]:
        error_code = 0

        in_buf = struct.pack(self._pack, va)
        try:
            out_buf = self.ioctl(IOCTL_VA2PA, in_buf)
            pa = struct.unpack(self._pack, out_buf)[0]
        except IOError as err:
            if logger().DEBUG:
                logger().log_error(f'[helper] Error in va2pa: getting PA for VA 0x{va:016X} failed with IOError: {err.strerror}')
            return (None, err.errno)

        # Check if PA > max physical address
        max_pa = self.cpuid(0x80000008, 0x0)[0] & 0xFF
        if pa > 1 << max_pa:
            if logger().DEBUG:
                logger().log_error(f'[helper] Error in va2pa: PA higher that max physical address: VA (0x{va:016X}) -> PA (0x{pa:016X})')
            error_code = 1
        return (pa, error_code)

    def read_pci_reg(self, bus: int, device: int, function: int, offset: int, size: int = 4) -> int:
        _PCI_DOM = 0  # Change PCI domain, if there is more than one.
        d = struct.pack(f'5{self._pack}', ((_PCI_DOM << 16) | bus), ((device << 16) | function), offset, size, 0)
        try:
            ret = self.ioctl(IOCTL_RDPCI, d)
        except IOError:
            if logger().DEBUG:
                logger().log_error("IOError\n")
            return 0
        x = struct.unpack(f'5{self._pack}', ret)
        return x[4]

    def write_pci_reg(self, bus: int, device: int, function: int, offset: int, value: int, size: int = 4) -> int:
        _PCI_DOM = 0  # Change PCI domain, if there is more than one.
        d = struct.pack(f'5{self._pack}', ((_PCI_DOM << 16) | bus), ((device << 16) | function), offset, size, value)
        try:
            ret = self.ioctl(IOCTL_WRPCI, d)
        except IOError:
            if logger().DEBUG:
                logger().log_error("IOError\n")
            return 0
        x = struct.unpack(f'5{self._pack}', ret)
        return x[4]

    def load_ucode_update(self, cpu_thread_id: int, ucode_update_buf: bytes) -> bool:
        cpu_ucode_thread_id = ctypes.c_int(cpu_thread_id)

        in_buf = struct.pack('=BH', cpu_thread_id, len(ucode_update_buf)) + ucode_update_buf
        in_buf_final = array.array("c", in_buf)
        out_length = 0
        try:
            out_buf = self.ioctl(IOCTL_LOAD_UCODE_PATCH, in_buf_final)
        except IOError:
            if logger().DEBUG:
                logger().log_error("IOError IOCTL Load Patch\n")
            return False

        return True

    def read_io_port(self, io_port: int, size: int) -> int:
        in_buf = struct.pack(f'3{self._pack}', io_port, size, 0)
        out_buf = self.ioctl(IOCTL_RDIO, in_buf)
        try:
            if 1 == size:
                value = struct.unpack(f'3{self._pack}', out_buf)[2] & 0xff
            elif 2 == size:
                value = struct.unpack(f'3{self._pack}', out_buf)[2] & 0xffff
            else:
                value = struct.unpack(f'3{self._pack}', out_buf)[2] & 0xffffffff
        except:
            if logger().DEBUG:
                logger().log_error(f"DeviceIoControl did not return value of proper size {size:x} (value = '{out_buf}'): returning 0")
            value = 0

        return value

    def write_io_port(self, io_port: int, value: int, size: int) -> bytes:
        in_buf = struct.pack(f'3{self._pack}', io_port, size, value)
        return self.ioctl(IOCTL_WRIO, in_buf)

    def read_cr(self, cpu_thread_id: int, cr_number: int) -> int:
        self.set_affinity(cpu_thread_id)
        cr = 0
        in_buf = struct.pack(f'3{self._pack}', cpu_thread_id, cr_number, cr)
        unbuf = struct.unpack(f'3{self._pack}', self.ioctl(IOCTL_RDCR, in_buf))
        return (unbuf[2])

    def write_cr(self, cpu_thread_id: int, cr_number: int, value: int):
        self.set_affinity(cpu_thread_id)
        in_buf = struct.pack(f'3{self._pack}', cpu_thread_id, cr_number, value)
        self.ioctl(IOCTL_WRCR, in_buf)
        return

    def read_msr(self, thread_id: int, msr_addr: int) -> Tuple[int, int]:
        self.set_affinity(thread_id)
        edx = eax = 0
        in_buf = struct.pack(f'4{self._pack}', thread_id, msr_addr, edx, eax)
        unbuf = struct.unpack(f'4{self._pack}', self.ioctl(IOCTL_RDMSR, in_buf))
        return (unbuf[3], unbuf[2])

    def write_msr(self, thread_id: int, msr_addr: int, eax: int, edx: int):
        self.set_affinity(thread_id)
        in_buf = struct.pack(f'4{self._pack}', thread_id, msr_addr, edx, eax)
        self.ioctl(IOCTL_WRMSR, in_buf)
        return

    def get_descriptor_table(self, cpu_thread_id: int, desc_table_code: int) -> Tuple[int, int, int]:
        self.set_affinity(cpu_thread_id)
        in_buf = struct.pack(f'5{self._pack}', cpu_thread_id, desc_table_code, 0, 0, 0)
        out_buf = self.ioctl(IOCTL_GET_CPU_DESCRIPTOR_TABLE, in_buf)
        (limit, base_hi, base_lo, pa_hi, pa_lo) = struct.unpack(f'5{self._pack}', out_buf)
        pa = (pa_hi << 32) + pa_lo
        base = (base_hi << 32) + base_lo
        return (limit, base, pa)

    def cpuid(self, eax: int, ecx: int) -> Tuple[int, int, int, int]:
        # add ecx
        in_buf = struct.pack(f'4{self._pack}', eax, 0, ecx, 0)
        out_buf = self.ioctl(IOCTL_CPUID, in_buf)
        return struct.unpack(f'4{self._pack}', out_buf)

    def alloc_phys_mem(self, num_bytes: int, max_addr: int):
        in_buf = struct.pack("2" + self._pack, num_bytes, max_addr)
        out_buf = self.ioctl(IOCTL_ALLOC_PHYSMEM, in_buf)
        return struct.unpack(f'2{self._pack}', out_buf)

    def free_phys_mem(self, physmem: int):
        in_buf = struct.pack(f'1{self._pack}', physmem)
        out_buf = self.ioctl(IOCTL_FREE_PHYSMEM, in_buf)
        return struct.unpack(f'1{self._pack}', out_buf)[0]

    def read_mmio_reg(self, phys_address: int, size: int) -> int:
        in_buf = struct.pack(f'2{self._pack}', phys_address, size)
        out_buf = self.ioctl(IOCTL_RDMMIO, in_buf)
        reg = out_buf[:size]
        return defines.unpack1(reg, size)

    def write_mmio_reg(self, phys_address: int, size: int, value: int):
        in_buf = struct.pack(f'3{self._pack}', phys_address, size, value)
        out_buf = self.ioctl(IOCTL_WRMMIO, in_buf)

    def get_ACPI_table(self, table_name:str) -> Optional['Array']:
        raise UnimplementedAPIError("get_ACPI_table")

    def enum_ACPI_tables(self) -> Optional['Array']:
        raise UnimplementedAPIError('enum_ACPI_table')

    #
    # IOSF Message Bus access
    #
    def msgbus_send_read_message(self, mcr: int, mcrx: int) -> Optional[int]:
        return self.msgbus_send_message(mcr, mcrx)

    def msgbus_send_write_message(self, mcr: int, mcrx: int, mdr: int) -> None:
        self.msgbus_send_message(mcr, mcrx, mdr)
        return None

    def msgbus_send_message(self, mcr: int, mcrx: int, mdr: Optional[int] = None) -> int:
        mdr_out = 0
        if mdr is None:
            in_buf = struct.pack(f'5{self._pack}', MSGBUS_MDR_OUT_MASK, mcr, mcrx, 0, mdr_out)
        else:
            in_buf = struct.pack(f'5{self._pack}', (MSGBUS_MDR_IN_MASK | MSGBUS_MDR_OUT_MASK), mcr, mcrx, mdr, mdr_out)
        out_buf = self.ioctl(IOCTL_MSGBUS_SEND_MESSAGE, in_buf)
        mdr_out = struct.unpack(f'5{self._pack}', out_buf)[4]
        return mdr_out

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

    #########################################################
    # (U)EFI Variable API
    #########################################################

    def EFI_supported(self) -> bool:
        return os.path.exists("/sys/firmware/efi/vars/") or os.path.exists("/sys/firmware/efi/efivars/")

    def delete_EFI_variable(self, name: str, guid: str) -> int:
        return self.kern_set_EFI_variable(name, guid, b"")

    def list_EFI_variables(self) -> Optional[Dict[str, List['EfiVariableType']]]:
        return self.kern_list_EFI_variables()

    def get_EFI_variable(self, name: str, guid: str, attrs: Optional[int] = None) -> bytes:
        return self.kern_get_EFI_variable(name, guid)

    def set_EFI_variable(self, name: str, guid: str, buffer: bytes, buffer_size: int, attrs: Optional[int] = None) -> int:
        return self.kern_set_EFI_variable(name, guid, buffer)

    #
    # Internal (U)EFI Variable API functions via CHIPSEC kernel module
    #

    def kern_get_EFI_variable_full(self, name: str, guid: str) -> 'EfiVariableType':
        status_dict = {0: "EFI_SUCCESS", 1: "EFI_LOAD_ERROR", 2: "EFI_INVALID_PARAMETER", 3: "EFI_UNSUPPORTED", 4: "EFI_BAD_BUFFER_SIZE", 5: "EFI_BUFFER_TOO_SMALL", 6: "EFI_NOT_READY", 7: "EFI_DEVICE_ERROR", 8: "EFI_WRITE_PROTECTED", 9: "EFI_OUT_OF_RESOURCES", 14: "EFI_NOT_FOUND", 26: "EFI_SECURITY_VIOLATION"}
        off = 0
        data = b''
        attr = 0
        buf = b''
        hdr = 0
        base = 12
        namelen = len(name)
        header_size = 52
        data_size = header_size + namelen
        guid0 = int(guid[:8], 16)
        guid1 = int(guid[9:13], 16)
        guid2 = int(guid[14:18], 16)
        guid3 = int(guid[19:21], 16)
        guid4 = int(guid[21:23], 16)
        guid5 = int(guid[24:26], 16)
        guid6 = int(guid[26:28], 16)
        guid7 = int(guid[28:30], 16)
        guid8 = int(guid[30:32], 16)
        guid9 = int(guid[32:34], 16)
        guid10 = int(guid[34:], 16)

        in_buf = struct.pack(f'13I{str(namelen)}s', data_size, guid0, guid1, guid2, guid3, guid4, guid5, guid6, guid7, guid8, guid9, guid10, namelen, name.encode())
        buffer = array.array("B", in_buf)
        stat = self.ioctl(IOCTL_GET_EFIVAR, buffer)
        new_size, status = struct.unpack("2I", buffer[:8])

        if (status == 0x5):
            data_size = new_size + header_size + namelen  # size sent by driver + size of header (size + guid) + size of name
            in_buf = struct.pack(f'13I{str(namelen + new_size)}s', data_size, guid0, guid1, guid2, guid3, guid4, guid5, guid6, guid7, guid8, guid9, guid10, namelen, name.encode())
            buffer = array.array("B", in_buf)
            try:
                stat = self.ioctl(IOCTL_GET_EFIVAR, buffer)
            except IOError:
                if logger().DEBUG:
                    logger().log_error("IOError IOCTL GetUEFIvar\n")
                return (off, buf, hdr, b'', guid, attr)
            new_size, status = struct.unpack("2I", buffer[:8])

        if (new_size > data_size):
            if logger().DEBUG:
                logger().log_error("Incorrect size returned from driver")
            return (off, buf, hdr, b'', guid, attr)

        if (status > 0):
            if logger().DEBUG:
                logger().log_error(f'Reading variable (GET_EFIVAR) did not succeed: {status_dict.get(status, "UNKNOWN")} ({status:d})')
            data = b''
            guid = ''
            attr = 0
        else:
            data = buffer[base:base + new_size].tobytes()
            attr = struct.unpack("I", buffer[8:12])[0]
        return (off, buf, hdr, data, guid, attr)

    def kern_get_EFI_variable(self, name: str, guid: str) -> bytes:
        (_, _, _, data, guid, _) = self.kern_get_EFI_variable_full(name, guid)
        return data

    def kern_list_EFI_variables(self) -> Optional[Dict[str, List['EfiVariableType']]]:
        varlist = []
        off = 0
        hdr = 0
        attr = 0
        try:
            if os.path.isdir('/sys/firmware/efi/efivars'):
                varlist = os.listdir('/sys/firmware/efi/efivars')
            elif os.path.isdir('/sys/firmware/efi/vars'):
                varlist = os.listdir('/sys/firmware/efi/vars')
            else:
                return None
        except Exception:
            if logger().DEBUG:
                logger().log_error('Failed to read /sys/firmware/efi/[vars|efivars]. Folder does not exist')
            return None
        variables = dict()
        for v in varlist:
            name = v[:-37]
            guid = v[len(name) + 1:]
            if name and name is not None:
                variables[name] = []
                var = self.kern_get_EFI_variable_full(name, guid)
                (off, buf, hdr, data, guid, attr) = var
                variables[name].append(var)
        return variables

    def kern_set_EFI_variable(self, name: str, guid: str, value: bytes, attr: int = 0x7) -> int:
        status_dict = {
            0: "EFI_SUCCESS",
            1: "EFI_LOAD_ERROR",
            2: "EFI_INVALID_PARAMETER",
            3: "EFI_UNSUPPORTED",
            4: "EFI_BAD_BUFFER_SIZE",
            5: "EFI_BUFFER_TOO_SMALL",
            6: "EFI_NOT_READY",
            7: "EFI_DEVICE_ERROR",
            8: "EFI_WRITE_PROTECTED",
            9: "EFI_OUT_OF_RESOURCES",
            14: "EFI_NOT_FOUND",
            26: "EFI_SECURITY_VIOLATION"
        }

        header_size = 60  # 4*15
        namelen = len(name)
        if value:
            datalen = len(value)
        else:
            datalen = 0
            value = struct.pack('B', 0x0)
        data_size = header_size + namelen + datalen
        guid0 = int(guid[:8], 16)
        guid1 = int(guid[9:13], 16)
        guid2 = int(guid[14:18], 16)
        guid3 = int(guid[19:21], 16)
        guid4 = int(guid[21:23], 16)
        guid5 = int(guid[24:26], 16)
        guid6 = int(guid[26:28], 16)
        guid7 = int(guid[28:30], 16)
        guid8 = int(guid[30:32], 16)
        guid9 = int(guid[32:34], 16)
        guid10 = int(guid[34:], 16)

        pack_formatting = f'15I{namelen}s{datalen}s'
        _guid = (guid0, guid1, guid2, guid3, guid4, guid5, guid6, guid7, guid8, guid9, guid10)
        in_buf = struct.pack(pack_formatting, data_size, *_guid, attr, namelen, datalen, name.encode('utf-8'), value)
        buffer = array.array("B", in_buf)
        self.ioctl(IOCTL_SET_EFIVAR, buffer)
        _, status = struct.unpack("2I", buffer[:8])

        if (status != 0):
            if logger().DEBUG:
                logger().log_error(f"Setting EFI (SET_EFIVAR) variable did not succeed: '{status_dict.get(status, 'UNKNOWN')}' ({status:d})")
        else:
            os.system('umount /sys/firmware/efi/efivars; mount -t efivarfs efivarfs /sys/firmware/efi/efivars')
        return status


    #
    # Hypercalls
    #
    def hypercall(self, rcx: int, rdx: int, r8: int, r9: int, r10: int, r11: int, rax: int, rbx: int, rdi: int, rsi: int, xmm_buffer: int) -> int:
        in_buf = struct.pack(f'<11{self._pack}', rcx, rdx, r8, r9, r10, r11, rax, rbx, rdi, rsi, xmm_buffer)
        out_buf = self.ioctl(IOCTL_HYPERCALL, in_buf)
        return struct.unpack(f'<11{self._pack}', out_buf)[0]

    #
    # Interrupts
    #
    def send_sw_smi(self, cpu_thread_id: int, SMI_code_data: int, _rax: int, _rbx: int, _rcx: int, _rdx: int, _rsi: int, _rdi: int) -> Optional[Tuple[int, int, int, int, int, int, int]]:
        self.set_affinity(cpu_thread_id)
        in_buf = struct.pack(f'7{self._pack}', SMI_code_data, _rax, _rbx, _rcx, _rdx, _rsi, _rdi)
        out_buf = self.ioctl(IOCTL_SWSMI, in_buf)
        ret = struct.unpack(f'7{self._pack}', out_buf)
        return ret

    def send_sw_smi_timed(self, cpu_thread_id: int, SMI_code_data: int, _rax: int, _rbx: int, _rcx: int, _rdx: int, _rsi: int, _rdi: int) -> Optional[Tuple[int, int, int, int, int, int, int]]:
        self.set_affinity(cpu_thread_id)
        in_buf = struct.pack(f'8{self._pack}', SMI_code_data, _rax, _rbx, _rcx, _rdx, _rsi, _rdi, 0)
        out_buf = self.ioctl(IOCTL_SWSMI_TIMED, in_buf)
        ret = struct.unpack(f'8{self._pack}', out_buf)
        return ret

    #
    # File system
    #
    def get_tool_info(self, tool_type: str) -> Tuple[Optional[str], str]:
        tool_name = _tools[tool_type] if tool_type in _tools else None
        tool_path = os.path.join(get_tools_path(), self.os_system.lower())
        return tool_name, tool_path

    def get_page_is_ram(self) -> Optional[bytes]:
        PROC_KALLSYMS = "/proc/kallsyms"
        symarr = chipsec.library.file.read_file(PROC_KALLSYMS).splitlines()
        for line in symarr:
            if b"page_is_ram" in line:
                return line.split(b" ")[0]
        return None

    def get_phys_mem_access_prot(self) -> Optional[bytes]:
        PROC_KALLSYMS = "/proc/kallsyms"
        symarr = chipsec.library.file.read_file(PROC_KALLSYMS).splitlines()
        for line in symarr:
            if b"phys_mem_access_prot" in line:
                return line.split(b" ")[0]
        return None

    #
    # Logical CPU count
    #
    def get_threads_count(self) -> int:
        import multiprocessing
        return multiprocessing.cpu_count()

    #
    # Speculation control
    #
    def retpoline_enabled(self):
        raise NotImplementedError("retpoline_enabled")


def get_helper():
    return LinuxHelper()
