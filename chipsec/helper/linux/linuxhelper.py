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

from chipsec import defines
from chipsec.helper.oshelper import get_tools_path
from chipsec.exceptions import OsHelperError, UnimplementedAPIError, UnimplementedNativeAPIError
from chipsec.helper.basehelper import Helper
from chipsec.logger import logger
import chipsec.file
from chipsec.hal.uefi_common import EFI_VARIABLE_NON_VOLATILE, EFI_VARIABLE_BOOTSERVICE_ACCESS, EFI_VARIABLE_RUNTIME_ACCESS
from chipsec.hal.uefi_common import EFI_VARIABLE_HARDWARE_ERROR_RECORD, EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS
from chipsec.hal.uefi_common import EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS, EFI_VARIABLE_APPEND_WRITE
from chipsec.helper.linux.legacy_pci import LEGACY_PCI

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

_tools = {}
class MemoryMapping(mmap.mmap):
    """Memory mapping based on Python's mmap.

    This subclass keeps tracks of the start and end of the mapping.
    """

    def __init__(self, fileno, length, flags, prot, offset):
        self.start = offset
        self.end = offset + length
        super().__init__()


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
        self.module_loaded = False
        self.legacy_pci = None

        # A list of all the mappings allocated via map_io_space. When using
        # read/write MMIO, if the region is already mapped in the process's
        # memory, simply read/write from there.
        self.mappings = []

###############################################################################################
# Driver/service management functions
###############################################################################################

    def get_dkms_module_location(self):
        version = defines.get_version()
        from os import listdir
        from os.path import isdir, join
        p = os.path.join(self.DKMS_DIR, self.MODULE_NAME, version, self.os_release)
        os_machine_dir_name = [f for f in listdir(p) if isdir(join(p, f))][0]
        return os.path.join(self.DKMS_DIR, self.MODULE_NAME, version, self.os_release, os_machine_dir_name, "module", "chipsec.ko")

    # This function load CHIPSEC driver

    def load_chipsec_module(self):
        if os.path.exists(self.DEVICE_NAME):
            if logger().DEBUG:
                logger().log("Module for {} already loaded".format(self.DEVICE_NAME))
            return

        page_is_ram = ""
        phys_mem_access_prot = ""
        a1 = ""
        a2 = ""
        if self.SUPPORT_KERNEL26_GET_PAGE_IS_RAM:
            page_is_ram = self.get_page_is_ram()
            if not page_is_ram:
                if logger().DEBUG:
                    logger().log("Cannot find symbol 'page_is_ram'")
            else:
                a1 = "a1=0x{}".format(page_is_ram)
        if self.SUPPORT_KERNEL26_GET_PHYS_MEM_ACCESS_PROT:
            phys_mem_access_prot = self.get_phys_mem_access_prot()
            if not phys_mem_access_prot:
                if logger().DEBUG:
                    logger().log("Cannot find symbol 'phys_mem_access_prot'")
            else:
                a2 = "a2=0x{}".format(phys_mem_access_prot)

        driver_path = os.path.join(chipsec.file.get_main_dir(), "chipsec", "helper", "linux", "chipsec.ko")
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
            self.module_loaded = True
        except Exception as err:
            raise Exception("Could not start Linux Helper, are you running as Admin/root?\n\t{}".format(err))
        uid = gid = 0
        os.chown(self.DEVICE_NAME, uid, gid)
        os.chmod(self.DEVICE_NAME, 600)
        if os.path.exists(self.DEVICE_NAME):
            if logger().DEBUG:
                logger().log("Module {} loaded successfully".format(self.DEVICE_NAME))
        else:
            logger().log_error("Fail to load module: {}".format(driver_path))
        self.driverpath = driver_path

    def unload_chipsec_module(self):
        if self.module_loaded:
            subprocess.call(["rmmod", self.MODULE_NAME])
            self.module_loaded = False
            if logger().DEBUG:
                logger().log("Module for {} unloaded successfully".format(self.DEVICE_NAME))

    def create(self, start_driver):
        if logger().DEBUG:
            logger().log("[helper] Linux Helper created")
        return True

    def start(self, start_driver, driver_exists=False):
        if start_driver:
            self.load_chipsec_module()
        self.init(start_driver)
        if logger().DEBUG:
            logger().log("[helper] Linux Helper started/loaded")
        return True

    def stop(self, start_driver):
        self.close()
        self.unload_chipsec_module()
        if logger().DEBUG:
            logger().log("[helper] Linux Helper stopped/unloaded")
        return True

    def delete(self, start_driver):
        if logger().DEBUG:
            logger().log("[helper] Linux Helper deleted")
        return True

    def init(self, start_driver):
        x64 = True if sys.maxsize > 2**32 else False
        self._pack = 'Q' if x64 else 'I'

        if start_driver:
            logger().log("****** Chipsec Linux Kernel module is licensed under GPL 2.0")

            try:
                self.dev_fh = open(self.DEVICE_NAME, "rb+")
                self.driver_loaded = True
            except IOError as e:
                raise OsHelperError("Unable to open chipsec device. Did you run as root/sudo and load the driver?\n {}".format(str(e)), e.errno)
            except BaseException as be:
                raise OsHelperError("Unable to open chipsec device. Did you run as root/sudo and load the driver?\n {}".format(str(be)), errno.ENXIO)

            self._ioctl_base = self.compute_ioctlbase()

    def devmem_available(self):
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
                                "{}".format(str(err)), err.errno)

    def devport_available(self):
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
                                "{}".format(str(err)), err.errno)

    def devmsr_available(self):
        """Check if /dev/cpu/CPUNUM/msr is usable.

           In case the driver is not loaded, we might be able to perform the
           requested operation via /dev/cpu/CPUNUM/msr. This requires loading
           the (more standard) msr driver. Returns True if /dev/cpu/CPUNUM/msr
           is accessible.
        """
        if self.dev_msr:
            return True

        try:
            self.dev_msr = dict()
            if not os.path.exists("/dev/cpu/0/msr"):
                os.system("modprobe msr")
            for cpu in os.listdir("/dev/cpu"):
                if logger().DEBUG:
                    logger().log("found cpu = {}".format(cpu))
                if cpu.isdigit():
                    cpu = int(cpu)
                    self.dev_msr[cpu] = os.open("/dev/cpu/" + str(cpu) + "/msr", os.O_RDWR)
                    if logger().DEBUG:
                        logger().log("Added dev_msr {}".format(str(cpu)))
            return True
        except IOError as err:
            raise OsHelperError("Unable to open /dev/cpu/CPUNUM/msr.\n"
                                "This command requires access to /dev/cpu/CPUNUM/msr.\n"
                                "Are you running this command as root?\n"
                                "Do you have the msr kernel module installed?\n"
                                "{}".format(str(err)), err.errno)

    def close(self):
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
    def compute_ioctlbase(self, itype='C'):
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

    def ioctl(self, nr, args, *mutate_flag):
        return fcntl.ioctl(self.dev_fh, self._ioctl_base + nr, args)

###############################################################################################
# Actual API functions to access HW resources
###############################################################################################
    def memory_mapping(self, base, size):
        """Returns the mmap region that fully encompasses this area.

        Returns None if no region matches.
        """
        for region in self.mappings:
            if region.start <= base and region.end >= base + size:
                return region
        return None

    def native_map_io_space(self, base, size, cache_type):
        """Map to memory a specific region."""
        if self.devmem_available() and not self.memory_mapping(base, size):
            if logger().DEBUG:
                logger().log("[helper] Mapping 0x{:x} to memory".format(base))
            length = max(size, resource.getpagesize())
            page_aligned_base = base - (base % resource.getpagesize())
            mapping = MemoryMapping(self.dev_mem, length, mmap.MAP_SHARED,
                                    mmap.PROT_READ | mmap.PROT_WRITE,
                                    offset=page_aligned_base)
            self.mappings.append(mapping)

    def map_io_space(self, base, size, cache_type):
        raise UnimplementedAPIError("map_io_space")

    def __mem_block(self, sz, newval=None):
        if newval is None:
            return self.dev_fh.read(sz)
        else:
            self.dev_fh.write(newval)
            self.dev_fh.flush()
        return 1

    def write_phys_mem(self, phys_address_hi, phys_address_lo, length, newval):
        if newval is None:
            return None
        addr = (phys_address_hi << 32) | phys_address_lo
        self.dev_fh.seek(addr)
        return self.__mem_block(length, newval)

    def native_write_phys_mem(self, phys_address_hi, phys_address_lo, length, newval):
        if newval is None:
            return None
        if self.devmem_available():
            addr = (phys_address_hi << 32) | phys_address_lo
            os.lseek(self.dev_mem, addr, os.SEEK_SET)
            written = os.write(self.dev_mem, newval)
            if written != length:
                if logger().DEBUG:
                    logger().log_error("Cannot write {} to memory {:016X} (wrote {:d} of {:d})".format(newval, addr, written, length))

    def read_phys_mem(self, phys_address_hi, phys_address_lo, length):
        addr = (phys_address_hi << 32) | phys_address_lo
        self.dev_fh.seek(addr)
        return self.__mem_block(length)

    def native_read_phys_mem(self, phys_address_hi, phys_address_lo, length):
        if self.devmem_available():
            addr = (phys_address_hi << 32) | phys_address_lo
            os.lseek(self.dev_mem, addr, os.SEEK_SET)
            return os.read(self.dev_mem, length)

    def va2pa(self, va):
        error_code = 0

        in_buf = struct.pack(self._pack, va)
        try:
            out_buf = self.ioctl(IOCTL_VA2PA, in_buf)
            pa = struct.unpack(self._pack, out_buf)[0]
        except IOError as err:
            if logger().DEBUG:
                logger().log_error("[helper] Error in va2pa: getting PA for VA 0x{:016X} failed with IOError: {}".format(va, err.strerror))
            return (None, err.errno)

        # Check if PA > max physical address
        max_pa = self.cpuid(0x80000008, 0x0)[0] & 0xFF
        if pa > 1 << max_pa:
            if logger().DEBUG:
                logger().log_error("[helper] Error in va2pa: PA higher that max physical address: VA (0x{:016X}) -> PA (0x{:016X})".format(va, pa))
            error_code = 1
        return (pa, error_code)

    def read_pci_reg(self, bus, device, function, offset, size=4):
        _PCI_DOM = 0  # Change PCI domain, if there is more than one.
        d = struct.pack("5" + self._pack, ((_PCI_DOM << 16) | bus), ((device << 16) | function), offset, size, 0)
        try:
            ret = self.ioctl(IOCTL_RDPCI, d)
        except IOError:
            if logger().DEBUG:
                logger().log_error("IOError\n")
            return None
        x = struct.unpack("5" + self._pack, ret)
        return x[4]

    def native_read_pci_reg(self, bus, device, function, offset, size, domain=0):
        device_name = "{domain:04x}:{bus:02x}:{device:02x}.{function}".format(
                      domain=domain, bus=bus, device=device, function=function)
        device_path = "/sys/bus/pci/devices/{}/config".format(device_name)
        if not os.path.exists(device_path):
            if offset < 256:
                if self.legacy_pci:
                    pci = self.legacy_pci
                else:
                    pci = LEGACY_PCI()
                    self.legacy_pci = pci
                value = pci.read_pci_config(bus, device, function, offset)
                return value
            else:
                byte = b"\xff"
                return defines.unpack1(byte * size, size)
        try:
            config = open(device_path, "rb")
        except IOError as err:
            raise OsHelperError("Unable to open {}".format(device_path), err.errno)
        config.seek(offset)
        reg = config.read(size)
        config.close()
        reg = defines.unpack1(reg, size)
        return reg

    def write_pci_reg(self, bus, device, function, offset, value, size=4):
        _PCI_DOM = 0  # Change PCI domain, if there is more than one.
        d = struct.pack("5" + self._pack, ((_PCI_DOM << 16) | bus), ((device << 16) | function), offset, size, value)
        try:
            ret = self.ioctl(IOCTL_WRPCI, d)
        except IOError:
            if logger().DEBUG:
                logger().log_error("IOError\n")
            return None
        x = struct.unpack("5" + self._pack, ret)
        return x[4]

    def native_write_pci_reg(self, bus, device, function, offset, value, size=4, domain=0):
        device_name = "{domain:04x}:{bus:02x}:{device:02x}.{function}".format(
                      domain=domain, bus=bus, device=device, function=function)
        device_path = "/sys/bus/pci/devices/{}/config".format(device_name)
        if not os.path.exists(device_path):
            if offset < 256:
                if self.legacy_pci:
                    pci = self.legacy_pci
                else:
                    pci = LEGACY_PCI()
                    self.legacy_pci = pci
                value = pci.write_pci_config(bus, device, function, offset, value)
                return False
        try:
            config = open(device_path, "wb")
        except IOError as err:
            raise OsHelperError("Unable to open {}".format(device_path), err.errno)
        config.seek(offset)
        config.write(defines.pack1(value, size))
        config.close()

    def load_ucode_update(self, cpu_thread_id, ucode_update_buf):
        cpu_ucode_thread_id = ctypes.c_int(cpu_thread_id)

        in_buf = struct.pack('=BH', cpu_thread_id, len(ucode_update_buf)) + ucode_update_buf
        in_buf_final = array.array("c", in_buf)
        # print_buffer(in_buf)
        out_length = 0
        try:
            out_buf = self.ioctl(IOCTL_LOAD_UCODE_PATCH, in_buf_final)
        except IOError:
            if logger().DEBUG:
                logger().log_error("IOError IOCTL Load Patch\n")
            return None

        return True

    def read_io_port(self, io_port, size):
        in_buf = struct.pack("3" + self._pack, io_port, size, 0)
        out_buf = self.ioctl(IOCTL_RDIO, in_buf)
        try:
            # print_buffer(out_buf)
            if 1 == size:
                value = struct.unpack("3" + self._pack, out_buf)[2] & 0xff
            elif 2 == size:
                value = struct.unpack("3" + self._pack, out_buf)[2] & 0xffff
            else:
                value = struct.unpack("3" + self._pack, out_buf)[2] & 0xffffffff
        except:
            if logger().DEBUG:
                logger().log_error("DeviceIoControl did not return value of proper size {:x} (value = '{}')".format(size, out_buf))

        return value

    def native_read_io_port(self, io_port, size):
        if self.devport_available():
            os.lseek(self.dev_port, io_port, os.SEEK_SET)

            value = os.read(self.dev_port, size)
            if 1 == size:
                return struct.unpack("B", value)[0]
            elif 2 == size:
                return struct.unpack("H", value)[0]
            elif 4 == size:
                return struct.unpack("I", value)[0]

    def write_io_port(self, io_port, value, size):
        in_buf = struct.pack("3" + self._pack, io_port, size, value)
        return self.ioctl(IOCTL_WRIO, in_buf)

    def native_write_io_port(self, io_port, newval, size):
        if self.devport_available():
            os.lseek(self.dev_port, io_port, os.SEEK_SET)
            if 1 == size:
                fmt = 'B'
            elif 2 == size:
                fmt = 'H'
            elif 4 == size:
                fmt = 'I'
            written = os.write(self.dev_port, struct.pack(fmt, newval))
            if written != size:
                if logger().DEBUG:
                    logger().log_error("Cannot write {} to port {:x} (wrote {:d} of {:d})".format(newval, io_port, written, size))

    def read_cr(self, cpu_thread_id, cr_number):
        self.set_affinity(cpu_thread_id)
        cr = 0
        in_buf = struct.pack("3" + self._pack, cpu_thread_id, cr_number, cr)
        unbuf = struct.unpack("3" + self._pack, self.ioctl(IOCTL_RDCR, in_buf))
        return (unbuf[2])

    def write_cr(self, cpu_thread_id, cr_number, value):
        self.set_affinity(cpu_thread_id)
        in_buf = struct.pack("3" + self._pack, cpu_thread_id, cr_number, value)
        self.ioctl(IOCTL_WRCR, in_buf)
        return

    def read_msr(self, thread_id, msr_addr):
        self.set_affinity(thread_id)
        edx = eax = 0
        in_buf = struct.pack("4" + self._pack, thread_id, msr_addr, edx, eax)
        unbuf = struct.unpack("4" + self._pack, self.ioctl(IOCTL_RDMSR, in_buf))
        return (unbuf[3], unbuf[2])

    def native_read_msr(self, thread_id, msr_addr):
        if self.devmsr_available():
            os.lseek(self.dev_msr[thread_id], msr_addr, os.SEEK_SET)
            buf = os.read(self.dev_msr[thread_id], 8)
            unbuf = struct.unpack("2I", buf)
            return (unbuf[0], unbuf[1])

    def write_msr(self, thread_id, msr_addr, eax, edx):
        self.set_affinity(thread_id)
        in_buf = struct.pack("4" + self._pack, thread_id, msr_addr, edx, eax)
        self.ioctl(IOCTL_WRMSR, in_buf)
        return

    def native_write_msr(self, thread_id, msr_addr, eax, edx):
        if self.devmsr_available():
            os.lseek(self.dev_msr[thread_id], msr_addr, os.SEEK_SET)
            buf = struct.pack("2I", eax, edx)
            written = os.write(self.dev_msr[thread_id], buf)
            if written != 8:
                if logger().DEBUG:
                    logger().log_error("Cannot write {:8X} to MSR {:x}".format(buf, msr_addr))

    def get_descriptor_table(self, cpu_thread_id, desc_table_code):
        self.set_affinity(cpu_thread_id)
        in_buf = struct.pack("5" + self._pack, cpu_thread_id, desc_table_code, 0, 0, 0)
        out_buf = self.ioctl(IOCTL_GET_CPU_DESCRIPTOR_TABLE, in_buf)
        (limit, base_hi, base_lo, pa_hi, pa_lo) = struct.unpack("5" + self._pack, out_buf)
        pa = (pa_hi << 32) + pa_lo
        base = (base_hi << 32) + base_lo
        return (limit, base, pa)

    def cpuid(self, eax, ecx):
        # add ecx
        in_buf = struct.pack("4" + self._pack, eax, 0, ecx, 0)
        out_buf = self.ioctl(IOCTL_CPUID, in_buf)
        return struct.unpack("4" + self._pack, out_buf)

    def native_cpuid(self, eax, ecx):
        import chipsec.helper.linux.cpuid as cpuid
        _cpuid = cpuid.CPUID()
        return _cpuid(eax, ecx)

    def alloc_phys_mem(self, num_bytes, max_addr):
        in_buf = struct.pack("2" + self._pack, num_bytes, max_addr)
        out_buf = self.ioctl(IOCTL_ALLOC_PHYSMEM, in_buf)
        return struct.unpack("2" + self._pack, out_buf)

    def free_phys_mem(self, physmem):
        in_buf = struct.pack("1" + self._pack, physmem)
        out_buf = self.ioctl(IOCTL_FREE_PHYSMEM, in_buf)
        return struct.unpack("1" + self._pack, out_buf)[0]

    def read_mmio_reg(self, phys_address, size):
        in_buf = struct.pack("2" + self._pack, phys_address, size)
        out_buf = self.ioctl(IOCTL_RDMMIO, in_buf)
        reg = out_buf[:size]
        return defines.unpack1(reg, size)

    def native_read_mmio_reg(self, bar_base, bar_size, offset, size):
        if bar_size is None or bar_size < offset:
            bar_size = offset + size
        if self.devmem_available():
            region = self.memory_mapping(bar_base, bar_size)
            if not region:
                self.native_map_io_space(bar_base, bar_size, 0)
                region = self.memory_mapping(bar_base, bar_size)
                if not region:
                    logger().log_error("Unable to map region {:08x}".format(bar_base))

            # Create memoryview into mmap'ed region in dword granularity
            region_mv = memoryview(region)
            region_dw = region_mv.cast('I')
            # read one DWORD
            offset_in_region = (bar_base + offset - region.start) // 4
            reg = region_dw[offset_in_region]
            return reg

    def write_mmio_reg(self, phys_address, size, value):
        in_buf = struct.pack("3" + self._pack, phys_address, size, value)
        out_buf = self.ioctl(IOCTL_WRMMIO, in_buf)

    def native_write_mmio_reg(self, bar_base, bar_size, offset, size, value):
        if bar_size is None:
            bar_size = offset + size
        if self.devmem_available():
            reg = defines.pack1(value, size)
            region = self.memory_mapping(bar_base, bar_size)
            if not region:
                self.native_map_io_space(bar_base, bar_size, 0)
                region = self.memory_mapping(bar_base, bar_size)
                if not region:
                    logger().log_error("Unable to map region {:08x}".format(bar_base))

            # Create memoryview into mmap'ed region in dword granularity
            region_mv = memoryview(region)
            region_dw = region_mv.cast('I')
            # Create memoryview containing data in dword
            data_mv = memoryview(reg)
            data_dw = data_mv.cast('I')
            # write one DWORD
            offset_in_region = (bar_base + offset - region.start) // 4
            region_dw[offset_in_region] = data_dw[0]

    def get_ACPI_SDT(self):
        raise UnimplementedAPIError("get_ACPI_SDT")
    # @TODO: implement ACPI access in native mode through file system

    def native_get_ACPI_table(self):
        raise UnimplementedNativeAPIError("native_get_ACPI_table")
    # ACPI access is implemented through ACPI HAL rather than through kernel module

    def get_ACPI_table(self, table_name):
        raise UnimplementedAPIError("get_ACPI_table")

    #
    # IOSF Message Bus access
    #
    def msgbus_send_read_message(self, mcr, mcrx):
        mdr_out = 0
        in_buf = struct.pack("5" + self._pack, MSGBUS_MDR_OUT_MASK, mcr, mcrx, 0, mdr_out)
        out_buf = self.ioctl(IOCTL_MSGBUS_SEND_MESSAGE, in_buf)
        mdr_out = struct.unpack("5" + self._pack, out_buf)[4]
        return mdr_out

    def msgbus_send_write_message(self, mcr, mcrx, mdr):
        in_buf = struct.pack("5" + self._pack, MSGBUS_MDR_IN_MASK, mcr, mcrx, mdr, 0)
        out_buf = self.ioctl(IOCTL_MSGBUS_SEND_MESSAGE, in_buf)
        return

    def msgbus_send_message(self, mcr, mcrx, mdr=None):
        mdr_out = 0
        if mdr is None:
            in_buf = struct.pack("5" + self._pack, MSGBUS_MDR_OUT_MASK, mcr, mcrx, 0, mdr_out)
        else:
            in_buf = struct.pack("5" + self._pack, (MSGBUS_MDR_IN_MASK | MSGBUS_MDR_OUT_MASK), mcr, mcrx, mdr, mdr_out)
        out_buf = self.ioctl(IOCTL_MSGBUS_SEND_MESSAGE, in_buf)
        mdr_out = struct.unpack("5" + self._pack, out_buf)[4]
        return mdr_out

    #
    # Affinity functions
    #

    def get_affinity(self):
        try:
            affinity = os.sched_getaffinity(0)
            return list(affinity)[0]
        except Exception:
            return None

    def set_affinity(self, thread_id):
        try:
            os.sched_setaffinity(os.getpid(), {thread_id})
            return thread_id
        except Exception:
            return None

    #########################################################
    # (U)EFI Variable API
    #########################################################

    def use_efivars(self):
        return os.path.exists("/sys/firmware/efi/efivars/")

    def EFI_supported(self):
        return os.path.exists("/sys/firmware/efi/vars/") or os.path.exists("/sys/firmware/efi/efivars/")

    def delete_EFI_variable(self, name, guid):
        return self.kern_set_EFI_variable(name, guid, "")

    def native_delete_EFI_variable(self, name, guid):
        if self.use_efivars():
            return self.EFIVARS_set_EFI_variable(name, guid, None)

    def list_EFI_variables(self):
        return self.kern_list_EFI_variables()

    def native_list_EFI_variables(self):
        if self.use_efivars():
            return self.EFIVARS_list_EFI_variables()
        else:
            return self.VARS_list_EFI_variables()

    def get_EFI_variable(self, name, guid, attrs=None):
        return self.kern_get_EFI_variable(name, guid)

    def native_get_EFI_variable(self, name, guid, attrs=None):
        if self.use_efivars():
            return self.EFIVARS_get_EFI_variable(name, guid)
        else:
            return self.VARS_get_EFI_variable(name, guid)

    def set_EFI_variable(self, name, guid, data, datasize, attrs=None):
        return self.kern_set_EFI_variable(name, guid, data)

    def native_set_EFI_variable(self, name, guid, data, datasize, attrs=None):
        if self.use_efivars():
            return self.EFIVARS_set_EFI_variable(name, guid, data, attrs)
        else:
            return self.VARS_set_EFI_variable(name, guid, data)

    #
    # Internal (U)EFI Variable API functions via CHIPSEC kernel module
    # Invoked when use_native_api() is False
    #

    def kern_get_EFI_variable_full(self, name, guid):
        status_dict = {0: "EFI_SUCCESS", 1: "EFI_LOAD_ERROR", 2: "EFI_INVALID_PARAMETER", 3: "EFI_UNSUPPORTED", 4: "EFI_BAD_BUFFER_SIZE", 5: "EFI_BUFFER_TOO_SMALL", 6: "EFI_NOT_READY", 7: "EFI_DEVICE_ERROR", 8: "EFI_WRITE_PROTECTED", 9: "EFI_OUT_OF_RESOURCES", 14: "EFI_NOT_FOUND", 26: "EFI_SECURITY_VIOLATION"}
        off = 0
        data = ""
        attr = 0
        buf = list()
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

        in_buf = struct.pack('13I' + str(namelen) + 's', data_size, guid0, guid1, guid2, guid3, guid4, guid5, guid6, guid7, guid8, guid9, guid10, namelen, name.encode())
        buffer = array.array("B", in_buf)
        stat = self.ioctl(IOCTL_GET_EFIVAR, buffer)
        new_size, status = struct.unpack("2I", buffer[:8])

        if (status == 0x5):
            data_size = new_size + header_size + namelen  # size sent by driver + size of header (size + guid) + size of name
            in_buf = struct.pack('13I' + str(namelen + new_size) + 's', data_size, guid0, guid1, guid2, guid3, guid4, guid5, guid6, guid7, guid8, guid9, guid10, namelen, name.encode())
            buffer = array.array("B", in_buf)
            try:
                stat = self.ioctl(IOCTL_GET_EFIVAR, buffer)
            except IOError:
                if logger().DEBUG:
                    logger().log_error("IOError IOCTL GetUEFIvar\n")
                return (off, buf, hdr, None, guid, attr)
            new_size, status = struct.unpack("2I", buffer[:8])

        if (new_size > data_size):
            if logger().DEBUG:
                logger().log_error("Incorrect size returned from driver")
            return (off, buf, hdr, None, guid, attr)

        if (status > 0):
            if logger().DEBUG:
                logger().log_error("Reading variable (GET_EFIVAR) did not succeed: {} ({:d})".format(status_dict.get(status, 'UNKNOWN'), status))
            data = ""
            guid = 0
            attr = 0
        else:
            data = buffer[base:base + new_size].tobytes()
            attr = struct.unpack("I", buffer[8:12])[0]
        return (off, buf, hdr, data, guid, attr)

    def kern_get_EFI_variable(self, name, guid):
        (off, buf, hdr, data, guid, attr) = self.kern_get_EFI_variable_full(name, guid)
        return data

    def kern_list_EFI_variables(self):
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

    def kern_set_EFI_variable(self, name, guid, value, attr=0x7):
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
                logger().log_error("Setting EFI (SET_EFIVAR) variable did not succeed: '{}' ({:d})".format(status_dict.get(status, 'UNKNOWN'), status))
        else:
            os.system('umount /sys/firmware/efi/efivars; mount -t efivarfs efivarfs /sys/firmware/efi/efivars')
        return status

    #
    # Internal (U)EFI Variable API functions via legacy /sys/firmware/efi/vars/
    # Invoked when use_native_api() is True
    #

    def VARS_get_efivar_from_sys(self, filename):
        off = 0
        buf = list()
        hdr = 0
        try:
            f = open('/sys/firmware/efi/vars/' + filename + '/data', 'r')
            data = f.read()
            f.close()

            f = open('/sys/firmware/efi/vars/' + filename + '/guid', 'r')
            guid = (f.read()).strip()
            f.close()

            f = open('/sys/firmware/efi/vars/' + filename + '/attributes', 'r')
            attrstring = f.read()
            attr = 0
            if fnmatch.fnmatch(attrstring, '*NON_VOLATILE*'):
                attr |= EFI_VARIABLE_NON_VOLATILE
            if fnmatch.fnmatch(attrstring, '*BOOTSERVICE*'):
                attr |= EFI_VARIABLE_BOOTSERVICE_ACCESS
            if fnmatch.fnmatch(attrstring, '*RUNTIME*'):
                attr |= EFI_VARIABLE_RUNTIME_ACCESS
            if fnmatch.fnmatch(attrstring, '*ERROR*'):
                attr |= EFI_VARIABLE_HARDWARE_ERROR_RECORD
            if fnmatch.fnmatch(attrstring, 'EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS'):
                attr |= EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS
            if fnmatch.fnmatch(attrstring, '*TIME_BASED_AUTHENTICATED*'):
                attr |= EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS
            if fnmatch.fnmatch(attrstring, '*APPEND_WRITE*'):
                attr |= EFI_VARIABLE_APPEND_WRITE
            f.close()

        except Exception as err:
            if logger().DEBUG:
                logger().log_error('Failed to read files under /sys/firmware/efi/vars/' + filename)
            data = ""
            guid = 0
            attr = 0

        finally:
            return (off, buf, hdr, data, guid, attr)

    def VARS_list_EFI_variables(self):
        varlist = []
        try:
            varlist = os.listdir('/sys/firmware/efi/vars')
        except Exception:
            if logger().DEBUG:
                logger().log_error('Failed to read /sys/firmware/efi/vars. Folder does not exist')
        variables = dict()
        for v in varlist:
            name = v[:-37]
            if name and name is not None:
                variables[name] = []
                var = self.VARS_get_efivar_from_sys(v)
                # did we get something real back?
                (off, buf, hdr, data, guid, attr) = var
                if data != "" or guid != 0 or attr != 0:
                    variables[name].append(var)
        return variables

    def VARS_get_EFI_variable(self, name, guid):
        if not name:
            name = '*'
        if not guid:
            guid = '*'
        for var in os.listdir('/sys/firmware/efi/vars'):
            if fnmatch.fnmatch(var, '{}-{}'.format(name, guid)):
                (off, buf, hdr, data, guid, attr) = self.VARS_get_efivar_from_sys(var)
                return data

    def VARS_set_EFI_variable(self, name, guid, value):
        ret = 21  # EFI_ABORTED
        if not name:
            name = '*'
        if not guid:
            guid = '*'
        for var in os.listdir('/sys/firmware/efi/vars'):
            if fnmatch.fnmatch(var, '{}-{}'.format(name, guid)):
                try:
                    f = open('/sys/firmware/efi/vars/' + var + '/data', 'w')
                    f.write(value)
                    ret = 0  # EFI_SUCCESS
                except Exception as err:
                    if logger().DEBUG:
                        logger().log_error('Failed to write EFI variable. {}'.format(err))
        return ret

    #
    # Internal (U)EFI Variable API functions via /sys/firmware/efi/efivars/ on Linux (kernel 3.10+)
    # Invoked when use_native_api() is True
    #

    def EFIVARS_get_efivar_from_sys(self, filename):
        guid = filename[filename.find('-') + 1:]
        off = 0
        buf = list()
        hdr = 0
        try:
            f = open('/sys/firmware/efi/efivars/' + filename, 'rb')
            data = f.read()
            attr = struct.unpack_from("<I", data)[0]
            data = data[4:]
            f.close()

        except Exception as err:
            if logger().DEBUG:
                logger().log_error('Failed to read /sys/firmware/efi/efivars/' + filename)
            data = ""
            guid = 0
            attr = 0

        finally:
            return (off, buf, hdr, data, guid, attr)

    def EFIVARS_list_EFI_variables(self):
        varlist = []
        try:
            varlist = os.listdir('/sys/firmware/efi/efivars')
        except Exception:
            if logger().DEBUG:
                logger().log_error('Failed to read /sys/firmware/efi/efivars. Folder does not exist')
            return None
        variables = dict()
        for v in varlist:
            name = v[:-37]
            if name and name is not None:
                variables[name] = []
                var = self.EFIVARS_get_efivar_from_sys(v)
                # did we get something real back?
                (off, buf, hdr, data, guid, attr) = var
                if data != "" or guid != 0 or attr != 0:
                    variables[name].append(var)
        return variables

    def EFIVARS_get_EFI_variable(self, name, guid):
        filename = name + "-" + guid
        try:
            f = open('/sys/firmware/efi/efivars/' + filename, 'rb')
            data = f.read()
            attr = struct.unpack_from("<I", data)[0]
            data = data[4:]
            f.close()

        except Exception as err:
            if logger().DEBUG:
                logger().log_error('Failed to read /sys/firmware/efi/efivars/' + filename)
            data = ""

        finally:
            return data

    def EFIVARS_set_EFI_variable(self, name, guid, value, attrs=None):
        ret = 21  # EFI_ABORTED
        if not name:
            name = '*'
        if not guid:
            guid = '*'

        path = '/sys/firmware/efi/efivars/{}-{}'.format(name, guid)
        if value is not None:
            try:
                if os.path.isfile(path):
                    # Variable already exists
                    if attrs is not None:
                        if logger().DEBUG:
                            logger().log_warning("Changing attributes on an existing variable is not supported. Keeping old attributes...")
                    f = open(path, 'r')
                    sattrs = f.read(4)
                else:
                    # Create new variable with attributes NV+BS+RT if attrs were not passed in
                    sattrs = struct.pack("I", 0x7) if attrs is None else struct.pack("I", attrs)
                f = open(path, 'w')
                f.write(sattrs + value)
                f.close()
                ret = 0  # EFI_SUCCESS
            except Exception as err:
                if logger().DEBUG:
                    logger().log_error('Failed to write EFI variable. {}'.format(err))
        else:
            try:
                os.remove(path)
                ret = 0  # EFI_SUCCESS
            except Exception as err:
                if logger().DEBUG:
                    logger().log_error('Failed to delete EFI variable. {}'.format(err))

        return ret

    #
    # Hypercalls
    #
    def hypercall(self, rcx, rdx, r8, r9, r10, r11, rax, rbx, rdi, rsi, xmm_buffer):
        in_buf = struct.pack('<11' + self._pack, rcx, rdx, r8, r9, r10, r11, rax, rbx, rdi, rsi, xmm_buffer)
        out_buf = self.ioctl(IOCTL_HYPERCALL, in_buf)
        return struct.unpack('<11' + self._pack, out_buf)[0]

    #
    # Interrupts
    #
    def send_sw_smi(self, cpu_thread_id, SMI_code_data, _rax, _rbx, _rcx, _rdx, _rsi, _rdi):
        self.set_affinity(cpu_thread_id)
        in_buf = struct.pack("7" + self._pack, SMI_code_data, _rax, _rbx, _rcx, _rdx, _rsi, _rdi)
        out_buf = self.ioctl(IOCTL_SWSMI, in_buf)
        ret = struct.unpack("7" + self._pack, out_buf)
        return ret

    #
    # File system
    #
    def get_tool_info(self, tool_type):
        tool_name = _tools[tool_type] if tool_type in _tools else None
        tool_path = os.path.join(get_tools_path(), self.os_system.lower())
        return tool_name, tool_path

    def getcwd(self):
        return os.getcwd()

    def get_page_is_ram(self):
        PROC_KALLSYMS = "/proc/kallsyms"
        symarr = chipsec.file.read_file(PROC_KALLSYMS).splitlines()
        for line in symarr:
            if "page_is_ram" in line:
                return line.split(" ")[0]

    def get_phys_mem_access_prot(self):
        PROC_KALLSYMS = "/proc/kallsyms"
        symarr = chipsec.file.read_file(PROC_KALLSYMS).splitlines()
        for line in symarr:
            if "phys_mem_access_prot" in line:
                return line.split(" ")[0]

    #
    # Logical CPU count
    #
    def get_threads_count(self):
        import multiprocessing
        return multiprocessing.cpu_count()

    #
    # Speculation control
    #
    def retpoline_enabled(self):
        raise UnimplementedAPIError("retpoline_enabled")


def get_helper():
    return LinuxHelper()
