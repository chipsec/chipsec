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
Native Linux helper
"""

import fnmatch
import mmap
import os
import platform
import resource
import struct
import subprocess
import sys
import shutil

from chipsec import defines
from chipsec.helper.oshelper import get_tools_path
from chipsec.exceptions import OsHelperError, UnimplementedAPIError
from chipsec.helper.basehelper import Helper
from chipsec.logger import logger
import chipsec.file
from chipsec.hal.uefi_common import EFI_VARIABLE_NON_VOLATILE, EFI_VARIABLE_BOOTSERVICE_ACCESS
from chipsec.hal.uefi_common import EFI_VARIABLE_HARDWARE_ERROR_RECORD, EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS
from chipsec.hal.uefi_common import EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS, EFI_VARIABLE_APPEND_WRITE
from chipsec.hal.uefi_common import EFI_VARIABLE_RUNTIME_ACCESS

LZMA = os.path.join(chipsec.file.get_main_dir(), chipsec.file.TOOLS_DIR, "compression", "bin", "LzmaCompress")
TIANO = os.path.join(chipsec.file.get_main_dir(), chipsec.file.TOOLS_DIR, "compression", "bin", "TianoCompress")
EFI = os.path.join(chipsec.file.get_main_dir(), chipsec.file.TOOLS_DIR, "compression", "bin", "TianoCompress")
BROTLI = os.path.join(chipsec.file.get_main_dir(), chipsec.file.TOOLS_DIR, "compression", "bin", "Brotli")

_tools = {
    chipsec.defines.COMPRESSION_TYPE_TIANO: 'TianoCompress',
    chipsec.defines.COMPRESSION_TYPE_LZMA: 'LzmaCompress',
    chipsec.defines.COMPRESSION_TYPE_BROTLI: 'Brotli'
}


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

    decompression_oder_type1 = [chipsec.defines.COMPRESSION_TYPE_TIANO, chipsec.defines.COMPRESSION_TYPE_UEFI]
    decompression_oder_type2 = [chipsec.defines.COMPRESSION_TYPE_TIANO,
                                chipsec.defines.COMPRESSION_TYPE_UEFI,
                                chipsec.defines.COMPRESSION_TYPE_LZMA,
                                chipsec.defines.COMPRESSION_TYPE_BROTLI]

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
    def create(self, start_driver):
        if logger().DEBUG:
            logger().log("[helper] Linux Helper created")
        return True

    def start(self, start_driver, driver_exists=False):
        self.init(start_driver)
        if logger().DEBUG:
            logger().log("[helper] Linux Helper started/loaded")
        return True

    def stop(self, start_driver):
        self.close()
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
        if self.dev_mem:
            os.close(self.dev_mem)
        self.dev_mem = None

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

    def map_io_space(self, base, size, cache_type):
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

    def write_phys_mem(self, phys_address_hi, phys_address_lo, length, newval):
        if newval is None:
            return None
        if self.devmem_available():
            addr = (phys_address_hi << 32) | phys_address_lo
            os.lseek(self.dev_mem, addr, os.SEEK_SET)
            written = os.write(self.dev_mem, newval)
            if written != length:
                if logger().DEBUG:
                    logger().error("Cannot write {} to memory {:016X} (wrote {:d} of {:d})".format(newval, addr, written, length))

    def read_phys_mem(self, phys_address_hi, phys_address_lo, length):
        if self.devmem_available():
            addr = (phys_address_hi << 32) | phys_address_lo
            os.lseek(self.dev_mem, addr, os.SEEK_SET)
            return os.read(self.dev_mem, length)

    def va2pa(self, va):
        raise UnimplementedAPIError("va2pa")

    def read_pci_reg(self, bus, device, function, offset, size, domain=0):
        device_name = "{domain:04x}:{bus:02x}:{device:02x}.{function}".format(
                      domain=domain, bus=bus, device=device, function=function)
        device_path = "/sys/bus/pci/devices/{}/config".format(device_name)
        if not os.path.exists(device_path):
            if offset < 256:
                from chipsec.helper.linuxnative.legacy_pci import LEGACY_PCI
                pci = LEGACY_PCI()
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

    def write_pci_reg(self, bus, device, function, offset, value, size=4, domain=0):
        device_name = "{domain:04x}:{bus:02x}:{device:02x}.{function}".format(
                      domain=domain, bus=bus, device=device, function=function)
        device_path = "/sys/bus/pci/devices/{}/config".format(device_name)
        if not os.path.exists(device_path):
            if offset < 256:
                from chipsec.helper.linuxnative.legacy_pci import LEGACY_PCI
                pci = LEGACY_PCI()
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
        raise UnimplementedAPIError("load_ucode_update")

    def read_io_port(self, io_port, size):
        if self.devport_available():
            os.lseek(self.dev_port, io_port, os.SEEK_SET)

            value = os.read(self.dev_port, size)
            if 1 == size:
                return struct.unpack("B", value)[0]
            elif 2 == size:
                return struct.unpack("H", value)[0]
            elif 4 == size:
                return struct.unpack("I", value)[0]

    def write_io_port(self, io_port, newval, size):
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
                    logger().error("Cannot write {} to port {:x} (wrote {:d} of {:d})".format(newval, io_port, written, size))

    def read_cr(self, cpu_thread_id, cr_number):
        raise UnimplementedAPIError("read_cr")

    def write_cr(self, cpu_thread_id, cr_number, value):
        raise UnimplementedAPIError("write_cr")

    def read_msr(self, thread_id, msr_addr):
        if self.devmsr_available():
            os.lseek(self.dev_msr[thread_id], msr_addr, os.SEEK_SET)
            buf = os.read(self.dev_msr[thread_id], 8)
            unbuf = struct.unpack("2I", buf)
            return (unbuf[0], unbuf[1])

    def write_msr(self, thread_id, msr_addr, eax, edx):
        if self.devmsr_available():
            os.lseek(self.dev_msr[thread_id], msr_addr, os.SEEK_SET)
            buf = struct.pack("2I", eax, edx)
            written = os.write(self.dev_msr[thread_id], buf)
            if written != 8:
                if logger().DEBUG:
                    logger().error("Cannot write {:8X} to MSR {:x}".format(buf, msr_addr))

    def get_descriptor_table(self, cpu_thread_id, desc_table_code):
        raise UnimplementedAPIError("get_descriptor_table")

    def cpuid(self, eax, ecx):
        import chipsec.helper.linuxnative.cpuid as cpuid
        _cpuid = cpuid.CPUID()
        return _cpuid(eax, ecx)

    def alloc_phys_mem(self, num_bytes, max_addr):
        raise UnimplementedAPIError("alloc_phys_mem")

    def free_phys_mem(self, physmem):
        raise UnimplementedAPIError("free_phys_mem")

    def read_mmio_reg(self, bar_base, size, offset, bar_size):
        if bar_size is None or bar_size < offset:
            bar_size = offset + size
        if self.devmem_available():
            region = self.memory_mapping(bar_base, bar_size)
            if not region:
                self.map_io_space(bar_base, bar_size, 0)
                region = self.memory_mapping(bar_base, bar_size)
                if not region:
                    logger().error("Unable to map region {:08x}".format(bar_base))

            # Create memoryview into mmap'ed region in dword granularity
            region_mv = memoryview(region)
            region_dw = region_mv.cast('I')
            # read one DWORD
            offset_in_region = (bar_base + offset - region.start) // 4
            reg = region_dw[offset_in_region]
            return reg

    def write_mmio_reg(self, bar_base, size, value, offset, bar_size):
        if bar_size is None:
            bar_size = offset + size
        if self.devmem_available():
            reg = defines.pack1(value, size)
            region = self.memory_mapping(bar_base, bar_size)
            if not region:
                self.map_io_space(bar_base, bar_size, 0)
                region = self.memory_mapping(bar_base, bar_size)
                if not region:
                    logger().error("Unable to map region {:08x}".format(bar_base))

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

    # ACPI access is implemented through ACPI HAL rather than through kernel module
    def get_ACPI_table(self, table_name):
        raise UnimplementedAPIError("get_ACPI_table")

    #
    # IOSF Message Bus access
    #
    def msgbus_send_read_message(self, mcr, mcrx):
        raise UnimplementedAPIError("get_ACPI_table")

    def msgbus_send_write_message(self, mcr, mcrx, mdr):
        raise UnimplementedAPIError("get_ACPI_table")

    def msgbus_send_message(self, mcr, mcrx, mdr=None):
        raise UnimplementedAPIError("get_ACPI_table")

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
        if self.use_efivars():
            return self.EFIVARS_set_EFI_variable(name, guid, None)

    def list_EFI_variables(self):
        if self.use_efivars():
            return self.EFIVARS_list_EFI_variables()
        else:
            return self.VARS_list_EFI_variables()

    def get_EFI_variable(self, name, guid, attrs=None):
        if self.use_efivars():
            return self.EFIVARS_get_EFI_variable(name, guid)
        else:
            return self.VARS_get_EFI_variable(name, guid)

    def set_EFI_variable(self, name, guid, data, datasize, attrs=None):
        if self.use_efivars():
            return self.EFIVARS_set_EFI_variable(name, guid, data, attrs)
        else:
            return self.VARS_set_EFI_variable(name, guid, data)

    #
    # Internal (U)EFI Variable API functions via legacy /sys/firmware/efi/vars/
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

        except Exception:
            if logger().DEBUG:
                logger().error('Failed to read files under /sys/firmware/efi/vars/' + filename)
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
                logger().error('Failed to read /sys/firmware/efi/vars. Folder does not exist')
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
                        logger().error('Failed to write EFI variable. {}'.format(err))
        return ret

    #
    # Internal (U)EFI Variable API functions via /sys/firmware/efi/efivars/ on Linux (kernel 3.10+)
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

        except Exception:
            if logger().DEBUG:
                logger().error('Failed to read /sys/firmware/efi/efivars/' + filename)
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
                logger().error('Failed to read /sys/firmware/efi/efivars. Folder does not exist')
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
            data = data[4:]
            f.close()

        except Exception:
            if logger().DEBUG:
                logger().error('Failed to read /sys/firmware/efi/efivars/' + filename)
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
                            logger().warn("Changing attributes on an existing variable is not supported. Keeping old attributes...")
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
                    logger().error('Failed to write EFI variable. {}'.format(err))
        else:
            try:
                os.remove(path)
                ret = 0  # EFI_SUCCESS
            except Exception as err:
                if logger().DEBUG:
                    logger().error('Failed to delete EFI variable. {}'.format(err))

        return ret

    #
    # Hypercalls
    #
    def hypercall(self, rcx, rdx, r8, r9, r10, r11, rax, rbx, rdi, rsi, xmm_buffer):
        raise UnimplementedAPIError("hypercall")

    #
    # Interrupts
    #
    def send_sw_smi(self, cpu_thread_id, SMI_code_data, _rax, _rbx, _rcx, _rdx, _rsi, _rdi):
        raise UnimplementedAPIError("send_sw_smi")

    #
    # File system
    #
    def get_tool_info(self, tool_type):
        tool_name = _tools[tool_type] if tool_type in _tools else None
        tool_path = os.path.join(get_tools_path(), self.os_system.lower())
        return tool_name, tool_path

    def getcwd(self):
        return os.getcwd()

    def rotate_list(self, list, n):
        return list[n:] + list[:n]

    def unknown_decompress(self, CompressedFileName, OutputFileName):
        failed_times = 0
        for CompressionType in self.decompression_oder_type2:
            res = self.decompress_file(CompressedFileName, OutputFileName, CompressionType)
            if res is True:
                self.rotate_list(self.decompression_oder_type2, failed_times)
                break
            else:
                failed_times += 1
        return res

    def unknown_efi_decompress(self, CompressedFileName, OutputFileName):
        failed_times = 0
        for CompressionType in self.decompression_oder_type1:
            res = self.decompress_file(CompressedFileName, OutputFileName, CompressionType)
            if res is True:
                self.rotate_list(self.decompression_oder_type1, failed_times)
                break
            else:
                failed_times += 1
        return res

    #
    # Compress binary file
    #
    def compress_file(self, FileName, OutputFileName, CompressionType):
        if CompressionType not in [i for i in chipsec.defines.COMPRESSION_TYPES]:
            return False
        encode_str = " -e -o {} ".format(OutputFileName)
        if CompressionType == chipsec.defines.COMPRESSION_TYPE_NONE:
            shutil.copyfile(FileName, OutputFileName)
            return True
        elif CompressionType == chipsec.defines.COMPRESSION_TYPE_TIANO:
            encode_str = TIANO + encode_str
        elif CompressionType == chipsec.defines.COMPRESSION_TYPE_UEFI:
            encode_str = EFI + encode_str + "--uefi "
        elif CompressionType == chipsec.defines.COMPRESSION_TYPE_LZMA:
            encode_str = LZMA + encode_str
        elif CompressionType == chipsec.defines.COMPRESSION_TYPE_BROTLI:
            encode_str = BROTLI + encode_str
        encode_str += FileName
        data = subprocess.check_output(encode_str, shell=True)
        if not data == 0 and logger().VERBOSE:
            logger().error("Cannot compress file({})".format(FileName))
            return False
        return True

    #
    # Decompress binary
    #
    def decompress_file(self, CompressedFileName, OutputFileName, CompressionType):
        if CompressionType not in [i for i in chipsec.defines.COMPRESSION_TYPES]:
            return False
        if CompressionType == chipsec.defines.COMPRESSION_TYPE_UNKNOWN:
            data = self.unknown_decompress(CompressedFileName, OutputFileName)
            return data
        elif CompressionType == chipsec.defines.COMPRESSION_TYPE_EFI_STANDARD:
            data = self.unknown_efi_decompress(CompressedFileName, OutputFileName)
            return data
        decode_str = " -d -o {} ".format(OutputFileName)
        if CompressionType == chipsec.defines.COMPRESSION_TYPE_NONE:
            shutil.copyfile(CompressedFileName, OutputFileName)
            return True
        elif CompressionType == chipsec.defines.COMPRESSION_TYPE_TIANO:
            decode_str = TIANO + decode_str
        elif CompressionType == chipsec.defines.COMPRESSION_TYPE_UEFI:
            decode_str = EFI + decode_str + "--uefi "
        elif CompressionType == chipsec.defines.COMPRESSION_TYPE_LZMA:
            decode_str = LZMA + decode_str
        elif CompressionType == chipsec.defines.COMPRESSION_TYPE_BROTLI:
            decode_str = BROTLI + decode_str
        decode_str += CompressedFileName
        data = subprocess.call(decode_str, shell=True)
        if not data == 0 and logger().VERBOSE:
            logger().error("Cannot decompress file({})".format(CompressedFileName))
            return False
        return True

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
    return LinuxNativeHelper()
