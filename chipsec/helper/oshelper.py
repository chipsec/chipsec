# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2021, Intel Corporation

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

# Contact information:
# chipsec@intel.com

"""
Abstracts support for various OS/environments, wrapper around platform specific code that invokes kernel driver
"""

import os
import re
import errno
import traceback
import sys

import chipsec.file
from chipsec.logger import logger
from chipsec.exceptions import UnimplementedAPIError, OsHelperError

avail_helpers = []

ZIP_HELPER_RE = re.compile(r"^chipsec\/helper\/\w+\/\w+\.pyc$", re.IGNORECASE)


def f_mod_zip(x):
    return (x.find('__init__') == -1 and ZIP_HELPER_RE.match(x))


def map_modname_zip(x):
    return (x.rpartition('.')[0]).replace('/', '.')


def get_tools_path():
    return os.path.normpath(os.path.join(chipsec.file.get_main_dir(), chipsec.file.TOOLS_DIR))


import chipsec.helper.helpers as chiphelpers


# OS Helper
#
# Abstracts support for various OS/environments, wrapper around platform specific code that invokes kernel driver
class OsHelper:
    def __init__(self):
        self.helper = None
        self.loadHelpers()
        self.filecmds = None
        if(not self.helper):
            import platform
            os_system = platform.system()
            raise OsHelperError("Could not load any helpers for '{}' environment (unsupported environment?)".format(os_system), errno.ENODEV)
        else:
            self.os_system = self.helper.os_system
            self.os_release = self.helper.os_release
            self.os_version = self.helper.os_version
            self.os_machine = self.helper.os_machine

    def loadHelpers(self):
        for helper in avail_helpers:
            try:
                self.helper = getattr(chiphelpers, helper).get_helper()
                break
            except OsHelperError:
                raise
            except Exception:
                logger().log_debug("Unable to load helper: {}".format(helper))

    def start(self, start_driver, driver_exists=None, to_file=None, from_file=False):
        if to_file is not None:
            from chipsec.helper.file.filehelper import FileCmds
            self.filecmds = FileCmds(to_file)
        if driver_exists is not None:
            for name in avail_helpers:
                if name == driver_exists:
                    self.helper = getattr(chiphelpers, name).get_helper()
        try:
            if not self.helper.create(start_driver):
                raise OsHelperError("failed to create OS helper", 1)
            if not self.helper.start(start_driver, from_file):
                raise OsHelperError("failed to start OS helper", 1)
        except Exception as msg:
            logger().log_debug(traceback.format_exc())
            error_no = errno.ENXIO
            if hasattr(msg, 'errorcode'):
                error_no = msg.errorcode
            raise OsHelperError("Message: \"{}\"".format(msg), error_no)

    def stop(self, start_driver):
        if self.filecmds is not None:
            self.filecmds.Save()
        if not self.helper.stop(start_driver):
            logger().log_warning("failed to stop OS helper")
        else:
            if not self.helper.delete(start_driver):
                logger().log_warning("failed to delete OS helper")

    def is_dal(self):
        return ('itpii' in sys.modules)

    def is_efi(self):
        return self.os_system.lower().startswith('efi') or self.os_system.lower().startswith('uefi')

    def is_linux(self):
        return ('linux' == self.os_system.lower())

    def is_windows(self):
        return ('windows' == self.os_system.lower())

    def is_win8_or_greater(self):
        win8_or_greater = self.is_windows() and (self.os_release.startswith('8') or ('2008Server' in self.os_release) or ('2012Server' in self.os_release))
        return win8_or_greater

    def is_macos(self):
        return ('darwin' == self.os_system.lower())

    #################################################################################################
    # Actual OS helper functionality accessible to HAL components

    #
    # Read/Write PCI configuration registers via legacy CF8/CFC ports
    #
    def read_pci_reg(self, bus, device, function, address, size):
        """Read PCI configuration registers via legacy CF8/CFC ports"""
        if (0 != (address & (size - 1))):
            logger().log_debug("Config register address is not naturally aligned")

        ret = self.helper.read_pci_reg(bus, device, function, address, size)
        if self.filecmds is not None:
            self.filecmds.AddElement("read_pci_reg", (bus, device, function, address, size), ret)
        return ret

    def write_pci_reg(self, bus, device, function, address, value, size):
        """Write PCI configuration registers via legacy CF8/CFC ports"""
        if (0 != (address & (size - 1))):
            logger().log_debug("Config register address is not naturally aligned")

        ret = self.helper.write_pci_reg(bus, device, function, address, value, size)
        if self.filecmds is not None:
            self.filecmds.AddElement("write_pci_reg", (bus, device, function, address, size), ret)
        return ret

    #
    # read/write mmio
    #
    def read_mmio_reg(self, bar_base, size, offset=0, bar_size=None):
        ret = self.helper.read_mmio_reg(bar_base, size, offset, bar_size)
        if self.filecmds is not None:
            self.filecmds.AddElement("read_mmio_reg", (bar_base + offset, size), ret)
        return ret

    def write_mmio_reg(self, bar_base, size, value, offset=0, bar_size=None):
        ret = self.helper.write_mmio_reg(bar_base, size, value, offset, bar_size)
        if self.filecmds is not None:
            self.filecmds.AddElement("write_mmio_reg", (bar_base + offset, size, value), ret)
        return ret

    #
    # physical_address is 64 bit integer
    #
    def read_physical_mem(self, phys_address, length):
        ret = self.helper.read_phys_mem((phys_address >> 32) & 0xFFFFFFFF, phys_address & 0xFFFFFFFF, length)
        if self.filecmds is not None:
            self.filecmds.AddElement("read_physical_mem", ((phys_address >> 32) & 0xFFFFFFFF, phys_address & 0xFFFFFFFF, length), ret)
        return ret

    def write_physical_mem(self, phys_address, length, buf):
        ret = self.helper.write_phys_mem((phys_address >> 32) & 0xFFFFFFFF, phys_address & 0xFFFFFFFF, length, buf)
        if self.filecmds is not None:
            self.filecmds.AddElement("write_physical_mem", ((phys_address >> 32) & 0xFFFFFFFF, phys_address & 0xFFFFFFFF, length, buf), ret)
        return ret

    def alloc_physical_mem(self, length, max_phys_address):
        ret = self.helper.alloc_phys_mem(length, max_phys_address)
        if self.filecmds is not None:
            self.filecmds.AddElement("alloc_physical_mem", (length, max_phys_address), ret)
        return ret

    def free_physical_mem(self, physical_address):
        ret = self.helper.free_phys_mem(physical_address)
        if self.filecmds is not None:
            self.filecmds.AddElement("free_physical_mem", (physical_address), ret)
        return ret

    def va2pa(self, va):
        ret = self.helper.va2pa(va)
        if self.filecmds is not None:
            self.filecmds.AddElement("va2pa", (va), ret)
        return ret

    def map_io_space(self, physical_address, length, cache_type):
        try:
            ret = self.helper.map_io_space(physical_address, length, cache_type)
            if self.filecmds is not None:
                self.filecmds.AddElement("map_io_space", (physical_address, length, cache_type), ret)
            return ret
        except NotImplementedError:
            raise UnimplementedAPIError('map_io_space')

    #
    # Read/Write I/O port
    #
    def read_io_port(self, io_port, size):
        ret = self.helper.read_io_port(io_port, size)
        if self.filecmds is not None:
            self.filecmds.AddElement("read_io_port", (io_port, size), ret)
        return ret

    def write_io_port(self, io_port, value, size):
        ret = self.helper.write_io_port(io_port, value, size)
        if self.filecmds is not None:
            self.filecmds.AddElement("write_io_port", (io_port, value, size), ret)
        return ret

    #
    # Read/Write CR registers
    #
    def read_cr(self, cpu_thread_id, cr_number):
        ret = self.helper.read_cr(cpu_thread_id, cr_number)
        if self.filecmds is not None:
            self.filecmds.AddElement("read_cr", (cpu_thread_id, cr_number), ret)
        return ret

    def write_cr(self, cpu_thread_id, cr_number, value):
        ret = self.helper.write_cr(cpu_thread_id, cr_number, value)
        if self.filecmds is not None:
            self.filecmds.AddElement("write_cr", (cpu_thread_id, cr_number, value), ret)
        return ret

    #
    # Read/Write MSR on a specific CPU thread
    #
    def read_msr(self, cpu_thread_id, msr_addr):
        ret = self.helper.read_msr(cpu_thread_id, msr_addr)
        if self.filecmds is not None:
            self.filecmds.AddElement("read_msr", (cpu_thread_id, msr_addr), ret)
        return ret

    def write_msr(self, cpu_thread_id, msr_addr, eax, edx):
        ret = self.helper.write_msr(cpu_thread_id, msr_addr, eax, edx)
        if self.filecmds is not None:
            self.filecmds.AddElement("write_msr", (cpu_thread_id, msr_addr, eax, edx), ret)
        return ret

    #
    # Load CPU microcode update on a specific CPU thread
    #
    def load_ucode_update(self, cpu_thread_id, ucode_update_buf):
        ret = self.helper.load_ucode_update(cpu_thread_id, ucode_update_buf)
        if self.filecmds is not None:
            self.filecmds.AddElement("load_ucode_update", (cpu_thread_id, ucode_update_buf), ret)
        return ret

    #
    # Read IDTR/GDTR/LDTR on a specific CPU thread
    #
    def get_descriptor_table(self, cpu_thread_id, desc_table_code):
        ret = self.helper.get_descriptor_table(cpu_thread_id, desc_table_code)
        if self.filecmds is not None:
            self.filecmds.AddElement("get_descriptor_table", (cpu_thread_id, desc_table_code), ret)
        return ret

    #
    # EFI Variable API
    #
    def EFI_supported(self):
        ret = self.helper.EFI_supported()
        if self.filecmds is not None:
            self.filecmds.AddElement("EFI_supported", (), ret)
        return ret

    def get_EFI_variable(self, name, guid):
        ret = self.helper.get_EFI_variable(name, guid)
        if self.filecmds is not None:
            self.filecmds.AddElement("get_EFI_variable", (name, guid), ret)
        return ret

    def set_EFI_variable(self, name, guid, data, datasize=None, attrs=None):
        ret = self.helper.set_EFI_variable(name, guid, data, datasize, attrs)
        if self.filecmds is not None:
            self.filecmds.AddElement("set_EFI_variable", (name, guid, data, datasize, attrs), ret)
        return ret

    def delete_EFI_variable(self, name, guid):
        ret = self.helper.delete_EFI_variable(name, guid)
        if self.filecmds is not None:
            self.filecmds.AddElement("delete_EFI_variable", (name, guid), ret)
        return ret

    def list_EFI_variables(self):
        ret = self.helper.list_EFI_variables()
        if self.filecmds is not None:
            self.filecmds.AddElement("list_EFI_variables", (), ret)
        return ret

    #
    # ACPI
    #
    def get_ACPI_SDT(self):
        ret = self.helper.get_ACPI_SDT()
        if self.filecmds is not None:
            self.filecmds.AddElement("get_ACPI_SDT", (), ret)
        return ret

    def get_ACPI_table(self, table_name):
        ret = self.helper.get_ACPI_table(table_name)
        if self.filecmds is not None:
            self.filecmds.AddElement("get_ACPI_table", (table_name), ret)
        return ret

    #
    # CPUID
    #
    def cpuid(self, eax, ecx):
        ret = self.helper.cpuid(eax, ecx)
        if self.filecmds is not None:
            self.filecmds.AddElement("cpuid", (eax, ecx), ret)
        return ret

    #
    # IOSF Message Bus access
    #

    def msgbus_send_read_message(self, mcr, mcrx):
        ret = self.helper.msgbus_send_read_message(mcr, mcrx)
        if self.filecmds is not None:
            self.filecmds.AddElement("msgbus_send_read_message", (mcr, mcrx), ret)
        return ret

    def msgbus_send_write_message(self, mcr, mcrx, mdr):
        ret = self.helper.msgbus_send_write_message(mcr, mcrx, mdr)
        if self.filecmds is not None:
            self.filecmds.AddElement("msgbus_send_write_message", (mcr, mcrx, mdr), ret)
        return ret

    def msgbus_send_message(self, mcr, mcrx, mdr):
        ret = self.helper.msgbus_send_message(mcr, mcrx, mdr)
        if self.filecmds is not None:
            self.filecmds.AddElement("msgbus_send_message", (mcr, mcrx, mdr), ret)
        return ret

    #
    # Affinity
    #
    def get_affinity(self):
        ret = self.helper.get_affinity()
        if self.filecmds is not None:
            self.filecmds.AddElement("get_affinity", (), ret)
        return ret

    def set_affinity(self, value):
        ret = self.helper.set_affinity(value)
        if self.filecmds is not None:
            self.filecmds.AddElement("set_affinity", (value), ret)
        return ret

    #
    # Logical CPU count
    #
    def get_threads_count(self):
        ret = self.helper.get_threads_count()
        if self.filecmds is not None:
            self.filecmds.AddElement("get_threads_count", (), ret)
        return ret

    #
    # Send SW SMI
    #
    def send_sw_smi(self, cpu_thread_id, SMI_code_data, _rax, _rbx, _rcx, _rdx, _rsi, _rdi):
        ret = self.helper.send_sw_smi(cpu_thread_id, SMI_code_data, _rax, _rbx, _rcx, _rdx, _rsi, _rdi)
        if self.filecmds is not None:
            self.filecmds.AddElement("send_sw_smi", (cpu_thread_id, SMI_code_data, _rax, _rbx, _rcx, _rdx, _rsi, _rdi), ret)
        return ret

    #
    # Hypercall
    #
    def hypercall(self, rcx=0, rdx=0, r8=0, r9=0, r10=0, r11=0, rax=0, rbx=0, rdi=0, rsi=0, xmm_buffer=0):
        ret = self.helper.hypercall(rcx, rdx, r8, r9, r10, r11, rax, rbx, rdi, rsi, xmm_buffer)
        if self.filecmds is not None:
            self.filecmds.AddElement("hypercall", (rcx, rdx, r8, r9, r10, r11, rax, rbx, rdi, rsi, xmm_buffer), ret)
        return ret

    #
    # Speculation control
    #

    def retpoline_enabled(self):
        ret = self.helper.retpoline_enabled()
        if self.filecmds is not None:
            self.filecmds.AddElement("retpoline_enabled", (), ret)
        return ret

    #
    # File system
    #
    def getcwd(self):
        ret = self.helper.getcwd()
        if self.filecmds is not None:
            self.filecmds.AddElement("getcwd", (), ret)
        return ret


_helper = None


def helper():
    global _helper
    if _helper is None:
        try:
            _helper = OsHelper()
        except BaseException as msg:
            logger().log_debug(str(msg))
            logger().log_debug(traceback.format_exc())
            raise
    return _helper
