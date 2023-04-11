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
Abstracts support for various OS/environments, wrapper around platform specific code that invokes kernel driver
"""

import os
import errno
import importlib
import platform
import traceback
import sys
from ctypes import Array
from typing import Tuple, List, Dict, Optional, AnyStr, Any, TYPE_CHECKING
if TYPE_CHECKING:
    from chipsec.library.types import EfiVariableType
from chipsec.file import get_main_dir, TOOLS_DIR
from chipsec.logger import logger
from chipsec.helper.basehelper import Helper
from chipsec.exceptions import UnimplementedAPIError, OsHelperError

avail_helpers = []


def get_tools_path() -> str:
    return os.path.normpath(os.path.join(get_main_dir(), TOOLS_DIR))


import chipsec.helper.helpers as chiphelpers

# OS Helper
#
# Abstracts support for various OS/environments, wrapper around platform specific code that invokes kernel driver


class OsHelper:
    def __init__(self):
        self.avail_helpers = {}
        self.loadHelpers()
        self.filecmds = None
        self.helper = self.getDefaultHelper()
        if (not self.helper):
            os_system = platform.system()
            raise OsHelperError("Could not load any helpers for '{}' environment (unsupported environment?)".format(os_system), errno.ENODEV)
        else:
            if sys.version[0] == "2":
                logger().log_warning("*****************************************************************************")
                logger().log_warning("* !! Python 2 is deprecated and not supported. Please update to Python 3 !! *")
                logger().log_warning("* !!                           Exiting CHIPSEC                           !! *")
                logger().log_warning("*****************************************************************************")
                sys.exit(0)
            self.os_system = self.helper.os_system
            self.os_release = self.helper.os_release
            self.os_version = self.helper.os_version
            self.os_machine = self.helper.os_machine

    def loadHelpers(self) -> None:
        helper_dir = os.path.join(get_main_dir(), "chipsec", "helper")
        helpers = [os.path.basename(f) for f in os.listdir(helper_dir)
                    if os.path.isdir(os.path.join(helper_dir, f)) and not os.path.basename(f).startswith("__")]

        for helper in helpers:
            helper_path = ''
            try:
                helper_path = f'chipsec.helper.{helper}.{helper}helper'
                hlpr = importlib.import_module(helper_path)
                self.avail_helpers[f'{helper}helper'] = hlpr
            except ImportError as msg:
                logger().log_debug(f"Unable to load helper: {helper}")

    def getHelper(self, name: str) -> Any:
        ret = None
        if name in self.avail_helpers:
            ret = self.avail_helpers[name].get_helper()
        return ret

    def getAvailableHelpers(self) -> List[str]:
        return self.avail_helpers.keys()

    def getBaseHelper(self):
        return Helper()

    def getDefaultHelper(self):
        ret = None
        if self.is_linux():
            ret = self.getHelper("linuxhelper")
        elif self.is_windows():
            ret = self.getHelper("windowshelper")
        elif self.is_efi():
            ret = self.getHelper("efihelper")
        elif self.is_dal():
            ret = self.getHelper("dalhelper")
        if ret is None:
            ret = self.getBaseHelper()
        return ret

    def start(self, start_driver: bool, driver_exists: Optional[bool] = None) -> None:
        if driver_exists is not None:
            for name in self.avail_helpers:
                if name == driver_exists:
                    self.helper = getattr(chiphelpers, name).get_helper()
        try:
            if not self.helper.create(start_driver):
                raise OsHelperError("failed to create OS helper", 1)
            if not self.helper.start(start_driver):
                raise OsHelperError("failed to start OS helper", 1)
        except Exception as msg:
            if logger().DEBUG:
                logger().log_bad(traceback.format_exc())
            error_no = errno.ENXIO
            if hasattr(msg, 'errorcode'):
                error_no = msg.errorcode
            raise OsHelperError("Message: \"{}\"".format(msg), error_no)

    def stop(self, start_driver: bool) -> None:
        if self.filecmds is not None:
            self.filecmds.Save()
        if not self.helper.stop(start_driver):
            logger().log_warning("failed to stop OS helper")
        else:
            if not self.helper.delete(start_driver):
                logger().log_warning("failed to delete OS helper")


    def is_dal(self) -> bool:
        return 'itpii' in sys.modules

    def is_efi(self) -> bool:
        return platform.system().lower().startswith('efi') or platform.system().lower().startswith('uefi')

    def is_linux(self) -> bool:
        return 'linux' == platform.system().lower()

    def is_windows(self) -> bool:
        return 'windows' == platform.system().lower()

    def is_win8_or_greater(self) -> bool:
        win8_or_greater = self.is_windows() and (self.os_release.startswith('8') or ('2008Server' in self.os_release) or ('2012Server' in self.os_release))
        return win8_or_greater

    def is_macos(self) -> bool:
        return 'darwin' == platform.system().lower()

    #################################################################################################
    # Actual OS helper functionality accessible to HAL components

    #
    # Read/Write PCI configuration registers via legacy CF8/CFC ports
    #
    def read_pci_reg(self, bus: int, device: int, function: int, address: int, size: int) -> int:
        """Read PCI configuration registers via legacy CF8/CFC ports"""
        if (0 != (address & (size - 1))):
            if logger().DEBUG:
                logger().log_warning("Config register address is not naturally aligned")

        ret = self.helper.read_pci_reg(bus, device, function, address, size)
        if self.filecmds is not None:
            self.filecmds.AddElement("read_pci_reg", (bus, device, function, address, size), ret)
        return ret

    def write_pci_reg(self, bus: int, device: int, function: int, address: int, value: int, size: int) -> int:
        """Write PCI configuration registers via legacy CF8/CFC ports"""
        if (0 != (address & (size - 1))):
            if logger().DEBUG:
                logger().log_warning("Config register address is not naturally aligned")

        ret = self.helper.write_pci_reg(bus, device, function, address, value, size)
        if self.filecmds is not None:
            self.filecmds.AddElement("write_pci_reg", (bus, device, function, address, size), ret)
        return ret

    #
    # read/write mmio
    #
    def read_mmio_reg(self, bar_base: int, size: int, offset: int = 0, bar_size: Optional[int] = None) -> int:
        ret = self.helper.read_mmio_reg(bar_base + offset, size)
        if self.filecmds is not None:
            self.filecmds.AddElement("read_mmio_reg", (bar_base + offset, size), ret)
        return ret

    def write_mmio_reg(self, bar_base: int, size: int, value: int, offset: int = 0, bar_size: Optional[int] = None) -> int:
        ret = self.helper.write_mmio_reg(bar_base + offset, size, value)
        if self.filecmds is not None:
            self.filecmds.AddElement("write_mmio_reg", (bar_base + offset, size, value), ret)
        return ret

    #
    # physical_address is 64 bit integer
    #
    def read_physical_mem(self, phys_address: int, length: int) -> bytes:
        ret = self.helper.read_phys_mem((phys_address >> 32) & 0xFFFFFFFF, phys_address & 0xFFFFFFFF, length)
        if self.filecmds is not None:
            self.filecmds.AddElement("read_physical_mem", ((phys_address >> 32) & 0xFFFFFFFF, phys_address & 0xFFFFFFFF, length), ret)
        return ret

    def write_physical_mem(self, phys_address: int, length: int, buf: AnyStr) -> int:
        ret = self.helper.write_phys_mem((phys_address >> 32) & 0xFFFFFFFF, phys_address & 0xFFFFFFFF, length, buf)
        if self.filecmds is not None:
            self.filecmds.AddElement("write_physical_mem", ((phys_address >> 32) & 0xFFFFFFFF, phys_address & 0xFFFFFFFF, length, buf), ret)
        return ret

    def alloc_physical_mem(self, length: int, max_phys_address: int) -> Tuple[int, int]:
        ret = self.helper.alloc_phys_mem(length, max_phys_address)
        if self.filecmds is not None:
            self.filecmds.AddElement("alloc_physical_mem", (length, max_phys_address), ret)
        return ret

    def free_physical_mem(self, physical_address: int) -> int:
        ret = self.helper.free_phys_mem(physical_address)
        if self.filecmds is not None:
            self.filecmds.AddElement("free_physical_mem", (physical_address), ret)
        return ret

    def va2pa(self, va: int) -> Tuple[int, int]:
        ret = self.helper.va2pa(va)
        if self.filecmds is not None:
            self.filecmds.AddElement("va2pa", (va), ret)
        return ret

    def map_io_space(self, physical_address: int, length: int, cache_type: int) -> int:
        try:
            ret = self.helper.map_io_space(physical_address, length, cache_type)
            if self.filecmds is not None:
                self.filecmds.AddElement("map_io_space", (physical_address, length, cache_type), ret)
            return ret
        except NotImplementedError:
            pass
        raise UnimplementedAPIError('map_io_space')

    #
    # Read/Write I/O port
    #
    def read_io_port(self, io_port: int, size: int) -> int:
        ret = self.helper.read_io_port(io_port, size)
        if self.filecmds is not None:
            self.filecmds.AddElement("read_io_port", (io_port, size), ret)
        return ret

    def write_io_port(self, io_port: int, value: int, size: int) -> int:
        ret = self.helper.write_io_port(io_port, value, size)
        if self.filecmds is not None:
            self.filecmds.AddElement("write_io_port", (io_port, value, size), ret)
        return ret

    #
    # Read/Write CR registers
    #
    def read_cr(self, cpu_thread_id: int, cr_number: int) -> int:
        ret = self.helper.read_cr(cpu_thread_id, cr_number)
        if self.filecmds is not None:
            self.filecmds.AddElement("read_cr", (cpu_thread_id, cr_number), ret)
        return ret

    def write_cr(self, cpu_thread_id: int, cr_number: int, value: int) -> int:
        ret = self.helper.write_cr(cpu_thread_id, cr_number, value)
        if self.filecmds is not None:
            self.filecmds.AddElement("write_cr", (cpu_thread_id, cr_number, value), ret)
        return ret

    #
    # Read/Write MSR on a specific CPU thread
    #
    def read_msr(self, cpu_thread_id: int, msr_addr: int) -> Tuple[int, int]:
        ret = self.helper.read_msr(cpu_thread_id, msr_addr)
        if self.filecmds is not None:
            self.filecmds.AddElement("read_msr", (cpu_thread_id, msr_addr), ret)
        return ret

    def write_msr(self, cpu_thread_id: int, msr_addr: int, eax: int, edx: int) -> int:
        ret = self.helper.write_msr(cpu_thread_id, msr_addr, eax, edx)
        if self.filecmds is not None:
            self.filecmds.AddElement("write_msr", (cpu_thread_id, msr_addr, eax, edx), ret)
        return ret

    #
    # Load CPU microcode update on a specific CPU thread
    #
    def load_ucode_update(self, cpu_thread_id: int, ucode_update_buf: int) -> bool:
        ret = self.helper.load_ucode_update(cpu_thread_id, ucode_update_buf)
        if self.filecmds is not None:
            self.filecmds.AddElement("load_ucode_update", (cpu_thread_id, ucode_update_buf), ret)
        return ret

    #
    # Read IDTR/GDTR/LDTR on a specific CPU thread
    #
    def get_descriptor_table(self, cpu_thread_id: int, desc_table_code: int) -> Optional[Tuple[int, int, int]]:
        ret = self.helper.get_descriptor_table(cpu_thread_id, desc_table_code)
        if self.filecmds is not None:
            self.filecmds.AddElement("get_descriptor_table", (cpu_thread_id, desc_table_code), ret)
        return ret

    #
    # EFI Variable API
    #
    def EFI_supported(self) -> bool:
        ret = self.helper.EFI_supported()
        if self.filecmds is not None:
            self.filecmds.AddElement("EFI_supported", (), ret)
        return ret

    def get_EFI_variable(self, name: str, guid: str) -> Optional[bytes]:
        ret = self.helper.get_EFI_variable(name, guid)
        if self.filecmds is not None:
            self.filecmds.AddElement("get_EFI_variable", (name, guid), ret)
        return ret

    def set_EFI_variable(self, name: str, guid: str, data: bytes, datasize: Optional[int] = None, attrs: Optional[int] = None) -> Optional[int]:
        ret = self.helper.set_EFI_variable(name, guid, data, datasize, attrs)
        if self.filecmds is not None:
            self.filecmds.AddElement("set_EFI_variable", (name, guid, data, datasize, attrs), ret)
        return ret

    def delete_EFI_variable(self, name: str, guid: str) -> Optional[int]:
        ret = self.helper.delete_EFI_variable(name, guid)
        if self.filecmds is not None:
            self.filecmds.AddElement("delete_EFI_variable", (name, guid), ret)
        return ret

    def list_EFI_variables(self) -> Optional[Dict[str, List['EfiVariableType']]]:
        ret = self.helper.list_EFI_variables()
        if self.filecmds is not None:
            self.filecmds.AddElement("list_EFI_variables", (), ret)
        return ret

    #
    # ACPI
    #
    def get_ACPI_SDT(self) -> Tuple[Optional[Array], bool]:
        ret, xsdt = self.helper.get_ACPI_SDT()
        if self.filecmds is not None:
            self.filecmds.AddElement("get_ACPI_SDT", (), ret)
        return ret, xsdt

    def get_ACPI_table(self, table_name: str) -> Optional[Array]:
        # return self.helper.get_ACPI_table( table_name )
        ret = self.helper.get_ACPI_table(table_name)
        if self.filecmds is not None:
            self.filecmds.AddElement("get_ACPI_table", (table_name), ret)
        return ret

    #
    # CPUID
    #
    def cpuid(self, eax: int, ecx: int) -> Tuple[int, int, int, int]:
        ret = self.helper.cpuid(eax, ecx)
        if self.filecmds is not None:
            self.filecmds.AddElement("cpuid", (eax, ecx), ret)
        return ret

    #
    # IOSF Message Bus access
    #

    def msgbus_send_read_message(self, mcr: int, mcrx: int) -> Optional[int]:
        ret = self.helper.msgbus_send_read_message(mcr, mcrx)
        if self.filecmds is not None:
            self.filecmds.AddElement("msgbus_send_read_message", (mcr, mcrx), ret)
        return ret

    def msgbus_send_write_message(self, mcr: int, mcrx: int, mdr: int) -> None:
        ret = self.helper.msgbus_send_write_message(mcr, mcrx, mdr)
        if self.filecmds is not None:
            self.filecmds.AddElement("msgbus_send_write_message", (mcr, mcrx, mdr), ret)
        return ret

    def msgbus_send_message(self, mcr: int, mcrx: int, mdr: Optional[int]) -> Optional[int]:
        ret = self.helper.msgbus_send_message(mcr, mcrx, mdr)
        if self.filecmds is not None:
            self.filecmds.AddElement("msgbus_send_message", (mcr, mcrx, mdr), ret)
        return ret

    #
    # Affinity
    #
    def get_affinity(self) -> Optional[int]:
        ret = self.helper.get_affinity()
        if self.filecmds is not None:
            self.filecmds.AddElement("get_affinity", (), ret)
        return ret

    def set_affinity(self, value: int) -> Optional[int]:
        ret = self.helper.set_affinity(value)
        if self.filecmds is not None:
            self.filecmds.AddElement("set_affinity", (value), ret)
        return ret

    #
    # Logical CPU count
    #
    def get_threads_count(self) -> int:
        ret = self.helper.get_threads_count()
        if self.filecmds is not None:
            self.filecmds.AddElement("get_threads_count", (), ret)
        return ret

    #
    # Send SW SMI
    #
    def send_sw_smi(self, cpu_thread_id: int, SMI_code_data: int, _rax: int, _rbx: int, _rcx: int, _rdx: int, _rsi: int, _rdi: int) -> Optional[Tuple[int, int, int, int, int, int, int]]:
        ret = self.helper.send_sw_smi(cpu_thread_id, SMI_code_data, _rax, _rbx, _rcx, _rdx, _rsi, _rdi)
        if self.filecmds is not None:
            self.filecmds.AddElement("send_sw_smi", (cpu_thread_id, SMI_code_data, _rax, _rbx, _rcx, _rdx, _rsi, _rdi), ret)
        return ret

    #
    # Hypercall
    #
    def hypercall(self, rcx: int = 0, rdx: int = 0, r8: int = 0, r9: int = 0, r10: int = 0, r11: int = 0,
                  rax: int = 0, rbx: int = 0, rdi: int = 0, rsi: int = 0, xmm_buffer: int = 0) -> int:
        ret = self.helper.hypercall(rcx, rdx, r8, r9, r10, r11, rax, rbx, rdi, rsi, xmm_buffer)
        if self.filecmds is not None:
            self.filecmds.AddElement("hypercall", (rcx, rdx, r8, r9, r10, r11, rax, rbx, rdi, rsi, xmm_buffer), ret)
        return ret

    #
    # Speculation control
    #

    def retpoline_enabled(self) -> bool:
        ret = self.helper.retpoline_enabled()
        if self.filecmds is not None:
            self.filecmds.AddElement("retpoline_enabled", (), ret)
        return ret

    #
    # File system
    #
    def getcwd(self) -> str:
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
            if logger().DEBUG:
                logger().log_error(str(msg))
                logger().log_bad(traceback.format_exc())
            raise
    return _helper
