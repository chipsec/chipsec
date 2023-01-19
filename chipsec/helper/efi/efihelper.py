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

from chipsec.defines import bytestostring
from chipsec.logger import logger
from chipsec.helper.oshelper import get_tools_path
from chipsec.helper.basehelper import Helper


_tools = {
}


class EfiHelper(Helper):

    def __init__(self):
        super(EfiHelper, self).__init__()
        self.name = "EfiHelper"
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

    def create(self, start_driver):
        if logger().DEBUG:
            logger().log("[helper] UEFI Helper created")
        return True

    def start(self, start_driver, driver_exists=False):
        # The driver is part of the modified version of edk2.
        # It is always considered as loaded.
        self.driver_loaded = True
        if logger().DEBUG:
            logger().log("[helper] UEFI Helper started/loaded")
        return True

    def stop(self, start_driver):
        if logger().DEBUG:
            logger().log("[helper] UEFI Helper stopped/unloaded")
        return True

    def delete(self, start_driver):
        if logger().DEBUG:
            logger().log("[helper] UEFI Helper deleted")
        return True


###############################################################################################
# Actual API functions to access HW resources
###############################################################################################

    #
    # Physical memory access
    #

    def read_phys_mem(self, phys_address_hi, phys_address_lo, length):
        return edk2.readmem(phys_address_lo, phys_address_hi, length)

    def write_phys_mem(self, phys_address_hi, phys_address_lo, length, buf):
        if 4 == length:
            dword_value = struct.unpack('I', buf)[0]
            edk2.writemem_dword(phys_address_lo, phys_address_hi, dword_value)
        else:
            edk2.writemem(phys_address_lo, phys_address_hi, buf, length)

    def alloc_phys_mem(self, length, max_pa):
        va = edk2.allocphysmem(length, max_pa)[0]
        (pa, _) = self.va2pa(va)
        return (va, pa)

    def va2pa(self, va):
        pa = va  # UEFI shell has identity mapping
        if logger().DEBUG:
            logger().log("[helper] VA (0X{:016X}) -> PA (0X{:016X})".format(va, pa))
        return (pa, 0)

    def pa2va(self, pa):
        va = pa  # UEFI Shell has identity mapping
        if logger().DEBUG:
            logger().log('[helper] PA (0X{:016X}) -> VA (0X{:016X})'.format(pa, va))
        return va

    #
    # Memory-mapped I/O (MMIO) access
    #

    def map_io_space(self, physical_address, length, cache_type):
        return self.pa2va(physical_address)

    def read_mmio_reg(self, phys_address, size):
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

    def write_mmio_reg(self, phys_address, size, value):
        phys_address_lo = phys_address & 0xFFFFFFFF
        phys_address_hi = (phys_address >> 32) & 0xFFFFFFFF
        if size == 4:
            return edk2.writemem_dword(phys_address_lo, phys_address_hi, value)
        else:
            buf = bytestostring(struct.pack(size * "B", value))
            edk2.writemem(phys_address_lo, phys_address_hi, buf, size)

    #
    # PCIe configuration access
    #

    def read_pci_reg(self, bus, device, function, address, size):
        if (1 == size):
            return (edk2.readpci(bus, device, function, address, size) & 0xFF)
        elif (2 == size):
            return (edk2.readpci(bus, device, function, address, size) & 0xFFFF)
        else:
            return edk2.readpci(bus, device, function, address, size)

    def write_pci_reg(self, bus, device, function, address, value, size):
        return edk2.writepci(bus, device, function, address, value, size)

    #
    # CPU I/O port access
    #

    def read_io_port(self, io_port, size):
        if (1 == size):
            return (edk2.readio(io_port, size) & 0xFF)
        elif (2 == size):
            return (edk2.readio(io_port, size) & 0xFFFF)
        else:
            return edk2.readio(io_port, size)

    def write_io_port(self, io_port, value, size):
        return edk2.writeio(io_port, size, value)

    #
    # SMI events
    #

    def send_sw_smi(self, cpu_thread_id, SMI_code_data, _rax, _rbx, _rcx, _rdx, _rsi, _rdi):
        return edk2.swsmi(SMI_code_data, _rax, _rbx, _rcx, _rdx, _rsi, _rdi)

    #
    # CPU related API
    #

    def read_msr(self, cpu_thread_id, msr_addr):
        (eax, edx) = edk2.rdmsr(msr_addr)
        eax = eax % 2**32
        edx = edx % 2**32
        return (eax, edx)

    def write_msr(self, cpu_thread_id, msr_addr, eax, edx):
        edk2.wrmsr(msr_addr, eax, edx)

    def read_cr(self, cpu_thread_id, cr_number):
        return 0

    def write_cr(self, cpu_thread_id, cr_number, value):
        return False

    def load_ucode_update(self, cpu_thread_id, ucode_update_buf):
        if logger().DEBUG:
            logger().log_error("[efi] load_ucode_update is not supported yet")
        return 0

    def get_threads_count(self):
        if logger().DEBUG:
            logger().log_error("EFI helper hasn't implemented get_threads_count yet")
        return 0

    def cpuid(self, eax, ecx):
        (reax, rebx, recx, redx) = edk2.cpuid(eax, ecx)
        return (reax, rebx, recx, redx)

    def get_descriptor_table(self, cpu_thread_id, desc_table_code):
        if logger().DEBUG:
            logger().log_error("EFI helper has not implemented get_descriptor_table yet")
        return 0

    #
    # File system
    #

    def get_tool_info(self, tool_type):
        tool_name = _tools[tool_type] if tool_type in _tools else None
        tool_path = os.path.join(get_tools_path(), self.os_system.lower())
        return tool_name, tool_path

    def getcwd(self):
        return os.getcwd()

    #
    # EFI Variable API
    #

    def EFI_supported(self):
        return True

    def get_EFI_variable_full(self, name, guidstr):

        size = 100
        (Status, Attributes, newdata, DataSize) = edk2.GetVariable(name, guidstr, size)

        if Status == 5:
            size = DataSize + 1
            (Status, Attributes, newdata, DataSize) = edk2.GetVariable(name, guidstr, size)

        return (Status, newdata, Attributes)

    def get_EFI_variable(self, name, guidstr):
        (_, data, _) = self.get_EFI_variable_full(name, guidstr)
        return data

    def set_EFI_variable(self, name, guidstr, data, datasize=None, attrs=0x7):

        if data is None:
            data = '\0' * 4
        if datasize is None:
            datasize = len(data)
        if attrs is None:
            attrs = 0x07
            if logger().VERBOSE:
                logger().log_important("Setting attributes to: {:04X}".format(attrs))

        (Status, datasize, guidstr) = edk2.SetVariable(name, guidstr, int(attrs), data, datasize)

        return Status

    def delete_EFI_variable(self, name, guid):
        return self.set_EFI_variable(name, guid, None, 0, 0)

    def list_EFI_variables(self):

        off = 0
        buf = list()
        hdr = 0
        attr = 0
        var_list = list()
        variables = dict()

        status_dict = {0: "EFI_SUCCESS", 1: "EFI_LOAD_ERROR", 2: "EFI_INVALID_PARAMETER", 3: "EFI_UNSUPPORTED", 4: "EFI_BAD_BUFFER_SIZE", 5: "EFI_BUFFER_TOO_SMALL", 6: "EFI_NOT_READY", 7: "EFI_DEVICE_ERROR", 8: "EFI_WRITE_PROTECTED", 9: "EFI_OUT_OF_RESOURCES", 14: "EFI_NOT_FOUND", 26: "EFI_SECURITY_VIOLATION"}

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
                if logger().DEBUG:
                    logger().log("[helper] EFI Variable name size was too small increasing to {:d}".format(size))
                (status, namestr, size, guidstr) = edk2.GetNextVariableName(size, name, guid)

            if logger().DEBUG:
                logger().log("[helper] Returned {}. Status is {}".format(name, status_dict[status]))

            if status:
                search_complete = True
            else:
                if (namestr, guidstr) in var_list:
                    continue
                else:
                    var_list.append((namestr, guidstr))

                if logger().DEBUG:
                    logger().log("[helper] Found variable '{}' - [{}]".format(name, guidstr))

        for (name, guidstr) in var_list:
            (status, data, attr) = self.get_EFI_variable_full(name, guidstr)

            if status:
                logger().log_verbose('[helper] Error reading variable {}.  Status = {:d} - {}'.format(name, status, status_dict[status]))

            var_data = (off, buf, hdr, data, guidstr, attr)

            if name in variables:
                logger().log_verbose('[helper] Duplicate variable name {} - {}'.format(name, guidstr))
                continue
            else:
                variables[name] = []

            if data != '' or guidstr != '' or attr != 0:
                variables[name].append(var_data)

        return variables

    #
    # ACPI tables access
    #

    def get_ACPI_SDT(self):
        if logger().DEBUG:
            logger().log_error("[efi] ACPI is not supported yet")
        return 0

    #
    # IOSF Message Bus access
    #

    def msgbus_send_read_message(self, mcr, mcrx):
        if logger().DEBUG:
            logger().log_error("[efi] Message Bus is not supported yet")
        return None

    def msgbus_send_write_message(self, mcr, mcrx, mdr):
        if logger().DEBUG:
            logger().log_error("[efi] Message Bus is not supported yet")
        return None

    def msgbus_send_message(self, mcr, mcrx, mdr=None):
        if logger().DEBUG:
            logger().log_error("[efi] Message Bus is not supported yet")
        return None

    def set_affinity(self, value):
        if logger().DEBUG:
            logger().log_error('[efi] API set_affinity() is not supported')
        return 0


def get_helper():
    return EfiHelper()
