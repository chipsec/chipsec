# CHIPSEC: Platform Security Assessment Framework
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
#

import struct

from chipsec.helper.basehelper import Helper
from chipsec.library.exceptions import UnimplementedAPIError
from typing import Optional, TYPE_CHECKING
if TYPE_CHECKING:
    from ctypes import Array


class TestHelper(Helper):
    """Default test helper that emulates a Broadwell architecture.

    See datasheet for registers definition.
    http://www.intel.com/content/www/us/en/chipsets/9-series-chipset-pch-datasheet.html
    """

    def __init__(self):
        super(TestHelper, self).__init__()
        self.os_system = "test_helper"
        self.os_release = "0"
        self.os_version = "0"
        self.os_machine = "test"
        self.driver_loaded = True
        self.name = "TestHelper"

    def create(self):
        return True

    def delete(self):
        return True

    def start(self):
        return True

    def stop(self):
        return True

    def _generate_size_ffs(self, size: int) -> int:
        return ~(~0xFF << (size-1) * 8)

     # This will be used to probe the device, fake a Broadwell CPU
    def read_pci_reg(self, bus, device, function, address, size):
        if (bus, device, function) == (0, 0, 0):
            if size == 1:
                return 0x86
            elif size == 2:
                return 0x8086
            else:
                return 0x16008086
        elif (bus, device, function) == (0, 0x1f, 0):
            if size == 1:
                return 0x86
            elif size == 2:
                return 0x8086
            else:
                return 0x9D438086
        else:
            return self._generate_size_ffs(size)

    def get_threads_count(self):
        return 2

    def cpuid(self, eax, ecx):
        return 0x406F1, 0, 0, 0

    def write_pci_reg(self, bus, device, function, address, value, size):
        raise UnimplementedAPIError('write_pci_reg')

    def get_info(self):
        return self.name, self.driverpath

    def read_mmio_reg(self, phys_address, size):
        raise UnimplementedAPIError('read_mmio_reg')

    def write_mmio_reg(self, phys_address, size, value):
        raise UnimplementedAPIError('write_mmio_reg')

    def read_phys_mem(self, phys_address, length):
        raise UnimplementedAPIError('read_phys_mem')

    def write_phys_mem(self, phys_address, length, buf):
        raise UnimplementedAPIError('write_phys_mem')

    def alloc_phys_mem(self, length, max_phys_address):
        raise UnimplementedAPIError('alloc_phys_mem')

    def free_phys_mem(self, physical_address):
        raise UnimplementedAPIError('free_phys_mem')

    def va2pa(self, va):
        raise UnimplementedAPIError('va2pa')

    def map_io_space(self, physical_address, length, cache_type):
        raise UnimplementedAPIError('map_io_space')

    def read_io_port(self, io_port, size):
        raise UnimplementedAPIError('read_io_port')

    def write_io_port(self, io_port, value, size):
        raise UnimplementedAPIError('write_io_port')

    def read_cr(self, cpu_thread_id, cr_number):
        raise UnimplementedAPIError('read_cr')

    def write_cr(self, cpu_thread_id, cr_number, value):
        raise UnimplementedAPIError('write_cr')

    def read_msr(self, cpu_thread_id, msr_addr):
        raise UnimplementedAPIError('read_msr')

    def write_msr(self, cpu_thread_id, msr_addr, eax, edx):
        raise UnimplementedAPIError('write_msr')

    def load_ucode_update(self, cpu_thread_id, ucode_update_buf):
        raise UnimplementedAPIError('load_ucode_update')

    def get_descriptor_table(self, cpu_thread_id, desc_table_code):
        raise UnimplementedAPIError('get_descriptor_table')

    def EFI_supported(self):
        raise UnimplementedAPIError('EFI_supported')

    def get_EFI_variable(self, name, guid):
        raise UnimplementedAPIError('get_EFI_variable')

    def set_EFI_variable(self, name, guid, buffer, buffer_size, attrs):
        raise UnimplementedAPIError('set_EFI_variable')

    def delete_EFI_variable(self, name, guid):
        raise UnimplementedAPIError('delete_EFI_variable')

    def list_EFI_variables(self):
        raise UnimplementedAPIError('list_EFI_variables')

    def get_ACPI_table(self, table_name: str) -> Optional['Array']:
        raise UnimplementedAPIError('get_ACPI_table')

    def enum_ACPI_tables(self) -> Optional['Array']:
        raise UnimplementedAPIError('enum_ACPI_table')

    def msgbus_send_read_message(self, mcr, mcrx):
        raise UnimplementedAPIError('msgbus_send_read_message')

    def msgbus_send_write_message(self, mcr, mcrx, mdr):
        raise UnimplementedAPIError('msgbus_send_write_message')

    def msgbus_send_message(self, mcr, mcrx, mdr):
        raise UnimplementedAPIError('msgbus_send_message')

    def get_affinity(self):
        raise UnimplementedAPIError('get_affinity')

    def set_affinity(self, value):
        raise UnimplementedAPIError('set_affinity')

    def send_sw_smi(self, cpu_thread_id, SMI_code_data, _rax, _rbx, _rcx, _rdx, _rsi, _rdi):
        raise UnimplementedAPIError('send_sw_smi')

    def hypercall(self, rcx, rdx, r8, r9, r10, r11, rax, rbx, rdi, rsi, xmm_buffer):
        raise UnimplementedAPIError('hypercall')

    def getcwd(self):
        raise UnimplementedAPIError('getcwd')

    def retpoline_enabled(self) -> bool:
        return False


class ACPIHelper(TestHelper):
    """Generic ACPI emulation

    Emulates an RSDP that points to an RSDT by default.

    An XSDT is also provided.

    The provided RSDT and XSDT will contain the entries specified
    in RSDT_ENTRIES and XSDT_ENTRIES.

    RSDP will be placed inside EBDA which by default is located
    at 0x96000. In particular, RSDP can be found in 0x96100.

    Three regions are defined:
      * RSDP table [0x96100, 0x96114] or [0x96100, 0x96124]
      * XSDT table [0x100, 0x124 + 8 * len(XSDT_ENTRIES)]
      * RSDT table [0x200, 0x224 + 4 * len(RSDT_ENTRIES)]
    """
    USE_RSDP_REV_0 = True
    TABLE_HEADER_SIZE = 36

    EBDA_ADDRESS = 0x96000
    EBDA_PADDING = 0x100
    RSDP_ADDRESS = EBDA_ADDRESS + EBDA_PADDING

    XSDT_ADDRESS = 0x100
    RSDT_ADDRESS = 0x200

    def _create_rsdp(self):
        rsdp = b""
        if self.USE_RSDP_REV_0:
            # Emulate initial version of RSDP described in ACPI v1.0
            rsdp = (b"RSD PTR " +                            # Signature
                    struct.pack("<B", 0x1) +                # Checksum
                    b"TEST00" +                              # OEMID
                    struct.pack("<B", 0x0) +                # Revision
                    struct.pack("<I", self.RSDT_ADDRESS))   # RSDT Address
        else:
            # Emulate RSDP described in ACPI v2.0 onwards
            rsdp = (b"RSD PTR " +                            # Signature
                    struct.pack("<B", 0x1) +                # Checksum
                    b"TEST00" +                              # OEMID
                    struct.pack("<B", 0x2) +                # Revision
                    struct.pack("<I", self.RSDT_ADDRESS) +  # RSDT Address
                    struct.pack("<I", 0x24) +               # Length
                    struct.pack("<Q", self.XSDT_ADDRESS) +  # XSDT Address
                    struct.pack("<B", 0x0) +                # Extended Checksum
                    b"AAA")                                  # Reserved
        return rsdp

    def _create_generic_acpi_table_header(self, signature, length):
        return (signature +                  # Signature
                struct.pack("<I", length) +  # Length
                struct.pack("<B", 0x1) +     # Revision
                struct.pack("<B", 0x1) +     # Checksum
                b"OEMIDT" +                   # OEMID
                b"OEMTBLID" +                 # OEM Table ID
                b"OEMR" +                     # OEM Revision
                b"CRID" +                     # Creator ID
                b"CRRV")                      # Creator Revision

    def _create_rsdt(self):
        rsdt_length = self.TABLE_HEADER_SIZE + 4 * len(self.rsdt_entries)
        rsdt = self._create_generic_acpi_table_header(b"RSDT", rsdt_length)
        for rsdt_entry in self.rsdt_entries:
            rsdt += struct.pack("<I", rsdt_entry)
        return rsdt

    def _create_xsdt(self):
        xsdt_length = self.TABLE_HEADER_SIZE + 8 * len(self.xsdt_entries)
        xsdt = self._create_generic_acpi_table_header(b"XSDT", xsdt_length)
        for xsdt_entry in self.xsdt_entries:
            xsdt += struct.pack("<Q", xsdt_entry)
        return xsdt

    def _add_entry_to_rsdt(self, entry):
        self.rsdt_entries.append(entry)
        self.rsdt_descriptor = self._create_rsdt()

    def _add_entry_to_xsdt(self, entry):
        self.xsdt_entries.append(entry)
        self.xsdt_descriptor = self._create_xsdt()

    def __init__(self):
        super(ACPIHelper, self).__init__()
        self.rsdt_entries = []
        self.xsdt_entries = []
        self.rsdp_descriptor = self._create_rsdp()
        self.rsdt_descriptor = self._create_rsdt()
        self.xsdt_descriptor = self._create_xsdt()

    def read_phys_mem(self, pa, length):
        pa_lo = pa & 0xFFFFFFFF
        if pa_lo == 0x40E:
            return struct.pack("<H", self.EBDA_ADDRESS >> 4)
        elif (pa_lo >= self.EBDA_ADDRESS and
              pa_lo < self.RSDP_ADDRESS + len(self.rsdp_descriptor)):
            mem = b"\x00" * self.EBDA_PADDING + self.rsdp_descriptor
            offset = pa_lo - self.EBDA_ADDRESS
            return mem[offset:offset + length]
        elif pa_lo == self.RSDT_ADDRESS:
            return self.rsdt_descriptor[:length]
        elif pa_lo == self.XSDT_ADDRESS:
            return self.xsdt_descriptor[:length]
        else:
            return b"\xFF" * length


class DSDTParsingHelper(ACPIHelper):
    """Test helper containing generic descriptors for RSDP, RSDT and FADT

    Default entry for DSDT and X_DSDT inside FADT is 0x0

    One additional region is defined:
      * FADT table [0x400, 0x514]
    """
    USE_FADT_WITH_X_DSDT = True

    FADT_ADDRESS = 0x400
    DSDT_ADDRESS = 0x0
    X_DSDT_ADDRESS = 0x0

    def _add_fadt_to_sdt_entries(self):
        if self.USE_RSDP_REV_0:
            self._add_entry_to_rsdt(self.FADT_ADDRESS)
        else:
            self._add_entry_to_xsdt(self.FADT_ADDRESS)

    def _create_fadt(self):
        fadt = b""
        if self.USE_FADT_WITH_X_DSDT:
            fadt = self._create_generic_acpi_table_header(b"FACP", 0x10C)
            fadt += struct.pack("<I", 0x500)                # Address of FACS
            fadt += struct.pack("<I", self.DSDT_ADDRESS)    # DSDT
            fadt += struct.pack("<B", 0x1) * 96             # Padding
            fadt += struct.pack("<Q", self.X_DSDT_ADDRESS)  # X_DSDT
            fadt += struct.pack("<B", 0x1) * 120            # Remaining fields
        else:
            fadt = self._create_generic_acpi_table_header(b"FACP", 0x74)
            fadt += struct.pack("<I", 0x500)                # Address of FACS
            fadt += struct.pack("<I", self.DSDT_ADDRESS)    # DSDT
            fadt += struct.pack("<B", 0x1) * 72             # Remaining fields
        return fadt

    def __init__(self):
        super(DSDTParsingHelper, self).__init__()
        self._add_fadt_to_sdt_entries()
        self.fadt_descriptor = self._create_fadt()

    def read_phys_mem(self, pa, length):
        pa_lo = pa & 0xFFFFFFFF
        if pa_lo == self.FADT_ADDRESS:
            return self.fadt_descriptor[:length]
        else:
            parent = super(DSDTParsingHelper, self)
            return parent.read_phys_mem(pa, length)


class SPIHelper(TestHelper):
    """Generic SPI emulation

    Two regions are defined:
      * The flash descriptor [0x1000, 0x1FFF]
      * The BIOS image [0x2000, 0x2FFF]
    """
    RCBA_ADDR = 0xFED0000
    SPIBAR_ADDR = RCBA_ADDR + 0x3800
    SPIBAR_END = SPIBAR_ADDR + 0x200
    HSFS = SPIBAR_ADDR + 0x4
    FRAP = SPIBAR_ADDR + 0x50
    FREG0 = SPIBAR_ADDR + 0x54
    LPC_BRIDGE_DEVICE = (0, 0x1F, 0)

    def read_pci_reg(self, bus, device, function, address, size):
        if (bus, device, function) == self.LPC_BRIDGE_DEVICE:
            if address == 0xF0:
                return self.RCBA_ADDR
            elif address == 0xDC:
                return 0xDEADBEEF
            elif address == 0x0:
                return 0xAAAA8086
        return super(SPIHelper, self).read_pci_reg(bus, device,
                                                       function,
                                                       address, size)

    def read_mmio_reg(self, pa, size):
        if pa == self.FREG0:
            return 0x00010001
        elif pa == self.FREG0 + 4:
            return 0x00020002
        elif pa == self.FRAP:
            return 0xEEEEEEEE
        elif pa == self.HSFS:
            return (1 << 14)  # FDV = 1, the flash descriptor is valid
        elif pa >= self.SPIBAR_ADDR and pa < self.SPIBAR_END:
            return 0x0
        else:
            raise Exception("Unexpected address")

    def write_mmio_reg(self, pa, size, value):
        if pa < self.SPIBAR_ADDR or pa > self.SPIBAR_END:
            raise Exception("Write to outside of SPIBAR")

    def map_io_space(self, base, size, cache_type):
        raise UnimplementedAPIError("Not implemented")


class ValidChipsetHelper(TestHelper):
    def read_pci_reg(self, bus, device, function, address, size):
        if (bus, device, function) == (0, 0, 0):
            if size == 1:
                return 0x86
            elif size == 2:
                return 0x8086
            else:
                return 0x19048086
        elif (bus, device, function) == (0, 0x1f, 0):
            if size == 1:
                return 0x86
            elif size == 2:
                return 0x8086
            else:
                return 0x9D438086
        else:
            return self._generate_size_ffs(size)


class InvalidChipsetHelper(TestHelper):
    def read_pci_reg(self, bus, device, function, address, size):
        if (bus, device, function) == (0, 0, 0):
            if size == 1:
                return 0x86
            elif size == 2:
                return 0x8086
            else:
                return 0xBEEF8086
        elif (bus, device, function) == (0, 0x1f, 0):
            if size == 1:
                return 0x86
            elif size == 2:
                return 0x8086
            else:
                return 0x9D438086
        else:
            return self._generate_size_ffs(size)

    def cpuid(self, eax, ecx):
        return 0xfffff, 0, 0, 0


class InvalidPchHelper(TestHelper):
    def read_pci_reg(self, bus, device, function, address, size):
        if (bus, device, function) == (0, 0, 0):
            if size == 1:
                return 0x86
            elif size == 2:
                return 0x8086
            else:
                return 0x19048086
        elif (bus, device, function) == (0, 0x1f, 0):
            if size == 1:
                return 0x86
            elif size == 2:
                return 0x8086
            else:
                return 0xBEEF8086
        else:
            return self._generate_size_ffs(size)
