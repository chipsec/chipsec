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
Functionality encapsulating interrupt generation
CPU Interrupts specific functions (SMI, NMI)

usage:
    >>> send_SMI_APMC( 0xDE )
    >>> send_NMI()
"""

# TODO IPIs through Local APIC??

import struct
import uuid
from typing import Optional, Tuple
from chipsec.hal import hal_base
from chipsec.library.logger import logger, print_buffer_bytes
from chipsec.hal.acpi import ACPI
from chipsec.hal.acpi_tables import UEFI_TABLE, GAS
from chipsec.library.defines import bytestostring

SMI_APMC_PORT = 0xB2
SMI_DATA_PORT = 0xB3

NMI_TCO1_CTL = 0x8  # NMI_NOW is bit [8] in TCO1_CTL (or bit [1] in TCO1_CTL + 1)
NMI_NOW = 0x1


class Interrupts(hal_base.HALBase):

    def __init__(self, cs):
        super(Interrupts, self).__init__(cs)

    def send_SW_SMI(self, thread_id: int, SMI_code_port_value: int, SMI_data_port_value: int, _rax: int, _rbx: int, _rcx: int, _rdx: int, _rsi: int, _rdi: int) -> Optional[Tuple[int, int, int, int, int, int, int]]:
        SMI_code_data = (SMI_data_port_value << 8 | SMI_code_port_value)
        logger().log_hal(
            f"[intr] Sending SW SMI: code port 0x{SMI_APMC_PORT:02X} <- 0x{SMI_code_port_value:02X}, data port 0x{SMI_APMC_PORT + 1:02X} <- 0x{SMI_data_port_value:02X} (0x{SMI_code_data:04X})")
        logger().log_hal(f"       RAX = 0x{_rax:016X} (AX will be overridden with values of SW SMI ports B2/B3)")
        logger().log_hal(f"       RBX = 0x{_rbx:016X}")
        logger().log_hal(f"       RCX = 0x{_rcx:016X}")
        logger().log_hal(f"       RDX = 0x{_rdx:016X} (DX will be overridden with 0x00B2)")
        logger().log_hal(f"       RSI = 0x{_rsi:016X}")
        logger().log_hal(f"       RDI = 0x{_rdi:016X}")
        return self.cs.helper.send_sw_smi(thread_id, SMI_code_data, _rax, _rbx, _rcx, _rdx, _rsi, _rdi)

    def send_SW_SMI_timed(self, thread_id: int, SMI_code_port_value: int, SMI_data_port_value: int, _rax: int, _rbx: int, _rcx: int, _rdx: int, _rsi: int, _rdi: int) -> Optional[Tuple[int, int, int, int, int, int, int]]:
        SMI_code_data = (SMI_data_port_value << 8 | SMI_code_port_value)
        logger().log_hal(
            f"[intr] Sending SW SMI: code port 0x{SMI_APMC_PORT:02X} <- 0x{SMI_code_port_value:02X}, data port 0x{SMI_APMC_PORT + 1:02X} <- 0x{SMI_data_port_value:02X} (0x{SMI_code_data:04X})")
        logger().log_hal(f"       RAX = 0x{_rax:016X} (AX will be overridden with values of SW SMI ports B2/B3)")
        logger().log_hal(f"       RBX = 0x{_rbx:016X}")
        logger().log_hal(f"       RCX = 0x{_rcx:016X}")
        logger().log_hal(f"       RDX = 0x{_rdx:016X} (DX will be overridden with 0x00B2)")
        logger().log_hal(f"       RSI = 0x{_rsi:016X}")
        logger().log_hal(f"       RDI = 0x{_rdi:016X}")
        return self.cs.helper.send_sw_smi_timed(thread_id, SMI_code_data, _rax, _rbx, _rcx, _rdx, _rsi, _rdi)

    def send_SMI_APMC(self, SMI_code_port_value: int, SMI_data_port_value: int) -> None:
        logger().log_hal(f"[intr] sending SMI via APMC ports: code 0xB2 <- 0x{SMI_code_port_value:02X}, data 0xB3 <- 0x{SMI_data_port_value:02X}")
        self.cs.io.write_port_byte(SMI_DATA_PORT, SMI_data_port_value)
        return self.cs.io.write_port_byte(SMI_APMC_PORT, SMI_code_port_value)

    def send_NMI(self) -> None:
        logger().log_hal("[intr] Sending NMI# through TCO1_CTL[NMI_NOW]")
        reg, ba = self.cs.device.get_IO_space("TCOBASE")
        tcobase = self.cs.register.read_field(reg, ba)
        return self.cs.io.write_port_byte(tcobase + NMI_TCO1_CTL + 1, NMI_NOW)

    def find_ACPI_SMI_Buffer(self) -> Optional[UEFI_TABLE.CommBuffInfo]:
        logger().log_hal("Parsing ACPI tables to identify Communication Buffer")
        _acpi = ACPI(self.cs).get_ACPI_table("UEFI")
        if len(_acpi):
            _uefi = UEFI_TABLE()
            _uefi.parse(_acpi[0][1])
            logger().log_hal(str(_uefi))
            return _uefi.get_commbuf_info()
        logger().log_hal("Unable to find Communication Buffer")
        return None

    def send_ACPI_SMI(self, thread_id: int, smi_num: int, buf_addr: int, invoc_reg: GAS, guid: str, data: bytes) -> Optional[int]:
        # Prepare Communication Data buffer
        # typedef struct {
        #   EFI_GUID HeaderGuid;
        #   UINTN MessageLength;
        #   UINT8 Data[ANYSIZE_ARRAY];
        # } EFI_SMM_COMMUNICATE_HEADER;
        _guid = uuid.UUID(guid).bytes_le
        data_hdr = _guid + struct.pack("Q", len(data)) + data
        if not invoc_reg is None:
            # need to write data_hdr to comm buffer
            self.cs.helper.write_phys_mem(buf_addr, len(data_hdr), data_hdr)
            # USING GAS need to write buf_addr into invoc_reg
            if invoc_reg.addrSpaceID == 0:
                self.cs.helper.write_phys_mem(invoc_reg.addr, invoc_reg.accessSize, buf_addr)
                # check for return status
                ret_buf = self.cs.helper.read_phys_mem(buf_addr, 8)
            elif invoc_reg.addrSpaceID == 1:
                self.cs.helper.write_io_port(invoc_reg.addr, invoc_reg.accessSize, buf_addr)
                # check for return status
                ret_buf = self.cs.helper.read_io_port(buf_addr, 8)
            else:
                logger().log_error("Functionality is currently not implemented")
                ret_buf = None
            return ret_buf

        else:
            # Wait for Communication buffer to be empty
            buf = 1
            while not buf == b"\x00\x00":
                buf = self.cs.helper.read_phys_mem(buf_addr, 2)
            # write data to commbuffer
            self.cs.helper.write_phys_mem(buf_addr, len(data_hdr), data_hdr)
            # call SWSMI
            self.send_SW_SMI(thread_id, smi_num, 0, 0, 0, 0, 0, 0, 0)
            # clear CommBuffer
            self.cs.helper.write_phys_mem(buf_addr, len(data_hdr), b"\x00" * len(data_hdr))
            return None

    # scan phys mem range start-end looking for 'smmc'
    def find_smmc(self, start: int, end: int) -> int:
        chunk_sz = 1024 * 8  # 8KB chunks
        phys_address = start
        found_at = 0
        while phys_address <= end:
            buffer = self.cs.mem.read_physical_mem(phys_address, chunk_sz)
            buffer = bytestostring(buffer)
            offset = buffer.find('smmc')
            if offset != -1:
                found_at = phys_address + offset
                break
            phys_address += chunk_sz
        return found_at

    '''
Send SWSMI in the same way as EFI_SMM_COMMUNICATION_PROTOCOL
    - Write Commbuffer location and Commbuffer size to 'smmc' structure
    - Write 0 to 0xb3 and 0xb2

MdeModulePkg/Core/PiSmmCore/PiSmmCorePrivateData.h

#define SMM_CORE_PRIVATE_DATA_SIGNATURE  SIGNATURE_32 ('s', 'm', 'm', 'c')
 struct {
  UINTN                           Signature;
   This field is used by the SMM Communicatioon Protocol to pass a buffer into
   a software SMI handler and for the software SMI handler to pass a buffer back to
   the caller of the SMM Communication Protocol.
  VOID                            *CommunicationBuffer;
  UINTN                           BufferSize;

  EFI_STATUS                      ReturnStatus;
} SMM_CORE_PRIVATE_DATA;
    '''

    def send_smmc_SMI(self, smmc: int, guid: str, payload: bytes, payload_loc: int, CommandPort: int = 0x0, DataPort: int = 0x0) -> int:
        guid_b = uuid.UUID(guid).bytes_le
        payload_sz = len(payload)

        data_hdr = guid_b + struct.pack("Q", payload_sz) + payload
        # write payload to payload_loc
        CommBuffer_offset = 56
        BufferSize_offset = CommBuffer_offset + 8
        ReturnStatus_offset = BufferSize_offset + 8

        self.cs.mem.write_physical_mem(smmc + CommBuffer_offset, 8, struct.pack("Q", payload_loc))
        self.cs.mem.write_physical_mem(smmc + BufferSize_offset, 8, struct.pack("Q", len(data_hdr)))
        self.cs.mem.write_physical_mem(payload_loc, len(data_hdr), data_hdr)

        if self.logger.VERBOSE:
            self.logger.log("[*] Communication buffer on input")
            print_buffer_bytes(self.cs.mem.read_physical_mem(payload_loc, len(data_hdr)))
            self.logger.log("")

        self.send_SMI_APMC(CommandPort, DataPort)

        if self.logger.VERBOSE:
            self.logger.log("[*] Communication buffer on output")
            print_buffer_bytes(self.cs.mem.read_physical_mem(payload_loc, len(data_hdr)))
            self.logger.log("")

        ReturnStatus = struct.unpack("Q", self.cs.mem.read_physical_mem(smmc + ReturnStatus_offset, 8))[0]
        return ReturnStatus
