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
Trusted Platform Module (TPM) HAL component

https://trustedcomputinggroup.org
"""

import struct
from typing import Tuple

from chipsec.library.logger import print_buffer
from chipsec.hal import hal_base
from chipsec.library.tpm import tpm_defines


class TPM_BASE(hal_base.HALBase):
    def __init__(self, cs):
        super(TPM_BASE, self).__init__(cs)
        self.TPM_BASE = self.cs.Cfg.MEMORY_RANGES['TPM']['address']
        self.access_address = 0x0

    # def get_registers(self) -> list:
    #    return self.list_of_registers

    def request_locality(self, Locality: int) -> bool:
        self.access_address = self.TPM_BASE | Locality | tpm_defines.TPM_ACCESS
        if self.helper.read_mmio_reg(self.access_address, 4) == tpm_defines.BEENSEIZED:
            self.helper.write_mmio_reg(self.access_address, 4, tpm_defines.REQUESTUSE)
            return True
        return False

    def command(self, commandName: str, locality: str, *command_argv: str) -> None:
        raise NotImplementedError()

    def send_command(self, Locality: int, command: bytes, size: int) -> None:
        raise NotImplementedError()

    def read_response(self, Locality: int) -> Tuple[tpm_defines.tpm1_commands.TPM_RESPONSE_HEADER, bytes, bytearray, bytearray]:
        raise NotImplementedError()


class TPM1(TPM_BASE):
    def __init__(self, cs):
        super(TPM1, self).__init__(cs)
        self.helper = cs.helper

    def command(self, commandName: str, locality: str, *command_argv: str) -> None:
        """Send command to the TPM and receive data"""
        try:
            Locality = tpm_defines.LOCALITY[locality]
        except:
            if self.logger.HAL: self.logger.log_bad("Invalid locality value\n")
            return

        requestedUse = self.request_locality(Locality)

        #
        # Build command (big endian) and send/receive
        #
        (command, size) = tpm_defines.COMMANDS_12[commandName](command_argv)
        self.send_command(Locality, command, size)

        (header, _, _, data_blob) = self.read_response(Locality)
        self.logger.log(str(header))
        print_buffer(str(data_blob))
        self.logger.log('\n')

        #
        # Release locality if needed
        #
        if requestedUse:
            self.helper.write_mmio_reg(self.access_address, 4, tpm_defines.BEENSEIZED)
        self.helper.write_mmio_reg(self.access_address, 1, tpm_defines.ACTIVELOCALITY)

    def send_command(self, Locality: int, command: bytes, size: int) -> None:
        """Send a command to the TPM using the locality specified"""
        count = 0

        datafifo_address = self.TPM_BASE | Locality | tpm_defines.TPM_DATAFIFO
        sts_address = self.TPM_BASE | Locality | tpm_defines.TPM_STS
        self.access_address = self.TPM_BASE | Locality | tpm_defines.TPM_ACCESS

        self.helper.write_mmio_reg(self.access_address, 1, tpm_defines.REQUESTUSE)
        #
        # Set status to command ready
        #
        sts_value = self.helper.read_mmio_reg(sts_address, 1)
        while (0 == (sts_value & tpm_defines.COMMANDREADY)):
            self.helper.write_mmio_reg(sts_address, 1, tpm_defines.COMMANDREADY)
            sts_value = self.helper.read_mmio_reg(sts_address, 1)

        while count < size:
            sts_value = self.helper.read_mmio_reg(sts_address, 4)
            burst_count = ((sts_value>>8) & 0xFFFFFF)
            burst_index = 0
            while (burst_index < burst_count) and (count < size):
                datafifo_value = command[count]
                self.helper.write_mmio_reg(datafifo_address, 1, datafifo_value)
                count += 1
                burst_index += 0x1

        self.helper.write_mmio_reg(sts_address, 1, tpm_defines.TPMGO)

    def read_response(self, Locality: int) -> Tuple[tpm_defines.tpm1_commands.TPM_RESPONSE_HEADER, bytes, bytearray, bytearray]:
        """Read the TPM's response using the specified locality"""
        count = 0
        header = ""
        header_blob = bytearray()
        data = ""
        data_blob = bytearray()
        #
        # Build FIFO address
        #
        datafifo_address = self.TPM_BASE | Locality | tpm_defines.TPM_DATAFIFO
        self.access_address = self.TPM_BASE | Locality| tpm_defines.TPM_ACCESS
        sts_address = self.TPM_BASE | Locality| tpm_defines.TPM_STS

        sts_value = self.helper.read_mmio_reg(sts_address, 1)
        data_avail = bin(sts_value & (1<<4))[2]
        #
        # Read data available
        #
        # watchdog?
        while data_avail == '0':
            sts_value = self.helper.read_mmio_reg(sts_address, 1)
            self.helper.write_mmio_reg(sts_address, 1, tpm_defines.DATAAVAIL)
            data_avail = bin(sts_value & (1<<4))[2]

        while count < tpm_defines.HEADERSIZE:
            sts_value = self.helper.read_mmio_reg(sts_address, 4)
            burst_count = ((sts_value>>8) & 0xFFFFFF)
            burst_index = 0
            while (burst_index < burst_count) and (count < tpm_defines.HEADERSIZE):
                header_blob.append(self.helper.read_mmio_reg(datafifo_address, 1))
                count += 1
                burst_index += 0x1

        header = tpm_defines.COMMANDS_12['header'](*struct.unpack_from(tpm_defines.HEADERFORMAT, header_blob))

        count = 0
        if header.DataSize > 10 and header.ReturnCode == 0:
            length = header.DataSize - tpm_defines.HEADERSIZE
            while count < length:
                sts_value = self.helper.read_mmio_reg(sts_address, 4)
                burst_count = ((sts_value>>8) & 0xFFFFFF)
                burst_index = 0
                while (burst_index < burst_count) and (count < length):
                    data_blob.append(self.helper.read_mmio_reg(datafifo_address, 1))
                    count += 1
                    burst_index += 0x1

        return (header, data, header_blob, data_blob)


class TPM2(TPM_BASE):
    def __init__(self, cs, buffer_type = 'fifo_legacy'):
        super(TPM2, self).__init__(cs)
        self.helper = cs.helper
        self.buffer_type = buffer_type

    def command(self, commandName: str, locality: str, *command_argv: str) -> None:
        """Send command to the TPM and receive data"""
        try:
            Locality = tpm_defines.LOCALITY[locality]
        except Exception as e:
            self.logger.log_bad(f"Invalid locality value\n\t{e}")
            return

        requestedUse = self.request_locality(Locality)

        #
        # Build command (big endian) and send/receive
        #
        try:
            (command, size) = tpm_defines.COMMANDS_20[commandName](command_argv)
        except Exception as e:
            self.logger.log_bad(f'Unable to build command\n\t{e}')
            return

        try:
            self.send_command(Locality, command, size)
        except Exception as e:
            self.logger.log_bad(f'Unable to send command\n\t{e}')
            return
        (header, _, _, data_blob) = self.read_response(Locality)
        self.logger.log(str(header))
        print_buffer(str(data_blob))
        self.logger.log('\n')

        #
        # Release locality if needed
        #
        if requestedUse:
            self.helper.write_mmio_reg(self.access_address, 4, tpm_defines.BEENSEIZED)
        self.helper.write_mmio_reg(self.access_address, 1, tpm_defines.ACTIVELOCALITY)

    def send_command(self, Locality: int, command: bytes, size: int) -> None:
        """Send a command to the TPM using the locality specified"""
        count = 0

        datafifo_address = self.TPM_BASE | Locality | tpm_defines.TPM_DATAFIFO
        sts_address = self.TPM_BASE | Locality | tpm_defines.TPM_STS
        self.access_address = self.TPM_BASE | Locality | tpm_defines.TPM_ACCESS

        self.helper.write_mmio_reg(self.access_address, 1, tpm_defines.REQUESTUSE)
        #
        # Set status to command ready
        #
        sts_value = self.helper.read_mmio_reg(sts_address, 1)
        while (0 == (sts_value & tpm_defines.COMMANDREADY)):
            self.helper.write_mmio_reg(sts_address, 1, tpm_defines.COMMANDREADY)
            sts_value = self.helper.read_mmio_reg(sts_address, 1)

        while count < size:
            sts_value = self.helper.read_mmio_reg(sts_address, 4)
            burst_count = ((sts_value>>8) & 0xFFFFFF)
            burst_index = 0
            while (burst_index < burst_count) and (count < size):
                datafifo_value = command[count]
                self.helper.write_mmio_reg(datafifo_address, 1, datafifo_value)
                count += 1
                burst_index += 0x1

        self.helper.write_mmio_reg(sts_address, 1, tpm_defines.TPMGO)

    def read_response(self, Locality: int) -> Tuple[tpm_defines.tpm2_commands.TPM_RESPONSE_HEADER, bytes, bytearray, bytearray]:
        """Read the TPM's response using the specified locality"""
        count = 0
        header = ""
        header_blob = bytearray()
        data = ""
        data_blob = bytearray()
        #
        # Build FIFO address
        #
        datafifo_address = self.TPM_BASE | Locality | tpm_defines.TPM_DATAFIFO
        self.access_address = self.TPM_BASE | Locality| tpm_defines.TPM_ACCESS
        sts_address = self.TPM_BASE | Locality| tpm_defines.TPM_STS

        sts_value = self.helper.read_mmio_reg(sts_address, 1)
        data_avail = bin(sts_value & (1<<4))[2]
        #
        # Read data available
        #
        # watchdog?
        while data_avail == '0':
            sts_value = self.helper.read_mmio_reg(sts_address, 1)
            self.helper.write_mmio_reg(sts_address, 1, tpm_defines.DATAAVAIL)
            data_avail = bin(sts_value & (1<<4))[2]

        while count < tpm_defines.HEADERSIZE:
            sts_value = self.helper.read_mmio_reg(sts_address, 4)
            burst_count = ((sts_value>>8) & 0xFFFFFF)
            burst_index = 0
            while (burst_index < burst_count) and (count < tpm_defines.HEADERSIZE):
                header_blob.append(self.helper.read_mmio_reg(datafifo_address, 1))
                count += 1
                burst_index += 0x1

        header = tpm_defines.COMMANDS_20['header'](*struct.unpack_from(tpm_defines.HEADERFORMAT, header_blob))

        count = 0
        if header.DataSize > 10 and header.ReturnCode == 0:
            length = header.DataSize - tpm_defines.HEADERSIZE
            while count < length:
                sts_value = self.helper.read_mmio_reg(sts_address, 4)
                burst_count = ((sts_value>>8) & 0xFFFFFF)
                burst_index = 0
                while (burst_index < burst_count) and (count < length):
                    data_blob.append(self.helper.read_mmio_reg(datafifo_address, 1))
                    count += 1
                    burst_index += 0x1

        return (header, data, header_blob, data_blob)


# class TPM2_CRB(TPM_BASE):
#     def __init__(self, cs):
#         super(TPM2_CRB, self).__init__(cs)
#         self.helper = cs.helper
#         self.TPM_BASE = self.cs.Cfg.MEMORY_RANGES['TPM']['address']
#         self.list_of_registers = []

#     def send_command(self, Locality: int, command: bytes, size: int) -> None:
#         raise NotImplementedError()

#     def read_response(self, Locality: int) -> Tuple[TPM_RESPONSE_HEADER, bytes, bytearray, bytearray]:
#         raise NotImplementedError()


# class TPM2_FIFO_LEGACY(TPM1):
#     def __init__(self, cs):
#         super(TPM2_FIFO_LEGACY, self).__init__(cs)
#         self.helper = cs.helper
#         self.TPM_BASE = self.cs.Cfg.MEMORY_RANGES['TPM']['address']
#         self.list_of_registers = ['TPM_ACCESS', 'TPM_STS', 'TPM_DID_VID', 'TPM_RID', 'TPM_INTF_CAPABILITY', 'TPM_INT_ENABLE']
