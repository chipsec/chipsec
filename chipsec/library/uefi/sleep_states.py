# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2024, Intel Corporation
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

import struct
from typing import List, Dict, Optional, Tuple

from chipsec.library.logger import print_buffer_bytes, logger, dump_buffer, dump_buffer_bytes

########################################################################################################
#
# S3 Resume Boot-Script Parsing Functionality
#
########################################################################################################

BOOTSCRIPT_TABLE_OFFSET = 24
RUNTIME_SCRIPT_TABLE_BASE_OFFSET = 32
ACPI_VARIABLE_SET_STRUCT_SIZE = 0x48
S3_BOOTSCRIPT_VARIABLES = ['AcpiGlobalVariable']

MAX_S3_BOOTSCRIPT_ENTRY_LENGTH = 0x200


#
# MdePkg\Include\Pi\PiS3BootScript.h
#
# //*******************************************
# // EFI Boot Script Opcode definitions
# //*******************************************

class S3BootScriptOpcode:
    EFI_BOOT_SCRIPT_IO_WRITE_OPCODE = 0x00
    EFI_BOOT_SCRIPT_IO_READ_WRITE_OPCODE = 0x01
    EFI_BOOT_SCRIPT_MEM_WRITE_OPCODE = 0x02
    EFI_BOOT_SCRIPT_MEM_READ_WRITE_OPCODE = 0x03
    EFI_BOOT_SCRIPT_PCI_CONFIG_WRITE_OPCODE = 0x04
    EFI_BOOT_SCRIPT_PCI_CONFIG_READ_WRITE_OPCODE = 0x05
    EFI_BOOT_SCRIPT_SMBUS_EXECUTE_OPCODE = 0x06
    EFI_BOOT_SCRIPT_STALL_OPCODE = 0x07
    EFI_BOOT_SCRIPT_DISPATCH_OPCODE = 0x08
    EFI_BOOT_SCRIPT_TERMINATE_OPCODE = 0xFF


class S3BootScriptOpcode_MDE (S3BootScriptOpcode):
    EFI_BOOT_SCRIPT_DISPATCH_2_OPCODE = 0x09
    EFI_BOOT_SCRIPT_INFORMATION_OPCODE = 0x0A
    EFI_BOOT_SCRIPT_PCI_CONFIG2_WRITE_OPCODE = 0x0B
    EFI_BOOT_SCRIPT_PCI_CONFIG2_READ_WRITE_OPCODE = 0x0C
    EFI_BOOT_SCRIPT_IO_POLL_OPCODE = 0x0D
    EFI_BOOT_SCRIPT_MEM_POLL_OPCODE = 0x0E
    EFI_BOOT_SCRIPT_PCI_CONFIG_POLL_OPCODE = 0x0F
    EFI_BOOT_SCRIPT_PCI_CONFIG2_POLL_OPCODE = 0x10

#
# EdkCompatibilityPkg\Foundation\Framework\Include\EfiBootScript.h
#


class S3BootScriptOpcode_EdkCompat (S3BootScriptOpcode):
    EFI_BOOT_SCRIPT_MEM_POLL_OPCODE = 0x09
    EFI_BOOT_SCRIPT_INFORMATION_OPCODE = 0x0A
    EFI_BOOT_SCRIPT_PCI_CONFIG2_WRITE_OPCODE = 0x0B
    EFI_BOOT_SCRIPT_PCI_CONFIG2_READ_WRITE_OPCODE = 0x0C
    EFI_BOOT_SCRIPT_TABLE_OPCODE = 0xAA


#
# Names of S3 Boot Script Opcodes
#
script_opcodes: Dict[int, str] = {
    S3BootScriptOpcode.EFI_BOOT_SCRIPT_IO_WRITE_OPCODE: "S3_BOOTSCRIPT_IO_WRITE",
    S3BootScriptOpcode.EFI_BOOT_SCRIPT_IO_READ_WRITE_OPCODE: "S3_BOOTSCRIPT_IO_READ_WRITE",
    S3BootScriptOpcode.EFI_BOOT_SCRIPT_MEM_WRITE_OPCODE: "S3_BOOTSCRIPT_MEM_WRITE",
    S3BootScriptOpcode.EFI_BOOT_SCRIPT_MEM_READ_WRITE_OPCODE: "S3_BOOTSCRIPT_MEM_READ_WRITE",
    S3BootScriptOpcode.EFI_BOOT_SCRIPT_PCI_CONFIG_WRITE_OPCODE: "S3_BOOTSCRIPT_PCI_CONFIG_WRITE",
    S3BootScriptOpcode.EFI_BOOT_SCRIPT_PCI_CONFIG_READ_WRITE_OPCODE: "S3_BOOTSCRIPT_PCI_CONFIG_READ_WRITE",
    S3BootScriptOpcode.EFI_BOOT_SCRIPT_SMBUS_EXECUTE_OPCODE: "S3_BOOTSCRIPT_SMBUS_EXECUTE",
    S3BootScriptOpcode.EFI_BOOT_SCRIPT_STALL_OPCODE: "S3_BOOTSCRIPT_STALL",
    S3BootScriptOpcode.EFI_BOOT_SCRIPT_DISPATCH_OPCODE: "S3_BOOTSCRIPT_DISPATCH",
    # S3BootScriptOpcode.EFI_BOOT_SCRIPT_DISPATCH_2_OPCODE:             "S3_BOOTSCRIPT_DISPATCH_2",
    # S3BootScriptOpcode.EFI_BOOT_SCRIPT_INFORMATION_OPCODE:            "S3_BOOTSCRIPT_INFORMATION",
    # S3BootScriptOpcode.EFI_BOOT_SCRIPT_PCI_CONFIG2_WRITE_OPCODE:      "S3_BOOTSCRIPT_PCI_CONFIG2_WRITE",
    # S3BootScriptOpcode.EFI_BOOT_SCRIPT_PCI_CONFIG2_READ_WRITE_OPCODE: "S3_BOOTSCRIPT_PCI_CONFIG2_READ_WRITE",
    # S3BootScriptOpcode.EFI_BOOT_SCRIPT_IO_POLL_OPCODE:                "S3_BOOTSCRIPT_IO_POLL",
    # S3BootScriptOpcode.EFI_BOOT_SCRIPT_MEM_POLL_OPCODE:               "S3_BOOTSCRIPT_MEM_POLL",
    # S3BootScriptOpcode.EFI_BOOT_SCRIPT_PCI_CONFIG_POLL_OPCODE:        "S3_BOOTSCRIPT_PCI_CONFIG_POLL",
    # S3BootScriptOpcode.EFI_BOOT_SCRIPT_PCI_CONFIG2_POLL_OPCODE:       "S3_BOOTSCRIPT_PCI_CONFIG2_POLL",
    # S3BootScriptOpcode.EFI_BOOT_SCRIPT_TABLE_OPCODE:                  "S3_BOOTSCRIPT_TABLE",
    S3BootScriptOpcode.EFI_BOOT_SCRIPT_TERMINATE_OPCODE: "S3_BOOTSCRIPT_TERMINATE"
}


class S3BootScriptWidth:
    EFI_BOOT_SCRIPT_WIDTH_UINT8 = 0x00
    EFI_BOOT_SCRIPT_WIDTH_UINT16 = 0x01
    EFI_BOOT_SCRIPT_WIDTH_UINT32 = 0x02
    EFI_BOOT_SCRIPT_WIDTH_UINT64 = 0x03


script_width_sizes: Dict[int, int] = {
    S3BootScriptWidth.EFI_BOOT_SCRIPT_WIDTH_UINT8: 1,
    S3BootScriptWidth.EFI_BOOT_SCRIPT_WIDTH_UINT16: 2,
    S3BootScriptWidth.EFI_BOOT_SCRIPT_WIDTH_UINT32: 4,
    S3BootScriptWidth.EFI_BOOT_SCRIPT_WIDTH_UINT64: 8
}

script_width_values: Dict[int, int] = {
    1: S3BootScriptWidth.EFI_BOOT_SCRIPT_WIDTH_UINT8,
    2: S3BootScriptWidth.EFI_BOOT_SCRIPT_WIDTH_UINT16,
    4: S3BootScriptWidth.EFI_BOOT_SCRIPT_WIDTH_UINT32,
    8: S3BootScriptWidth.EFI_BOOT_SCRIPT_WIDTH_UINT64
}

script_width_formats: Dict[int, str] = {
    S3BootScriptWidth.EFI_BOOT_SCRIPT_WIDTH_UINT8: 'B',
    S3BootScriptWidth.EFI_BOOT_SCRIPT_WIDTH_UINT16: 'H',
    S3BootScriptWidth.EFI_BOOT_SCRIPT_WIDTH_UINT32: 'I',
    S3BootScriptWidth.EFI_BOOT_SCRIPT_WIDTH_UINT64: 'Q'
}

# //************************************************
# // EFI_SMBUS_DEVICE_ADDRESS
# //************************************************
# typedef struct _EFI_SMBUS_DEVICE_ADDRESS {
# UINTN SmbusDeviceAddress:7;
# } EFI_SMBUS_DEVICE_ADDRESS;
# //************************************************
# // EFI_SMBUS_DEVICE_COMMAND
# //************************************************
# typedef UINTN EFI_SMBUS_DEVICE_COMMAND;
#
# //************************************************
# // EFI_SMBUS_OPERATION
# //************************************************
# typedef enum _EFI_SMBUS_OPERATION {
# EfiSmbusQuickRead,
# EfiSmbusQuickWrite,
# EfiSmbusReceiveByte,
# EfiSmbusSendByte,
# EfiSmbusReadByte,
# EfiSmbusWriteByte,
# EfiSmbusReadWord,
# EfiSmbusWriteWord,
# EfiSmbusReadBlock,
# EfiSmbusWriteBlock,
# EfiSmbusProcessCall,
# EfiSmbusBWBRProcessCall
# } EFI_SMBUS_OPERATION;


class S3BootScriptSmbusOperation:
    QUICK_READ = 0x00
    QUICK_WRITE = 0x01
    RECEIVE_BYTE = 0x02
    SEND_BYTE = 0x03
    READ_BYTE = 0x04
    WRITE_BYTE = 0x05
    READ_WORD = 0x06
    WRITE_WORD = 0x07
    READ_BLOCK = 0x08
    WRITE_BLOCK = 0x09
    PROCESS_CALL = 0x0A
    BWBR_PROCESS_CALL = 0x0B


class op_io_pci_mem:
    def __init__(self, opcode: int, size: int, width: int, address: int, unknown: Optional[int], count: Optional[int],
                 buffer: Optional[bytes], value: Optional[int] = None, mask: Optional[int] = None):
        self.opcode = opcode
        self.size = size
        self.width = width
        self.address = address
        self.unknown = unknown
        self.count = count
        self.value = value
        self.mask = mask
        self.name = script_opcodes[opcode]
        self.buffer = buffer  # data[ self.size : ]
        self.values = None
        if self.count is not None and self.count > 0 and self.buffer is not None:
            sz = self.count * script_width_sizes[self.width]
            if len(self.buffer) != sz:
                logger().log(f'[?] buffer size (0x{len(self.buffer):X}) != Width x Count (0x{sz:X})')
            else:
                self.values = list(struct.unpack((f'<{self.count:d}{script_width_formats[self.width]:1}'), self.buffer))

    def __str__(self) -> str:
        str_r = f'  Opcode : {self.name} (0x{self.opcode:04X})\n'
        str_r += f'  Width  : 0x{self.width:02X} ({script_width_sizes[self.width]:X} bytes)\n'
        str_r += f'  Address: 0x{self.address:08X}\n'
        if self.value is not None:
            str_r += f'  Value  : 0x{self.value:08X}\n'
        if self.mask is not None:
            str_r += f'  Mask   : 0x{self.mask:08X}\n'
        if self.unknown is not None:
            str_r += f'  Unknown: 0x{self.unknown:04X}\n'
        if self.count is not None:
            str_r += f'  Count  : 0x{self.count:X}\n'
        if self.values is not None:
            fmt = f'0x{{:0{script_width_sizes[self.width] * 2:d}X}}'
            values_str = '  '.join([fmt.format(v) for v in self.values])
            str_r += f'  Values : {values_str}\n'
        elif self.buffer is not None:
            str_r += f'  Buffer (size = 0x{len(self.buffer):X}):\n{dump_buffer(self.buffer, 16)}'
        return str_r


class op_smbus_execute:
    def __init__(self, opcode: int, size: int, address: int, command: int, operation: int, peccheck: int):
        self.opcode = opcode
        self.size = size
        self.address = address
        self.command = command
        self.operation = operation
        self.peccheck = peccheck
        self.name = script_opcodes[opcode]

    def __str__(self) -> str:
        str_r = f'  Opcode           : {self.name} (0x{self.opcode:04X})\n'
        str_r += f'  Secondary Address: 0x{self.address:02X}\n'
        str_r += f'  Command          : 0x{self.command:08X}\n'
        str_r += f'  Operation        : 0x{self.operation:02X}\n'
        str_r += f'  PEC Check        : {self.peccheck:d}\n'
        return str_r

# typedef struct {
#  UINT16  OpCode;
#  UINT8   Length;
#  UINT64  Duration;
# } EFI_BOOT_SCRIPT_STALL;


class op_stall:
    def __init__(self, opcode: int, size: int, duration: int):
        self.opcode = opcode
        self.size = size
        self.duration = duration
        self.name = script_opcodes[self.opcode]

    def __str__(self) -> str:
        str_r = f'  Opcode  : {self.name} (0x{self.opcode:04X})\n'
        str_r += f'  Duration: 0x{self.duration:08X} (us)\n'
        return str_r

# typedef struct {
#  UINT16                OpCode;
#  UINT8                 Length;
#  EFI_PHYSICAL_ADDRESS  EntryPoint;
# } EFI_BOOT_SCRIPT_DISPATCH;


class op_dispatch:
    def __init__(self, opcode: int, size: int, entrypoint: int, context: Optional[int] = None):
        self.opcode = opcode
        self.size = size
        self.entrypoint = entrypoint
        self.context = context
        self.name = script_opcodes[self.opcode]

    def __str__(self) -> str:
        str_r = f'  Opcode     : {self.name} (0x{self.opcode:04X})\n'
        str_r += f'  Entry Point: 0x{self.entrypoint:016X}\n'
        if self.context is not None:
            str_r += f'  Context    : 0x{self.context:016X}\n'
        return str_r

# typedef struct {
#  UINT16  OpCode;
#  UINT8   Length;
#  UINT32  Width;
#  UINT64  Address;
#  UINT64  Duration;
#  UINT64  LoopTimes;
# } EFI_BOOT_SCRIPT_MEM_POLL;


class op_mem_poll:
    def __init__(self, opcode: int, size: int, width: int, address: int, duration: int, looptimes: int):
        self.opcode = opcode
        self.size = size
        self.width = width
        self.address = address
        self.duration = duration
        self.looptimes = looptimes
        self.name = 'S3_BOOTSCRIPT_MEM_POLL'

    def __str__(self) -> str:
        str_r = f'  Opcode    : {self.name} (0x{self.opcode:04X})\n'
        str_r += f'  Width     : 0x{self.width:02X} ({script_width_sizes[self.width]:X} bytes)\n'
        str_r += f'  Address   : 0x{self.address:016X}\n'
        str_r += f'  Duration? : 0x{self.duration:016X}\n'
        str_r += f'  LoopTimes?: 0x{self.looptimes:016X}\n'
        return str_r


class op_terminate:
    def __init__(self, opcode: int, size: int):
        self.opcode = opcode
        self.size = size
        self.name = script_opcodes[self.opcode]

    def __str__(self) -> str:
        return f'  Opcode     : {self.name} (0x{self.opcode:02X})\n'


class op_unknown:
    def __init__(self, opcode: int, size: int):
        self.opcode = opcode
        self.size = size

    def __str__(self) -> str:
        return f'  Opcode     : unknown (0x{self.opcode:02X})\n'


class S3BOOTSCRIPT_ENTRY:
    def __init__(self, script_type: int, index: Optional[int], offset_in_script: int, length: int, data: Optional[bytes] = None):
        self.script_type = script_type
        self.index = index
        self.offset_in_script = offset_in_script
        self.length = length
        self.data = data
        self.decoded_opcode = None
        self.header_length = 0

    def __str__(self) -> str:
        entry_str = '' if self.index is None else (f'[{self.index:03d}] ')
        entry_str += f'Entry at offset 0x{self.offset_in_script:04X} (len = 0x{self.length:X}, header len = 0x{self.header_length:X}):'
        if self.data:
            entry_str = entry_str + f'\nData:\n{dump_buffer_bytes(self.data, 16)}'
        if self.decoded_opcode:
            entry_str = entry_str + f'Decoded:\n{str(self.decoded_opcode)}'
        return entry_str


#
# Decoding S3 Resume Boot Script
#

class S3BootScriptType:
    EFI_BOOT_SCRIPT_TYPE_DEFAULT = 0x00
    EFI_BOOT_SCRIPT_TYPE_EDKCOMPAT = 0xAA


def decode_s3bs_opcode(s3bootscript_type, script_data):
    if S3BootScriptType.EFI_BOOT_SCRIPT_TYPE_EDKCOMPAT == s3bootscript_type:
        return decode_s3bs_opcode_edkcompat(script_data)
    else:
        return decode_s3bs_opcode_def(script_data)


def encode_s3bs_opcode(s3bootscript_type: int, op: S3BOOTSCRIPT_ENTRY) -> bytes:
    if S3BootScriptType.EFI_BOOT_SCRIPT_TYPE_EDKCOMPAT == s3bootscript_type:
        return encode_s3bs_opcode_edkcompat(op)
    else:
        return encode_s3bs_opcode_def(op)


def decode_s3bs_opcode_def(data):
    opcode = None
    size = None
    width = None
    unknown = None
    count = None
    value = None
    mask = None

    op = None
    opcode, = struct.unpack('<B', data[: 1])
    try:
        logger().log_hal(script_opcodes[opcode])
    except Exception:
        pass
    if S3BootScriptOpcode_MDE.EFI_BOOT_SCRIPT_IO_WRITE_OPCODE == opcode:
        frmt = '<BBHIQ'
        size = struct.calcsize(frmt)
        opcode, width, address, alignment, count = struct.unpack(frmt, data[: size])
        op = op_io_pci_mem(opcode, size, width, address, unknown, count, data[size:], value, mask)
    elif S3BootScriptOpcode_MDE.EFI_BOOT_SCRIPT_IO_READ_WRITE_OPCODE == opcode:
        frmt = '<BBHIQQ'
        size = struct.calcsize(frmt)
        opcode, width, address, _, value, mask = struct.unpack(frmt, data[: size])
        op = op_io_pci_mem(opcode, size, width, address, unknown, count, None, value, mask)
    elif S3BootScriptOpcode_MDE.EFI_BOOT_SCRIPT_PCI_CONFIG_WRITE_OPCODE == opcode:
        frmt = '<BBHIQQ'
        size = struct.calcsize(frmt)
        opcode, width, unknown, _, address, count = struct.unpack(frmt, data[: size])
        op = op_io_pci_mem(opcode, size, width, address, unknown, count, data[size:], value, mask)
    elif S3BootScriptOpcode_MDE.EFI_BOOT_SCRIPT_PCI_CONFIG_READ_WRITE_OPCODE == opcode:
        frmt = '<BBHIQQQ'
        size = struct.calcsize(frmt)
        opcode, width, unknown, _, address, value, mask = struct.unpack(frmt, data[: size])
        op = op_io_pci_mem(opcode, size, width, address, unknown, count, None, value, mask)
    elif S3BootScriptOpcode_MDE.EFI_BOOT_SCRIPT_MEM_WRITE_OPCODE == opcode:
        frmt = '<BBHIQQ'
        size = struct.calcsize(frmt)
        opcode, width, unknown, _, address, count = struct.unpack(frmt, data[: size])
        op = op_io_pci_mem(opcode, size, width, address, unknown, count, data[size:], value, mask)
    elif S3BootScriptOpcode_MDE.EFI_BOOT_SCRIPT_MEM_READ_WRITE_OPCODE == opcode:
        frmt = '<BBHIQQQ'
        size = struct.calcsize(frmt)
        opcode, width, unknown, _, address, value, mask = struct.unpack(frmt, data[: size])
        op = op_io_pci_mem(opcode, size, width, address, unknown, count, None, value, mask)
    elif S3BootScriptOpcode_MDE.EFI_BOOT_SCRIPT_SMBUS_EXECUTE_OPCODE == opcode:
        frmt = '<BBQBB'
        size = struct.calcsize(frmt)
        opcode, address, command, operation, peccheck = struct.unpack(frmt, data[: size])
        op = op_smbus_execute(opcode, size, address, command, operation, peccheck)
    elif S3BootScriptOpcode_MDE.EFI_BOOT_SCRIPT_STALL_OPCODE == opcode:
        frmt = '<BBQ'
        size = struct.calcsize(frmt)
        opcode, _, duration = struct.unpack(frmt, data[: size])
        op = op_stall(opcode, size, duration)
    elif S3BootScriptOpcode_MDE.EFI_BOOT_SCRIPT_DISPATCH_OPCODE == opcode:
        frmt = '<BBHIQ'
        size = struct.calcsize(frmt)
        opcode, _, _, _, entrypoint = struct.unpack(frmt, data[: size])
        op = op_dispatch(opcode, size, entrypoint)
    elif S3BootScriptOpcode_MDE.EFI_BOOT_SCRIPT_DISPATCH_2_OPCODE == opcode:
        frmt = '<BBHIQQ'
        size = struct.calcsize(frmt)
        opcode, _, _, _, entrypoint, context = struct.unpack(frmt, data[: size])
        op = op_dispatch(opcode, size, entrypoint, context)
    elif S3BootScriptOpcode_MDE.EFI_BOOT_SCRIPT_TERMINATE_OPCODE == opcode:
        frmt = '<B'
        size = struct.calcsize(frmt)
        opcode, = struct.unpack(frmt, data[: size])
        op = op_terminate(opcode, size)
    else:
        op = op_unknown(opcode, 1)
        if logger().HAL:
            logger().log_warning(f'Unrecognized opcode {opcode:X}')

    return op

#
# @TODO: encode functions are not fully implemented
#


def encode_s3bs_opcode_def(op) -> bytes:
    encoded_opcode = b''

    if S3BootScriptOpcode_MDE.EFI_BOOT_SCRIPT_IO_WRITE_OPCODE == op.opcode:
        encoded_hdr = struct.pack('<BBHIQ', op.opcode, op.width, op.address, 0x0, op.count)
        if op.values is None:
            encoded_opcode = encoded_hdr + op.buffer
        else:
            encoded_opcode = encoded_hdr + struct.pack(script_width_formats[op.width] * op.count, *op.values)

    elif S3BootScriptOpcode_MDE.EFI_BOOT_SCRIPT_IO_READ_WRITE_OPCODE == op.opcode:
        encoded_opcode = struct.pack('<BBHIQQ', op.opcode, op.width, op.address, 0x0, op.value, op.mask)

    elif S3BootScriptOpcode_MDE.EFI_BOOT_SCRIPT_PCI_CONFIG_WRITE_OPCODE == op.opcode or \
            S3BootScriptOpcode_MDE.EFI_BOOT_SCRIPT_MEM_WRITE_OPCODE == op.opcode:
        encoded_hdr = struct.pack('<BBHIQQ', op.opcode, op.width, op.unknown, 0x0, op.address, op.count)
        if op.values is None:
            encoded_opcode = encoded_hdr + op.buffer
        else:
            encoded_opcode = encoded_hdr + struct.pack(script_width_formats[op.width] * op.count, *op.values)

    elif S3BootScriptOpcode_MDE.EFI_BOOT_SCRIPT_PCI_CONFIG_READ_WRITE_OPCODE == op.opcode:
        frmt = '<BBHIQQQ'

    elif S3BootScriptOpcode_MDE.EFI_BOOT_SCRIPT_MEM_READ_WRITE_OPCODE == op.opcode:
        encoded_opcode = struct.pack('<BBHIQQQ', op.opcode, op.width, op.unknown, 0x0, op.address, op.value, op.mask)

    elif S3BootScriptOpcode_MDE.EFI_BOOT_SCRIPT_SMBUS_EXECUTE_OPCODE == op.opcode:
        frmt = '<BBQBB'

    elif S3BootScriptOpcode_MDE.EFI_BOOT_SCRIPT_STALL_OPCODE == op.opcode:
        frmt = '<BBQ'

    elif S3BootScriptOpcode_MDE.EFI_BOOT_SCRIPT_DISPATCH_OPCODE == op.opcode:
        encoded_opcode = struct.pack('<BBHIQ', op.opcode, 0x0, 0x0, 0x0, op.entrypoint)

    elif S3BootScriptOpcode_MDE.EFI_BOOT_SCRIPT_DISPATCH_2_OPCODE == op.opcode:
        encoded_opcode = struct.pack('<BBHIQQ', op.opcode, 0x0, 0x0, 0x0, op.entrypoint, op.context)

    elif S3BootScriptOpcode_MDE.EFI_BOOT_SCRIPT_TERMINATE_OPCODE == op.opcode:
        frmt = '<B'

    else:
        if logger().HAL:
            logger().log_warning(f'Unrecognized opcode {op.opcode:X}')

    return encoded_opcode


def decode_s3bs_opcode_edkcompat(data: bytes):
    opcode = None
    width = None
    count = None
    value = None
    mask = None

    op = None

    hdr_frmt = '<HB'
    header_size = struct.calcsize(hdr_frmt)
    opcode, size = struct.unpack(hdr_frmt, data[: header_size])
    opcode_data = data[header_size:]
    try:
        logger().log_hal(script_opcodes[opcode])
    except Exception:
        pass

    if S3BootScriptOpcode_EdkCompat.EFI_BOOT_SCRIPT_IO_WRITE_OPCODE == opcode or \
            S3BootScriptOpcode_EdkCompat.EFI_BOOT_SCRIPT_PCI_CONFIG_WRITE_OPCODE == opcode or \
            S3BootScriptOpcode_EdkCompat.EFI_BOOT_SCRIPT_MEM_WRITE_OPCODE == opcode:

        frmt = '<IIQ'
        op_size = struct.calcsize(frmt)
        width, count, address = struct.unpack(frmt, opcode_data[: op_size])
        op = op_io_pci_mem(opcode, size, width, address, None, count, opcode_data[op_size:], value, mask)

    elif S3BootScriptOpcode_EdkCompat.EFI_BOOT_SCRIPT_IO_READ_WRITE_OPCODE == opcode or \
            S3BootScriptOpcode_EdkCompat.EFI_BOOT_SCRIPT_PCI_CONFIG_READ_WRITE_OPCODE == opcode or \
            S3BootScriptOpcode_EdkCompat.EFI_BOOT_SCRIPT_MEM_READ_WRITE_OPCODE == opcode:
        frmt = '<IQ'
        sz = struct.calcsize(frmt)
        width, address = struct.unpack(frmt, opcode_data[: sz])
        frmt = 2 * script_width_formats[width]
        op_size = sz + struct.calcsize(frmt)
        value, mask = struct.unpack(frmt, opcode_data[sz: op_size])
        op = op_io_pci_mem(opcode, size, width, address, None, count, None, value, mask)

    elif S3BootScriptOpcode_EdkCompat.EFI_BOOT_SCRIPT_SMBUS_EXECUTE_OPCODE == opcode:
        if logger().UTIL_TRACE or logger().HAL:
            logger().log_warning(f'Cannot parse opcode {opcode:X} yet')

    elif S3BootScriptOpcode_EdkCompat.EFI_BOOT_SCRIPT_STALL_OPCODE == opcode:
        frmt = '<Q'
        op_size = struct.calcsize(frmt)
        duration, = struct.unpack(frmt, opcode_data[: op_size])
        op = op_stall(opcode, size, duration)

    elif S3BootScriptOpcode_EdkCompat.EFI_BOOT_SCRIPT_DISPATCH_OPCODE == opcode:
        frmt = '<Q'
        op_size = struct.calcsize(frmt)
        entrypoint, = struct.unpack(frmt, opcode_data[: op_size])
        op = op_dispatch(opcode, size, entrypoint)

    elif S3BootScriptOpcode_EdkCompat.EFI_BOOT_SCRIPT_MEM_POLL_OPCODE == opcode:
        frmt = '<IQQQ'
        op_size = struct.calcsize(frmt)
        width, address, duration, looptimes = struct.unpack(frmt, opcode_data[: op_size])
        op = op_mem_poll(opcode, size, width, address, duration, looptimes)

    elif S3BootScriptOpcode_EdkCompat.EFI_BOOT_SCRIPT_TERMINATE_OPCODE == opcode:
        op = op_terminate(opcode, size)

    else:
        op = op_unknown(opcode, size)
        if logger().HAL:
            logger().log_warning(f'Unrecognized opcode {opcode:X}')

    return op

#
# @TODO: encode functions are not fully implemented
#


def encode_s3bs_opcode_edkcompat(op: S3BOOTSCRIPT_ENTRY) -> bytes:
    encoded_opcode = b''

    if S3BootScriptOpcode_EdkCompat.EFI_BOOT_SCRIPT_IO_WRITE_OPCODE == op.opcode or \
            S3BootScriptOpcode_EdkCompat.EFI_BOOT_SCRIPT_PCI_CONFIG_WRITE_OPCODE == op.opcode or \
            S3BootScriptOpcode_EdkCompat.EFI_BOOT_SCRIPT_MEM_WRITE_OPCODE == op.opcode:

        encoded_hdr = struct.pack('<IIQ', op.width, op.count, op.address)
        if op.values is None:
            encoded_opcode = encoded_hdr + op.buffer
        else:
            encoded_opcode = encoded_hdr + struct.pack(script_width_formats[op.width] * op.count, *op.values)

    elif S3BootScriptOpcode_EdkCompat.EFI_BOOT_SCRIPT_IO_READ_WRITE_OPCODE == op.opcode or \
            S3BootScriptOpcode_EdkCompat.EFI_BOOT_SCRIPT_PCI_CONFIG_READ_WRITE_OPCODE == op.opcode or \
            S3BootScriptOpcode_EdkCompat.EFI_BOOT_SCRIPT_MEM_READ_WRITE_OPCODE == op.opcode:

        frmt = f'<IQ2{script_width_formats[op.width]}'
        encoded_opcode = struct.pack(frmt, op.width, op.address, op.value, op.mask)

    elif S3BootScriptOpcode_EdkCompat.EFI_BOOT_SCRIPT_SMBUS_EXECUTE_OPCODE == op.opcode:
        pass

    elif S3BootScriptOpcode_EdkCompat.EFI_BOOT_SCRIPT_STALL_OPCODE == op.opcode:
        frmt = '<Q'

    elif S3BootScriptOpcode_EdkCompat.EFI_BOOT_SCRIPT_DISPATCH_OPCODE == op.opcode:
        encoded_opcode = struct.pack('<Q', op.entrypoint)

    elif S3BootScriptOpcode_EdkCompat.EFI_BOOT_SCRIPT_MEM_POLL_OPCODE == op.opcode:
        encoded_opcode = struct.pack('<IQQQ', op.width, op.address, op.duration, op.looptimes)

    elif S3BootScriptOpcode_EdkCompat.EFI_BOOT_SCRIPT_TERMINATE_OPCODE == op.opcode:
        pass

    return encoded_opcode


def parse_s3bootscript_entry(s3bootscript_type: int, script: bytes, off: int, log_script: bool = False):
    entry_index = None
    entry_length = 0
    opcode = None
    entry_data = None

    remaining_len = len(script[off:])

    if S3BootScriptType.EFI_BOOT_SCRIPT_TYPE_EDKCOMPAT == s3bootscript_type:
        fhdr = '<HB'
        hdr_length = struct.calcsize(fhdr)
        if remaining_len < hdr_length:
            if logger().HAL:
                logger().log_warning(f'The script should have at least 0x{hdr_length:X} bytes to parse next entry')
            return (0, None)

        opcode, entry_length = struct.unpack(fhdr, script[off: off + hdr_length])
        if S3BootScriptOpcode_EdkCompat.EFI_BOOT_SCRIPT_TERMINATE_OPCODE == opcode:
            entry_length = hdr_length
        entry_data = script[off: off + entry_length]

        if entry_length > MAX_S3_BOOTSCRIPT_ENTRY_LENGTH:
            logger().log_error(f'[uefi] Unrecognized S3 boot script format (entry length = 0x{entry_length:X})')
            return (0, None)

        s3script_entry = S3BOOTSCRIPT_ENTRY(s3bootscript_type, entry_index, off, entry_length, entry_data)

    else:  # S3BootScriptType.EFI_BOOT_SCRIPT_TYPE_DEFAULT

        fhdr = '<II'
        hdr_length = struct.calcsize(fhdr)
        f = fhdr + 'B'
        if remaining_len < (hdr_length + 1):
            if logger().HAL:
                logger().log_warning(f'The script should have at least 0x{hdr_length + 1:X} bytes to parse next entry')
            return (0, None)

        entry_index, entry_length, opcode = struct.unpack(f, script[off: off + hdr_length + 1])
        if S3BootScriptOpcode_MDE.EFI_BOOT_SCRIPT_TERMINATE_OPCODE == opcode:
            entry_length = hdr_length + 1
            entry_index = -1
        entry_data = script[off + hdr_length: off + entry_length]

        if entry_length > MAX_S3_BOOTSCRIPT_ENTRY_LENGTH:
            logger().log_error(f'[uefi] Unrecognized S3 boot script format (entry length = 0x{entry_length:X})')
            return (0, None)

        s3script_entry = S3BOOTSCRIPT_ENTRY(s3bootscript_type, entry_index, off, entry_length, entry_data)
        s3script_entry.header_length = hdr_length

    s3script_entry.decoded_opcode = decode_s3bs_opcode(s3bootscript_type, s3script_entry.data)

    if log_script:
        logger().log(str(s3script_entry))
    return (opcode, s3script_entry)


def encode_s3bootscript_entry(entry) -> Optional[bytes]:
    if S3BootScriptType.EFI_BOOT_SCRIPT_TYPE_EDKCOMPAT == entry.script_type:
        entry_hdr_buf = struct.pack('<HB', entry.decoded_opcode.opcode, entry.length)
    else:  # S3BootScriptType.EFI_BOOT_SCRIPT_TYPE_DEFAULT
        entry_hdr_buf = struct.pack('<II', entry.index, entry.length)

    entry_val_buf = encode_s3bs_opcode(entry.script_type, entry.decoded_opcode)
    entry_buf = None
    if entry_val_buf is not None:
        entry_buf = entry_hdr_buf + entry_val_buf
    else:
        logger().log_warning(f'Could not encode opcode of boot script entry (type 0x{entry.script_type:X})')

    return entry_buf


def create_s3bootscript_entry_buffer(script_type: int, op, index=None) -> bytes:
    entry_val_buf = encode_s3bs_opcode(script_type, op)
    length = len(entry_val_buf)
    if S3BootScriptType.EFI_BOOT_SCRIPT_TYPE_EDKCOMPAT == script_type:
        length += struct.calcsize('<HB')
        entry_hdr_buf = struct.pack('<HB', op.opcode, length)
    else:  # S3BootScriptType.EFI_BOOT_SCRIPT_TYPE_DEFAULT
        length += struct.calcsize('<II')
        entry_hdr_buf = struct.pack('<II', index, length)

    return (entry_hdr_buf + entry_val_buf)


def id_s3bootscript_type(script: bytes, log_script: bool = False) -> Tuple[int, int]:
    script_header_length = 0

    start_op, = struct.unpack('<B', script[: 1])
    if S3BootScriptOpcode_EdkCompat.EFI_BOOT_SCRIPT_TABLE_OPCODE == start_op:
        logger().log_hal('S3 Boot Script AA Parser')
        script_type = S3BootScriptType.EFI_BOOT_SCRIPT_TYPE_EDKCOMPAT
        if log_script:
            logger().log(f'[uefi] Start opcode 0x{start_op:X}')
        # MdeModulePkg\Library\PiDxeS3BootScriptLib\BootScriptInternalFormat.h
        script_header_length = struct.calcsize("<HBHLHH")
    else:
        logger().log_hal('S3 Boot Script DEFAULT Parser')
        script_type = S3BootScriptType.EFI_BOOT_SCRIPT_TYPE_DEFAULT

    return (script_type, script_header_length)


########################################################################################################
#
# S3 Resume Boot-Script Parsing Functionality
#
########################################################################################################

def parse_script(script: bytes, log_script: bool = False) -> List['S3BOOTSCRIPT_ENTRY']:
    off = 0
    entry_type = 0
    s3_boot_script_entries = []
    len_s = len(script)

    if log_script:
        logger().log('[uefi] +++ S3 Resume Boot-Script +++\n')
    script_type, script_header_length = id_s3bootscript_type(script, log_script)
    off += script_header_length

    while (off < len_s) and (entry_type != S3BootScriptOpcode.EFI_BOOT_SCRIPT_TERMINATE_OPCODE):
        entry_type, s3script_entry = parse_s3bootscript_entry(script_type, script, off, log_script)
        # couldn't parse the next entry - return what has been parsed so far
        if s3script_entry is None:
            return s3_boot_script_entries
        s3_boot_script_entries.append(s3script_entry)
        off += s3script_entry.length

    if log_script:
        logger().log('[uefi] +++ End of S3 Resume Boot-Script +++')

    logger().log_hal(f'[uefi] S3 Resume Boot-Script size: 0x{off:X}')
    logger().log_hal('\n[uefi] [++++++++++ S3 Resume Boot-Script Buffer ++++++++++]')
    if logger().HAL:
        print_buffer_bytes(script[: off])

    return s3_boot_script_entries
