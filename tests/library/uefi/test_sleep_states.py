# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2026, Intel Corporation
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
import unittest

from chipsec.library.uefi.sleep_states import (
    MAX_S3_BOOTSCRIPT_ENTRY_LENGTH,
    S3BOOTSCRIPT_ENTRY,
    S3BootScriptOpcode,
    S3BootScriptOpcode_EdkCompat,
    S3BootScriptOpcode_MDE,
    S3BootScriptType,
    S3BootScriptWidth,
    create_s3bootscript_entry_buffer,
    decode_s3bs_opcode,
    encode_s3bootscript_entry,
    encode_s3bs_opcode,
    id_s3bootscript_type,
    op_dispatch,
    op_io_pci_mem,
    op_mem_poll,
    op_smbus_execute,
    op_stall,
    op_terminate,
    op_unknown,
    parse_s3bootscript_entry,
    parse_script,
    script_width_formats,
    script_width_sizes,
)

OPCODE = S3BootScriptOpcode_MDE
EDK = S3BootScriptOpcode_EdkCompat
DEFAULT_TYPE = S3BootScriptType.EFI_BOOT_SCRIPT_TYPE_DEFAULT
EDKCOMPAT_TYPE = S3BootScriptType.EFI_BOOT_SCRIPT_TYPE_EDKCOMPAT
UINT32 = S3BootScriptWidth.EFI_BOOT_SCRIPT_WIDTH_UINT32


def default_entry(payload: bytes, index: int = 0) -> bytes:
    """Wrap an opcode payload in a default-format boot script entry header."""
    return struct.pack('<II', index, len(payload) + 8) + payload


def io_write(width=UINT32, address=0x80, count=1, values=(0xAABBCCDD,)):
    fmt = script_width_formats[width]
    buffer = struct.pack(f'<{len(values)}{fmt}', *values)
    return struct.pack('<BBHIQ', OPCODE.EFI_BOOT_SCRIPT_IO_WRITE_OPCODE, width, address, 0, count) + buffer


def mem_write(width=UINT32, address=0xFED00000, unknown=0x1234, count=1, values=(0x11223344,)):
    fmt = script_width_formats[width]
    buffer = struct.pack(f'<{len(values)}{fmt}', *values)
    header = struct.pack('<BBHIQQ', OPCODE.EFI_BOOT_SCRIPT_MEM_WRITE_OPCODE, width, unknown, 0, address, count)
    return header + buffer


class TestOpcodeDecodeDefault(unittest.TestCase):
    """The default (MdePkg) boot script encodes each opcode with its own layout."""

    def test_io_write_exposes_address_width_and_payload(self):
        op = decode_s3bs_opcode(DEFAULT_TYPE, io_write(address=0xB2, values=(0xDEADBEEF,)))

        self.assertIsInstance(op, op_io_pci_mem)
        self.assertEqual(op.opcode, OPCODE.EFI_BOOT_SCRIPT_IO_WRITE_OPCODE)
        self.assertEqual(op.address, 0xB2)
        self.assertEqual(op.width, UINT32)
        self.assertEqual(op.values, [0xDEADBEEF])

    def test_io_write_decodes_every_value_in_the_payload(self):
        op = decode_s3bs_opcode(DEFAULT_TYPE, io_write(count=3, values=(1, 2, 3)))

        self.assertEqual(op.values, [1, 2, 3])

    def test_payload_that_disagrees_with_the_count_is_left_undecoded(self):
        op = decode_s3bs_opcode(DEFAULT_TYPE, io_write(count=4, values=(1, 2)))

        self.assertIsNone(op.values)
        self.assertEqual(len(op.buffer), 8)

    def test_io_read_write_exposes_value_and_mask(self):
        data = struct.pack('<BBHIQQ', OPCODE.EFI_BOOT_SCRIPT_IO_READ_WRITE_OPCODE, UINT32, 0xB2, 0, 0xAA, 0xFF)

        op = decode_s3bs_opcode(DEFAULT_TYPE, data)

        self.assertEqual(op.address, 0xB2)
        self.assertEqual((op.value, op.mask), (0xAA, 0xFF))

    def test_mem_write_exposes_a_64_bit_address(self):
        op = decode_s3bs_opcode(DEFAULT_TYPE, mem_write(address=0xFED00000))

        self.assertEqual(op.address, 0xFED00000)
        self.assertEqual(op.values, [0x11223344])

    def test_mem_read_write_exposes_value_and_mask(self):
        data = struct.pack('<BBHIQQQ', OPCODE.EFI_BOOT_SCRIPT_MEM_READ_WRITE_OPCODE,
                           UINT32, 0, 0, 0xFED00000, 0x1, 0xF)

        op = decode_s3bs_opcode(DEFAULT_TYPE, data)

        self.assertEqual(op.address, 0xFED00000)
        self.assertEqual((op.value, op.mask), (0x1, 0xF))

    def test_pci_config_write_exposes_the_config_address(self):
        data = struct.pack('<BBHIQQ', OPCODE.EFI_BOOT_SCRIPT_PCI_CONFIG_WRITE_OPCODE,
                           UINT32, 0, 0, 0x000000F8, 1) + struct.pack('<I', 0x5A5A5A5A)

        op = decode_s3bs_opcode(DEFAULT_TYPE, data)

        self.assertEqual(op.address, 0xF8)
        self.assertEqual(op.values, [0x5A5A5A5A])

    def test_pci_config_read_write_exposes_value_and_mask(self):
        data = struct.pack('<BBHIQQQ', OPCODE.EFI_BOOT_SCRIPT_PCI_CONFIG_READ_WRITE_OPCODE,
                           UINT32, 0, 0, 0xF8, 0x1, 0xF)

        op = decode_s3bs_opcode(DEFAULT_TYPE, data)

        self.assertEqual((op.value, op.mask), (0x1, 0xF))

    def test_smbus_execute_exposes_the_transaction_details(self):
        data = struct.pack('<BBQBB', OPCODE.EFI_BOOT_SCRIPT_SMBUS_EXECUTE_OPCODE, 0x50, 0x10, 0x04, 1)

        op = decode_s3bs_opcode(DEFAULT_TYPE, data)

        self.assertIsInstance(op, op_smbus_execute)
        self.assertEqual(op.address, 0x50)
        self.assertEqual(op.command, 0x10)
        self.assertEqual(op.operation, 0x04)
        self.assertEqual(op.peccheck, 1)

    def test_stall_exposes_its_duration(self):
        data = struct.pack('<BBQ', OPCODE.EFI_BOOT_SCRIPT_STALL_OPCODE, 0, 0x1388)

        op = decode_s3bs_opcode(DEFAULT_TYPE, data)

        self.assertIsInstance(op, op_stall)
        self.assertEqual(op.duration, 0x1388)

    def test_dispatch_exposes_its_entry_point(self):
        data = struct.pack('<BBHIQ', OPCODE.EFI_BOOT_SCRIPT_DISPATCH_OPCODE, 0, 0, 0, 0x7A000000)

        op = decode_s3bs_opcode(DEFAULT_TYPE, data)

        self.assertIsInstance(op, op_dispatch)
        self.assertEqual(op.entrypoint, 0x7A000000)
        self.assertIsNone(op.context)

    def test_terminate_is_a_single_byte_opcode(self):
        op = decode_s3bs_opcode(DEFAULT_TYPE, struct.pack('<B', OPCODE.EFI_BOOT_SCRIPT_TERMINATE_OPCODE))

        self.assertIsInstance(op, op_terminate)
        self.assertEqual(op.size, 1)

    def test_unrecognized_opcodes_are_reported_rather_than_dropped(self):
        op = decode_s3bs_opcode(DEFAULT_TYPE, b'\x7f' + b'\x00' * 16)

        self.assertIsInstance(op, op_unknown)
        self.assertEqual(op.opcode, 0x7F)


class TestOpcodeDecodeEdkCompat(unittest.TestCase):
    """The EdkCompat boot script prefixes each opcode with a 16-bit id and length."""

    @staticmethod
    def _entry(opcode, payload):
        return struct.pack('<HB', opcode, len(payload) + 3) + payload

    def test_io_write_exposes_address_width_and_payload(self):
        payload = struct.pack('<IIQ', UINT32, 1, 0xB2) + struct.pack('<I', 0xDEADBEEF)

        op = decode_s3bs_opcode(EDKCOMPAT_TYPE, self._entry(EDK.EFI_BOOT_SCRIPT_IO_WRITE_OPCODE, payload))

        self.assertEqual(op.address, 0xB2)
        self.assertEqual(op.values, [0xDEADBEEF])

    def test_mem_write_shares_the_write_layout(self):
        payload = struct.pack('<IIQ', UINT32, 2, 0xFED00000) + struct.pack('<2I', 1, 2)

        op = decode_s3bs_opcode(EDKCOMPAT_TYPE, self._entry(EDK.EFI_BOOT_SCRIPT_MEM_WRITE_OPCODE, payload))

        self.assertEqual(op.address, 0xFED00000)
        self.assertEqual(op.values, [1, 2])

    def test_read_write_value_and_mask_are_sized_by_the_width_field(self):
        payload = struct.pack('<IQ', UINT32, 0xFED00000) + struct.pack('=2I', 0xAA, 0xFF)

        op = decode_s3bs_opcode(EDKCOMPAT_TYPE, self._entry(EDK.EFI_BOOT_SCRIPT_MEM_READ_WRITE_OPCODE, payload))

        self.assertEqual((op.value, op.mask), (0xAA, 0xFF))

    def test_stall_exposes_its_duration(self):
        payload = struct.pack('<Q', 0x64)

        op = decode_s3bs_opcode(EDKCOMPAT_TYPE, self._entry(EDK.EFI_BOOT_SCRIPT_STALL_OPCODE, payload))

        self.assertIsInstance(op, op_stall)
        self.assertEqual(op.duration, 0x64)

    def test_dispatch_exposes_its_entry_point(self):
        payload = struct.pack('<Q', 0x7A000000)

        op = decode_s3bs_opcode(EDKCOMPAT_TYPE, self._entry(EDK.EFI_BOOT_SCRIPT_DISPATCH_OPCODE, payload))

        self.assertEqual(op.entrypoint, 0x7A000000)

    def test_mem_poll_exposes_duration_and_loop_count(self):
        payload = struct.pack('<IQQQ', UINT32, 0xFED00000, 0x10, 0x20)

        op = decode_s3bs_opcode(EDKCOMPAT_TYPE, self._entry(EDK.EFI_BOOT_SCRIPT_MEM_POLL_OPCODE, payload))

        self.assertIsInstance(op, op_mem_poll)
        self.assertEqual(op.address, 0xFED00000)
        self.assertEqual((op.duration, op.looptimes), (0x10, 0x20))

    def test_terminate_is_recognized(self):
        op = decode_s3bs_opcode(EDKCOMPAT_TYPE, self._entry(EDK.EFI_BOOT_SCRIPT_TERMINATE_OPCODE, b''))

        self.assertIsInstance(op, op_terminate)

    def test_smbus_execute_is_not_decoded_yet(self):
        op = decode_s3bs_opcode(EDKCOMPAT_TYPE, self._entry(EDK.EFI_BOOT_SCRIPT_SMBUS_EXECUTE_OPCODE, b'\x00' * 8))

        self.assertIsNone(op)

    def test_unrecognized_opcodes_are_reported_rather_than_dropped(self):
        op = decode_s3bs_opcode(EDKCOMPAT_TYPE, self._entry(0x7F, b'\x00' * 8))

        self.assertIsInstance(op, op_unknown)


class TestOpcodeEncoding(unittest.TestCase):
    """Opcodes that support encoding must round-trip through decode."""

    def _round_trip(self, script_type, data):
        decoded = decode_s3bs_opcode(script_type, data)
        return encode_s3bs_opcode(script_type, decoded)

    def test_default_io_write_round_trips(self):
        data = io_write(address=0xB2, count=2, values=(1, 2))

        self.assertEqual(self._round_trip(DEFAULT_TYPE, data), data)

    def test_default_io_read_write_round_trips(self):
        data = struct.pack('<BBHIQQ', OPCODE.EFI_BOOT_SCRIPT_IO_READ_WRITE_OPCODE, UINT32, 0xB2, 0, 0xAA, 0xFF)

        self.assertEqual(self._round_trip(DEFAULT_TYPE, data), data)

    def test_default_mem_write_round_trips(self):
        data = mem_write(count=2, values=(1, 2))

        self.assertEqual(self._round_trip(DEFAULT_TYPE, data), data)

    def test_default_mem_read_write_round_trips(self):
        data = struct.pack('<BBHIQQQ', OPCODE.EFI_BOOT_SCRIPT_MEM_READ_WRITE_OPCODE,
                           UINT32, 0x11, 0, 0xFED00000, 0x1, 0xF)

        self.assertEqual(self._round_trip(DEFAULT_TYPE, data), data)

    def test_default_dispatch_round_trips(self):
        data = struct.pack('<BBHIQ', OPCODE.EFI_BOOT_SCRIPT_DISPATCH_OPCODE, 0, 0, 0, 0x7A000000)

        self.assertEqual(self._round_trip(DEFAULT_TYPE, data), data)

    def test_edkcompat_write_payload_round_trips(self):
        payload = struct.pack('<IIQ', UINT32, 2, 0xFED00000) + struct.pack('<2I', 1, 2)
        entry = struct.pack('<HB', EDK.EFI_BOOT_SCRIPT_MEM_WRITE_OPCODE, len(payload) + 3) + payload

        self.assertEqual(self._round_trip(EDKCOMPAT_TYPE, entry), payload)

    def test_edkcompat_dispatch_payload_round_trips(self):
        payload = struct.pack('<Q', 0x7A000000)
        entry = struct.pack('<HB', EDK.EFI_BOOT_SCRIPT_DISPATCH_OPCODE, len(payload) + 3) + payload

        self.assertEqual(self._round_trip(EDKCOMPAT_TYPE, entry), payload)

    def test_edkcompat_mem_poll_payload_round_trips(self):
        payload = struct.pack('<IQQQ', UINT32, 0xFED00000, 0x10, 0x20)
        entry = struct.pack('<HB', EDK.EFI_BOOT_SCRIPT_MEM_POLL_OPCODE, len(payload) + 3) + payload

        self.assertEqual(self._round_trip(EDKCOMPAT_TYPE, entry), payload)

    def test_unsupported_opcodes_encode_to_nothing(self):
        data = struct.pack('<BBQ', OPCODE.EFI_BOOT_SCRIPT_STALL_OPCODE, 0, 0x1388)

        self.assertEqual(self._round_trip(DEFAULT_TYPE, data), b'')


class TestEntryBufferCreation(unittest.TestCase):
    """Entry buffers pair an opcode payload with the script-type specific header."""

    def test_default_entry_buffer_declares_its_own_length(self):
        op = decode_s3bs_opcode(DEFAULT_TYPE, io_write())

        buf = create_s3bootscript_entry_buffer(DEFAULT_TYPE, op, index=7)

        index, length = struct.unpack('<II', buf[:8])
        self.assertEqual(index, 7)
        self.assertEqual(length, len(buf))

    def test_edkcompat_entry_buffer_declares_its_own_length(self):
        payload = struct.pack('<Q', 0x7A000000)
        entry = struct.pack('<HB', EDK.EFI_BOOT_SCRIPT_DISPATCH_OPCODE, len(payload) + 3) + payload
        op = decode_s3bs_opcode(EDKCOMPAT_TYPE, entry)

        buf = create_s3bootscript_entry_buffer(EDKCOMPAT_TYPE, op)

        opcode, length = struct.unpack('<HB', buf[:3])
        self.assertEqual(opcode, EDK.EFI_BOOT_SCRIPT_DISPATCH_OPCODE)
        self.assertEqual(length, len(buf))

    def test_a_created_entry_can_be_parsed_back(self):
        op = decode_s3bs_opcode(DEFAULT_TYPE, io_write(address=0xB2, values=(0x1234,)))
        buf = create_s3bootscript_entry_buffer(DEFAULT_TYPE, op, index=0)

        _opcode, entry = parse_s3bootscript_entry(DEFAULT_TYPE, buf, 0)

        self.assertEqual(entry.decoded_opcode.address, 0xB2)

    def test_parsed_entries_can_be_re_encoded(self):
        buf = default_entry(io_write(address=0xB2), index=3)
        _opcode, entry = parse_s3bootscript_entry(DEFAULT_TYPE, buf, 0)

        self.assertEqual(encode_s3bootscript_entry(entry), buf)


class TestEntryParsing(unittest.TestCase):
    """Entry parsing must respect declared lengths and reject malformed headers."""

    def test_default_entry_reports_its_index_and_length(self):
        buf = default_entry(io_write(), index=5)

        opcode, entry = parse_s3bootscript_entry(DEFAULT_TYPE, buf, 0)

        self.assertEqual(opcode, OPCODE.EFI_BOOT_SCRIPT_IO_WRITE_OPCODE)
        self.assertEqual(entry.index, 5)
        self.assertEqual(entry.length, len(buf))
        self.assertEqual(entry.header_length, 8)

    def test_default_entry_is_parsed_at_the_requested_offset(self):
        buf = b'\xcc' * 16 + default_entry(io_write(address=0xB2))

        _opcode, entry = parse_s3bootscript_entry(DEFAULT_TYPE, buf, 16)

        self.assertEqual(entry.offset_in_script, 16)
        self.assertEqual(entry.decoded_opcode.address, 0xB2)

    def test_default_terminate_entry_uses_the_minimum_length(self):
        buf = struct.pack('<II', 0, 0) + struct.pack('<B', OPCODE.EFI_BOOT_SCRIPT_TERMINATE_OPCODE)

        opcode, entry = parse_s3bootscript_entry(DEFAULT_TYPE, buf, 0)

        self.assertEqual(opcode, OPCODE.EFI_BOOT_SCRIPT_TERMINATE_OPCODE)
        self.assertEqual(entry.length, 9)
        self.assertEqual(entry.index, -1)

    def test_default_entry_shorter_than_a_header_is_rejected(self):
        self.assertEqual(parse_s3bootscript_entry(DEFAULT_TYPE, b'\x00' * 4, 0), (0, None))

    def test_implausibly_long_entries_are_rejected(self):
        buf = struct.pack('<II', 0, MAX_S3_BOOTSCRIPT_ENTRY_LENGTH + 1) + b'\x00' * 8

        self.assertEqual(parse_s3bootscript_entry(DEFAULT_TYPE, buf, 0), (0, None))

    def test_edkcompat_entry_reports_its_length(self):
        payload = struct.pack('<Q', 0x7A000000)
        buf = struct.pack('<HB', EDK.EFI_BOOT_SCRIPT_DISPATCH_OPCODE, len(payload) + 3) + payload

        opcode, entry = parse_s3bootscript_entry(EDKCOMPAT_TYPE, buf, 0)

        self.assertEqual(opcode, EDK.EFI_BOOT_SCRIPT_DISPATCH_OPCODE)
        self.assertEqual(entry.length, len(buf))

    def test_edkcompat_terminate_entry_uses_the_header_length(self):
        buf = struct.pack('<HB', EDK.EFI_BOOT_SCRIPT_TERMINATE_OPCODE, 0xFF)

        _opcode, entry = parse_s3bootscript_entry(EDKCOMPAT_TYPE, buf, 0)

        self.assertEqual(entry.length, 3)

    def test_edkcompat_entry_shorter_than_a_header_is_rejected(self):
        self.assertEqual(parse_s3bootscript_entry(EDKCOMPAT_TYPE, b'\x00' * 2, 0), (0, None))


class TestScriptTypeIdentification(unittest.TestCase):

    def test_a_table_opcode_marks_an_edkcompat_script(self):
        script_type, header_length = id_s3bootscript_type(b'\xaa' + b'\x00' * 32)

        self.assertEqual(script_type, EDKCOMPAT_TYPE)
        self.assertEqual(header_length, 13)

    def test_anything_else_is_a_default_script(self):
        script_type, header_length = id_s3bootscript_type(b'\x00' * 32)

        self.assertEqual(script_type, DEFAULT_TYPE)
        self.assertEqual(header_length, 0)


class TestScriptParsing(unittest.TestCase):
    """parse_script walks a whole boot script until the terminate opcode."""

    @staticmethod
    def _default_script(*payloads):
        script = b''
        for index, payload in enumerate(payloads):
            script += default_entry(payload, index)
        script += struct.pack('<II', 0, 0) + struct.pack('<B', OPCODE.EFI_BOOT_SCRIPT_TERMINATE_OPCODE)
        return script

    def test_every_entry_up_to_terminate_is_returned(self):
        script = self._default_script(io_write(address=0xB2), mem_write(address=0xFED00000))

        entries = parse_script(script)

        self.assertEqual(len(entries), 3)
        self.assertIsInstance(entries[-1].decoded_opcode, op_terminate)

    def test_entries_are_reported_at_increasing_offsets(self):
        script = self._default_script(io_write(), io_write())

        offsets = [entry.offset_in_script for entry in parse_script(script)]

        self.assertEqual(offsets, sorted(offsets))
        self.assertEqual(offsets[0], 0)

    def test_parsing_stops_at_the_terminate_opcode(self):
        script = self._default_script(io_write()) + default_entry(io_write(), 99)

        entries = parse_script(script)

        self.assertEqual(len(entries), 2)

    def test_content_after_a_malformed_entry_is_discarded(self):
        script = default_entry(io_write()) + b'\x00' * 4

        entries = parse_script(script)

        self.assertEqual(len(entries), 1)

    def test_edkcompat_scripts_skip_their_table_header(self):
        payload = struct.pack('<Q', 0x7A000000)
        header = b'\xaa' + b'\x00' * 12
        dispatch = struct.pack('<HB', EDK.EFI_BOOT_SCRIPT_DISPATCH_OPCODE, len(payload) + 3) + payload
        terminate = struct.pack('<HB', EDK.EFI_BOOT_SCRIPT_TERMINATE_OPCODE, 3)

        entries = parse_script(header + dispatch + terminate)

        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0].offset_in_script, 13)


class TestOpcodeRendering(unittest.TestCase):
    """Every decoded opcode must render without raising."""

    def test_write_opcode_lists_its_values(self):
        op = decode_s3bs_opcode(DEFAULT_TYPE, io_write(count=2, values=(1, 2)))

        rendered = str(op)

        self.assertIn('S3_BOOTSCRIPT_IO_WRITE', rendered)
        self.assertIn('Values', rendered)

    def test_write_opcode_lists_its_address_and_width(self):
        op = decode_s3bs_opcode(DEFAULT_TYPE, mem_write(address=0xFED00000))

        rendered = str(op)

        self.assertIn('0xFED00000', rendered)
        self.assertIn('Width', rendered)

    def test_read_write_opcode_shows_value_and_mask(self):
        data = struct.pack('<BBHIQQ', OPCODE.EFI_BOOT_SCRIPT_IO_READ_WRITE_OPCODE, UINT32, 0xB2, 0, 0xAA, 0xFF)

        rendered = str(decode_s3bs_opcode(DEFAULT_TYPE, data))

        self.assertIn('Value', rendered)
        self.assertIn('Mask', rendered)

    def test_other_opcodes_render(self):
        rendered = [
            str(op_smbus_execute(OPCODE.EFI_BOOT_SCRIPT_SMBUS_EXECUTE_OPCODE, 12, 0x50, 0x10, 4, 1)),
            str(op_stall(OPCODE.EFI_BOOT_SCRIPT_STALL_OPCODE, 10, 0x64)),
            str(op_dispatch(OPCODE.EFI_BOOT_SCRIPT_DISPATCH_OPCODE, 16, 0x7A000000, context=0x1000)),
            str(op_mem_poll(EDK.EFI_BOOT_SCRIPT_MEM_POLL_OPCODE, 31, UINT32, 0xFED00000, 1, 2)),
            str(op_terminate(OPCODE.EFI_BOOT_SCRIPT_TERMINATE_OPCODE, 1)),
            str(op_unknown(0x7F, 1)),
        ]

        self.assertTrue(all(rendered))

    def test_entry_rendering_includes_the_decoded_opcode(self):
        buf = default_entry(io_write(address=0xB2))
        _opcode, entry = parse_s3bootscript_entry(DEFAULT_TYPE, buf, 0)

        rendered = str(entry)

        self.assertIn('Entry at offset', rendered)
        self.assertIn('Decoded', rendered)

    def test_entry_without_data_renders_a_header_only(self):
        entry = S3BOOTSCRIPT_ENTRY(DEFAULT_TYPE, None, 0x10, 0x20)

        self.assertIn('Entry at offset 0x0010', str(entry))


class TestWidthTables(unittest.TestCase):
    """Width encodings, byte sizes and struct formats must stay consistent."""

    def test_every_width_has_a_size_and_a_format(self):
        for width in script_width_sizes:
            self.assertIn(width, script_width_formats)
            self.assertEqual(struct.calcsize(f'<{script_width_formats[width]}'), script_width_sizes[width])

    def test_opcode_ids_are_shared_between_the_two_script_dialects(self):
        for name in ('EFI_BOOT_SCRIPT_IO_WRITE_OPCODE', 'EFI_BOOT_SCRIPT_TERMINATE_OPCODE'):
            self.assertEqual(getattr(OPCODE, name), getattr(S3BootScriptOpcode, name))
            self.assertEqual(getattr(EDK, name), getattr(S3BootScriptOpcode, name))


if __name__ == '__main__':
    unittest.main()
