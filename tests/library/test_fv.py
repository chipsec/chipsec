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

"""Unit tests for chipsec.library.uefi.fv — firmware volume parsing and assembly."""

import struct
import unittest
from uuid import UUID

from chipsec.library.uefi.fv import (
    EFI_FIRMWARE_VOLUME_HEADER, EFI_FIRMWARE_VOLUME_HEADER_size,
    EFI_FV_BLOCK_MAP_ENTRY,
    EFI_FFS_FILE_HEADER,
    EFI_COMMON_SECTION_HEADER,
    EFI_FIRMWARE_FILE_SYSTEM2_GUID,
    EFI_FIRMWARE_FILE_SYSTEM3_GUID,
    EFI_FVB2_ERASE_POLARITY,
    EFI_FV_FILETYPE_FREEFORM, EFI_FV_FILETYPE_RAW,
    EFI_SECTION_RAW, EFI_SECTION_PE32, EFI_SECTION_COMPRESSION,
    EFI_SECTION_USER_INTERFACE,
    FFS_ATTRIB_CHECKSUM, FFS_FIXED_CHECKSUM,
    FvSum8, FvChecksum8, FvSum16, FvChecksum16,
    ValidateFwVolumeHeader,
    NextFwVolume, GetFvHeader, NextFwFile, NextFwFileSection,
    assemble_uefi_file, assemble_uefi_section, assemble_uefi_raw,
    align_image, get_guid_bin,
    decode_depex,
    EFI_FV, EFI_FILE, EFI_SECTION, EFI_MODULE,
    SECTION_NAMES, FILE_TYPE_NAMES,
    EFI_FIRMWARE_VOLUME_EXT_HEADER, EFI_FIRMWARE_VOLUME_EXT_HEADER_size,
    EFI_FIRMWARE_VOLUME_EXT_ENTRY,
)
from chipsec.library.uefi.common import align


# ---------------------------------------------------------------------------
# Helper: build a minimal valid firmware volume binary
# ---------------------------------------------------------------------------

TEST_FV_GUID = EFI_FIRMWARE_FILE_SYSTEM2_GUID

def _make_fv(fv_length: int, guid: UUID = TEST_FV_GUID,
             attributes: int = EFI_FVB2_ERASE_POLARITY,
             ext_header_offset: int = 0,
             body: bytes = b'',
             revision: int = 2) -> bytes:
    """Build a minimal firmware volume with a single block-map entry and correct checksum."""
    block_map_entry_fmt = EFI_FV_BLOCK_MAP_ENTRY  # "<II"
    block_map_terminator = struct.pack(block_map_entry_fmt, 0, 0)
    # block-map: 1 block of fv_length bytes
    block_map = struct.pack(block_map_entry_fmt, 1, fv_length) + block_map_terminator
    header_length = EFI_FIRMWARE_VOLUME_HEADER_size + len(block_map)

    # Pack header with checksum=0 first, then compute
    zero_vector = b'\x00' * 16
    guid_bytes = guid.bytes_le
    signature = 0x4856465F  # "_FVH"
    hdr = struct.pack(EFI_FIRMWARE_VOLUME_HEADER,
                      zero_vector, guid_bytes,
                      fv_length, signature, attributes,
                      header_length, 0,  # checksum placeholder
                      ext_header_offset, 0, revision)
    hdr += block_map
    checksum = FvChecksum16(hdr)
    # Re-pack with real checksum
    hdr = struct.pack(EFI_FIRMWARE_VOLUME_HEADER,
                      zero_vector, guid_bytes,
                      fv_length, signature, attributes,
                      header_length, checksum,
                      ext_header_offset, 0, revision)
    hdr += block_map

    # Pad body to fv_length
    padding_len = fv_length - len(hdr) - len(body)
    if padding_len < 0:
        raise ValueError("body too large for fv_length")
    return hdr + body + (b'\xff' * padding_len)


def _make_ffs_file(guid: UUID, file_type: int, body: bytes,
                   attributes: int = FFS_ATTRIB_CHECKSUM,
                   state: int = 0xF8) -> bytes:
    """Build a minimal FFS file with proper checksums."""
    hdr_size = struct.calcsize(EFI_FFS_FILE_HEADER)
    total_size = hdr_size + len(body)
    size_bytes = struct.pack('<I', total_size)[:3]

    # Pack with zero checksum for computation
    guid_bytes = guid.bytes_le
    hdr_for_sum = struct.pack(EFI_FFS_FILE_HEADER,
                              guid_bytes, 0, file_type, attributes, size_bytes, 0)
    hsum = FvChecksum8(hdr_for_sum)
    if attributes & FFS_ATTRIB_CHECKSUM:
        fsum = FvChecksum8(body)
    else:
        fsum = FFS_FIXED_CHECKSUM
    checksum = hsum | (fsum << 8)

    size_state = int.from_bytes(size_bytes, 'little') | (state << 24)
    size_state_bytes = struct.pack('<I', size_state)[:3]

    file_data = struct.pack(EFI_FFS_FILE_HEADER,
                            guid_bytes, checksum, file_type, attributes,
                            size_state_bytes, state)
    return file_data + body


def _make_section(section_type: int, body: bytes) -> bytes:
    """Build a minimal common section header + body."""
    total_size = struct.calcsize(EFI_COMMON_SECTION_HEADER) + len(body)
    size_bytes = struct.pack('<I', total_size)[:3]
    hdr = struct.pack(EFI_COMMON_SECTION_HEADER, size_bytes, section_type)
    return hdr + body


# ===========================================================================
# Tests for checksum functions
# ===========================================================================

class TestChecksums(unittest.TestCase):
    """Tests for FvSum8, FvChecksum8, FvSum16, FvChecksum16."""

    def test_fvsum8_zeros(self):
        self.assertEqual(FvSum8(b'\x00' * 16), 0)

    def test_fvsum8_simple(self):
        # 0x01 + 0x02 + 0x03 = 0x06
        self.assertEqual(FvSum8(b'\x01\x02\x03'), 0x06)

    def test_fvsum8_overflow(self):
        # 0xFF + 0x01 = 0x100 & 0xFF = 0x00
        self.assertEqual(FvSum8(b'\xff\x01'), 0x00)

    def test_fvchecksum8_roundtrip(self):
        data = b'\x10\x20\x30\x40'
        cs = FvChecksum8(data)
        # Sum of data + checksum byte == 0 mod 256
        self.assertEqual((FvSum8(data) + cs) & 0xFF, 0)

    def test_fvsum16_zeros(self):
        self.assertEqual(FvSum16(b'\x00' * 16), 0)

    def test_fvsum16_simple(self):
        # 0x0201 + 0x0403 = 0x0604
        self.assertEqual(FvSum16(b'\x01\x02\x03\x04'), 0x0604)

    def test_fvsum16_overflow(self):
        self.assertEqual(FvSum16(b'\xff\xff\x01\x00'), 0)

    def test_fvchecksum16_roundtrip(self):
        data = b'\x11\x22\x33\x44\x55\x66'
        cs = FvChecksum16(data)
        self.assertEqual((FvSum16(data) + cs) & 0xFFFF, 0)

    def test_fvsum16_odd_length(self):
        # Odd-length buffer: last byte ignored
        result = FvSum16(b'\x01\x02\x03')
        self.assertEqual(result, 0x0201)


# ===========================================================================
# Tests for ValidateFwVolumeHeader
# ===========================================================================

class TestValidateFwVolumeHeader(unittest.TestCase):

    def test_valid_header(self):
        self.assertTrue(ValidateFwVolumeHeader(
            FsGuid=TEST_FV_GUID, FvLength=0x10000, HeaderLength=0x48,
            ExtHeaderOffset=0, Reserved=0, size=0x10000,
            Calcsum=0x1234, Checksum=0x1234
        ))

    def test_nonzero_reserved(self):
        # Should return False when reserved is nonzero
        self.assertFalse(ValidateFwVolumeHeader(
            FsGuid=TEST_FV_GUID, FvLength=0x10000, HeaderLength=0x48,
            ExtHeaderOffset=0, Reserved=1, size=0x10000,
            Calcsum=0x1234, Checksum=0x1234
        ))

    def test_fv_length_exceeds_size(self):
        self.assertFalse(ValidateFwVolumeHeader(
            FsGuid=TEST_FV_GUID, FvLength=0x20000, HeaderLength=0x48,
            ExtHeaderOffset=0, Reserved=0, size=0x10000,
            Calcsum=0x1234, Checksum=0x1234
        ))

    def test_header_length_exceeds_fv_length(self):
        self.assertFalse(ValidateFwVolumeHeader(
            FsGuid=TEST_FV_GUID, FvLength=0x100, HeaderLength=0x100,
            ExtHeaderOffset=0, Reserved=0, size=0x200,
            Calcsum=0x1234, Checksum=0x1234
        ))

    def test_checksum_mismatch_still_validates_structure(self):
        # Checksum mismatch doesn't fail validation by itself (only logged)
        self.assertTrue(ValidateFwVolumeHeader(
            FsGuid=TEST_FV_GUID, FvLength=0x10000, HeaderLength=0x48,
            ExtHeaderOffset=0, Reserved=0, size=0x10000,
            Calcsum=0x1111, Checksum=0x2222
        ))


# ===========================================================================
# Tests for NextFwVolume
# ===========================================================================

class TestNextFwVolume(unittest.TestCase):

    def test_find_single_fv(self):
        fv_length = 0x1000
        fv_data = _make_fv(fv_length)
        result = NextFwVolume(fv_data)
        self.assertIsNotNone(result)
        self.assertIsInstance(result, EFI_FV)
        self.assertEqual(result.Offset, 0)
        self.assertEqual(result.Size, fv_length)
        self.assertEqual(result.Guid, TEST_FV_GUID)

    def test_fv_at_offset(self):
        """FV preceded by padding should be found at the correct offset."""
        padding = b'\x00' * 0x100
        fv_length = 0x1000
        fv_data = _make_fv(fv_length)
        full = padding + fv_data
        result = NextFwVolume(full)
        self.assertIsNotNone(result)
        self.assertEqual(result.Offset, 0x100)

    def test_two_fvs(self):
        """Iterate through two consecutive FVs."""
        fv1_len = 0x1000
        fv2_len = 0x2000
        fv1 = _make_fv(fv1_len)
        fv2 = _make_fv(fv2_len, guid=EFI_FIRMWARE_FILE_SYSTEM3_GUID)
        full = fv1 + fv2
        first = NextFwVolume(full)
        self.assertIsNotNone(first)
        self.assertEqual(first.Size, fv1_len)
        second = NextFwVolume(full, first.Offset, first.Size)
        self.assertIsNotNone(second)
        self.assertEqual(second.Size, fv2_len)
        self.assertEqual(second.Guid, EFI_FIRMWARE_FILE_SYSTEM3_GUID)

    def test_empty_buffer(self):
        self.assertIsNone(NextFwVolume(b''))

    def test_truncated_buffer(self):
        fv_data = _make_fv(0x1000)
        # Truncate to less than EFI_FIRMWARE_VOLUME_HEADER_size
        self.assertIsNone(NextFwVolume(fv_data[:0x20]))

    def test_no_fv_signature(self):
        self.assertIsNone(NextFwVolume(b'\xff' * 0x1000))

    def test_fv_with_erase_polarity(self):
        fv_data = _make_fv(0x1000, attributes=EFI_FVB2_ERASE_POLARITY)
        result = NextFwVolume(fv_data)
        self.assertIsNotNone(result)
        self.assertTrue(result.Attributes & EFI_FVB2_ERASE_POLARITY)

    def test_fv_checksum_matches(self):
        fv_data = _make_fv(0x1000)
        result = NextFwVolume(fv_data)
        self.assertIsNotNone(result)
        self.assertEqual(result.Checksum, result.CalcSum)

    def test_fv_with_ext_header(self):
        """FV with extended header containing FV Name GUID."""
        fv_length = 0x2000
        fv_name_guid = UUID('AABBCCDD-1122-3344-5566-778899AABBCC')
        # Build the ext header body (placed right after the main header)
        ext_hdr = struct.pack(EFI_FIRMWARE_VOLUME_EXT_HEADER,
                              fv_name_guid.bytes_le, EFI_FIRMWARE_VOLUME_EXT_HEADER_size)
        # The ext header offset is from the start of the FV image
        # It must be placed at the header_length offset
        # First compute header_length without ext header to know where it goes
        block_map = struct.pack(EFI_FV_BLOCK_MAP_ENTRY, 1, fv_length) + struct.pack(EFI_FV_BLOCK_MAP_ENTRY, 0, 0)
        header_length = EFI_FIRMWARE_VOLUME_HEADER_size + len(block_map)
        ext_header_offset = header_length

        # Build the full FV with ext header
        zero_vector = b'\x00' * 16
        guid_bytes = TEST_FV_GUID.bytes_le
        signature = 0x4856465F
        attributes = EFI_FVB2_ERASE_POLARITY

        hdr = struct.pack(EFI_FIRMWARE_VOLUME_HEADER,
                          zero_vector, guid_bytes,
                          fv_length, signature, attributes,
                          header_length, 0, ext_header_offset, 0, 2)
        hdr += block_map
        checksum = FvChecksum16(hdr)
        hdr = struct.pack(EFI_FIRMWARE_VOLUME_HEADER,
                          zero_vector, guid_bytes,
                          fv_length, signature, attributes,
                          header_length, checksum, ext_header_offset, 0, 2)
        hdr += block_map
        full = hdr + ext_hdr + b'\xff' * (fv_length - len(hdr) - len(ext_hdr))

        result = NextFwVolume(full)
        self.assertIsNotNone(result)
        self.assertEqual(result.FvNameGuid, fv_name_guid)


# ===========================================================================
# Tests for GetFvHeader
# ===========================================================================

class TestGetFvHeader(unittest.TestCase):

    def test_basic_header(self):
        fv_data = _make_fv(0x1000)
        size, hdr_size, attrs = GetFvHeader(fv_data)
        self.assertEqual(size, 0x1000)
        self.assertGreater(hdr_size, 0)
        self.assertTrue(attrs & EFI_FVB2_ERASE_POLARITY)

    def test_empty_buffer(self):
        size, hdr_size, attrs = GetFvHeader(b'')
        self.assertEqual((size, hdr_size, attrs), (0, 0, 0))

    def test_truncated_buffer(self):
        size, hdr_size, attrs = GetFvHeader(b'\x00' * 10)
        self.assertEqual((size, hdr_size, attrs), (0, 0, 0))


# ===========================================================================
# Tests for NextFwFile
# ===========================================================================

class TestNextFwFile(unittest.TestCase):

    def _make_fv_with_file(self, file_body: bytes, file_type: int = EFI_FV_FILETYPE_FREEFORM,
                           file_guid: UUID = UUID('12345678-1234-1234-1234-123456789ABC'),
                           polarity: bool = True) -> tuple:
        """Build an FV containing one FFS file; return (fv_image, fv_size, header_size, polarity)."""
        ffs = _make_ffs_file(file_guid, file_type, file_body)
        # Align FFS to 8 bytes
        if len(ffs) % 8:
            ffs += b'\xff' * (8 - len(ffs) % 8)
        fv_length = 0x2000
        fv = _make_fv(fv_length, body=ffs, attributes=EFI_FVB2_ERASE_POLARITY if polarity else 0)
        size, hdr_size, attrs = GetFvHeader(fv)
        return fv, size, hdr_size, polarity

    def test_find_single_file(self):
        file_guid = UUID('AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE')
        body = b'\xDE\xAD\xBE\xEF' * 4
        fv, fv_size, hdr_size, pol = self._make_fv_with_file(body, file_guid=file_guid)
        result = NextFwFile(fv, fv_size, hdr_size, pol)
        self.assertIsNotNone(result)
        self.assertIsInstance(result, EFI_FILE)
        self.assertEqual(result.Guid, file_guid)
        self.assertEqual(result.Type, EFI_FV_FILETYPE_FREEFORM)

    def test_file_body_content(self):
        body = b'\x01\x02\x03\x04'
        fv, fv_size, hdr_size, pol = self._make_fv_with_file(body)
        result = NextFwFile(fv, fv_size, hdr_size, pol)
        self.assertIsNotNone(result)
        hdr_len = result.HeaderSize
        extracted_body = result.Image[hdr_len:]
        self.assertEqual(extracted_body, body)

    def test_no_file_in_empty_fv(self):
        fv = _make_fv(0x1000)
        size, hdr_size, attrs = GetFvHeader(fv)
        pol = bool(attrs & EFI_FVB2_ERASE_POLARITY)
        result = NextFwFile(fv, size, hdr_size, pol)
        self.assertIsNone(result)

    def test_file_checksum_valid(self):
        body = b'\xAA\xBB\xCC\xDD' * 8
        fv, fv_size, hdr_size, pol = self._make_fv_with_file(body)
        result = NextFwFile(fv, fv_size, hdr_size, pol)
        self.assertIsNotNone(result)
        # Checksum should match for properly constructed file
        self.assertEqual(result.Checksum, result.CalcSum)


# ===========================================================================
# Tests for NextFwFileSection
# ===========================================================================

class TestNextFwFileSection(unittest.TestCase):

    def test_single_raw_section(self):
        body = b'\x11\x22\x33\x44'
        sec_data = _make_section(EFI_SECTION_RAW, body)
        result = NextFwFileSection(sec_data, len(sec_data), 0, True)
        self.assertIsNotNone(result)
        self.assertIsInstance(result, EFI_SECTION)
        self.assertEqual(result.Type, EFI_SECTION_RAW)
        self.assertEqual(result.Name, 'S_RAW')

    def test_section_body_content(self):
        body = b'\xAA\xBB\xCC\xDD'
        sec_data = _make_section(EFI_SECTION_RAW, body)
        result = NextFwFileSection(sec_data, len(sec_data), 0, True)
        self.assertIsNotNone(result)
        extracted = result.Image[result.HeaderSize:]
        self.assertEqual(extracted, body)

    def test_two_sections(self):
        sec1 = _make_section(EFI_SECTION_RAW, b'\x01\x02')
        # Align to 4 bytes between sections
        pad = (4 - len(sec1) % 4) % 4
        sec1_padded = sec1 + b'\x00' * pad
        sec2 = _make_section(EFI_SECTION_PE32, b'\x03\x04')
        combined = sec1_padded + sec2
        first = NextFwFileSection(combined, len(combined), 0, True)
        self.assertIsNotNone(first)
        self.assertEqual(first.Type, EFI_SECTION_RAW)
        second = NextFwFileSection(combined, len(combined), first.Size + first.Offset, True)
        self.assertIsNotNone(second)
        self.assertEqual(second.Type, EFI_SECTION_PE32)

    def test_empty_sections_data(self):
        result = NextFwFileSection(b'', 0, 0, True)
        self.assertIsNone(result)

    def test_unknown_section_type(self):
        body = b'\xAB\xCD'
        sec_data = _make_section(0xFE, body)  # non-standard type
        result = NextFwFileSection(sec_data, len(sec_data), 0, True)
        self.assertIsNotNone(result)
        self.assertIn('S_UNKNOWN', result.Name)

    def test_ui_section(self):
        # UI section: UCS-2 string with null terminator
        ui_string = 'TestDriver'
        body = ui_string.encode('utf-16-le') + b'\x00\x00'
        sec_data = _make_section(EFI_SECTION_USER_INTERFACE, body)
        result = NextFwFileSection(sec_data, len(sec_data), 0, True)
        self.assertIsNotNone(result)
        self.assertEqual(result.Type, EFI_SECTION_USER_INTERFACE)
        self.assertEqual(result.Name, 'S_USER_INTERFACE')


# ===========================================================================
# Tests for assembly functions
# ===========================================================================

class TestAssemblyFunctions(unittest.TestCase):

    def test_assemble_uefi_raw_roundtrip(self):
        """Raw section assembled then parsed should yield same content."""
        content = b'\x01\x02\x03\x04\x05\x06\x07\x08'
        raw_section = assemble_uefi_raw(content)
        result = NextFwFileSection(raw_section, len(raw_section), 0, True)
        self.assertIsNotNone(result)
        self.assertEqual(result.Type, EFI_SECTION_RAW)
        extracted = result.Image[result.HeaderSize:]
        self.assertEqual(extracted, content)

    def test_assemble_uefi_raw_alignment(self):
        """Assembled raw section should be 8-byte aligned."""
        content = b'\x01\x02\x03'  # 3 bytes
        raw_section = assemble_uefi_raw(content)
        self.assertEqual(len(raw_section) % 8, 0)

    def test_assemble_uefi_file_roundtrip(self):
        """FFS file assembled then parsed should yield same GUID and content."""
        guid = UUID('DEADBEEF-1234-5678-9ABC-DEF012345678')
        content = b'\xAA\xBB\xCC\xDD' * 4
        raw_section = assemble_uefi_raw(content)
        ffs = assemble_uefi_file(guid, raw_section)
        # Build an FV containing this file
        if len(ffs) % 8:
            ffs += b'\xff' * (8 - len(ffs) % 8)
        fv = _make_fv(0x2000, body=ffs)
        size, hdr_size, attrs = GetFvHeader(fv)
        pol = bool(attrs & EFI_FVB2_ERASE_POLARITY)
        file_result = NextFwFile(fv, size, hdr_size, pol)
        self.assertIsNotNone(file_result)
        self.assertEqual(file_result.Guid, guid)

    def test_assemble_uefi_section_compression(self):
        """Compression section should have correct type and uncompressed size."""
        content = b'\x00' * 100
        compressed = assemble_uefi_section(content, 200, 1)
        # The section header encodes: [3-byte size + type] [4-byte uncomp_size] [1-byte comp_type]
        # Total = 4 + 4 + 1 + len(content) = 109
        expected_size = 4 + 4 + 1 + len(content)
        # Extract type from byte 3
        self.assertEqual(compressed[3], EFI_SECTION_COMPRESSION)
        # Extract uncompressed size
        uncomp_size = struct.unpack('<I', compressed[4:8])[0]
        self.assertEqual(uncomp_size, 200)
        # Extract compression type
        self.assertEqual(compressed[8], 0x01)  # EFI_STANDARD_COMPRESSION

    def test_assemble_uefi_section_not_compressed(self):
        content = b'\x00' * 50
        section = assemble_uefi_section(content, 50, 0)
        self.assertEqual(section[8], 0x00)  # EFI_NOT_COMPRESSED

    def test_align_image(self):
        img = b'\x01\x02\x03'
        aligned = align_image(img, 8, b'\xff')
        self.assertEqual(len(aligned) % 8, 0)
        self.assertEqual(aligned[:3], img)
        self.assertTrue(all(b == 0xff for b in aligned[3:]))

    def test_align_image_already_aligned(self):
        img = b'\x01' * 8
        aligned = align_image(img, 8)
        self.assertEqual(len(aligned), 8)

    def test_get_guid_bin(self):
        guid = UUID('12345678-1234-1234-1234-123456789ABC')
        result = get_guid_bin(guid)
        self.assertEqual(len(result), 16)
        # Round-trip: bytes_le -> UUID should match
        self.assertEqual(UUID(bytes_le=result), guid)


# ===========================================================================
# Tests for decode_depex
# ===========================================================================

class TestDecodeDepex(unittest.TestCase):

    def test_true_end(self):
        # DEPEX: TRUE END
        data = bytes([0x04, 0x06])
        result = decode_depex(data)
        self.assertEqual(result, 'TRUE END')

    def test_false_end(self):
        data = bytes([0x05, 0x06])
        result = decode_depex(data)
        self.assertEqual(result, 'FALSE END')

    def test_push_and_end(self):
        guid = UUID('AABBCCDD-1122-3344-5566-778899001122')
        data = bytes([0x00]) + guid.bytes_le + bytes([0x06])
        result = decode_depex(data)
        self.assertIn('PUSH', result)
        self.assertIn(str(guid), result.lower())
        self.assertIn('END', result)

    def test_push_push_and_end(self):
        g1 = UUID('11111111-1111-1111-1111-111111111111')
        g2 = UUID('22222222-2222-2222-2222-222222222222')
        data = bytes([0x00]) + g1.bytes_le + bytes([0x00]) + g2.bytes_le + bytes([0x01, 0x06])
        result = decode_depex(data)
        self.assertIn('AND', result)

    def test_truncated_push(self):
        # PUSH with only 4 bytes of GUID (needs 16)
        data = bytes([0x00, 0x01, 0x02, 0x03, 0x04])
        result = decode_depex(data)
        self.assertIn('TRUNCATED', result)

    def test_empty(self):
        result = decode_depex(b'')
        self.assertEqual(result, '')

    def test_unknown_opcode(self):
        data = bytes([0xFF])
        result = decode_depex(data)
        self.assertIn('UNKNOWN', result)

    def test_sor_opcode(self):
        data = bytes([0x07, 0x04, 0x06])  # SOR TRUE END
        result = decode_depex(data)
        self.assertEqual(result, 'SOR TRUE END')

    def test_before_opcode(self):
        guid = UUID('CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCCCCCC')
        data = bytes([0x08]) + guid.bytes_le + bytes([0x06])
        result = decode_depex(data)
        self.assertIn('BEFORE', result)
        self.assertIn('END', result)


# ===========================================================================
# Tests for EFI module classes
# ===========================================================================

class TestEFIModuleClasses(unittest.TestCase):

    def test_efi_module_calc_hashes(self):
        img = b'\xDE\xAD\xBE\xEF'
        m = EFI_MODULE(0, None, 0, 0, img)
        m.calc_hashes()
        self.assertIsNotNone(m.MD5)
        self.assertIsNotNone(m.SHA1)
        self.assertIsNotNone(m.SHA256)

    def test_efi_module_calc_hashes_with_offset(self):
        img = b'\x00\x00\xDE\xAD\xBE\xEF'
        m = EFI_MODULE(0, None, 2, 0, img)
        m.calc_hashes(off=2)
        self.assertIsNotNone(m.SHA256)

    def test_efi_module_calc_hashes_none_image(self):
        m = EFI_MODULE(0, None, 0, 0, None)
        m.calc_hashes()
        self.assertIsNone(m.MD5)

    def test_efi_fv_str(self):
        guid = UUID('12345678-1234-1234-1234-123456789ABC')
        fv = EFI_FV(0, guid, 0x1000, 0, 0x48, 0x1234, 0, b'\x00' * 0x1000, 0x1234)
        s = str(fv)
        self.assertIn('12345678', s.lower())
        self.assertNotIn('checksum mismatch', s)

    def test_efi_fv_checksum_mismatch_str(self):
        guid = UUID('12345678-1234-1234-1234-123456789ABC')
        fv = EFI_FV(0, guid, 0x1000, 0, 0x48, 0x1234, 0, b'\x00' * 0x1000, 0x5678)
        s = str(fv)
        self.assertIn('checksum mismatch', s)

    def test_efi_file_str(self):
        guid = UUID('AABBCCDD-1122-3344-5566-778899AABBCC')
        f = EFI_FILE(0x100, guid, EFI_FV_FILETYPE_FREEFORM, 0, 0xF8, 0xAA00, 0x100, b'\x00' * 0x100, 24, False, 0xAA00)
        s = str(f)
        self.assertIn('aabbccdd', s.lower())
        self.assertNotIn('checksum mismatch', s)

    def test_efi_section_str(self):
        sec = EFI_SECTION(0x200, 'S_RAW', EFI_SECTION_RAW, b'\x00' * 16, 4, 16)
        sec.parentGuid = UUID('11111111-1111-1111-1111-111111111111')
        s = str(sec)
        self.assertIn('S_RAW', s)
        self.assertIn('11111111', s.lower())

    def test_file_type_names_coverage(self):
        # Ensure file type names include standard types
        self.assertIn(0x07, FILE_TYPE_NAMES)  # FV_DRIVER
        self.assertEqual(FILE_TYPE_NAMES[0x07], 'FV_DRIVER')

    def test_section_names_coverage(self):
        self.assertIn(EFI_SECTION_RAW, SECTION_NAMES)
        self.assertEqual(SECTION_NAMES[EFI_SECTION_RAW], 'S_RAW')

    def test_oem_file_type_names(self):
        for i in range(0xC0, 0xE0):
            self.assertIn(i, FILE_TYPE_NAMES)
            self.assertTrue(FILE_TYPE_NAMES[i].startswith('FV_OEM_'))


# ===========================================================================
# Regression tests for recursive parsing fixes
# ===========================================================================

class TestNextFwFileCorruptHeaderBreaks(unittest.TestCase):
    """Verify that NextFwFile stops scanning on a corrupt FFS header.

    Regression test for the break-vs-continue fix: when an FFS header has an
    invalid size (0 or exceeding remaining volume), the function must break
    immediately rather than continuing to scan.  The old (buggy) behaviour
    would skip past corrupt headers and find false-positive files in garbage
    data, which prevented the caller from treating the entire tail as
    Non-UEFI_Data and recursively scanning it for embedded firmware volumes.
    """

    def _fv_with_two_files_and_corrupt_gap(self):
        """Build FV: [valid_file_1] [corrupt_header] [valid_file_2].

        After finding file_1, the next call to NextFwFile should hit the
        corrupt header and return None — it must NOT skip over the corrupt
        header and return file_2.
        """
        g1 = UUID('11111111-1111-1111-1111-111111111111')
        g2 = UUID('22222222-2222-2222-2222-222222222222')

        sec1 = assemble_uefi_raw(b'\xAA' * 16)
        ffs1 = assemble_uefi_file(g1, sec1)
        if len(ffs1) % 8:
            ffs1 += b'\xff' * (8 - len(ffs1) % 8)

        sec2 = assemble_uefi_raw(b'\xBB' * 16)
        ffs2 = assemble_uefi_file(g2, sec2)
        if len(ffs2) % 8:
            ffs2 += b'\xff' * (8 - len(ffs2) % 8)

        # Corrupt header: 24 bytes of non-blank, non-valid FFS data.
        # Use bytes that won't look blank (not all-0xFF) and will produce
        # an invalid fsize (0 from the 3-byte Size field = 0x000000).
        hdr_size = struct.calcsize(EFI_FFS_FILE_HEADER)
        corrupt = b'\x42' * hdr_size
        # Align to 8 bytes
        if len(corrupt) % 8:
            corrupt += b'\x42' * (8 - len(corrupt) % 8)

        body = ffs1 + corrupt + ffs2
        fv = _make_fv(0x4000, body=body)
        size, hdr_size_fv, attrs = GetFvHeader(fv)
        pol = bool(attrs & EFI_FVB2_ERASE_POLARITY)
        return fv, size, hdr_size_fv, pol, g1, g2

    def test_finds_first_file(self):
        fv, fv_size, hdr_size, pol, g1, g2 = self._fv_with_two_files_and_corrupt_gap()
        f1 = NextFwFile(fv, fv_size, hdr_size, pol)
        self.assertIsNotNone(f1)
        self.assertEqual(f1.Guid, g1)

    def test_corrupt_header_stops_scanning(self):
        """After file_1, NextFwFile must return None at the corrupt header."""
        fv, fv_size, hdr_size, pol, g1, g2 = self._fv_with_two_files_and_corrupt_gap()
        f1 = NextFwFile(fv, fv_size, hdr_size, pol)
        self.assertIsNotNone(f1)
        # Try to get next file — should hit corrupt header and stop
        f2 = NextFwFile(fv, fv_size, f1.Offset + f1.Size, pol)
        self.assertIsNone(f2, "NextFwFile must break on corrupt FFS header, not skip past it")

    def test_corrupt_header_does_not_find_file2(self):
        """file_2 (GUID 22222222...) must NOT be found when corrupt data precedes it."""
        fv, fv_size, hdr_size, pol, g1, g2 = self._fv_with_two_files_and_corrupt_gap()
        # Iterate all files
        found_guids = []
        offset = hdr_size
        while True:
            f = NextFwFile(fv, fv_size, offset, pol)
            if f is None:
                break
            found_guids.append(f.Guid)
            offset = f.Offset + f.Size
        self.assertIn(g1, found_guids)
        self.assertNotIn(g2, found_guids,
                         "File after corrupt header must not be found (break, not continue)")


class TestNextFwFileBlankHeaderSkip(unittest.TestCase):
    """Verify blank (erased) header handling in NextFwFile.

    Files separated by blank gaps are NOT found through direct iteration —
    the 8-byte skip window is smaller than the 24-byte header check, so the
    last skip before a file always overlaps into the file header, parsing it
    as a corrupt header and breaking.  This is correct: higher-level code
    (build_efi_file_tree) handles the remaining data as Non-UEFI_Data and
    recursively scans it for embedded firmware volumes.
    """

    def test_trailing_blank_returns_none(self):
        """A file followed by blank (erased) space should cleanly return None."""
        g1 = UUID('AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA')
        sec1 = assemble_uefi_raw(b'\x01' * 8)
        ffs1 = assemble_uefi_file(g1, sec1)
        if len(ffs1) % 8:
            ffs1 += b'\xff' * (8 - len(ffs1) % 8)

        fv = _make_fv(0x4000, body=ffs1, attributes=EFI_FVB2_ERASE_POLARITY)
        size, hdr_size, attrs = GetFvHeader(fv)
        pol = bool(attrs & EFI_FVB2_ERASE_POLARITY)

        f1 = NextFwFile(fv, size, hdr_size, pol)
        self.assertIsNotNone(f1)
        self.assertEqual(f1.Guid, g1)

        # Remaining FV is all 0xFF — should return None cleanly
        f2 = NextFwFile(fv, size, f1.Offset + f1.Size, pol)
        self.assertIsNone(f2)

    def test_gap_stops_iteration(self):
        """Files separated by a blank gap are NOT found via direct iteration.

        This is expected: the gap/file boundary creates a false FFS header
        that triggers the corrupt-header break.  The higher-level code
        (build_efi_file_tree) handles finding file_2 through recursive
        scanning of the Non-UEFI_Data tail.
        """
        g1 = UUID('AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA')
        g2 = UUID('BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB')

        sec1 = assemble_uefi_raw(b'\x01' * 8)
        ffs1 = assemble_uefi_file(g1, sec1)
        if len(ffs1) % 8:
            ffs1 += b'\xff' * (8 - len(ffs1) % 8)

        sec2 = assemble_uefi_raw(b'\x02' * 8)
        ffs2 = assemble_uefi_file(g2, sec2)
        if len(ffs2) % 8:
            ffs2 += b'\xff' * (8 - len(ffs2) % 8)

        blank_gap = b'\xff' * 0x40
        body = ffs1 + blank_gap + ffs2
        fv = _make_fv(0x4000, body=body, attributes=EFI_FVB2_ERASE_POLARITY)
        size, hdr_size, attrs = GetFvHeader(fv)
        pol = bool(attrs & EFI_FVB2_ERASE_POLARITY)

        f1 = NextFwFile(fv, size, hdr_size, pol)
        self.assertIsNotNone(f1)
        self.assertEqual(f1.Guid, g1)

        # file_2 is NOT reachable via direct iteration (gap boundary)
        f2 = NextFwFile(fv, size, f1.Offset + f1.Size, pol)
        self.assertIsNone(f2, "Files after blank gaps require recursive scanning, not direct iteration")


class TestNextFwFileSectionInvalidSkip(unittest.TestCase):
    """Verify that invalid section headers (0xFFFFFF/0xFF) are skipped."""

    def test_invalid_section_then_valid(self):
        """An all-FF section header followed by a valid section should find the valid one.

        When Size=0xFFFFFF, the parser reads 4 more bytes as extended size.
        We insert 4 zero bytes after the invalid header so the extended size
        reads as 0, triggering the Size==0 skip path.  The parser then
        advances and finds the valid section.
        """
        # Invalid section: Size=0xFFFFFF, Type=0xFF
        invalid_hdr = struct.pack(EFI_COMMON_SECTION_HEADER, b'\xff\xff\xff', 0xFF)
        # 4 zero bytes consumed as extended size (=0), triggering the skip
        invalid_padded = invalid_hdr + b'\x00' * 4

        # Valid section after, aligned to 4 bytes
        valid_body = b'\xDE\xAD\xBE\xEF'
        valid_sec = _make_section(EFI_SECTION_RAW, valid_body)

        combined = invalid_padded + valid_sec
        result = NextFwFileSection(combined, len(combined), 0, True)
        self.assertIsNotNone(result, "Valid section after invalid header must be found")
        self.assertEqual(result.Type, EFI_SECTION_RAW)
        extracted = result.Image[result.HeaderSize:]
        self.assertEqual(extracted, valid_body)

    def test_zero_size_section_skipped(self):
        """A section with Size=0 should be skipped."""
        zero_hdr = struct.pack(EFI_COMMON_SECTION_HEADER, b'\x00\x00\x00', EFI_SECTION_RAW)
        pad = (4 - len(zero_hdr) % 4) % 4
        zero_padded = zero_hdr + b'\x00' * pad

        valid_body = b'\xCA\xFE'
        valid_sec = _make_section(EFI_SECTION_PE32, valid_body)

        combined = zero_padded + valid_sec
        result = NextFwFileSection(combined, len(combined), 0, True)
        self.assertIsNotNone(result)
        self.assertEqual(result.Type, EFI_SECTION_PE32)


class TestNextFwVolumeSkipsInvalid(unittest.TestCase):
    """Verify that NextFwVolume skips invalid FV candidates and finds the next valid one."""

    def test_corrupted_fv_then_valid_fv(self):
        """An FV with bad FvLength should be skipped; the next valid FV is found."""
        # Build a valid FV
        valid_fv = _make_fv(0x2000)
        # Build a corrupt FV header: valid signature but FvLength exceeds buffer
        corrupt_fv_length = 0xFFFFFFFF  # way too large
        zero_vector = b'\x00' * 16
        guid_bytes = TEST_FV_GUID.bytes_le
        signature = 0x4856465F
        block_map = struct.pack(EFI_FV_BLOCK_MAP_ENTRY, 1, corrupt_fv_length) + \
                    struct.pack(EFI_FV_BLOCK_MAP_ENTRY, 0, 0)
        header_length = EFI_FIRMWARE_VOLUME_HEADER_size + len(block_map)
        corrupt_hdr = struct.pack(EFI_FIRMWARE_VOLUME_HEADER,
                                  zero_vector, guid_bytes,
                                  corrupt_fv_length, signature, EFI_FVB2_ERASE_POLARITY,
                                  header_length, 0, 0, 0, 2)
        corrupt_hdr += block_map
        # Pad corrupt header to at least 0x100 so the valid FV is findable
        corrupt_padded = corrupt_hdr + b'\x00' * (0x100 - len(corrupt_hdr))

        full = corrupt_padded + valid_fv
        result = NextFwVolume(full)
        self.assertIsNotNone(result, "Valid FV after corrupt FV header must be found")
        self.assertEqual(result.Size, 0x2000)
        self.assertEqual(result.Offset, 0x100)


# ===========================================================================
# Tests for full round-trip: assemble -> parse
# ===========================================================================

class TestRoundTrip(unittest.TestCase):
    """End-to-end: build a complete FV with a file containing sections, then parse it back."""

    def test_fv_file_section_roundtrip(self):
        guid = UUID('01020304-0506-0708-090A-0B0C0D0E0F10')
        payload = b'Hello UEFI World!'

        # Build: raw section -> FFS file -> FV
        raw_sec = assemble_uefi_raw(payload)
        ffs = assemble_uefi_file(guid, raw_sec)
        if len(ffs) % 8:
            ffs += b'\xff' * (8 - len(ffs) % 8)
        fv = _make_fv(0x4000, body=ffs)

        # Parse FV
        fv_obj = NextFwVolume(fv)
        self.assertIsNotNone(fv_obj)

        # Parse file
        size, hdr_size, attrs = GetFvHeader(fv)
        pol = bool(attrs & EFI_FVB2_ERASE_POLARITY)
        file_obj = NextFwFile(fv, size, hdr_size, pol)
        self.assertIsNotNone(file_obj)
        self.assertEqual(file_obj.Guid, guid)

        # Parse section within the file
        sec_data = file_obj.Image[file_obj.HeaderSize:]
        sec_obj = NextFwFileSection(sec_data, len(sec_data), 0, pol)
        self.assertIsNotNone(sec_obj)
        self.assertEqual(sec_obj.Type, EFI_SECTION_RAW)
        extracted = sec_obj.Image[sec_obj.HeaderSize:]
        self.assertEqual(extracted, payload)

    def test_multiple_files_iteration(self):
        """Two files in an FV should be iterable."""
        g1 = UUID('11111111-1111-1111-1111-111111111111')
        g2 = UUID('22222222-2222-2222-2222-222222222222')

        sec1 = assemble_uefi_raw(b'\x01' * 16)
        ffs1 = assemble_uefi_file(g1, sec1)
        if len(ffs1) % 8:
            ffs1 += b'\xff' * (8 - len(ffs1) % 8)

        sec2 = assemble_uefi_raw(b'\x02' * 16)
        ffs2 = assemble_uefi_file(g2, sec2)
        if len(ffs2) % 8:
            ffs2 += b'\xff' * (8 - len(ffs2) % 8)

        body = ffs1 + ffs2
        fv = _make_fv(0x4000, body=body)
        size, hdr_size, attrs = GetFvHeader(fv)
        pol = bool(attrs & EFI_FVB2_ERASE_POLARITY)

        f1 = NextFwFile(fv, size, hdr_size, pol)
        self.assertIsNotNone(f1)
        self.assertEqual(f1.Guid, g1)

        f2 = NextFwFile(fv, size, f1.Offset + f1.Size, pol)
        self.assertIsNotNone(f2)
        self.assertEqual(f2.Guid, g2)

        f3 = NextFwFile(fv, size, f2.Offset + f2.Size, pol)
        self.assertIsNone(f3)


if __name__ == '__main__':
    unittest.main()
