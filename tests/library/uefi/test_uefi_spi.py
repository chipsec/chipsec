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

"""Unit tests for the content-identification, encapsulation and decode-entry
helpers of chipsec.library.uefi.spi.

Everything is driven from synthetic blobs assembled with struct.pack, so no
firmware image, hardware or network access is required.  tests/library/test_spi.py
covers the FV/FFS walking; this file covers the pieces it leaves untouched:
microcode/ACPI/PE-TE identification, GUID-defined section handling, compression
plumbing and the file-system entry points.
"""

import json
import os
import struct
import tempfile
import unittest
from unittest.mock import patch
from uuid import UUID

from chipsec.library.uefi.compression import (
    COMPRESSION_TYPE_BROTLI,
    COMPRESSION_TYPE_EFI_STANDARD,
    COMPRESSION_TYPE_GZIP,
    COMPRESSION_TYPE_LZMA,
    COMPRESSION_TYPE_LZMAF86,
    COMPRESSION_TYPE_UNKNOWN,
    COMPRESSION_TYPE_ZLIB_AMD,
)
from chipsec.library.uefi.fv import (
    EFI_CAPSULE_GUID,
    EFI_CAPSULE_HEADER_FMT,
    EFI_CAPSULE_HEADER_SIZE,
    EFI_CERT_TYPE_RSA_2048_SHA256_GUID,
    EFI_COMMON_SECTION_HEADER,
    EFI_COMPRESSION_SECTION,
    EFI_CRC32_GUIDED_SECTION_EXTRACTION_PROTOCOL_GUID,
    EFI_FIRMWARE_CONTENTS_SIGNED_GUID,
    EFI_FIRMWARE_FILE_SYSTEM2_GUID,
    EFI_FIRMWARE_VOLUME_HEADER,
    EFI_FIRMWARE_VOLUME_HEADER_size,
    EFI_FREEFORM_SUBTYPE_GUID_SECTION,
    EFI_FTW_WORKING_BLOCK_GUID,
    EFI_FV_BLOCK_MAP_ENTRY,
    EFI_FVB2_ERASE_POLARITY,
    EFI_FFS_FILE_HEADER,
    EFI_FV_FILETYPE_DRIVER,
    EFI_FV_FILETYPE_FFS_PAD,
    EFI_FV_FILETYPE_FREEFORM,
    EFI_FV_FILETYPE_RAW,
    EFI_GUID_DEFINED_SECTION,
    EFI_GUIDED_SECTION_AMI_SIGNED,
    EFI_GUIDED_SECTION_BROTLI,
    EFI_GUIDED_SECTION_GZIP,
    EFI_GUIDED_SECTION_LZMA,
    EFI_GUIDED_SECTION_LZMA_HP,
    EFI_GUIDED_SECTION_LZMA_MS,
    EFI_GUIDED_SECTION_LZMAF86,
    EFI_GUIDED_SECTION_TIANO,
    EFI_GUIDED_SECTION_ZLIB_AMD1,
    EFI_GUIDED_SECTION_ZLIB_AMD2,
    EFI_SECTION,
    EFI_SECTION_COMPATIBILITY16,
    EFI_SECTION_COMPRESSION,
    EFI_SECTION_FIRMWARE_VOLUME_IMAGE,
    EFI_SECTION_FREEFORM_SUBTYPE_GUID,
    EFI_SECTION_GUID_DEFINED,
    EFI_SECTION_PE32,
    EFI_SECTION_RAW,
    EFI_SECTION_TE,
    EFI_SECTION_USER_INTERFACE,
    EFI_SECTION_VERSION,
    EFI_VERSION_SECTION,
    FFS_ATTRIB_CHECKSUM,
    FFS_FIXED_CHECKSUM,
    FvChecksum8,
    FvChecksum16,
    WIN_CERTIFICATE,
    WIN_CERT_TYPE_EFI_GUID,
    WIN_CERT_TYPE_EFI_PKCS115,
    WIN_CERT_TYPE_PKCS_SIGNED_DATA,
)
from chipsec.library.uefi.platform import EFI_NVRAM_GUIDS, FWType, NVAR_NVRAM_FS_FILE
from chipsec.library.uefi.spi import (
    EFIModuleType,
    FILENAME,
    _identify_acpi_table,
    _identify_microcode,
    _parse_pe_te_metadata,
    build_efi_file_tree,
    build_efi_model,
    build_efi_modules_tree,
    build_efi_tree,
    compress_image,
    decode_uefi_region,
    decompress_section_data,
    dump_efi_module,
    modify_uefi_region,
    parse_uefi_region_from_file,
    save_efi_tree,
    search_efi_tree,
    strip_capsule_header,
)

# ---------------------------------------------------------------------------
# Binary builders
# ---------------------------------------------------------------------------

SECTION_HEADER_SIZE = struct.calcsize(EFI_COMMON_SECTION_HEADER)
GUID_DEFINED_SIZE = struct.calcsize(EFI_GUID_DEFINED_SECTION)
GUID_DEFINED_DATA_OFFSET = SECTION_HEADER_SIZE + GUID_DEFINED_SIZE


def _make_section(section_type: int, body: bytes) -> bytes:
    total_size = SECTION_HEADER_SIZE + len(body)
    size_bytes = struct.pack('<I', total_size)[:3]
    return struct.pack(EFI_COMMON_SECTION_HEADER, size_bytes, section_type) + body


def _make_guided_section(guid: UUID, payload: bytes, data_offset: int = GUID_DEFINED_DATA_OFFSET,
                         attributes: int = 0) -> bytes:
    header = struct.pack(EFI_GUID_DEFINED_SECTION, guid.bytes_le, data_offset, attributes)
    return _make_section(EFI_SECTION_GUID_DEFINED, header + payload)


def _make_fv(fv_length: int, guid: UUID = EFI_FIRMWARE_FILE_SYSTEM2_GUID,
             attributes: int = EFI_FVB2_ERASE_POLARITY, body: bytes = b'') -> bytes:
    """Minimal firmware volume with one block-map entry and a correct header checksum."""
    block_map = struct.pack(EFI_FV_BLOCK_MAP_ENTRY, 1, fv_length) + struct.pack(EFI_FV_BLOCK_MAP_ENTRY, 0, 0)
    header_length = EFI_FIRMWARE_VOLUME_HEADER_size + len(block_map)
    hdr = struct.pack(EFI_FIRMWARE_VOLUME_HEADER, b'\x00' * 16, guid.bytes_le,
                      fv_length, 0x4856465F, attributes, header_length, 0, 0, 0, 2) + block_map
    checksum = FvChecksum16(hdr)
    hdr = struct.pack(EFI_FIRMWARE_VOLUME_HEADER, b'\x00' * 16, guid.bytes_le,
                      fv_length, 0x4856465F, attributes, header_length, checksum, 0, 0, 2) + block_map
    return hdr + body + (b'\xff' * (fv_length - len(hdr) - len(body)))


def _make_ffs_file(guid: UUID, file_type: int, body: bytes, state: int = 0xF8) -> bytes:
    hdr_size = struct.calcsize(EFI_FFS_FILE_HEADER)
    size_bytes = struct.pack('<I', hdr_size + len(body))[:3]
    guid_bytes = guid.bytes_le
    hsum = FvChecksum8(struct.pack(EFI_FFS_FILE_HEADER, guid_bytes, 0, file_type,
                                   FFS_ATTRIB_CHECKSUM, size_bytes, 0))
    checksum = hsum | (FvChecksum8(body) << 8)
    ffs = struct.pack(EFI_FFS_FILE_HEADER, guid_bytes, checksum, file_type,
                      FFS_ATTRIB_CHECKSUM, size_bytes, state) + body
    return ffs + b'\xff' * ((-len(ffs)) % 8)


def _make_ucode(cpuid=0x000506E3, rev=0x000000C6, date=0x07142020, total_size=0x40,
                hdr_ver=1, blob_len=0x40) -> bytes:
    blob = bytearray(b'\x00' * blob_len)
    struct.pack_into('<IIII', blob, 0, hdr_ver, rev, date, cpuid)
    struct.pack_into('<I', blob, 0x20, total_size)
    return bytes(blob)


def _make_acpi(sig=b'DSDT', length=0x40, revision=2, oem=b'INTEL\x00',
               oem_table=b'TESTTBL\x00', blob_len=0x40) -> bytes:
    blob = bytearray(b'\x00' * blob_len)
    blob[0:4] = sig
    struct.pack_into('<I', blob, 4, length)
    blob[8] = revision
    blob[0x0A:0x10] = oem
    blob[0x10:0x18] = oem_table
    return bytes(blob)


def _make_te(machine=0x8664, sections=3, subsystem=11, entry=0x240, blob_len=64) -> bytes:
    blob = bytearray(b'\x00' * blob_len)
    blob[0:2] = b'VZ'
    struct.pack_into('<HBB', blob, 2, machine, sections, subsystem)
    struct.pack_into('<I', blob, 8, entry)
    return bytes(blob)


PE_OFFSET = 0x80
COFF_OFF = PE_OFFSET + 4
OPT_OFF = COFF_OFF + 20


def _make_pe(machine=0x8664, sections=4, size_opt=240, magic=0x20B, entry=0x1000,
             image_size=0x8000, subsystem=10, blob_len=0x200, pe_sig=b'PE\x00\x00',
             pe_offset=PE_OFFSET) -> bytes:
    blob = bytearray(b'\x00' * blob_len)
    blob[0:2] = b'MZ'
    struct.pack_into('<I', blob, 0x3C, pe_offset)
    blob[pe_offset:pe_offset + 4] = pe_sig
    struct.pack_into('<HH', blob, COFF_OFF, machine, sections)
    struct.pack_into('<H', blob, COFF_OFF + 16, size_opt)
    struct.pack_into('<H', blob, OPT_OFF, magic)
    struct.pack_into('<I', blob, OPT_OFF + 16, entry)
    struct.pack_into('<I', blob, OPT_OFF + 56, image_size)
    struct.pack_into('<H', blob, OPT_OFF + 68, subsystem)
    return bytes(blob)


# ===========================================================================
# _identify_microcode
# ===========================================================================

class TestIdentifyMicrocode(unittest.TestCase):

    def test_valid_microcode(self):
        self.assertEqual(
            _identify_microcode(_make_ucode()),
            'Intel Microcode: CPUID=0x000506E3, Rev=0x000000C6, Date=07/14/2020, Size=0x40')

    def test_zero_total_size_defaults_to_2048(self):
        blob = _make_ucode(total_size=0, blob_len=2048)
        self.assertEqual(
            _identify_microcode(blob),
            'Intel Microcode: CPUID=0x000506E3, Rev=0x000000C6, Date=07/14/2020, Size=0x800')

    def test_zero_cpuid_is_accepted(self):
        result = _identify_microcode(_make_ucode(cpuid=0))
        self.assertIsNotNone(result)
        self.assertIn('CPUID=0x00000000', result)

    def test_too_short(self):
        self.assertIsNone(_identify_microcode(b'\x01' + b'\x00' * 46))

    def test_wrong_header_version(self):
        self.assertIsNone(_identify_microcode(_make_ucode(hdr_ver=2)))

    def test_cpu_family_below_four(self):
        # family == (cpuid >> 8) & 0xF == 3 and cpuid != 0
        self.assertIsNone(_identify_microcode(_make_ucode(cpuid=0x00000300)))

    def test_bad_bcd_month_zero(self):
        self.assertIsNone(_identify_microcode(_make_ucode(date=0x00142020)))

    def test_bad_bcd_month_too_large(self):
        self.assertIsNone(_identify_microcode(_make_ucode(date=0x13142020)))

    def test_bad_bcd_day_zero(self):
        self.assertIsNone(_identify_microcode(_make_ucode(date=0x07002020)))

    def test_bad_bcd_day_too_large(self):
        self.assertIsNone(_identify_microcode(_make_ucode(date=0x07322020)))

    def test_total_size_exceeds_data(self):
        self.assertIsNone(_identify_microcode(_make_ucode(total_size=0x100, blob_len=0x40)))

    def test_total_size_below_header(self):
        self.assertIsNone(_identify_microcode(_make_ucode(total_size=0x10)))


# ===========================================================================
# _identify_acpi_table
# ===========================================================================

class TestIdentifyAcpiTable(unittest.TestCase):

    def test_valid_table(self):
        self.assertEqual(
            _identify_acpi_table(_make_acpi()),
            'ACPI DSDT: Rev=2, Length=0x40, OemId="INTEL", OemTableId="TESTTBL"')

    def test_oem_padding_is_stripped(self):
        blob = _make_acpi(oem=b'INTL  ', oem_table=b'TBL     ')
        self.assertEqual(
            _identify_acpi_table(blob),
            'ACPI DSDT: Rev=2, Length=0x40, OemId="INTL", OemTableId="TBL"')

    def test_too_short(self):
        self.assertIsNone(_identify_acpi_table(_make_acpi(blob_len=35)[:35]))

    def test_unknown_signature(self):
        self.assertIsNone(_identify_acpi_table(_make_acpi(sig=b'ZZZZ')))

    def test_length_below_header(self):
        self.assertIsNone(_identify_acpi_table(_make_acpi(length=0x10)))

    def test_length_exceeds_data(self):
        self.assertIsNone(_identify_acpi_table(_make_acpi(length=0x100)))


# ===========================================================================
# _parse_pe_te_metadata
# ===========================================================================

class TestParsePeTeMetadata(unittest.TestCase):

    def test_te_image(self):
        self.assertEqual(
            _parse_pe_te_metadata(EFI_SECTION_TE, _make_te()),
            'TE: Machine=X64, Subsystem=EFI_BOOT_SERVICE_DRIVER, EntryPoint=0x240, Sections=3')

    def test_te_unknown_machine_and_subsystem(self):
        self.assertEqual(
            _parse_pe_te_metadata(EFI_SECTION_TE, _make_te(machine=0x1234, subsystem=0x63)),
            'TE: Machine=0x1234, Subsystem=0x63, EntryPoint=0x240, Sections=3')

    def test_te_truncated(self):
        self.assertIsNone(_parse_pe_te_metadata(EFI_SECTION_TE, _make_te()[:39]))

    def test_te_signature_with_non_te_section_type(self):
        # 'VZ' is only honoured for EFI_SECTION_TE
        self.assertIsNone(_parse_pe_te_metadata(EFI_SECTION_PE32, _make_te()))

    def test_pe32_plus(self):
        self.assertEqual(
            _parse_pe_te_metadata(EFI_SECTION_PE32, _make_pe()),
            'PE32+: Machine=X64, Subsystem=EFI_APPLICATION, EntryPoint=0x1000, ImageSize=0x8000')

    def test_pe32(self):
        blob = _make_pe(machine=0x014C, size_opt=224, magic=0x10B, entry=0x2000,
                        image_size=0x4000, subsystem=12)
        self.assertEqual(
            _parse_pe_te_metadata(EFI_SECTION_PE32, blob),
            'PE32: Machine=I386, Subsystem=EFI_RUNTIME_DRIVER, EntryPoint=0x2000, ImageSize=0x4000')

    def test_pe_accepted_for_compatibility16_section(self):
        result = _parse_pe_te_metadata(EFI_SECTION_COMPATIBILITY16, _make_pe(machine=0xAA64))
        self.assertEqual(
            result,
            'PE32+: Machine=AARCH64, Subsystem=EFI_APPLICATION, EntryPoint=0x1000, ImageSize=0x8000')

    def test_pe_optional_header_too_small(self):
        self.assertEqual(
            _parse_pe_te_metadata(EFI_SECTION_PE32, _make_pe(size_opt=16)),
            'PE: Machine=X64, Sections=4')

    def test_pe_optional_header_overruns_data(self):
        self.assertEqual(
            _parse_pe_te_metadata(EFI_SECTION_PE32, _make_pe(size_opt=0x400)),
            'PE: Machine=X64, Sections=4')

    def test_pe_unknown_optional_magic(self):
        self.assertEqual(
            _parse_pe_te_metadata(EFI_SECTION_PE32, _make_pe(magic=0x107)),
            'PE: Machine=X64, Sections=4')

    def test_pe32_plus_magic_with_short_optional_header(self):
        # magic says PE32+ but SizeOfOptionalHeader is under the 112-byte minimum
        self.assertEqual(
            _parse_pe_te_metadata(EFI_SECTION_PE32, _make_pe(size_opt=100)),
            'PE: Machine=X64, Sections=4')

    def test_pe_bad_signature(self):
        self.assertIsNone(_parse_pe_te_metadata(EFI_SECTION_PE32, _make_pe(pe_sig=b'NE\x00\x00')))

    def test_pe_offset_out_of_range(self):
        # e_lfanew points so far into the image that the COFF header cannot fit
        blob = bytearray(b'\x00' * 0x100)
        blob[0:2] = b'MZ'
        struct.pack_into('<I', blob, 0x3C, 0xF0)
        self.assertIsNone(_parse_pe_te_metadata(EFI_SECTION_PE32, bytes(blob)))

    def test_pe_dos_header_truncated(self):
        self.assertIsNone(_parse_pe_te_metadata(EFI_SECTION_PE32, b'MZ' + b'\x00' * 0x30))

    def test_data_too_short(self):
        self.assertIsNone(_parse_pe_te_metadata(EFI_SECTION_PE32, b'M'))

    def test_unrecognized_signature(self):
        self.assertIsNone(_parse_pe_te_metadata(EFI_SECTION_PE32, b'XX' + b'\x00' * 0x100))


# ===========================================================================
# compression plumbing
# ===========================================================================

class TestCompressionHelpers(unittest.TestCase):

    def test_decompress_section_data_delegates(self):
        with patch('chipsec.library.uefi.spi.UefiCompression') as uc:
            uc.return_value.decompress_efi_binary.return_value = b'PLAIN'
            result = decompress_section_data('sect00_abcd', b'PACKED', 0x11)
        self.assertEqual(result, b'PLAIN')
        uc.return_value.decompress_efi_binary.assert_called_once_with(b'PACKED', 0x11)

    def test_compress_image_delegates(self):
        with patch('chipsec.library.uefi.spi.UefiCompression') as uc:
            uc.return_value.compress_efi_binary.return_value = b'PACKED'
            result = compress_image(b'PLAIN', 0x22)
        self.assertEqual(result, b'PACKED')
        uc.return_value.compress_efi_binary.assert_called_once_with(b'PLAIN', 0x22)


# ===========================================================================
# build_efi_modules_tree: leaf sections
# ===========================================================================

class TestSectionContentIdentification(unittest.TestCase):

    def _one_section(self, blob):
        modules = build_efi_modules_tree(None, blob, len(blob), 0, True)
        self.assertEqual(len(modules), 1)
        return modules[0]

    def test_pe32_section_records_metadata_comment(self):
        sec = self._one_section(_make_section(EFI_SECTION_PE32, _make_pe()))
        self.assertEqual(
            sec.Comments,
            'PE32+: Machine=X64, Subsystem=EFI_APPLICATION, EntryPoint=0x1000, ImageSize=0x8000')

    def test_exe_section_hashes_are_calculated(self):
        sec = self._one_section(_make_section(EFI_SECTION_TE, _make_te()))
        self.assertEqual(sec.Comments,
                         'TE: Machine=X64, Subsystem=EFI_BOOT_SERVICE_DRIVER, '
                         'EntryPoint=0x240, Sections=3')
        self.assertTrue(sec.SHA256)
        self.assertTrue(sec.MD5)

    def test_exe_section_without_recognizable_header_has_no_comment(self):
        sec = self._one_section(_make_section(EFI_SECTION_PE32, b'\x00' * 0x80))
        self.assertFalse(sec.Comments)

    def test_raw_section_identifies_microcode(self):
        sec = self._one_section(_make_section(EFI_SECTION_RAW, _make_ucode()))
        self.assertEqual(
            sec.Comments,
            'Intel Microcode: CPUID=0x000506E3, Rev=0x000000C6, Date=07/14/2020, Size=0x40')

    def test_raw_section_identifies_acpi_table(self):
        sec = self._one_section(_make_section(EFI_SECTION_RAW, _make_acpi()))
        self.assertEqual(
            sec.Comments,
            'ACPI DSDT: Rev=2, Length=0x40, OemId="INTEL", OemTableId="TESTTBL"')

    def test_raw_section_with_unidentifiable_payload(self):
        sec = self._one_section(_make_section(EFI_SECTION_RAW, b'\x5A' * 0x40))
        self.assertFalse(sec.Comments)

    def test_freeform_subtype_guid_section(self):
        subtype = UUID('01020304-0506-0708-090A-0B0C0D0E0F10')
        body = struct.pack(EFI_FREEFORM_SUBTYPE_GUID_SECTION, subtype.bytes_le) + b'\xAA' * 8
        sec = self._one_section(_make_section(EFI_SECTION_FREEFORM_SUBTYPE_GUID, body))
        self.assertEqual(sec.Guid, subtype)
        self.assertEqual(sec.Comments, f'SubTypeGuid={{{subtype}}}')

    def test_version_section_with_undecodable_string(self):
        # A lone UTF-16 high surrogate makes the optional version string undecodable;
        # the BuildNumber must still be reported.
        body = struct.pack(EFI_VERSION_SECTION, 7) + b'\x00\xd8'
        sec = self._one_section(_make_section(EFI_SECTION_VERSION, body))
        self.assertEqual(sec.Comments, 'BuildNumber=7')

    def test_unknown_section_type_is_named_and_kept(self):
        sec = self._one_section(_make_section(0x50, b'\x11' * 0x20))
        self.assertEqual(sec.Name, 'S_UNKNOWN_50')
        self.assertEqual(sec.children, [])

    def test_ui_section_with_undecodable_name_keeps_default(self):
        # An odd byte count cannot be UCS-2; the section survives without a UI name.
        sec = self._one_section(_make_section(EFI_SECTION_USER_INTERFACE, b'\x41\x00\x42'))
        self.assertEqual(sec.ui_string, '')

    def test_firmware_volume_image_section_children(self):
        inner_file = _make_ffs_file(UUID('44444444-4444-4444-4444-444444444444'),
                                    EFI_FV_FILETYPE_FREEFORM,
                                    _make_section(EFI_SECTION_RAW, b'NESTED!!'))
        fv = _make_fv(0x1000, body=inner_file)
        sec = self._one_section(_make_section(EFI_SECTION_FIRMWARE_VOLUME_IMAGE, fv))
        self.assertTrue(sec.children)


class TestCompressionSections(unittest.TestCase):

    def test_uncompressed_compression_section_is_expanded(self):
        inner = _make_section(EFI_SECTION_RAW, b'UNCOMPRESSED')
        body = struct.pack(EFI_COMPRESSION_SECTION, len(inner), 0x00) + inner
        blob = _make_section(EFI_SECTION_COMPRESSION, body)
        modules = build_efi_modules_tree(None, blob, len(blob), 0, False)
        self.assertEqual(len(modules), 1)
        self.assertEqual([c.Type for c in modules[0].children], [EFI_SECTION_RAW])

    def test_standard_compression_section_uses_efi_decompression(self):
        inner = _make_section(EFI_SECTION_RAW, b'DECOMPRESSED')
        body = struct.pack(EFI_COMPRESSION_SECTION, len(inner), 0x01) + b'\xCC' * 16
        blob = _make_section(EFI_SECTION_COMPRESSION, body)
        with patch('chipsec.library.uefi.spi.decompress_section_data', return_value=inner) as dsd:
            modules = build_efi_modules_tree(None, blob, len(blob), 0, False)
        self.assertEqual([c.Type for c in modules[0].children], [EFI_SECTION_RAW])
        self.assertEqual(dsd.call_count, 1)

    def test_unknown_compression_type_falls_back_to_brute_force(self):
        inner = _make_section(EFI_SECTION_RAW, b'BRUTEFORCED!')
        body = struct.pack(EFI_COMPRESSION_SECTION, len(inner), 0x07) + b'\xCC' * 16
        blob = _make_section(EFI_SECTION_COMPRESSION, body)
        with patch('chipsec.library.uefi.spi.decompress_section_data',
                   side_effect=[b'', inner]) as dsd:
            modules = build_efi_modules_tree(None, blob, len(blob), 0, False)
        # Spec-directed decode is skipped for an unknown type; the brute-force loop runs.
        self.assertGreaterEqual(dsd.call_count, 2)
        self.assertEqual([c.Type for c in modules[0].children], [EFI_SECTION_RAW])


class TestGuidDefinedSections(unittest.TestCase):

    def _one_section(self, blob, polarity=False):
        modules = build_efi_modules_tree(None, blob, len(blob), 0, polarity)
        self.assertEqual(len(modules), 1)
        return modules[0]

    def test_crc32_guided_section_recurses_into_payload(self):
        payload = _make_section(EFI_SECTION_RAW, b'CRC32PAYLOAD')
        blob = _make_guided_section(EFI_CRC32_GUIDED_SECTION_EXTRACTION_PROTOCOL_GUID, payload)
        sec = self._one_section(blob)
        self.assertEqual(sec.Guid, EFI_CRC32_GUIDED_SECTION_EXTRACTION_PROTOCOL_GUID)
        self.assertEqual([c.Type for c in sec.children], [EFI_SECTION_RAW])

    def test_lzma_guided_section_decompresses_and_recurses(self):
        payload = _make_section(EFI_SECTION_RAW, b'LZMAPAYLOAD!')
        blob = _make_guided_section(EFI_GUIDED_SECTION_LZMA, b'\x5D' * 24)
        with patch('chipsec.library.uefi.spi.decompress_section_data', return_value=payload):
            sec = self._one_section(blob)
        self.assertEqual([c.Type for c in sec.children], [EFI_SECTION_RAW])
        self.assertFalse(sec.Comments)

    def test_lzma_guided_section_reports_failed_decompression(self):
        blob = _make_guided_section(EFI_GUIDED_SECTION_LZMA, b'\x5D' * 24)
        with patch('chipsec.library.uefi.spi.decompress_section_data', return_value=b'') as dsd:
            sec = self._one_section(blob)
        self.assertEqual(sec.Comments, 'Unable to decompress image')
        self.assertEqual(sec.children, [])
        # LZMA attempt, then a final COMPRESSION_TYPE_UNKNOWN attempt.
        self.assertEqual([c.args[2] for c in dsd.call_args_list],
                         [COMPRESSION_TYPE_LZMA, COMPRESSION_TYPE_UNKNOWN])

    def test_each_compression_guid_selects_its_algorithm(self):
        cases = [
            (EFI_GUIDED_SECTION_LZMA, COMPRESSION_TYPE_LZMA),
            (EFI_GUIDED_SECTION_LZMA_HP, COMPRESSION_TYPE_LZMA),
            (EFI_GUIDED_SECTION_LZMA_MS, COMPRESSION_TYPE_LZMA),
            (EFI_GUIDED_SECTION_LZMAF86, COMPRESSION_TYPE_LZMAF86),
            (EFI_GUIDED_SECTION_BROTLI, COMPRESSION_TYPE_BROTLI),
            (EFI_GUIDED_SECTION_GZIP, COMPRESSION_TYPE_GZIP),
            (EFI_GUIDED_SECTION_ZLIB_AMD1, COMPRESSION_TYPE_ZLIB_AMD),
            (EFI_GUIDED_SECTION_ZLIB_AMD2, COMPRESSION_TYPE_ZLIB_AMD),
            (EFI_GUIDED_SECTION_TIANO, COMPRESSION_TYPE_EFI_STANDARD),
        ]
        payload = _make_section(EFI_SECTION_RAW, b'GUIDEDDATA!!')
        for guid, expected_type in cases:
            with self.subTest(guid=str(guid)):
                blob = _make_guided_section(guid, b'\x5D' * 24)
                with patch('chipsec.library.uefi.spi.decompress_section_data',
                           return_value=payload) as dsd:
                    sec = self._one_section(blob)
                self.assertEqual(dsd.call_count, 1)
                self.assertEqual(dsd.call_args[0][2], expected_type)
                self.assertEqual([c.Type for c in sec.children], [EFI_SECTION_RAW])

    def test_rsa2048_sha256_guided_section(self):
        blob = _make_guided_section(EFI_CERT_TYPE_RSA_2048_SHA256_GUID, b'\x00' * 32)
        sec = self._one_section(blob)
        self.assertEqual(sec.Comments, 'Certificate Type RSA2048/SHA256')
        self.assertEqual(sec.children, [])

    def _signed_contents(self, cert_type, cert_guid=EFI_CERT_TYPE_RSA_2048_SHA256_GUID):
        win_cert = struct.pack(WIN_CERTIFICATE, struct.calcsize(WIN_CERTIFICATE),
                               0x0200, cert_type, cert_guid.bytes_le)
        return _make_guided_section(EFI_FIRMWARE_CONTENTS_SIGNED_GUID, win_cert)

    def test_signed_contents_uefi_guid_certificate(self):
        sec = self._one_section(self._signed_contents(WIN_CERT_TYPE_EFI_GUID))
        self.assertEqual(sec.Comments,
                         'Found UEFI Certificate. Cert of type RSA2048/SHA256!')

    def test_signed_contents_unknown_certificate_guid(self):
        other = UUID('DEADBEEF-1111-2222-3333-444444444444')
        sec = self._one_section(self._signed_contents(WIN_CERT_TYPE_EFI_GUID, other))
        self.assertEqual(sec.Comments,
                         f'Found UEFI Certificate. Cert of unknown type! But the guid is: {other}')

    def test_signed_contents_pkcs_certificate(self):
        sec = self._one_section(self._signed_contents(WIN_CERT_TYPE_PKCS_SIGNED_DATA))
        self.assertEqual(sec.Comments, 'Found PKCS SIGNED Certificate')

    def test_signed_contents_pkcs115_certificate(self):
        sec = self._one_section(self._signed_contents(WIN_CERT_TYPE_EFI_PKCS115))
        self.assertEqual(sec.Comments, 'Found UEFI PKCS1_15 SIGNED Certificate')

    def test_signed_contents_unknown_cert_type(self):
        sec = self._one_section(self._signed_contents(0x1234))
        self.assertEqual(sec.Comments, 'Unknown cert type: 4660')

    def test_vendor_guided_section_falls_back_to_generic_scan(self):
        blob = _make_guided_section(EFI_GUIDED_SECTION_AMI_SIGNED, b'\x77' * 32)
        with patch('chipsec.library.uefi.spi.decompress_section_data', return_value=b'') as dsd:
            sec = self._one_section(blob)
        self.assertEqual(
            sec.Comments,
            f'Vendor signed/wrapped section GUID={{{EFI_GUIDED_SECTION_AMI_SIGNED}}}')
        self.assertEqual(dsd.call_count, 3)
        self.assertEqual(sec.children, [])

    def test_vendor_guided_section_decompresses_when_possible(self):
        payload = _make_section(EFI_SECTION_RAW, b'VENDORDATA!!')
        blob = _make_guided_section(EFI_GUIDED_SECTION_AMI_SIGNED, b'\x77' * 32)
        with patch('chipsec.library.uefi.spi.decompress_section_data', return_value=payload) as dsd:
            sec = self._one_section(blob)
        self.assertEqual(dsd.call_count, 1)
        self.assertEqual([c.Type for c in sec.children], [EFI_SECTION_RAW])

    def test_vendor_guided_section_with_empty_payload_is_not_decompressed(self):
        # DataOffset points past the end of the section, so there is nothing to unpack.
        blob = _make_guided_section(EFI_GUIDED_SECTION_AMI_SIGNED, b'\x77' * 8,
                                    data_offset=GUID_DEFINED_DATA_OFFSET + 8)
        with patch('chipsec.library.uefi.spi.decompress_section_data') as dsd:
            sec = self._one_section(blob)
        dsd.assert_not_called()
        self.assertEqual(sec.children, [])

    def test_unknown_guided_section_is_scanned_generically(self):
        unknown = UUID('AABBCCDD-EEFF-0011-2233-445566778899')
        sec = self._one_section(_make_guided_section(unknown, b'\x33' * 32))
        self.assertEqual(sec.Guid, unknown)
        self.assertEqual(sec.children, [])

    def test_guided_section_missing_guid_uses_zeroed_guid(self):
        # Total size 8: the common header is valid but there is not even room for a GUID.
        blob = _make_section(EFI_SECTION_GUID_DEFINED, b'\x01\x02\x03\x04')
        sec = self._one_section(blob)
        self.assertEqual(sec.Guid, UUID(int=0))

    def test_guided_section_with_guid_but_truncated_header(self):
        # 4-byte header + 16-byte GUID + 2 bytes: enough for the GUID, not the full struct.
        guid = UUID('12345678-90AB-CDEF-1234-567890ABCDEF')
        blob = _make_section(EFI_SECTION_GUID_DEFINED, guid.bytes_le + b'\x00\x00')
        sec = self._one_section(blob)
        self.assertEqual(sec.Guid, guid)
        self.assertEqual(sec.DataOffset, len(sec.Image) - 1)


# ===========================================================================
# build_efi_file_tree / build_efi_tree
# ===========================================================================

class TestFileAndVolumeTrees(unittest.TestCase):

    def test_raw_type_file_is_kept(self):
        guid = UUID('55555555-5555-5555-5555-555555555555')
        fv = _make_fv(0x2000, body=_make_ffs_file(guid, EFI_FV_FILETYPE_RAW, b'\xA5' * 0x40))
        files = build_efi_file_tree(fv, None)
        self.assertIn(guid, [getattr(f, 'Guid', None) for f in files])

    def test_pad_type_file_becomes_a_padding_section(self):
        guid = UUID('66666666-6666-6666-6666-666666666666')
        fv = _make_fv(0x2000, body=_make_ffs_file(guid, EFI_FV_FILETYPE_FFS_PAD, b'\x00' * 0x40))
        nodes = build_efi_file_tree(fv, None)
        # A pad file is reported as a Padding section, never as an EFI_FILE.
        self.assertEqual([n.Name for n in nodes],
                         ['Non-UEFI_Padding', 'Padding', 'Non-UEFI_Data'])
        padding = nodes[1]
        self.assertEqual(padding.Type, EFI_FV_FILETYPE_FFS_PAD)
        self.assertEqual(padding.Comments, 'Attempting to identify modules in Padding Section')

    def test_driver_file_sections_are_parsed(self):
        guid = UUID('77777777-7777-7777-7777-777777777777')
        body = _make_section(EFI_SECTION_PE32, _make_pe())
        fv = _make_fv(0x2000, body=_make_ffs_file(guid, EFI_FV_FILETYPE_DRIVER, body))
        files = [f for f in build_efi_file_tree(fv, None) if getattr(f, 'Guid', None) == guid]
        self.assertEqual(len(files), 1)
        self.assertEqual([c.Type for c in files[0].children], [EFI_SECTION_PE32])

    def test_nvram_volume_is_flagged(self):
        fv = _make_fv(0x2000, guid=EFI_NVRAM_GUIDS[0])
        with patch('chipsec.library.uefi.spi.identify_EFI_NVRAM', return_value='vss') as ident:
            tree = build_efi_tree(fv, None)
        ident.assert_called_once()
        self.assertEqual(len(tree), 1)
        self.assertTrue(tree[0].isNVRAM)
        self.assertEqual(tree[0].NVRAMType, 'vss')

    def test_nvram_volume_with_explicit_fwtype_skips_identification(self):
        fv = _make_fv(0x2000, guid=EFI_NVRAM_GUIDS[0])
        with patch('chipsec.library.uefi.spi.identify_EFI_NVRAM') as ident:
            tree = build_efi_tree(fv, 'evsa')
        ident.assert_not_called()
        self.assertEqual(tree[0].NVRAMType, 'evsa')

    def test_nvram_identification_failure_is_contained(self):
        fv = _make_fv(0x2000, guid=EFI_NVRAM_GUIDS[0])
        with patch('chipsec.library.uefi.spi.identify_EFI_NVRAM',
                   side_effect=ValueError('boom')):
            tree = build_efi_tree(fv, None)
        self.assertEqual(len(tree), 1)
        self.assertTrue(tree[0].isNVRAM)
        # The volume stays flagged as NVRAM but keeps its default (unset) type.
        self.assertEqual(tree[0].NVRAMType, '')

    def test_fault_tolerant_write_volume(self):
        fv = _make_fv(0x2000, guid=EFI_FTW_WORKING_BLOCK_GUID)
        tree = build_efi_tree(fv, None)
        self.assertEqual(len(tree), 1)
        self.assertTrue(tree[0].isNVRAM)
        self.assertEqual(tree[0].NVRAMType, 'FTW')
        self.assertEqual(tree[0].children, [])

    def test_unknown_volume_guid_is_still_parsed_as_ffs(self):
        guid = UUID('0BADF00D-0BAD-0BAD-0BAD-0BADF00D0BAD')
        file_guid = UUID('88888888-8888-8888-8888-888888888888')
        body = _make_ffs_file(file_guid, EFI_FV_FILETYPE_FREEFORM,
                              _make_section(EFI_SECTION_RAW, b'UNKNOWNFV!!!'))
        tree = build_efi_tree(_make_fv(0x2000, guid=guid, body=body), None)
        self.assertEqual(len(tree), 1)
        self.assertEqual(tree[0].Guid, guid)
        self.assertIn(file_guid, [getattr(c, 'Guid', None) for c in tree[0].children])

    def test_nvram_volume_children_are_attached(self):
        body = _make_ffs_file(UUID('89898989-8989-8989-8989-898989898989'),
                              EFI_FV_FILETYPE_FREEFORM,
                              _make_section(EFI_SECTION_RAW, b'NVRAMCHILD!!'))
        fv = _make_fv(0x2000, guid=EFI_NVRAM_GUIDS[0], body=body)
        with patch('chipsec.library.uefi.spi.identify_EFI_NVRAM', return_value='vss'):
            tree = build_efi_tree(fv, None)
        self.assertTrue(tree[0].children)

    def test_nvar_raw_file_is_flagged_as_nvar_nvram(self):
        fv = _make_fv(0x2000, body=_make_ffs_file(NVAR_NVRAM_FS_FILE,
                                                  EFI_FV_FILETYPE_RAW, b'\xA5' * 0x40))
        nvar = [f for f in build_efi_file_tree(fv, None)
                if getattr(f, 'Guid', None) == NVAR_NVRAM_FS_FILE]
        self.assertEqual(len(nvar), 1)
        self.assertTrue(nvar[0].isNVRAM)
        self.assertEqual(nvar[0].NVRAMType, FWType.EFI_FW_TYPE_NVAR)
        self.assertEqual(nvar[0].children, [])


# ===========================================================================
# dump_efi_module / search_efi_tree / save_efi_tree
# ===========================================================================

class TestDumpEfiModule(unittest.TestCase):

    def test_section_hashes_are_written_alongside_image(self):
        image = _make_section(EFI_SECTION_PE32, _make_pe())
        sec = EFI_SECTION(0, 'S_PE32', EFI_SECTION_PE32, image, SECTION_HEADER_SIZE, len(image))
        sec.calc_hashes(SECTION_HEADER_SIZE)
        with tempfile.TemporaryDirectory() as tmp:
            mod_path = dump_efi_module(sec, None, 3, tmp)
            self.assertEqual(os.path.basename(mod_path), f'03_{FILENAME(sec, None, 3)[3:]}')
            with open(mod_path, 'rb') as fh:
                self.assertEqual(fh.read(), image[SECTION_HEADER_SIZE:])
            for ext in ('md5', 'sha1', 'sha256'):
                self.assertTrue(os.path.exists(f'{mod_path}.{ext}'), ext)

    def test_section_without_hashes_writes_only_image(self):
        image = _make_section(EFI_SECTION_RAW, b'\x01' * 16)
        sec = EFI_SECTION(0, 'S_RAW', EFI_SECTION_RAW, image, SECTION_HEADER_SIZE, len(image))
        with tempfile.TemporaryDirectory() as tmp:
            mod_path = dump_efi_module(sec, None, 0, tmp)
            self.assertEqual(os.listdir(tmp), [os.path.basename(mod_path)])

    def test_exe_section_without_parent_uses_type_extension(self):
        sec = EFI_SECTION(0, 'S_PE32', EFI_SECTION_PE32, b'\x00' * 32, SECTION_HEADER_SIZE, 32)
        self.assertEqual(FILENAME(sec, None, 1), '01_S_PE32.pe32')

    def test_unknown_file_type_filename(self):
        fv = _make_fv(0x2000, body=_make_ffs_file(
            UUID('99999999-9999-9999-9999-999999999999'), 0x42,
            _make_section(EFI_SECTION_RAW, b'ODDTYPE!')))
        files = [f for f in build_efi_file_tree(fv, None) if getattr(f, 'Type', None) == 0x42]
        self.assertEqual(len(files), 1)
        self.assertTrue(FILENAME(files[0], None, 0).endswith('.UNKNOWN_42'))


class TestSearchEfiTreeRecursion(unittest.TestCase):

    def test_first_match_in_children_returns_the_parent(self):
        fv = _make_fv(0x2000, body=_make_ffs_file(
            UUID('ABABABAB-ABAB-ABAB-ABAB-ABABABABABAB'), EFI_FV_FILETYPE_DRIVER,
            _make_section(EFI_SECTION_PE32, _make_pe())))
        model = build_efi_model(fv, None)
        result = search_efi_tree(model, lambda m: m.Type == EFI_SECTION_PE32,
                                 match_module_types=EFIModuleType.SECTION_EXE,
                                 findall=False)
        # findall=False unwinds by returning the node that owns the match.
        self.assertEqual(len(result), 1)
        self.assertIs(result[0], model[0])

    def test_callback_none_never_matches(self):
        fv = _make_fv(0x2000, body=_make_ffs_file(
            UUID('ACACACAC-ACAC-ACAC-ACAC-ACACACACACAC'), EFI_FV_FILETYPE_DRIVER,
            _make_section(EFI_SECTION_PE32, _make_pe())))
        model = build_efi_model(fv, None)
        self.assertEqual(search_efi_tree(model, None, EFIModuleType.ALL), [])


class TestSaveEfiTreeLogging(unittest.TestCase):

    def test_log_goes_to_logger_when_no_line_buffer_given(self):
        fv = _make_fv(0x2000, body=_make_ffs_file(
            UUID('BABABABA-BABA-BABA-BABA-BABABABABABA'), EFI_FV_FILETYPE_FREEFORM,
            _make_section(EFI_SECTION_RAW, b'LOGGEDDATA!!')))
        model = build_efi_model(fv, None)
        with patch('chipsec.library.uefi.spi.logger') as log:
            save_efi_tree(model, save_modules=False, save_log=True)
        self.assertTrue(log.return_value.log.called)

    def test_filetype_filter_only_logs_matching_files(self):
        fv = _make_fv(0x2000, body=_make_ffs_file(
            UUID('BCBCBCBC-BCBC-BCBC-BCBC-BCBCBCBCBCBC'), EFI_FV_FILETYPE_DRIVER,
            _make_section(EFI_SECTION_RAW, b'FILTEREDDD!!')))
        model = build_efi_model(fv, None)
        lines = []
        save_efi_tree(model, save_modules=False, save_log=True,
                      filetype=[EFI_FV_FILETYPE_DRIVER], lst_lines=lines)
        self.assertEqual(len(lines), 1)

        other = []
        save_efi_tree(model, save_modules=False, save_log=True,
                      filetype=[EFI_FV_FILETYPE_FREEFORM], lst_lines=other)
        self.assertEqual(other, [])

    def test_nvram_node_without_parent_is_reported_not_raised(self):
        fv = _make_fv(0x2000, guid=EFI_NVRAM_GUIDS[0])
        with patch('chipsec.library.uefi.spi.identify_EFI_NVRAM', return_value='vss'):
            model = build_efi_tree(fv, None)
        with tempfile.TemporaryDirectory() as tmp:
            with patch('chipsec.library.uefi.spi.logger') as log:
                result = save_efi_tree(model, path=tmp, save_modules=True, save_log=False)
            self.assertTrue(log.return_value.log_warning.called)
        self.assertEqual(len(result), 1)
        self.assertTrue(result[0]['isNVRAM'])


# ===========================================================================
# strip_capsule_header
# ===========================================================================

class TestStripCapsuleHeaderEdges(unittest.TestCase):

    def _capsule(self, payload, hdr_size=EFI_CAPSULE_HEADER_SIZE, img_size=None,
                 guid=EFI_CAPSULE_GUID):
        if img_size is None:
            img_size = hdr_size + len(payload)
        return struct.pack(EFI_CAPSULE_HEADER_FMT, guid.bytes_le, hdr_size, 0, img_size) + payload

    def test_nested_capsules_are_all_stripped(self):
        payload = b'\xAB' * 64
        data = self._capsule(self._capsule(payload))
        self.assertEqual(strip_capsule_header(data), payload)

    def test_header_size_below_minimum_is_rejected(self):
        data = self._capsule(b'\xCD' * 64, hdr_size=4)
        self.assertEqual(strip_capsule_header(data), data)

    def test_header_size_beyond_data_is_rejected(self):
        data = self._capsule(b'\xCD' * 64, hdr_size=0x10000)
        self.assertEqual(strip_capsule_header(data), data)

    def test_oversized_image_size_still_strips(self):
        payload = b'\xEF' * 64
        data = self._capsule(payload, img_size=0x10000)
        self.assertEqual(strip_capsule_header(data), payload)


# ===========================================================================
# parse_uefi_region_from_file / decode_uefi_region
# ===========================================================================

def _write_rom(directory, name='image.rom'):
    fv = _make_fv(0x2000, body=_make_ffs_file(
        UUID('CDCDCDCD-CDCD-CDCD-CDCD-CDCDCDCDCDCD'), EFI_FV_FILETYPE_FREEFORM,
        _make_section(EFI_SECTION_RAW, b'ROMPAYLOAD!!')))
    path = os.path.join(directory, name)
    with open(path, 'wb') as fh:
        fh.write(fv)
    return path


class TestParseUefiRegionFromFile(unittest.TestCase):

    def test_default_output_directory_and_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            rom = _write_rom(tmp)
            tree = parse_uefi_region_from_file(rom, None)
            self.assertEqual(len(tree), 1)
            self.assertTrue(os.path.isdir(f'{rom}.dir'))
            with open(f'{rom}.UEFI.json') as fh:
                parsed = json.load(fh)
            self.assertEqual(len(parsed), 1)
            self.assertEqual(parsed[0]['class'], 'EFI_FV')
            self.assertTrue(os.path.exists(f'{rom}.UEFI.lst'))

    def test_explicit_output_directory_is_created(self):
        with tempfile.TemporaryDirectory() as tmp:
            rom = _write_rom(tmp)
            out = os.path.join(tmp, 'nested', 'FV')
            tree = parse_uefi_region_from_file(rom, None, out)
            self.assertTrue(os.path.isdir(out))
            self.assertTrue(os.listdir(out))
            self.assertEqual(len(tree), 1)

    def test_capsule_wrapped_image_is_unwrapped_before_parsing(self):
        with tempfile.TemporaryDirectory() as tmp:
            fv = _make_fv(0x2000, body=_make_ffs_file(
                UUID('DADADADA-DADA-DADA-DADA-DADADADADADA'), EFI_FV_FILETYPE_FREEFORM,
                _make_section(EFI_SECTION_RAW, b'CAPSULED!!!!')))
            capsule = struct.pack(EFI_CAPSULE_HEADER_FMT, EFI_CAPSULE_GUID.bytes_le,
                                  EFI_CAPSULE_HEADER_SIZE, 0,
                                  EFI_CAPSULE_HEADER_SIZE + len(fv)) + fv
            rom = os.path.join(tmp, 'capsule.rom')
            with open(rom, 'wb') as fh:
                fh.write(capsule)
            tree = parse_uefi_region_from_file(rom, None, os.path.join(tmp, 'out'))
            self.assertEqual(len(tree), 1)
            self.assertEqual(tree[0].Offset, 0)


class TestDecodeUefiRegion(unittest.TestCase):

    def test_filetype_filter_short_circuits_nvram_decode(self):
        with tempfile.TemporaryDirectory() as tmp:
            rom = _write_rom(tmp)
            with patch('chipsec.library.uefi.spi.parse_EFI_variables') as pev:
                self.assertTrue(decode_uefi_region(tmp, rom, None,
                                                   filetype=[EFI_FV_FILETYPE_FREEFORM]))
            pev.assert_not_called()
            self.assertTrue(os.path.isdir(os.path.join(f'{rom}.dir', 'FV')))

    def test_unidentifiable_nvram_returns_tree_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            rom = _write_rom(tmp)
            with patch('chipsec.library.uefi.spi.identify_EFI_NVRAM', return_value=None), \
                    patch('chipsec.library.uefi.spi.parse_EFI_variables') as pev:
                self.assertTrue(decode_uefi_region(tmp, rom, None))
            pev.assert_not_called()

    def test_unrecognized_fwtype_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            rom = _write_rom(tmp)
            with patch('chipsec.library.uefi.spi.parse_EFI_variables') as pev:
                self.assertTrue(decode_uefi_region(tmp, rom, 'not_a_real_fwtype'))
            pev.assert_not_called()

    def test_unrecognized_fwtype_is_reported_in_hal_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            rom = _write_rom(tmp)
            with patch('chipsec.library.uefi.spi.logger') as log:
                log.return_value.HAL = True
                self.assertTrue(decode_uefi_region(tmp, rom, 'not_a_real_fwtype'))
            log.return_value.log_error.assert_called_once_with(
                'Unrecognized NVRAM type not_a_real_fwtype')

    def test_nvram_decode_writes_listing(self):
        with tempfile.TemporaryDirectory() as tmp:
            rom = _write_rom(tmp)

            def fake_parse(fname, data, *args, **kwargs):
                kwargs['lst_lines'].append('NVRAM LINE')
                return True

            with patch('chipsec.library.uefi.spi.identify_EFI_NVRAM', return_value='vss'), \
                    patch('chipsec.library.uefi.spi.parse_EFI_variables',
                          side_effect=fake_parse) as pev:
                self.assertTrue(decode_uefi_region(tmp, rom, None))
            pev.assert_called_once()
            listing = os.path.join(f'{rom}.dir', 'nvram_vss.nvram.lst')
            with open(listing) as fh:
                self.assertEqual(fh.read(), 'NVRAM LINE')

    def test_failed_nvram_parse_fails_the_decode(self):
        with tempfile.TemporaryDirectory() as tmp:
            rom = _write_rom(tmp)
            with patch('chipsec.library.uefi.spi.identify_EFI_NVRAM', return_value='vss'), \
                    patch('chipsec.library.uefi.spi.parse_EFI_variables', return_value=False):
                self.assertFalse(decode_uefi_region(tmp, rom, None))

    def test_no_firmware_volumes_yields_false(self):
        with tempfile.TemporaryDirectory() as tmp:
            rom = os.path.join(tmp, 'empty.rom')
            with open(rom, 'wb') as fh:
                fh.write(b'\xff' * 0x1000)
            with patch('chipsec.library.uefi.spi.identify_EFI_NVRAM', return_value=None):
                self.assertFalse(decode_uefi_region(tmp, rom, None))


if __name__ == '__main__':
    unittest.main()
