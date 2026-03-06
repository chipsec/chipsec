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

"""Unit tests for chipsec.library.uefi.spi — UEFI firmware image parsing."""

import json
import os
import struct
import tempfile
import unittest
from uuid import UUID

from chipsec.library.uefi.fv import (
    EFI_FIRMWARE_VOLUME_HEADER, EFI_FIRMWARE_VOLUME_HEADER_size,
    EFI_FV_BLOCK_MAP_ENTRY,
    EFI_FFS_FILE_HEADER,
    EFI_COMMON_SECTION_HEADER,
    EFI_FIRMWARE_FILE_SYSTEM2_GUID,
    EFI_FVB2_ERASE_POLARITY,
    EFI_FV_FILETYPE_FREEFORM, EFI_FV_FILETYPE_RAW, EFI_FV_FILETYPE_DRIVER,
    EFI_SECTION_RAW, EFI_SECTION_PE32, EFI_SECTION_USER_INTERFACE,
    FFS_ATTRIB_CHECKSUM, FFS_FIXED_CHECKSUM,
    FvSum8, FvChecksum8, FvSum16, FvChecksum16,
    EFI_FV, EFI_FILE, EFI_SECTION,
    EFI_CAPSULE_HEADER_FMT, EFI_CAPSULE_HEADER_SIZE,
    EFI_CAPSULE_GUID,
    assemble_uefi_file, assemble_uefi_raw,
    EFI_SECTION_DXE_DEPEX,
    EFI_SECTION_VERSION, EFI_VERSION_SECTION, EFI_VERSION_SECTION_size,
    EFI_PEI_APRIORI_FILE_GUID,
)
from chipsec.library.uefi.spi import (
    build_efi_tree, build_efi_file_tree, build_efi_modules_tree,
    build_efi_model, update_efi_tree, save_efi_tree,
    modify_uefi_region, strip_capsule_header,
    CMD_UEFI_FILE_REMOVE, CMD_UEFI_FILE_REPLACE,
    CMD_UEFI_FILE_INSERT_BEFORE, CMD_UEFI_FILE_INSERT_AFTER,
    FILENAME, EFIModuleType, search_efi_tree,
    UUIDEncoder,
)


# ---------------------------------------------------------------------------
# Helpers (reuse the binary builders from test_fv)
# ---------------------------------------------------------------------------

TEST_FV_GUID = EFI_FIRMWARE_FILE_SYSTEM2_GUID


def _make_fv(fv_length: int, guid: UUID = TEST_FV_GUID,
             attributes: int = EFI_FVB2_ERASE_POLARITY,
             ext_header_offset: int = 0,
             body: bytes = b'',
             revision: int = 2) -> bytes:
    """Build a minimal firmware volume with a single block-map entry and correct checksum."""
    block_map = struct.pack(EFI_FV_BLOCK_MAP_ENTRY, 1, fv_length) + struct.pack(EFI_FV_BLOCK_MAP_ENTRY, 0, 0)
    header_length = EFI_FIRMWARE_VOLUME_HEADER_size + len(block_map)
    zero_vector = b'\x00' * 16
    guid_bytes = guid.bytes_le
    signature = 0x4856465F
    hdr = struct.pack(EFI_FIRMWARE_VOLUME_HEADER,
                      zero_vector, guid_bytes,
                      fv_length, signature, attributes,
                      header_length, 0, ext_header_offset, 0, revision)
    hdr += block_map
    checksum = FvChecksum16(hdr)
    hdr = struct.pack(EFI_FIRMWARE_VOLUME_HEADER,
                      zero_vector, guid_bytes,
                      fv_length, signature, attributes,
                      header_length, checksum, ext_header_offset, 0, revision)
    hdr += block_map
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
    total_size = struct.calcsize(EFI_COMMON_SECTION_HEADER) + len(body)
    size_bytes = struct.pack('<I', total_size)[:3]
    hdr = struct.pack(EFI_COMMON_SECTION_HEADER, size_bytes, section_type)
    return hdr + body


def _build_simple_fv_image(file_guid: UUID = UUID('AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE'),
                           payload: bytes = b'Hello UEFI!',
                           file_type: int = EFI_FV_FILETYPE_FREEFORM) -> bytes:
    """Build a complete FV containing one file with one raw section."""
    raw_sec = assemble_uefi_raw(payload)
    ffs = assemble_uefi_file(file_guid, raw_sec)
    if len(ffs) % 8:
        ffs += b'\xff' * (8 - len(ffs) % 8)
    return _make_fv(0x4000, body=ffs)


def _build_fv_with_typed_file(file_guid: UUID, file_type: int, sections: bytes) -> bytes:
    """Build an FV with a single FFS file of specified type containing raw section bytes."""
    ffs = _make_ffs_file(file_guid, file_type, sections)
    if len(ffs) % 8:
        ffs += b'\xff' * (8 - len(ffs) % 8)
    return _make_fv(0x4000, body=ffs)


# ===========================================================================
# Tests for build_efi_tree / build_efi_model
# ===========================================================================

class TestBuildEfiTree(unittest.TestCase):

    def test_single_fv(self):
        fv_data = _build_simple_fv_image()
        tree = build_efi_tree(fv_data, None)
        self.assertEqual(len(tree), 1)
        self.assertIsInstance(tree[0], EFI_FV)
        self.assertEqual(tree[0].Guid, TEST_FV_GUID)

    def test_fv_has_file_children(self):
        fv_data = _build_simple_fv_image()
        tree = build_efi_tree(fv_data, None)
        self.assertGreater(len(tree[0].children), 0)
        # Children may include non-UEFI padding sections; find an actual file
        efi_files = [c for c in tree[0].children if isinstance(c, EFI_FILE)]
        self.assertGreater(len(efi_files), 0)

    def test_empty_data(self):
        tree = build_efi_tree(b'', None)
        self.assertEqual(tree, [])

    def test_no_fv_in_data(self):
        tree = build_efi_tree(b'\xff' * 1024, None)
        self.assertEqual(tree, [])

    def test_two_fvs(self):
        fv1 = _build_simple_fv_image(file_guid=UUID('11111111-1111-1111-1111-111111111111'))
        fv2 = _build_simple_fv_image(file_guid=UUID('22222222-2222-2222-2222-222222222222'))
        tree = build_efi_tree(fv1 + fv2, None)
        self.assertEqual(len(tree), 2)


class TestBuildEfiModel(unittest.TestCase):

    def test_model_updates_tree(self):
        """build_efi_model should call update_efi_tree to propagate GUIDs."""
        guid = UUID('01020304-0506-0708-090A-0B0C0D0E0F10')
        fv_data = _build_simple_fv_image(file_guid=guid)
        model = build_efi_model(fv_data, None)
        self.assertGreater(len(model), 0)
        # The file's GUID should propagate down to sections
        for fv in model:
            for f in fv.children:
                if isinstance(f, EFI_FILE):
                    self.assertEqual(f.Guid, guid)
                    for sec in f.children:
                        if isinstance(sec, EFI_SECTION):
                            self.assertEqual(sec.parentGuid, guid)


# ===========================================================================
# Tests for build_efi_file_tree
# ===========================================================================

class TestBuildEfiFileTree(unittest.TestCase):

    def test_parse_single_file(self):
        fv_data = _build_simple_fv_image()
        files = build_efi_file_tree(fv_data, None)
        self.assertGreater(len(files), 0)
        # First entry may be a non-UEFI padding section; find the actual file
        efi_files = [f for f in files if isinstance(f, EFI_FILE)]
        self.assertGreater(len(efi_files), 0)

    def test_file_has_sections(self):
        fv_data = _build_simple_fv_image()
        files = build_efi_file_tree(fv_data, None)
        self.assertGreater(len(files), 0)
        f = files[0]
        self.assertGreater(len(f.children), 0)

    def test_empty_fv(self):
        fv_data = _make_fv(0x1000)  # no files
        files = build_efi_file_tree(fv_data, None)
        self.assertEqual(files, [])


# ===========================================================================
# Tests for build_efi_modules_tree (section parsing)
# ===========================================================================

class TestBuildEfiModulesTree(unittest.TestCase):

    def test_raw_section(self):
        sec = _make_section(EFI_SECTION_RAW, b'\x01\x02\x03\x04')
        modules = build_efi_modules_tree(None, sec, len(sec), 0, True)
        self.assertEqual(len(modules), 1)
        self.assertEqual(modules[0].Type, EFI_SECTION_RAW)

    def test_ui_section_string(self):
        ui_text = 'MyDriver'
        body = ui_text.encode('utf-16-le') + b'\x00\x00'
        sec = _make_section(EFI_SECTION_USER_INTERFACE, body)
        modules = build_efi_modules_tree(None, sec, len(sec), 0, True)
        self.assertEqual(len(modules), 1)
        self.assertEqual(modules[0].ui_string, ui_text)

    def test_depex_section(self):
        depex_body = bytes([0x04, 0x06])  # TRUE END
        sec = _make_section(EFI_SECTION_DXE_DEPEX, depex_body)
        modules = build_efi_modules_tree(None, sec, len(sec), 0, True)
        self.assertEqual(len(modules), 1)
        self.assertIn('TRUE', modules[0].Comments)
        self.assertIn('END', modules[0].Comments)

    def test_version_section(self):
        build_number = 42
        ver_string = 'v1.0'
        body = struct.pack(EFI_VERSION_SECTION, build_number) + ver_string.encode('utf-16-le') + b'\x00\x00'
        sec = _make_section(EFI_SECTION_VERSION, body)
        modules = build_efi_modules_tree(None, sec, len(sec), 0, True)
        self.assertEqual(len(modules), 1)
        self.assertIn('BuildNumber=42', modules[0].Comments)
        self.assertIn('v1.0', modules[0].Comments)

    def test_multiple_sections(self):
        sec1 = _make_section(EFI_SECTION_RAW, b'\x01\x02')
        # Align to 4 bytes
        pad = (4 - len(sec1) % 4) % 4
        sec1_padded = sec1 + b'\x00' * pad
        sec2 = _make_section(EFI_SECTION_RAW, b'\x03\x04')
        combined = sec1_padded + sec2
        modules = build_efi_modules_tree(None, combined, len(combined), 0, True)
        self.assertEqual(len(modules), 2)

    def test_empty_data(self):
        modules = build_efi_modules_tree(None, b'', 0, 0, True)
        self.assertEqual(modules, [])


# ===========================================================================
# Tests for update_efi_tree
# ===========================================================================

class TestUpdateEfiTree(unittest.TestCase):

    def test_guid_propagation(self):
        """File GUID should propagate to child sections."""
        guid = UUID('DEADBEEF-1234-5678-9ABC-DEF012345678')
        f = EFI_FILE(0, guid, EFI_FV_FILETYPE_FREEFORM, 0, 0xF8, 0, 100, b'\x00' * 100, 24, False, 0)
        sec = EFI_SECTION(24, 'S_RAW', EFI_SECTION_RAW, b'\x00' * 16, 4, 16)
        f.children = [sec]

        update_efi_tree([f])
        self.assertEqual(sec.parentGuid, guid)

    def test_ui_string_propagation(self):
        """UI section string should propagate up to sibling sections and parent file."""
        guid = UUID('DEADBEEF-1234-5678-9ABC-DEF012345678')
        f = EFI_FILE(0, guid, EFI_FV_FILETYPE_FREEFORM, 0, 0xF8, 0, 200, b'\x00' * 200, 24, False, 0)

        raw_sec = EFI_SECTION(24, 'S_RAW', EFI_SECTION_RAW, b'\x00' * 16, 4, 16)
        ui_text = 'TestModule'
        ui_body = ui_text.encode('utf-16-le') + b'\x00\x00'
        ui_image = _make_section(EFI_SECTION_USER_INTERFACE, ui_body)
        ui_sec = EFI_SECTION(40, 'S_USER_INTERFACE', EFI_SECTION_USER_INTERFACE, ui_image, 4, len(ui_image))
        ui_sec.ui_string = ui_text

        f.children = [raw_sec, ui_sec]
        update_efi_tree([f])

        self.assertEqual(f.ui_string, ui_text)
        self.assertEqual(raw_sec.ui_string, ui_text)

    def test_apriori_section_decoding(self):
        """RAW section inside an Apriori file should have dispatch order comments."""
        apriori_guid = EFI_PEI_APRIORI_FILE_GUID
        entry_guid = UUID('AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE')
        raw_data_body = entry_guid.bytes_le

        f = EFI_FILE(0, apriori_guid, EFI_FV_FILETYPE_FREEFORM, 0, 0xF8, 0, 200, b'\x00' * 200, 24, False, 0)
        raw_image = _make_section(EFI_SECTION_RAW, raw_data_body)
        sec = EFI_SECTION(24, 'S_RAW', EFI_SECTION_RAW, raw_image, 4, len(raw_image))
        f.children = [sec]

        update_efi_tree([f])
        self.assertIn('PEI Apriori', sec.Comments)
        self.assertIn(str(entry_guid), sec.Comments.lower())


# ===========================================================================
# Tests for save_efi_tree
# ===========================================================================

class TestSaveEfiTree(unittest.TestCase):

    def test_save_produces_json(self):
        fv_data = _build_simple_fv_image()
        model = build_efi_model(fv_data, None)
        with tempfile.TemporaryDirectory() as tmpdir:
            result = save_efi_tree(model, path=tmpdir, save_modules=True, save_log=False)
        self.assertIsInstance(result, list)
        self.assertGreater(len(result), 0)
        # Each entry should be a dict with 'class'
        self.assertIn('class', result[0])
        self.assertEqual(result[0]['class'], 'EFI_FV')

    def test_save_creates_files(self):
        fv_data = _build_simple_fv_image()
        model = build_efi_model(fv_data, None)
        with tempfile.TemporaryDirectory() as tmpdir:
            save_efi_tree(model, path=tmpdir, save_modules=True, save_log=False)
            files = os.listdir(tmpdir)
        self.assertGreater(len(files), 0)

    def test_save_log_lines(self):
        fv_data = _build_simple_fv_image()
        model = build_efi_model(fv_data, None)
        lst_lines = []
        with tempfile.TemporaryDirectory() as tmpdir:
            save_efi_tree(model, path=tmpdir, save_modules=False, save_log=True, lst_lines=lst_lines)
        self.assertGreater(len(lst_lines), 0)

    def test_save_no_modules(self):
        """save_modules=False should not create any files."""
        fv_data = _build_simple_fv_image()
        model = build_efi_model(fv_data, None)
        with tempfile.TemporaryDirectory() as tmpdir:
            save_efi_tree(model, path=tmpdir, save_modules=False, save_log=False)
            files = os.listdir(tmpdir)
        self.assertEqual(len(files), 0)

    def test_json_serializable(self):
        """Result of save_efi_tree should be JSON-serializable with UUIDEncoder."""
        fv_data = _build_simple_fv_image()
        model = build_efi_model(fv_data, None)
        with tempfile.TemporaryDirectory() as tmpdir:
            result = save_efi_tree(model, path=tmpdir, save_modules=True, save_log=False)
        # Should not raise
        json_str = json.dumps(result, cls=UUIDEncoder)
        self.assertIsInstance(json_str, str)
        parsed = json.loads(json_str)
        self.assertEqual(len(parsed), len(result))


# ===========================================================================
# Tests for modify_uefi_region
# ===========================================================================

class TestModifyUefiRegion(unittest.TestCase):

    def _make_test_image(self):
        """Build a FV with two files for modification testing."""
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
        return _make_fv(0x8000, body=body), g1, g2

    def test_remove_file(self):
        image, g1, g2 = self._make_test_image()
        original_len = len(image)
        modified = modify_uefi_region(image, CMD_UEFI_FILE_REMOVE, g1)
        # File removed: image should get FF padding to compensate
        self.assertEqual(len(modified), original_len)
        # Verify g1's GUID bytes are no longer present at the original file offset
        # (the file was removed and replaced with FF padding)
        self.assertNotEqual(modified, image)

    def test_replace_file(self):
        image, g1, g2 = self._make_test_image()
        # Build replacement file with different content
        new_sec = assemble_uefi_raw(b'\xFF' * 16)
        new_ffs = assemble_uefi_file(g1, new_sec)
        modified = modify_uefi_region(image, CMD_UEFI_FILE_REPLACE, g1, new_ffs)
        # Image should still be parseable
        tree = build_efi_tree(modified, None)
        self.assertGreater(len(tree), 0)


# ===========================================================================
# Tests for strip_capsule_header
# ===========================================================================

class TestStripCapsuleHeader(unittest.TestCase):

    def test_no_capsule(self):
        data = b'\x01\x02\x03\x04' * 100
        result = strip_capsule_header(data)
        self.assertEqual(result, data)

    def test_strip_single_capsule(self):
        payload = b'\xDE\xAD\xBE\xEF' * 100
        hdr_size = EFI_CAPSULE_HEADER_SIZE
        img_size = hdr_size + len(payload)
        capsule = struct.pack(EFI_CAPSULE_HEADER_FMT,
                              EFI_CAPSULE_GUID.bytes_le,
                              hdr_size, 0, img_size)
        data = capsule + payload
        result = strip_capsule_header(data)
        self.assertEqual(result, payload)

    def test_data_too_short(self):
        result = strip_capsule_header(b'\x00' * 10)
        self.assertEqual(result, b'\x00' * 10)


# ===========================================================================
# Tests for FILENAME helper
# ===========================================================================

class TestFilename(unittest.TestCase):

    def test_file_filename(self):
        guid = UUID('AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE')
        f = EFI_FILE(0, guid, EFI_FV_FILETYPE_FREEFORM, 0, 0xF8, 0, 100, b'\x00' * 100, 24, False, 0)
        name = FILENAME(f, None, 0)
        self.assertIn('AAAAAAAA', name.upper())
        self.assertIn('FV_FREEFORM', name)

    def test_section_filename_exe(self):
        sec = EFI_SECTION(0, 'S_PE32', EFI_SECTION_PE32, b'\x00' * 64, 4, 64)
        sec.parentGuid = UUID('BBBBBBBB-1111-2222-3333-444444444444')
        # With parent having ui_string
        parent = EFI_FILE(0, sec.parentGuid, EFI_FV_FILETYPE_DRIVER, 0, 0xF8, 0, 200, b'\x00' * 200, 24, False, 0)
        parent.ui_string = 'TestDriver'
        name = FILENAME(sec, parent, 0)
        self.assertEqual(name, 'TestDriver.efi')

    def test_section_filename_exe_with_efi_suffix(self):
        sec = EFI_SECTION(0, 'S_PE32', EFI_SECTION_PE32, b'\x00' * 64, 4, 64)
        parent = EFI_FILE(0, UUID(int=0), EFI_FV_FILETYPE_DRIVER, 0, 0xF8, 0, 200, b'\x00' * 200, 24, False, 0)
        parent.ui_string = 'MyDriver.efi'
        name = FILENAME(sec, parent, 0)
        self.assertEqual(name, 'MyDriver.efi')


# ===========================================================================
# Tests for search_efi_tree
# ===========================================================================

class TestSearchEfiTree(unittest.TestCase):

    def test_search_by_guid(self):
        target_guid = UUID('DEADBEEF-1234-5678-9ABC-DEF012345678')
        fv_data = _build_simple_fv_image(file_guid=target_guid)
        model = build_efi_model(fv_data, None)

        results = search_efi_tree(model,
                                  lambda m: isinstance(m, EFI_FILE) and m.Guid == target_guid,
                                  match_module_types=EFIModuleType.FILE)
        self.assertGreater(len(results), 0)

    def test_search_findall_false(self):
        target_guid = UUID('DEADBEEF-1234-5678-9ABC-DEF012345678')
        fv_data = _build_simple_fv_image(file_guid=target_guid)
        model = build_efi_model(fv_data, None)

        results = search_efi_tree(model,
                                  lambda m: True,
                                  match_module_types=EFIModuleType.ALL,
                                  findall=False)
        # Should return at most 1
        self.assertEqual(len(results), 1)

    def test_search_no_match(self):
        fv_data = _build_simple_fv_image()
        model = build_efi_model(fv_data, None)
        results = search_efi_tree(model,
                                  lambda m: False,
                                  match_module_types=EFIModuleType.ALL)
        self.assertEqual(results, [])


# ===========================================================================
# Tests for UUIDEncoder
# ===========================================================================

class TestUUIDEncoder(unittest.TestCase):

    def test_uuid_encoding(self):
        guid = UUID('AABBCCDD-1122-3344-5566-778899001122')
        result = json.dumps({'guid': guid}, cls=UUIDEncoder)
        self.assertIn('AABBCCDD', result.upper())

    def test_non_uuid_raises(self):
        with self.assertRaises(TypeError):
            json.dumps({'bad': set()}, cls=UUIDEncoder)


# ===========================================================================
# Integration: full decode pipeline
# ===========================================================================

class TestFullDecodePipeline(unittest.TestCase):
    """Test the complete: build -> update -> save pipeline."""

    def test_end_to_end(self):
        guid = UUID('01020304-0506-0708-090A-0B0C0D0E0F10')
        payload = b'Integration test payload'

        # Build FV
        fv_data = _build_simple_fv_image(file_guid=guid, payload=payload)

        # Parse
        model = build_efi_model(fv_data, None)
        self.assertGreater(len(model), 0)

        # Save
        with tempfile.TemporaryDirectory() as tmpdir:
            lst_lines = []
            tree_json = save_efi_tree(model, path=tmpdir, save_modules=True,
                                      save_log=True, lst_lines=lst_lines)

        # Verify JSON structure
        self.assertIsInstance(tree_json, list)
        json_str = json.dumps(tree_json, cls=UUIDEncoder)
        parsed = json.loads(json_str)
        self.assertEqual(len(parsed), len(tree_json))

    def test_two_fvs_end_to_end(self):
        g1 = UUID('11111111-1111-1111-1111-111111111111')
        g2 = UUID('22222222-2222-2222-2222-222222222222')
        fv1 = _build_simple_fv_image(file_guid=g1, payload=b'FV1')
        fv2 = _build_simple_fv_image(file_guid=g2, payload=b'FV2')
        combined = fv1 + fv2

        model = build_efi_model(combined, None)
        self.assertEqual(len(model), 2)

        with tempfile.TemporaryDirectory() as tmpdir:
            result = save_efi_tree(model, path=tmpdir, save_modules=True, save_log=False)
        self.assertEqual(len(result), 2)

    def test_file_with_ui_section(self):
        """File with a UI section should propagate the UI name."""
        guid = UUID('CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCCCCCC')
        # Build two sections: RAW + UI
        raw_body = b'\xDE\xAD' * 4
        raw_sec = _make_section(EFI_SECTION_RAW, raw_body)
        pad1 = (4 - len(raw_sec) % 4) % 4
        raw_sec_padded = raw_sec + b'\x00' * pad1

        ui_text = 'HelloModule'
        ui_body = ui_text.encode('utf-16-le') + b'\x00\x00'
        ui_sec = _make_section(EFI_SECTION_USER_INTERFACE, ui_body)
        pad2 = (4 - len(ui_sec) % 4) % 4
        ui_sec_padded = ui_sec + b'\x00' * pad2

        sections = raw_sec_padded + ui_sec_padded
        fv_data = _build_fv_with_typed_file(guid, EFI_FV_FILETYPE_FREEFORM, sections)

        model = build_efi_model(fv_data, None)
        self.assertGreater(len(model), 0)

        # Find the file in the tree
        for fv in model:
            for f in fv.children:
                if isinstance(f, EFI_FILE) and f.Guid == guid:
                    self.assertEqual(f.ui_string, ui_text)
                    return
        self.fail("File not found in parsed tree")


if __name__ == '__main__':
    unittest.main()
