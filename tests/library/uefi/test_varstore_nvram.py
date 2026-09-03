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

import os
import struct
import tempfile
import unittest
from uuid import UUID

import chipsec.library.uefi.varstore as varstore
from chipsec.library.uefi.platform import FWType

VENDOR_GUID = UUID('8BE4DF61-93CA-11D2-AA0D-00E098032B8C')
VENDOR_GUID_BYTES = VENDOR_GUID.bytes_le
VAR_ADDED_STATE = 0x3F


def utf16(name: str) -> bytes:
    return (name + '\x00').encode('utf-16-le')


def vss_variable(name='TestVar', data=b'\xAA' * 8, state=VAR_ADDED_STATE, attributes=0x7):
    encoded = utf16(name)
    header = struct.pack(varstore.HDR_FMT_VSS, varstore.VARIABLE_DATA, state, 0,
                         attributes, len(encoded), len(data), VENDOR_GUID_BYTES)
    return header + encoded + data


def vss_auth_variable(name='AuthVar', data=b'\xBB' * 8, attributes=0x27):
    encoded = utf16(name)
    header = struct.pack(varstore.HDR_FMT_VSS_AUTH, varstore.VARIABLE_DATA, VAR_ADDED_STATE, 0,
                         attributes, 1, 0, 0, 0, len(encoded), len(data), VENDOR_GUID_BYTES)
    return header + encoded + data


def vss_apple_variable(name='AppleVar', data=b'\xCC' * 8, attributes=0x7):
    encoded = utf16(name)
    header = struct.pack(varstore.HDR_FMT_VSS_APPLE, varstore.VARIABLE_DATA, VAR_ADDED_STATE, 0,
                         attributes, len(encoded), len(data), VENDOR_GUID_BYTES, 0)
    return header + encoded + data


def vss_store(*variables):
    body = b''.join(variables) or vss_variable()
    size = struct.calcsize(varstore.VARIABLE_STORE_HEADER_FMT_VSS) + len(body)
    signature = struct.unpack('=I', varstore.VARIABLE_STORE_SIGNATURE_VSS)[0]
    header = struct.pack(varstore.VARIABLE_STORE_HEADER_FMT_VSS, signature, size,
                         varstore.VARIABLE_STORE_FORMATTED, varstore.VARIABLE_STORE_HEALTHY, 0, 0)
    return header + body


def vss2_store(signature=varstore.VARIABLE_STORE_SIGNATURE_VSS2, *variables):
    body = b''.join(variables) or vss_variable()
    size = struct.calcsize(varstore.VARIABLE_STORE_HEADER_FMT_VSS2) + len(body)
    header = struct.pack(varstore.VARIABLE_STORE_HEADER_FMT_VSS2, signature, size,
                         varstore.VARIABLE_STORE_FORMATTED, varstore.VARIABLE_STORE_HEALTHY, 0, 0)
    return header + body


def tlv(tag0: int, payload: bytes, tag1: int = 0) -> bytes:
    return struct.pack(varstore.TLV_HEADER, tag0, tag1, len(payload) + varstore.tlv_h_size) + payload


def evsa_store(name='TestVar', data=b'\xDE\xAD\xBE\xEF', attributes=0x7, guid_id=1, var_id=5):
    guid_record = tlv(0xED, struct.pack('<H16s', guid_id, VENDOR_GUID_BYTES))
    name_record = tlv(0xEE, struct.pack('<H16s', var_id, utf16(name)))
    value_record = tlv(0xEF, struct.pack(f'<HHI{len(data)}s', guid_id, var_id, attributes, data))
    length = varstore.tlv_h_size + 16 + len(guid_record) + len(name_record) + len(value_record)
    store_header = tlv(0xEC, varstore.VARIABLE_STORE_SIGNATURE_EVSA +
                       struct.pack('<III', 0, length, 0))
    return store_header + guid_record + name_record + value_record


class TestVSSStoreDiscovery(unittest.TestCase):
    """The VSS store is located by scanning for its signature."""

    def test_a_vss_store_is_located_by_offset_and_size(self):
        store = vss_store()

        offset, size, header = varstore.getNVstore_VSS(b'\xFF' * 32 + store)

        self.assertEqual(offset, 32)
        self.assertEqual(size, len(store))
        self.assertEqual(header.Format, varstore.VARIABLE_STORE_FORMATTED)

    def test_a_buffer_without_a_signature_has_no_store(self):
        self.assertEqual(varstore.getNVstore_VSS(b'\xFF' * 128), (-1, 0, None))

    def test_a_signature_without_a_valid_variable_is_rejected(self):
        signature = struct.unpack('=I', varstore.VARIABLE_STORE_SIGNATURE_VSS)[0]
        header = struct.pack(varstore.VARIABLE_STORE_HEADER_FMT_VSS, signature, 16, 0x5A, 0xFE, 0, 0)

        self.assertEqual(varstore.getNVstore_VSS(header + b'\xFF' * 64), (-1, 0, None))

    def test_a_vss2_store_is_located_by_its_guid_signature(self):
        store = vss2_store()

        offset, size, header = varstore.getNVstore_VSS2(store)

        self.assertEqual(offset, 0)
        self.assertEqual(size, len(store))
        self.assertEqual(header.Signature, varstore.VARIABLE_STORE_SIGNATURE_VSS2)

    def test_a_vss2_auth_store_uses_a_different_guid(self):
        store = vss2_store(varstore.VARIABLE_STORE_SIGNATURE_VSS2_AUTH, vss_auth_variable())

        offset, _size, _header = varstore.getNVstore_VSS2_AUTH(store)

        self.assertEqual(offset, 0)

    def test_a_vss_auth_store_is_located(self):
        store = vss_store(vss_auth_variable())

        offset, _size, _header = varstore.getNVstore_VSS_AUTH(store)

        self.assertEqual(offset, 0)

    def test_an_apple_store_is_located(self):
        store = vss_store(vss_apple_variable())

        offset, _size, _header = varstore.getNVstore_VSS_APPLE(store)

        self.assertEqual(offset, 0)

    def test_store_headers_render_their_signature(self):
        _off, _size, vss = varstore.getNVstore_VSS(vss_store())
        _off2, _size2, vss2 = varstore.getNVstore_VSS2(vss2_store())

        self.assertIn('$VSS', str(vss))
        self.assertIn(str(UUID(bytes_le=varstore.VARIABLE_STORE_SIGNATURE_VSS2)).upper(), str(vss2).upper())


class TestVSSTypeDetection(unittest.TestCase):

    def test_a_well_formed_vss_variable_confirms_the_type(self):
        self.assertTrue(varstore.isCorrectVSStype(vss_store(), FWType.EFI_FW_TYPE_VSS))

    def test_an_unknown_firmware_type_is_rejected(self):
        self.assertFalse(varstore.isCorrectVSStype(vss_store(), 'not-a-type'))

    def test_a_buffer_without_a_variable_signature_is_rejected(self):
        self.assertFalse(varstore.isCorrectVSStype(b'\x00' * 128, FWType.EFI_FW_TYPE_VSS))

    def test_a_variable_with_an_unprintable_name_is_rejected(self):
        header = struct.pack(varstore.HDR_FMT_VSS, varstore.VARIABLE_DATA, VAR_ADDED_STATE, 0,
                             0x7, 8, 8, VENDOR_GUID_BYTES)
        buf = header + b'\x01\x00' * 4 + b'\xAA' * 8

        self.assertFalse(varstore.isCorrectVSStype(buf, FWType.EFI_FW_TYPE_VSS))

    def test_padding_between_variables_is_tolerated(self):
        store = vss_store(vss_variable(), b'\xFF' * 4, vss_variable(name='Second'))

        self.assertTrue(varstore.isCorrectVSStype(store, FWType.EFI_FW_TYPE_VSS))


class TestVSSVariableExtraction(unittest.TestCase):

    def test_a_variable_name_and_data_are_recovered(self):
        variables = varstore.getEFIvariables_VSS(vss_store(vss_variable(data=b'\x01\x02\x03\x04')))

        self.assertIn('TestVar', variables)
        offset, _buf, header, data, guid, attrs = variables['TestVar'][0]
        self.assertEqual(data, b'\x01\x02\x03\x04')
        self.assertEqual(guid.upper(), str(VENDOR_GUID).upper())
        self.assertEqual(attrs, 0x7)
        self.assertEqual(header.StartId, varstore.VARIABLE_DATA)
        self.assertGreater(offset, 0)

    def test_consecutive_variables_are_all_recovered(self):
        store = vss_store(vss_variable(name='First'), vss_variable(name='Second'))

        variables = varstore.getEFIvariables_VSS(store)

        self.assertEqual(set(variables), {'First', 'Second'})

    def test_repeated_names_are_grouped_together(self):
        store = vss_store(vss_variable(data=b'\x01' * 8), vss_variable(data=b'\x02' * 8))

        variables = varstore.getEFIvariables_VSS(store)

        self.assertEqual(len(variables['TestVar']), 2)

    def test_a_buffer_without_variables_yields_nothing(self):
        self.assertEqual(varstore.getEFIvariables_VSS(b'\x00' * 128), {})

    def test_an_unknown_firmware_type_yields_nothing(self):
        self.assertEqual(varstore._getEFIvariables_VSS(vss_store(), 'not-a-type'), {})

    def test_auth_variables_expose_their_extra_header_fields(self):
        store = vss_store(vss_auth_variable(name='AuthVar', attributes=0x27))

        variables = varstore.getEFIvariables_VSS_AUTH(store)

        self.assertIn('AuthVar', variables)
        header = variables['AuthVar'][0][2]
        self.assertEqual(header.MonotonicCount, 1)
        self.assertEqual(variables['AuthVar'][0][5], 0x27)

    def test_apple_variables_expose_their_extra_field(self):
        store = vss_store(vss_apple_variable(name='AppleVar'))

        variables = varstore.getEFIvariables_VSS_APPLE(store)

        self.assertIn('AppleVar', variables)
        self.assertEqual(variables['AppleVar'][0][2].unknown, 0)

    def test_vss2_variables_use_the_plain_variable_header(self):
        store = vss2_store(varstore.VARIABLE_STORE_SIGNATURE_VSS2, vss_variable(name='Vss2Var'))

        variables = varstore.getEFIvariables_VSS2(store)

        self.assertIn('Vss2Var', variables)

    def test_headers_render_their_decoded_fields(self):
        store = vss_store(vss_variable())
        header = varstore.getEFIvariables_VSS(store)['TestVar'][0][2]

        self.assertIn('Header (VSS)', str(header))
        self.assertIn('Header (VSS_AUTH)', str(varstore.getEFIvariables_VSS_AUTH(
            vss_store(vss_auth_variable()))['AuthVar'][0][2]))
        self.assertIn('Header (VSS_APPLE)', str(varstore.getEFIvariables_VSS_APPLE(
            vss_store(vss_apple_variable()))['AppleVar'][0][2]))


class TestEVSAVariableExtraction(unittest.TestCase):

    def test_a_variable_is_recovered_from_an_evsa_store(self):
        variables = varstore.EFIvar_EVSA(evsa_store(data=b'\x01\x02\x03\x04'))

        self.assertIn('TestVar', variables)
        _off, _buf, _hdr, data, guid, attrs = variables['TestVar'][0]
        self.assertEqual(data, b'\x01\x02\x03\x04')
        self.assertEqual(guid.upper(), str(VENDOR_GUID).upper())
        self.assertEqual(attrs, 0x7)

    def test_the_store_can_be_found_after_other_content(self):
        variables = varstore.EFIvar_EVSA(b'\x00' * 64 + evsa_store())

        self.assertIn('TestVar', variables)

    def test_a_buffer_without_a_signature_yields_nothing(self):
        self.assertEqual(varstore.EFIvar_EVSA(b'\x00' * 128), {})

    def test_a_block_with_the_wrong_tag_is_skipped(self):
        store = bytearray(evsa_store())
        store[0] = 0xAA

        self.assertEqual(varstore.EFIvar_EVSA(bytes(store)), {})

    def test_a_value_without_a_matching_name_is_skipped(self):
        store = evsa_store(var_id=5)
        broken = bytearray(store)
        name_offset = store.find(utf16('TestVar')) - 2
        broken[name_offset] = 0x63  # different variable id

        self.assertEqual(varstore.EFIvar_EVSA(bytes(broken)), {})


class TestNVARVariableExtraction(unittest.TestCase):

    def test_the_simple_format_locates_the_store(self):
        buf = b'\xFF' * 16 + varstore.NVAR_EFIvar_signature + b'\x00' * 64

        self.assertEqual(varstore.getNVstore_NVAR_simple(buf), (16, -1, None))

    def test_a_buffer_without_the_signature_has_no_store(self):
        self.assertEqual(varstore.getNVstore_NVAR_simple(b'\x00' * 32), (-1, -1, None))

    def test_the_simple_format_recovers_names_and_data(self):
        data = b'\x01\x02\x03\x04'
        name = b'TestVar\x00'
        total = varstore.NVAR_HDR_SIZE + len(name) + len(data)
        signature = struct.unpack('=I', varstore.NVAR_EFIvar_signature)[0]
        entry = struct.pack(varstore.NVAR_HDR_FMT, signature, total, 0, 0, 0, 0x7, 0x7F)

        variables = varstore.getEFIvariables_NVAR_simple(entry + name + data)

        self.assertIn('TestVar', variables)
        _off, buf, header, parsed, _guid, attrs = variables['TestVar'][0]
        self.assertEqual(header.TotalSize, total)
        self.assertEqual(attrs, 0x7)
        self.assertEqual(len(buf), total)
        self.assertEqual(parsed, data)

    def test_a_name_without_a_terminator_is_rejected(self):
        signature = struct.unpack('=I', varstore.NVAR_EFIvar_signature)[0]
        total = varstore.NVAR_HDR_SIZE + 8
        entry = struct.pack(
            varstore.NVAR_HDR_FMT, signature, total, 0, 0, 0, 0x7, 0x7F)

        self.assertEqual(
            varstore.getEFIvariables_NVAR_simple(entry + b'NoNull!!'), {})

    def test_name_terminator_search_does_not_cross_entry_boundary(self):
        signature = struct.unpack('=I', varstore.NVAR_EFIvar_signature)[0]
        malformed_size = varstore.NVAR_HDR_SIZE + 8
        malformed = struct.pack(
            varstore.NVAR_HDR_FMT, signature, malformed_size,
            0, 0, 0, 0x7, 0x7F) + b'NoNull!!'
        valid_name = b'Valid\x00'
        valid_data = b'\x01\x02'
        valid_size = varstore.NVAR_HDR_SIZE + len(valid_name) + len(valid_data)
        valid = struct.pack(
            varstore.NVAR_HDR_FMT, signature, valid_size,
            0, 0, 0, 0x7, 0x7F) + valid_name + valid_data

        self.assertEqual(
            varstore.getEFIvariables_NVAR_simple(malformed + valid), {})

    def test_an_empty_buffer_yields_nothing(self):
        self.assertEqual(varstore.getEFIvariables_NVAR_simple(b'\x00' * 32), {})

    def test_the_nvar_header_renders_its_fields(self):
        header = varstore.EFI_HDR_NVAR1(0x5241564E, 0x20, 0, 0, 0, 0x7, 0x7F)

        self.assertIn('Header (NVAR)', str(header))

    def test_invalid_nvar_entries_stop_the_walk(self):
        self.assertEqual(varstore.getEFIvariables_NVAR(b'\x00' * 64), {})


class TestNVRAMIdentification(unittest.TestCase):

    def test_a_vss_store_is_identified(self):
        self.assertEqual(varstore.identify_EFI_NVRAM(vss_store()), FWType.EFI_FW_TYPE_VSS)

    def test_a_vss2_store_is_identified(self):
        self.assertEqual(varstore.identify_EFI_NVRAM(vss2_store()), FWType.EFI_FW_TYPE_VSS2)

    def test_an_unrecognized_buffer_is_not_identified(self):
        self.assertEqual(varstore.identify_EFI_NVRAM(b'\x00' * 256), '')


class TestVariableStoreLookup(unittest.TestCase):

    def test_the_store_is_carved_out_of_the_rom_image(self):
        store = vss_store()
        rom = b'\xFF' * 64 + store + b'\xFF' * 64

        self.assertEqual(varstore.find_EFI_variable_store(rom, FWType.EFI_FW_TYPE_VSS), store)

    def test_a_missing_rom_image_yields_nothing(self):
        self.assertEqual(varstore.find_EFI_variable_store(None, FWType.EFI_FW_TYPE_VSS), b'')

    def test_a_missing_firmware_type_yields_nothing(self):
        self.assertEqual(varstore.find_EFI_variable_store(vss_store(), None), b'')

    def test_a_rom_image_without_a_store_yields_nothing(self):
        self.assertEqual(varstore.find_EFI_variable_store(b'\xFF' * 256, FWType.EFI_FW_TYPE_VSS), b'')


class TestVariableStateFlags(unittest.TestCase):

    def test_an_added_variable_reports_the_added_state(self):
        self.assertTrue(varstore.IS_VARIABLE_STATE(0x3F, varstore.VAR_ADDED))

    def test_a_fully_erased_variable_reports_no_state(self):
        self.assertFalse(varstore.IS_VARIABLE_STATE(0xFF, varstore.VAR_ADDED))

    def test_a_deleted_variable_reports_the_deleted_state(self):
        self.assertTrue(varstore.IS_VARIABLE_STATE(0x3D, varstore.VAR_DELETED))


class TestVariableReporting(unittest.TestCase):

    def setUp(self):
        self.variables = varstore.getEFIvariables_VSS(vss_store(vss_variable(name='ZVar'),
                                                                vss_variable(name='AVar')))

    def test_printing_a_variable_does_not_raise(self):
        offset, buf, header, data, guid, attrs = self.variables['AVar'][0]

        varstore.print_efi_variable(offset, buf, header, 'AVar', data, guid, attrs)

    def test_printing_a_variable_without_a_header_does_not_raise(self):
        varstore.print_efi_variable(0, b'', None, 'AVar', b'\x00', str(VENDOR_GUID), 0x7)

    def test_printing_every_variable_does_not_raise(self):
        varstore.print_sorted_EFI_variables(self.variables)

    def test_decoding_writes_one_file_per_variable(self):
        with tempfile.TemporaryDirectory() as path:
            varstore.decode_EFI_variables(self.variables, path)

            self.assertEqual(len(os.listdir(path)), 2)

    def test_decoded_file_names_include_the_variable_name_and_guid(self):
        with tempfile.TemporaryDirectory() as path:
            varstore.decode_EFI_variables(self.variables, path)

            names = os.listdir(path)
            self.assertTrue(any(n.startswith('AVar_') for n in names))
            self.assertTrue(all(str(VENDOR_GUID).upper() in n.upper() for n in names))


class TestEndToEndParsing(unittest.TestCase):

    def test_a_rom_image_is_parsed_into_variable_files(self):
        rom = b'\xFF' * 32 + vss_store(vss_variable(name='TestVar'))
        with tempfile.TemporaryDirectory() as path:
            fname = os.path.join(path, 'rom.bin')

            self.assertTrue(varstore.parse_EFI_variables(fname, rom, False, FWType.EFI_FW_TYPE_VSS))

            self.assertTrue(os.path.exists(f'{fname}.nvram.bin'))
            self.assertTrue(os.path.isdir(f'{fname}.nvram.dir'))
            self.assertEqual(len(os.listdir(f'{fname}.nvram.dir')), 1)

    def test_an_unknown_firmware_type_is_rejected(self):
        with tempfile.TemporaryDirectory() as path:
            fname = os.path.join(path, 'rom.bin')

            self.assertFalse(varstore.parse_EFI_variables(fname, vss_store(), False, 'not-a-type'))

    def test_a_rom_image_without_nvram_is_reported(self):
        with tempfile.TemporaryDirectory() as path:
            fname = os.path.join(path, 'rom.bin')

            self.assertFalse(varstore.parse_EFI_variables(fname, b'\xFF' * 256, False,
                                                          FWType.EFI_FW_TYPE_VSS))


class TestCertificateDatabases(unittest.TestCase):

    def test_an_auth_certificate_list_is_split_into_entries(self):
        cert = b'\xAB' * 16
        name = utf16('certdb')
        node = struct.pack(varstore.AUTH_CERT_DB_DATA, VENDOR_GUID_BYTES,
                           varstore.AUTH_CERT_DB_DATA_size + len(name) + len(cert),
                           len(name) // 2, len(cert)) + name + cert
        db = struct.pack(varstore.AUTH_CERT_DB_LIST_HEAD,
                         varstore.AUTH_CERT_DB_LIST_HEAD_size + len(node)) + node

        with tempfile.TemporaryDirectory() as path:
            entries = varstore.parse_auth_var(db, path)

            self.assertEqual(entries, [cert])
            expected_name = f'{str(VENDOR_GUID).upper()}-certdb-00.bin'
            self.assertEqual(os.listdir(path), [expected_name])
            with open(os.path.join(path, expected_name), 'rb') as cert_file:
                self.assertEqual(cert_file.read(), cert)

    def test_auth_certificate_filename_replaces_unsafe_characters(self):
        cert = b'\xAB' * 16
        name = utf16('cert:db/name')
        node = struct.pack(
            varstore.AUTH_CERT_DB_DATA, VENDOR_GUID_BYTES,
            varstore.AUTH_CERT_DB_DATA_size + len(name) + len(cert),
            len(name) // 2, len(cert)) + name + cert
        db = struct.pack(
            varstore.AUTH_CERT_DB_LIST_HEAD,
            varstore.AUTH_CERT_DB_LIST_HEAD_size + len(node)) + node

        with tempfile.TemporaryDirectory() as path:
            varstore.parse_auth_var(db, path)

            expected_name = f'{str(VENDOR_GUID).upper()}-cert_db_name-00.bin'
            self.assertEqual(os.listdir(path), [expected_name])

    def test_an_empty_auth_list_yields_no_entries(self):
        with tempfile.TemporaryDirectory() as path:
            self.assertEqual(varstore.parse_auth_var(b'\x00\x00', path), [])

    def test_an_auth_list_with_a_wrong_size_is_rejected(self):
        with tempfile.TemporaryDirectory() as path:
            db = struct.pack(varstore.AUTH_CERT_DB_LIST_HEAD, 0x100) + b'\x00' * 32

            self.assertEqual(varstore.parse_auth_var(db, path), [])

    def test_an_esal_database_is_split_into_fixed_size_keys(self):
        db = b'\x01' * varstore.ESAL_SIG_SIZE + b'\x02' * varstore.ESAL_SIG_SIZE

        with tempfile.TemporaryDirectory() as path:
            entries = varstore.parse_esal_var(db, path)

            self.assertEqual(len(entries), 2)
            self.assertEqual(entries[0], b'\x01' * varstore.ESAL_SIG_SIZE)
            self.assertEqual(len(os.listdir(path)), 2)

    def test_an_esal_database_smaller_than_one_key_yields_nothing(self):
        with tempfile.TemporaryDirectory() as path:
            self.assertEqual(varstore.parse_esal_var(b'\x01' * 8, path), [])

    def test_an_unsupported_variable_type_is_reported(self):
        with tempfile.TemporaryDirectory() as path:
            fname = os.path.join(path, 'var.bin')

            varstore.parse_efivar_file(fname, b'\x00' * 16, var_type=99)

            self.assertTrue(os.path.isdir(f'{fname}.dir'))


if __name__ == '__main__':
    unittest.main()
