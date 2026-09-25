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
import unittest
from unittest.mock import MagicMock, patch

from chipsec.library.acpi_tables import (
    APIC,
    BERT,
    DMAR,
    EINJ,
    ERST,
    FADT,
    HEST,
    MSCT,
    NFIT,
    RASF,
    RSDP,
    RSDT,
    SPMI,
)


def gas(space_id=0, width=32, offset=0, access=3, addr=0xFED40000):
    """Build a 12 byte Generic Address Structure."""
    return struct.pack('<BBBBQ', space_id, width, offset, access, addr)


########################################################################################################
#
# RSDP validation corner cases
#
########################################################################################################


def build_rsdp_raw(revision=2, rsdt=0x7A611000, xsdt=0x7A612000,
                   length=36, signature=b'RSD PTR ', reserved=b'\x00\x00\x00'):
    """Build an extended RSDP with both checksums fixed up."""
    head = bytearray(struct.pack('<8sB6sBI', signature, 0, b'CHIPSC', revision, rsdt))
    head[8] = (-sum(head)) & 0xFF
    tail = bytearray(struct.pack('<IQB3s', length, xsdt, 0, reserved))
    tail[12] = (-(sum(head) + sum(tail))) & 0xFF
    return bytes(head + tail)


class TestRSDPExtendedValidation(unittest.TestCase):
    """Revision 2 RSDPs carry a length that has to agree with the buffer."""

    def test_extended_length_below_the_structure_size_is_invalid(self):
        rsdp = RSDP()
        rsdp.parse(build_rsdp_raw(length=20))

        self.assertEqual(rsdp.Length, 20)
        self.assertFalse(rsdp.is_RSDP_valid())

    def test_extended_length_beyond_the_buffer_is_invalid(self):
        rsdp = RSDP()
        rsdp.parse(build_rsdp_raw(length=64))

        self.assertEqual(rsdp.Length, 64)
        self.assertFalse(rsdp.is_RSDP_valid())

    def test_consistent_extended_rsdp_is_valid(self):
        rsdp = RSDP()
        rsdp.parse(build_rsdp_raw())

        self.assertTrue(rsdp.is_RSDP_valid())

    def test_rendering_hex_encodes_the_reserved_bytes(self):
        rsdp = RSDP()
        rsdp.parse(build_rsdp_raw(reserved=b'\xde\xad\xbe'))

        self.assertIn('Reserved         : deadbe', str(rsdp))


########################################################################################################
#
# RSDT rendering / degenerate content
#
########################################################################################################


class TestRSDTDegenerateContent(unittest.TestCase):

    def test_content_smaller_than_one_entry_yields_no_entries(self):
        rsdt = RSDT()
        rsdt.parse(b'\x00\x00')

        self.assertEqual(rsdt.Entries, ())

    def test_entries_are_listed_when_rendered(self):
        rsdt = RSDT()
        rsdt.parse(struct.pack('<2I', 0x7A611000, 0x7A612000))
        rendered = str(rsdt)

        self.assertIn('Root System Description Table (RSDT)', rendered)
        self.assertIn('0x000000007A611000', rendered)
        self.assertIn('0x000000007A612000', rendered)


########################################################################################################
#
# DMAR truncation and device scope rendering
#
########################################################################################################


DMAR_HEADER = struct.pack('=BB10s', 39, 1, b'\x00' * 10)


def device_scope(ds_type=1, enum_id=0, start_bus=0, path=b'\x1f\x00'):
    return struct.pack('=BBBBBB', ds_type, 6 + len(path), 0, 0, enum_id, start_bus) + path


class TestDMARExtended(unittest.TestCase):

    def setUp(self):
        self.dmar = DMAR()

    def test_header_fields_are_decoded(self):
        self.dmar.parse(DMAR_HEADER)

        self.assertEqual(self.dmar.HostAddrWidth, 39)
        self.assertEqual(self.dmar.Flags, 1)
        self.assertEqual(self.dmar.dmar_structures, [])

    def test_trailing_bytes_too_small_for_a_header_stop_parsing(self):
        # 12 byte header plus 2 stray bytes: the loop starts but cannot read a
        # 4 byte structure header.
        self.dmar.parse(DMAR_HEADER + b'\x00\x00')

        self.assertEqual(self.dmar.dmar_structures, [])
        self.assertEqual(self.dmar.HostAddrWidth, 39)

    def test_zero_length_device_scope_entry_stops_the_scope_walk(self):
        scopes = self.dmar._get_DMAR_Device_Scope_list(struct.pack('=BB', 1, 0) + b'\x00' * 6)

        self.assertEqual(scopes, [])

    def test_ats_capability_lists_its_device_scope(self):
        structure = struct.pack('=HHBBH', 2, 16, 0, 0, 0) + device_scope(ds_type=2)

        rendered = self.dmar._get_structure_DMAR(0x02, structure)

        self.assertIn('Root Port ATS Capability', rendered)
        self.assertIn('PCI-PCI Bridge', rendered)
        self.assertIn('Path: 1f00', rendered)

    def test_soc_translation_cache_lists_its_device_scope(self):
        # Types 5 and 6 are returned unwrapped, so the caller renders them.
        structure = struct.pack('HHBBH', 5, 16, 1, 0, 0) + device_scope(ds_type=1)

        rendered = str(self.dmar._get_structure_DMAR(0x05, structure))

        self.assertIn('SoC Integrated Address Translation Cache', rendered)
        self.assertIn('PCI Endpoint Device', rendered)

    def test_soc_device_property_lists_its_device_scope(self):
        structure = struct.pack('HHHH', 6, 16, 0, 0) + device_scope(ds_type=5)

        rendered = str(self.dmar._get_structure_DMAR(0x06, structure))

        self.assertIn('Reporting Structure', rendered)
        self.assertIn('ACPI Namespace Device', rendered)

    def test_table_rendering_includes_every_structure(self):
        drhd = struct.pack('=HHBBHQ', 0, 24, 1, 0, 0, 0xFED90000) + device_scope(ds_type=3)
        self.dmar.parse(DMAR_HEADER + drhd)
        rendered = str(self.dmar)

        self.assertIn('DMAR Table Contents', rendered)
        self.assertIn('Host Address Width  : 39', rendered)
        self.assertIn('Register Base Address : 0x00000000FED90000', rendered)
        self.assertIn('I/O APIC Device', rendered)


########################################################################################################
#
# APIC truncation, rendering and the local SAPIC structure
#
########################################################################################################


class TestAPICExtended(unittest.TestCase):

    def test_trailing_bytes_too_small_for_a_header_stop_parsing(self):
        # 8 byte header plus one stray byte: the loop starts but cannot read a
        # 2 byte structure header.
        apic = APIC()
        apic.parse(struct.pack('=II', 0xFEE00000, 1) + b'\x00')

        self.assertEqual(apic.apic_structs, [])

    def test_table_rendering_includes_the_parsed_structures(self):
        apic = APIC()
        body = struct.pack('<BBBBI', 0x00, 8, 1, 2, 1)
        body += struct.pack('<BBBBII', 0x01, 12, 2, 0, 0xFEC00000, 0)
        apic.parse(struct.pack('=II', 0xFEE00000, 1) + body)
        rendered = str(apic)

        self.assertEqual(len(apic.apic_structs), 2)
        self.assertIn('APIC Table Contents', rendered)
        self.assertIn('Local APIC Base  : 0x00000000FEE00000', rendered)
        self.assertIn('Flags            : 0x00000001', rendered)
        self.assertIn('Processor Local APIC', rendered)
        self.assertIn('I/O APIC', rendered)

    def test_local_sapic_string_field_cannot_be_rendered(self):
        # The parser stores ACPIProcUIDString as bytes but renders it with an
        # integer format specifier, so rendering the structure always fails.
        apic = APIC()
        data = struct.pack('<BBBBBHII', 0x07, 20, 1, 2, 3, 0, 1, 7) + b'CPU0\x00'

        with self.assertRaises(TypeError):
            apic.get_structure_APIC(0x07, data)


########################################################################################################
#
# FADT logging
#
########################################################################################################


class TestFADTLogging(unittest.TestCase):

    def test_missing_extended_pointer_is_logged_in_hal_mode(self):
        fadt = FADT()
        fake_logger = MagicMock()
        fake_logger.HAL = True

        with patch('chipsec.library.acpi_tables.logger', return_value=fake_logger):
            fadt.parse(bytes(64))

        self.assertIsNone(fadt.x_dsdt)
        fake_logger.log.assert_called_once_with('[acpi] Cannot find X_DSDT entry in FADT.')

    def test_nothing_is_logged_when_hal_mode_is_off(self):
        fadt = FADT()
        fake_logger = MagicMock()
        fake_logger.HAL = False

        with patch('chipsec.library.acpi_tables.logger', return_value=fake_logger):
            fadt.parse(bytes(64))

        fake_logger.log.assert_not_called()


########################################################################################################
#
# BERT Table
#
########################################################################################################


def bert_error_entry(severity=1, revision=2, validation=1, flags=0x01,
                     err_data_len=0, fru=(0, 0, 0, 0), fru_text=b'FRU-TEXT',
                     timestamp=(30, 45, 13, 1, 15, 6, 24, 20)):
    """Build a 72 byte Generic Error Data Entry."""
    data = struct.pack('<4L', 0xA5BC1114, 0x4EDE6F64, 0x833E63B8, 0xB1837CED)
    data += struct.pack('<L', severity)
    data += struct.pack('<HBB', revision, validation, flags)
    data += struct.pack('<L', err_data_len)
    data += struct.pack('<4L', *fru)
    data += struct.pack('<20s', fru_text)
    data += struct.pack('<8B', *timestamp)
    return data


def bert_boot_region(block_status=0x0000_0003, raw_offset=0x40, raw_len=0x10,
                     data_len=0x20, severity=2, entry=None):
    """Build a Generic Error Status Block followed by one data entry."""
    header = struct.pack('<5L', block_status, raw_offset, raw_len, data_len, severity)
    return header + (bert_error_entry() if entry is None else entry)


class TestBERT(unittest.TestCase):
    """BERT points at a boot error region holding a generic error status block."""

    def test_boot_region_pointer_is_decoded(self):
        bert = BERT(bert_boot_region())
        bert.parse(struct.pack('<LQ', 92, 0x7ABC0000))

        self.assertEqual(bert.BootRegionLen, 92)
        self.assertEqual(bert.BootRegionAddr, 0x7ABC0000)

    def test_constructor_retains_the_supplied_boot_region(self):
        region = bert_boot_region()
        bert = BERT(region)

        self.assertEqual(bert.bootRegion, region)

    def test_status_block_fields_are_decoded(self):
        bert = BERT(bert_boot_region())
        bert.parse(struct.pack('<LQ', 92, 0x7ABC0000))

        self.assertIn('Generic Error Status Block', bert.BootRegion)
        self.assertIn('Block Status                                    : 0x00000003', bert.BootRegion)
        self.assertIn('Raw Data Offset                                 : 0x00000040 ( 64 )', bert.BootRegion)
        self.assertIn('Error Severity                                  : 0x00000002 - Corrected', bert.BootRegion)

    def test_data_entry_severity_and_revision_are_decoded(self):
        bert = BERT(bert_boot_region(entry=bert_error_entry(severity=1, revision=2)))
        bert.parse(struct.pack('<LQ', 92, 0))

        self.assertIn('Error Severity                                : 1 - Fatal', bert.BootRegion)
        self.assertIn('Revision                                      : 0x0002 - Should be 0x003', bert.BootRegion)

    def test_expected_revision_is_not_flagged(self):
        bert = BERT(bert_boot_region(entry=bert_error_entry(revision=3)))
        bert.parse(struct.pack('<LQ', 92, 0))

        self.assertIn('Revision                                      : 0x0003\n', bert.BootRegion)

    def test_out_of_range_severity_falls_back_to_the_catch_all(self):
        bert = BERT(bert_boot_region(severity=9, entry=bert_error_entry(severity=9)))
        bert.parse(struct.pack('<LQ', 92, 0))

        self.assertIn('Error Severity                                : 9 - Unknown severity entry', bert.BootRegion)

    def test_all_zero_fru_id_is_flagged_as_the_default(self):
        bert = BERT(bert_boot_region())
        bert.parse(struct.pack('<LQ', 92, 0))

        self.assertIn('Default value, invalid FRU ID', bert.BootRegion)

    def test_populated_fru_id_is_not_flagged(self):
        bert = BERT(bert_boot_region(entry=bert_error_entry(fru=(1, 2, 3, 4))))
        bert.parse(struct.pack('<LQ', 92, 0))

        self.assertIn('FRU Id                                        : 1 2 3 4\n', bert.BootRegion)

    def test_timestamp_is_rendered_as_a_calendar_date(self):
        bert = BERT(bert_boot_region())
        bert.parse(struct.pack('<LQ', 92, 0))

        self.assertIn('13:45:30 6/15/2024 [m/d/y]', bert.BootRegion)
        self.assertIn('time is percise', bert.BootRegion)

    def test_imprecise_timestamp_omits_the_precision_note(self):
        entry = bert_error_entry(timestamp=(0, 0, 1, 0, 2, 3, 24, 20))
        bert = BERT(bert_boot_region(entry=entry))
        bert.parse(struct.pack('<LQ', 92, 0))

        self.assertIn('1:0:0 3/2/2024 [m/d/y]', bert.BootRegion)
        self.assertNotIn('time is percise', bert.BootRegion)

    def test_section_type_guid_is_reported_as_unknown(self):
        bert = BERT(bert_boot_region())

        decoded = bert.parseSectionType(struct.pack('<4L', 1, 2, 3, 4))

        self.assertEqual(decoded, '0x00000001 0x00000002 0x00000003 0x00000004 - Unknown')

    def test_flag_bits_are_broken_out(self):
        bert = BERT(bert_boot_region(entry=bert_error_entry(flags=0x05)))
        bert.parse(struct.pack('<LQ', 92, 0))

        self.assertIn('Primary                                     : 0x01', bert.BootRegion)
        self.assertIn('Reset                                       : 0x04', bert.BootRegion)
        self.assertIn('Containment Warning                         : 0x00', bert.BootRegion)

    def test_rendering_includes_the_boot_region(self):
        bert = BERT(bert_boot_region())
        bert.parse(struct.pack('<LQ', 92, 0x7ABC0000))
        rendered = str(bert)

        self.assertIn('Boot Region Length                                : 92', rendered)
        self.assertIn('Boot Region Address                               : 0x000000007ABC0000', rendered)
        self.assertIn('Generic Error Status Block', rendered)

    def test_entry_payload_cannot_be_decoded(self):
        # A non-zero error data length makes the parser unpack the payload with
        # the native-only 'P' format under a little-endian prefix.
        bert = BERT(bert_boot_region(entry=bert_error_entry(err_data_len=8)))

        with self.assertRaises(struct.error):
            bert.parse(struct.pack('<LQ', 92, 0))


########################################################################################################
#
# EINJ Table
#
########################################################################################################


def einj_entry(action=0, instruction=2, flags=1, reserved=0,
               value=0xDEADBEEF, mask=0xFFFFFFFF, register=None):
    """Build a 32 byte Injection Instruction Entry."""
    return (struct.pack('<4B', action, instruction, flags, reserved) +
            (gas() if register is None else register) +
            struct.pack('<QQ', value, mask))


def einj_table(header_size=48, flags=0, reserved=(0, 0, 0), entries=()):
    body = struct.pack('<L', header_size)
    body += struct.pack('<4B', flags, *reserved)
    body += struct.pack('<L', len(entries))
    return body + b''.join(entries)


class TestEINJ(unittest.TestCase):
    """EINJ describes the error injection action table."""

    def test_header_fields_are_decoded(self):
        einj = EINJ()
        einj.parse(einj_table(header_size=48, entries=(einj_entry(),)))
        rendered = str(einj)

        self.assertIn('Injection Header Size                             : 0x0000000000000030 ( 48 )', rendered)
        self.assertIn('Injection Entry Count                             : 0x00000001 ( 1 )', rendered)

    def test_non_zero_header_flags_are_flagged(self):
        einj = EINJ()
        einj.parse(einj_table(flags=1))

        self.assertIn('Injection Flags                                   : 0x01 - Error, this field should be 0', str(einj))

    def test_non_zero_reserved_bytes_are_flagged(self):
        einj = EINJ()
        einj.parse(einj_table(reserved=(1, 2, 3)))

        self.assertIn('Reserved                                        : 0x030201 - Error, this field should be 0', str(einj))

    def test_no_entries_produces_only_a_header(self):
        einj = EINJ()
        einj.parse(einj_table())

        self.assertNotIn('Injection Instruction Entry\n', str(einj))

    def test_known_action_and_instruction_are_named(self):
        einj = EINJ()
        einj.parse(einj_table(entries=(einj_entry(action=0, instruction=2, flags=1),)))
        rendered = str(einj)

        self.assertIn('Injection Action                                : 0x00 ( 0 ) - BEGIN_INJECTION_OPERATION', rendered)
        self.assertIn('Instruction                                     : 0x02 ( 2 ) - WRITE_REGISTER', rendered)
        self.assertIn('Flags                                           : 0x01 ( 1 ) - PRESERVE_REGISTER', rendered)

    def test_trigger_error_action_is_named(self):
        einj = EINJ()
        einj.parse(einj_table(entries=(einj_entry(action=0xFF),)))

        self.assertIn('0xFF ( 255 ) - TRIGGER_ERROR', str(einj))

    def test_unknown_action_and_instruction_fall_back(self):
        einj = EINJ()
        einj.parse(einj_table(entries=(einj_entry(action=0x20, instruction=0x20),)))
        rendered = str(einj)

        self.assertIn('not recognized as valid aciton', rendered)
        self.assertIn('not recognized as valid instruction', rendered)

    def test_zero_flags_are_ignored(self):
        einj = EINJ()
        einj.parse(einj_table(entries=(einj_entry(flags=0),)))

        self.assertIn('Flags                                           : 0x00 ( 0 ) - Ignore', str(einj))

    def test_preserve_register_only_applies_to_write_instructions(self):
        einj = EINJ()
        einj.parse(einj_table(entries=(einj_entry(instruction=0, flags=1),)))
        rendered = str(einj)

        self.assertIn('Flags                                           : 0x01 ( 1 )\n', rendered)
        self.assertNotIn('PRESERVE_REGISTER', rendered)

    def test_non_zero_entry_reserved_byte_is_flagged(self):
        einj = EINJ()
        einj.parse(einj_table(entries=(einj_entry(reserved=7),)))

        self.assertIn('Reserved                                        : 0x07 ( 7 ) - Error, must be 0', str(einj))

    def test_value_and_mask_are_decoded(self):
        einj = EINJ()
        einj.parse(einj_table(entries=(einj_entry(value=0x1122334455667788, mask=0xFF),)))
        rendered = str(einj)

        self.assertIn('Value                                           : 0x1122334455667788', rendered)
        self.assertIn('Mask                                            : 0x00000000000000FF', rendered)

    def test_each_entry_is_rendered(self):
        einj = EINJ()
        einj.parse(einj_table(entries=(einj_entry(action=0), einj_entry(action=4))))
        rendered = str(einj)

        self.assertEqual(rendered.count('Injection Instruction Entry'), 2)
        self.assertIn('END_OPERATION', rendered)

    def test_register_region_is_rendered_as_a_generic_address(self):
        einj = EINJ()
        einj.parse(einj_table(entries=(einj_entry(register=gas(space_id=1, addr=0xB2)),)))

        self.assertIn('Generic Address Structure', str(einj))


########################################################################################################
#
# ERST Table
#
########################################################################################################


def erst_entry(action=0, instruction=4, flags=1, reserved=0,
               value=0x11, mask=0x22, register=None):
    """Build a 32 byte Serialization Instruction Entry."""
    return (struct.pack('<4B', action, instruction, flags, reserved) +
            (gas() if register is None else register) +
            struct.pack('<QQ', value, mask))


def erst_table(header_size=48, reserved=0, entries=()):
    return struct.pack('<3L', header_size, reserved, len(entries)) + b''.join(entries)


class TestERST(unittest.TestCase):
    """ERST describes the error record serialization action table."""

    def test_header_fields_are_decoded(self):
        erst = ERST()
        erst.parse(erst_table(header_size=48, entries=(erst_entry(),)))
        rendered = str(erst)

        self.assertIn('Serialization Header Size                       : 0x00000030 ( 48 )', rendered)
        self.assertIn('Instruction Count Entry                         : 0x00000001 ( 1 )', rendered)

    def test_non_zero_reserved_field_is_flagged(self):
        erst = ERST()
        erst.parse(erst_table(reserved=1))

        self.assertIn('Reserved                                        : 0x00000001 - Error, this should be 0', str(erst))

    def test_no_entries_produces_only_a_header(self):
        erst = ERST()
        erst.parse(erst_table())

        self.assertNotIn('Serialization Intruction Entry', str(erst))

    def test_known_action_and_instruction_are_named(self):
        erst = ERST()
        erst.parse(erst_table(entries=(erst_entry(action=0, instruction=4),)))
        rendered = str(erst)

        self.assertIn('Serialized Action                             : 0x00 - BEGIN_WRITE_OPERATION', rendered)
        self.assertIn('Instruction                                   : 0x04 - NOOP', rendered)

    def test_preserve_register_flag_is_named(self):
        erst = ERST()
        erst.parse(erst_table(entries=(erst_entry(flags=1),)))

        self.assertIn('Flags                                         : 0x01 - PRESERVE_REGISTER', str(erst))

    def test_other_flag_values_are_not_annotated(self):
        erst = ERST()
        erst.parse(erst_table(entries=(erst_entry(flags=0),)))

        self.assertIn('Flags                                         : 0x00\n', str(erst))

    def test_out_of_range_action_is_unknown(self):
        erst = ERST()
        erst.parse(erst_table(entries=(erst_entry(action=0x20),)))

        self.assertIn('Serialized Action                             : 0x20 - Unknown', str(erst))

    def test_out_of_range_instruction_marks_the_action_unknown(self):
        # The parser overwrites the action name instead of the instruction name
        # when the instruction is out of range.
        erst = ERST()
        erst.parse(erst_table(entries=(erst_entry(action=0, instruction=0x20),)))
        rendered = str(erst)

        self.assertIn('Serialized Action                             : 0x00 - Unknown', rendered)
        self.assertIn('Instruction                                   : 0x20 - \n', rendered)

    def test_non_zero_reserved_byte_is_flagged(self):
        erst = ERST()
        erst.parse(erst_table(entries=(erst_entry(reserved=3),)))

        self.assertIn('Reserved                                      : 0x03 - Error, this should be 0', str(erst))

    def test_value_and_mask_are_decoded(self):
        erst = ERST()
        erst.parse(erst_table(entries=(erst_entry(value=0xAA, mask=0xBB),)))
        rendered = str(erst)

        self.assertIn('Value                                         : 0x00000000000000AA', rendered)
        self.assertIn('Mask                                          : 0x00000000000000BB', rendered)

    def test_every_entry_is_rendered(self):
        erst = ERST()
        erst.parse(erst_table(entries=(erst_entry(action=0), erst_entry(action=3), erst_entry(action=10))))
        rendered = str(erst)

        self.assertEqual(rendered.count('Serialization Intruction Entry'), 3)
        self.assertIn('END_OPERATION', rendered)
        self.assertIn('GET_RECORD_COUNT', rendered)


########################################################################################################
#
# HEST Table
#
########################################################################################################


def hest_notify(error_type=2, length=28, config_write_enable=0x3F,
                poll_interval=1000, vector=0, switch_value=0,
                switch_window=0, threshold_value=0, threshold_window=0):
    """Build a 28 byte Hardware Error Notification Structure."""
    return (struct.pack('<BBH', error_type, length, config_write_enable) +
            struct.pack('<6L', poll_interval, vector, switch_value,
                        switch_window, threshold_value, threshold_window))


def hest_amces(source_id=1, reserved=0, flags=0x05, enabled=1, records=2,
               max_sections=3, global_cap=0x11, global_ctrl=0x22, banks=0):
    """Build a 40 byte Architecture Machine Check Exception structure."""
    return (struct.pack('<HHHBB', 0, source_id, reserved, flags, enabled) +
            struct.pack('<LL', records, max_sections) +
            struct.pack('<QQ', global_cap, global_ctrl) +
            struct.pack('<B', banks) + b'\x00' * 7)


def hest_amcs(_type=1, source_id=2, flags=1, enabled=1, banks=0, notify=None):
    """Build a 48 byte Architecture Corrected/Deferred Machine Check structure."""
    return (struct.pack('<HHHBB', _type, source_id, 0, flags, enabled) +
            struct.pack('<LL', 1, 1) +
            (hest_notify() if notify is None else notify) +
            struct.pack('<B', banks) + b'\x00' * 3)


def hest_nmi(source_id=3, reserved=0):
    """Build a 20 byte Architecture NMI Error structure."""
    return (struct.pack('<HHL', 2, source_id, reserved) +
            struct.pack('<3L', 1, 2, 0x1000))


def hest_pcie(_type=6, source_id=4, flags=0x03, enabled=1, reserved2=0):
    """Build a PCI Express AER structure of the requested flavor."""
    data = (struct.pack('<HHHBB', _type, source_id, 0, flags, enabled) +
            struct.pack('<LL', 1, 2) +
            struct.pack('<L', 0x10) +
            struct.pack('<HHHH', 0x1C, 0x3, 0x7, reserved2) +
            struct.pack('<4L', 0xAA, 0xBB, 0xCC, 0xDD))
    if _type == 6:
        data += struct.pack('<L', 0xEE)
    elif _type == 8:
        data += struct.pack('<3L', 0x11, 0x22, 0x33)
    return data


def hest_ghess(_type=9, source_id=5, related=0xFFFF, flags=0, enabled=1,
               err_block_len=0x400):
    """Build a Generic Hardware Error Source structure (v1 or v2)."""
    data = (struct.pack('<HHHBB', _type, source_id, related, flags, enabled) +
            struct.pack('<3L', 1, 2, 0x1000) +
            gas(space_id=0, addr=0x7ABC0000) +
            hest_notify(error_type=10) +
            struct.pack('<L', err_block_len))
    if _type == 10:
        data += gas(space_id=1, addr=0xB2) + struct.pack('<QQ', 0x1, 0x2)
    return data


class TestHEST(unittest.TestCase):
    """HEST enumerates the platform hardware error sources."""

    def test_error_source_count_is_decoded(self):
        hest = HEST()
        hest.parse(struct.pack('<L', 1) + hest_nmi())

        self.assertEqual(hest.ErrorSourceCount, 1)
        self.assertIn('Error Source Count                              : 1', str(hest))

    def test_machine_check_exception_structure_is_decoded(self):
        hest = HEST()
        hest.parse(struct.pack('<L', 1) + hest_amces(source_id=0x1234, flags=0x05))
        rendered = str(hest)

        self.assertIn('Architecture Machine Check Exception Structure', rendered)
        self.assertIn('Source ID                                     : 0x1234', rendered)
        self.assertIn('FIRMWARE_FIRST                                : 1 - System firmware handles errors', rendered)
        self.assertIn('GHES_ASSIST                                   : 1 - Additional information given', rendered)

    def test_machine_check_exception_without_firmware_first(self):
        hest = HEST()
        hest.parse(struct.pack('<L', 1) + hest_amces(flags=0x00))
        rendered = str(hest)

        self.assertIn('FIRMWARE_FIRST                                : 0 - System firmware does not handle', rendered)
        self.assertIn('GHES_ASSIST                                   : 0 - Bit is reserved', rendered)

    def test_machine_check_exception_returns_its_size(self):
        hest = HEST()

        self.assertEqual(hest.parseAMCES(hest_amces()), 40)

    def test_corrected_machine_check_structure_is_decoded(self):
        hest = HEST()
        hest.parse(struct.pack('<L', 1) + hest_amcs(_type=1, source_id=0x22))
        rendered = str(hest)

        self.assertIn('Architecture Corrected Machine Check Structure', rendered)
        self.assertIn('Source ID                         : 0x0022', rendered)
        self.assertIn('Hardware Error Notification Structure', rendered)

    def test_deferred_machine_check_structure_is_decoded(self):
        hest = HEST()
        size = hest.parseAMCS(hest_amcs(_type=2), 2)

        self.assertEqual(size, 48)
        self.assertIn('Architecture Deferred Machine Check Structure', hest.result_str)

    def test_reserved_machine_check_flag_bits_are_flagged(self):
        hest = HEST()
        hest.parseAMCS(hest_amcs(flags=0x08), 1)

        self.assertIn('Flags                                         : 0x08 - Error, Reserved Bits are not 0', hest.result_str)

    def test_corrected_machine_check_reports_ghes_assist(self):
        hest = HEST()
        hest.parseAMCS(hest_amcs(flags=0x05), 1)

        self.assertIn('GHES_ASSIST                                 : 1 - Additional information given', hest.result_str)

    def test_machine_check_error_banks_cannot_be_decoded(self):
        # The bank parser unpacks a 4 byte reserved field from a single byte.
        hest = HEST()

        with self.assertRaises(struct.error):
            hest.parseAMCES(hest_amces(banks=1) + b'\x00' * 28)

    def test_corrected_machine_check_error_banks_cannot_be_decoded(self):
        hest = HEST()

        with self.assertRaises(struct.error):
            hest.parseAMCS(hest_amcs(banks=1) + b'\x00' * 28, 1)

    def test_notification_type_is_named(self):
        hest = HEST()
        rendered = hest.parseNotify(hest_notify(error_type=4, poll_interval=250))

        self.assertIn('Type                                        : 4 - NMI', rendered)
        self.assertIn('Poll Interval                               : 250 milliseconds', rendered)

    def test_out_of_range_notification_type_is_reserved(self):
        hest = HEST()

        self.assertIn('Type                                        : 20 - Reserved',
                      hest.parseNotify(hest_notify(error_type=20)))

    def test_gsiv_notification_annotates_the_vector(self):
        hest = HEST()

        self.assertIn('Specifies the GSIV triggerd by error source',
                      hest.parseNotify(hest_notify(error_type=10)))

    def test_nmi_error_structure_is_decoded(self):
        hest = HEST()
        hest.parse(struct.pack('<L', 1) + hest_nmi(source_id=0x33))
        rendered = str(hest)

        self.assertIn('Architecture NMI Error Structure', rendered)
        self.assertIn('Source ID                                     : 0x0033', rendered)
        self.assertIn('Max Raw Data Length                           : 0x00001000', rendered)

    def test_nmi_error_structure_flags_a_non_zero_reserved_field(self):
        hest = HEST()
        hest.parse(struct.pack('<L', 1) + hest_nmi(reserved=1))

        self.assertIn('Reserved                                      : 0x00000001 - Error, not 0', str(hest))

    def test_nmi_error_structure_returns_its_size(self):
        hest = HEST()

        self.assertEqual(hest.parseNMIStructure(hest_nmi()), 20)

    def test_root_port_aer_structure_is_decoded(self):
        hest = HEST()
        hest.parse(struct.pack('<L', 1) + hest_pcie(_type=6))
        rendered = str(hest)

        self.assertIn('PCI Express Root Port AER Structure', rendered)
        self.assertIn('Root Error Command                            : 0x000000EE', rendered)

    def test_device_aer_structure_is_decoded(self):
        hest = HEST()
        size = hest.parsePCIe(hest_pcie(_type=7), 7)

        self.assertEqual(size, 44)
        self.assertIn('PCI Express Device AER Structure', hest.result_str)

    def test_bridge_aer_structure_is_decoded(self):
        hest = HEST()
        size = hest.parsePCIe(hest_pcie(_type=8), 8)

        self.assertEqual(size, 56)
        self.assertIn('PCI Express Bridge AER Structure', hest.result_str)
        self.assertIn('Secondary Uncorrectable Error Mask            : 0x00000011', hest.result_str)

    def test_aer_global_and_firmware_first_flags_are_broken_out(self):
        hest = HEST()
        hest.parsePCIe(hest_pcie(_type=6, flags=0x03), 6)

        self.assertIn('Settings in table are for all PCIe Devices', hest.result_str)
        self.assertIn('This field should be ignored since Global is set', hest.result_str)
        self.assertIn('This field should be ignored since FIRMWARE_FIRST is set', hest.result_str)

    def test_aer_reserved_bits_are_flagged(self):
        hest = HEST()
        hest.parsePCIe(hest_pcie(_type=7, flags=0x04, reserved2=1), 7)

        self.assertIn('Error, reserved bits are not 0', hest.result_str)
        self.assertIn('Error, reserved bits should be 0', hest.result_str)

    def test_generic_error_source_structure_is_decoded(self):
        hest = HEST()
        hest.parse(struct.pack('<L', 1) + hest_ghess(_type=9))
        rendered = str(hest)

        self.assertIn('Generic Hardware Error Source Structure', rendered)
        self.assertIn('Error Status Block Length                     : 0x00000400', rendered)
        self.assertIn('Does not represent an alternate souce', rendered)

    def test_generic_error_source_v2_adds_the_read_ack_register(self):
        hest = HEST()
        size = hest.parseGHESS(hest_ghess(_type=10, related=1), 10)

        self.assertEqual(size, 64)
        self.assertIn('Generic Hardware Error Source Version 2', hest.result_str)
        self.assertIn('Read Ack Preserve                             : 0x0000000000000001', hest.result_str)
        self.assertIn('Read Ack Write                                : 0x0000000000000002', hest.result_str)

    def test_unknown_error_source_type_is_skipped(self):
        hest = HEST()
        hest.parse(struct.pack('<L', 1) + struct.pack('<HH', 5, 0) + b'\x00' * 16)

        self.assertEqual(hest.ErrorSourceCount, 1)
        self.assertNotIn('Structure', str(hest).replace('Error Source Count', ''))

    def test_multiple_error_sources_are_walked_in_order(self):
        hest = HEST()
        hest.parse(struct.pack('<L', 2) + hest_nmi(source_id=1) + hest_amces(source_id=2))
        rendered = str(hest)

        self.assertIn('Architecture NMI Error Structure', rendered)
        self.assertIn('Architecture Machine Check Exception Structure', rendered)
        self.assertIn('Source ID                                     : 0x0002', rendered)


########################################################################################################
#
# SPMI Table
#
########################################################################################################


class TestSPMI(unittest.TestCase):
    """SPMI describes the IPMI system interface."""

    @staticmethod
    def _table(interface_type=1, pci_flag=1, interrupt_type=0x3):
        return (struct.pack('<BBBHBBB', interface_type, 1, 0x10, interrupt_type, 0, 0, pci_flag) +
                struct.pack('<L', 0x20) + gas(space_id=1, addr=0xCA2) +
                b'\x00' * 4 + struct.pack('<4B', 0, 1, 0x1F, 0))

    def test_pci_device_details_are_decoded(self):
        spmi = SPMI()

        rendered = spmi.parseNonUID(struct.pack('<4B', 0, 1, 0x1F, 3))

        self.assertIn('PCI Segment GroupNumber                                 : 0x00', rendered)
        self.assertIn('PCI Bus Number                                          : 0x01', rendered)
        self.assertIn('PCI Device Number                                       : 0x1F', rendered)
        self.assertIn('PCI Function Number                                     : 0x03', rendered)

    def test_non_pci_uid_is_decoded(self):
        spmi = SPMI()

        self.assertIn('UID                                                     : 0x12345678',
                      spmi.parseUID(struct.pack('<L', 0x12345678)))

    def test_address_is_rendered_as_a_generic_address(self):
        spmi = SPMI()

        self.assertIn('Generic Address Structure', spmi.parseAddress(gas(space_id=1, addr=0xCA2)))

    def test_parse_cannot_decode_the_trailing_device_field(self):
        # The parser slices only three bytes for the PCI/UID field but both
        # decoders require four, so parsing always fails.
        spmi = SPMI()

        with self.assertRaises(struct.error):
            spmi.parse(self._table(pci_flag=1))

    def test_parse_fails_for_non_pci_devices_as_well(self):
        spmi = SPMI()

        with self.assertRaises(struct.error):
            spmi.parse(self._table(pci_flag=0))

    def test_parse_fails_for_every_defined_interface_type(self):
        for interface_type in (1, 2, 3, 4, 9):
            with self.subTest(interface_type=interface_type):
                with self.assertRaises(struct.error):
                    SPMI().parse(self._table(interface_type=interface_type))

    def test_parse_fails_when_no_interrupt_modes_are_advertised(self):
        spmi = SPMI()

        with self.assertRaises(struct.error):
            spmi.parse(self._table(interrupt_type=0))

    def test_rendering_before_a_successful_parse_is_not_possible(self):
        with self.assertRaises(AttributeError):
            str(SPMI())


########################################################################################################
#
# RASF Table
#
########################################################################################################


class TestRASF(unittest.TestCase):
    """RASF carries the platform communication channel identifier."""

    def test_channel_identifier_bytes_are_rendered(self):
        rasf = RASF()
        rasf.parse(bytes(range(1, 13)))
        rendered = str(rasf)

        self.assertIn('ACPI RAS Feature Table ( RASF )', rendered)
        self.assertIn('0x01 0x02 0x03 0x04 0x05 0x06 0x07 0x08 0x09 0x0A 0x0B 0x0C', rendered)

    def test_trailing_content_is_ignored(self):
        rasf = RASF()
        rasf.parse(b'\x00' * 12 + b'\xff' * 8)

        self.assertIn('0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00', str(rasf))

    def test_truncated_content_is_rejected(self):
        with self.assertRaises(struct.error):
            RASF().parse(b'\x00' * 4)


########################################################################################################
#
# MSCT Table
#
########################################################################################################


def msct_prox(revision=1, length=22, low=0, high=3, proc_cap=8, mem_cap=0x100000000):
    """Build a 22 byte Maximum Proximity Domain Information Structure."""
    return (struct.pack('<BB', revision, length) +
            struct.pack('<3L', low, high, proc_cap) +
            struct.pack('<Q', mem_cap))


class TestMSCT(unittest.TestCase):
    """MSCT reports the maximum system characteristics."""

    @staticmethod
    def _table(offset=0x38, clock_domains=2, max_phys=0x7FFFFFFFFF, domains=()):
        return (struct.pack('<3L', offset, len(domains), clock_domains) +
                struct.pack('<Q', max_phys) + b''.join(domains))

    def test_header_fields_are_decoded(self):
        msct = MSCT()
        msct.parse(self._table(domains=(msct_prox(),)))
        rendered = str(msct)

        self.assertIn('Maximum System Characteristics Table ( MSCT )', rendered)
        self.assertIn('Offset to Proximity Domain Information Structure        : 0x00000038', rendered)
        self.assertIn('Maximum Number of Proximity Domains                     : 0x00000001 ( 1 )', rendered)
        self.assertIn('Maximum Number of Clock Domains                         : 0x00000002 ( 2 )', rendered)
        self.assertIn('Maximum Physical Address                                : 0x0000007FFFFFFFFF', rendered)

    def test_proximity_domain_fields_are_decoded(self):
        msct = MSCT()
        msct.parse(self._table(domains=(msct_prox(low=1, high=4, proc_cap=16, mem_cap=0x200000000),)))
        rendered = str(msct)

        self.assertIn('Maximum Proximity Domain Informaiton Structure[0]', rendered)
        self.assertIn('Proximity Domain Range (low)                          : 0x0001', rendered)
        self.assertIn('Proximity Domain Range (high)                         : 0x0004', rendered)
        self.assertIn('Maximum Processor Capacity                            : 0x0010 ( 16 )', rendered)
        self.assertIn('Maximum Memory Capacity                               : 0x0000000200000000', rendered)

    def test_empty_processor_capacity_is_annotated(self):
        msct = MSCT()
        msct.parse(self._table(domains=(msct_prox(proc_cap=0, mem_cap=0),)))
        rendered = str(msct)

        self.assertIn('Proximity domains do not contain a processor', rendered)
        self.assertIn('Proximity domains do not contain memory', rendered)

    def test_multiple_domains_are_indexed(self):
        msct = MSCT()
        msct.parse(self._table(domains=(msct_prox(low=0), msct_prox(low=5))))
        rendered = str(msct)

        self.assertIn('Structure[0]', rendered)
        self.assertIn('Structure[1]', rendered)
        self.assertIn('Proximity Domain Range (low)                          : 0x0005', rendered)

    def test_table_without_domains_lists_nothing(self):
        msct = MSCT()
        msct.parse(self._table())

        self.assertNotIn('Maximum Proximity Domain Informaiton Structure', str(msct))


########################################################################################################
#
# NFIT Table
#
########################################################################################################


def nfit_header(length):
    return b'NFIT' + struct.pack('<L', length)


def nfit_spa(guid=(0x66f0d379, 0xb4f3, 0x4074, 0xac, 0x43, 0x0d, 0x33, 0x18, 0xb7, 0x8c, 0xdb),
             index=1, flags=1, proximity=2, base=0x100000000, length=0x40000000, attrs=0x8):
    """Build a 56 byte System Physical Address Range structure."""
    return (struct.pack('<HH', 0, 56) +
            struct.pack('<HH', index, flags) +
            struct.pack('<LL', 0, proximity) +
            struct.pack('<LHH8B', *guid) +
            struct.pack('<QQQ', base, length, attrs))


def nfit_map():
    """Build a 48 byte NVDIMM Region Mapping structure."""
    return (struct.pack('<HH', 1, 48) +
            struct.pack('<L', 0x11223344) +
            struct.pack('<4H', 0x1, 0x2, 0x3, 0x4) +
            struct.pack('<QQQ', 0x1000, 0x2000, 0x3000) +
            struct.pack('<4H', 0x5, 0x6, 0x7, 0x0))


def nfit_interleave(lines=(0x10, 0x20)):
    """Build an Interleave structure with one entry per supplied line."""
    length = 16 + 4 * len(lines)
    return (struct.pack('<HH', 2, length) +
            struct.pack('<HH', 1, 0) +
            struct.pack('<LL', len(lines), 0x100) +
            b''.join(struct.pack('<L', line) for line in lines))


def nfit_smbios():
    """Build an 8 byte SMBIOS Management Information structure."""
    return struct.pack('<HH', 3, 8) + struct.pack('<L', 0)


def nfit_control_region(windows=1, valid_fields=0):
    """Build an 80 byte NVDIMM Control Region structure."""
    data = (struct.pack('<HH', 4, 80) +
            struct.pack('<7H', 1, 0x8086, 0x1234, 0x1, 0x8087, 0x5678, 0x2) +
            struct.pack('<BB', valid_fields, 0x0A) +
            struct.pack('<HH', 0x2024, 0) +
            struct.pack('<L', 0xDEADBEEF) +
            struct.pack('<BB', 0x21, 0x43) +
            struct.pack('<H', windows))
    if windows:
        data += struct.pack('<5Q', 0x100, 0x8, 0x10, 0x20, 0x8)
        data += struct.pack('<H', 1) + b'\x00' * 6
    return data


def nfit_block_data_window():
    """Build a 40 byte NVDIMM Block Data Window Region structure."""
    return (struct.pack('<HH', 5, 40) +
            struct.pack('<HH', 1, 4) +
            struct.pack('<4Q', 0x1000, 0x2000, 0x3000, 0x4000))


def nfit_flush_hint(addresses=(0xFED10000,)):
    """Build a Flush Hint Address structure."""
    length = 16 + 8 * (len(addresses) - 1)
    return (struct.pack('<HH', 6, length) +
            struct.pack('<L', len(addresses)) +
            b''.join(struct.pack('<Q', addr) for addr in addresses))


def nfit_platform_capabilities(capabilities=7):
    """Build a 16 byte Platform Capabilities structure."""
    return (struct.pack('<HH', 7, 16) +
            struct.pack('<4B', 2, 0, 0, 0) +
            struct.pack('<LL', capabilities, 0))


def nfit_table(*structures):
    body = b''.join(structures)
    return NFIT(nfit_header(len(body))), struct.pack('<L', 0) + body


class TestNFIT(unittest.TestCase):
    """NFIT enumerates the NVDIMM firmware interface structures."""

    def test_total_length_comes_from_the_table_header(self):
        nfit = NFIT(nfit_header(0x120))

        self.assertEqual(nfit.total_length, 0x120)

    def test_system_physical_address_range_is_decoded(self):
        nfit, content = nfit_table(nfit_spa())
        nfit.parse(content)
        rendered = str(nfit)

        self.assertIn('NVDIMM Firmware Interface Table ( NFIT )', rendered)
        self.assertIn('System Physical Address (SPA) Range Structure [Type 1]', rendered)
        self.assertIn('SPA Range Structure Index                                   : 0x0001', rendered)
        self.assertIn('Byte Addressable Persistent Memory (PM) Region', rendered)
        self.assertIn('System Physical Address Range Base                          : 0x0000000100000000', rendered)
        self.assertIn('Control region only for hot add/online operation', rendered)

    def test_reserved_spa_range_index_is_flagged(self):
        nfit, content = nfit_table(nfit_spa(index=0, flags=0))
        nfit.parse(content)
        rendered = str(nfit)

        self.assertIn('Value of 0 is reserved and shall not be used as an index', rendered)
        self.assertIn('Control region not only for hot add/online operation', rendered)
        self.assertIn('Data in proximity region is not valid', rendered)

    def test_volatile_memory_guid_is_named(self):
        guid = (0x7305944f, 0xfdda, 0x44e3, 0xb1, 0x6c, 0x3f, 0x22, 0xd2, 0x52, 0xe5, 0xd0)
        nfit, content = nfit_table(nfit_spa(guid=guid))
        nfit.parse(content)

        self.assertIn('Volitile Memory Region', str(nfit))

    def test_unknown_guid_is_reported_as_vendor_defined(self):
        guid = (0x11111111, 0x2222, 0x3333, 0, 0, 0, 0, 0, 0, 0, 0)
        nfit, content = nfit_table(nfit_spa(guid=guid))
        nfit.parse(content)

        self.assertIn('could be a vendor defined GUID', str(nfit))

    def test_every_specified_address_range_guid_is_named(self):
        expected = {
            (0x92f701f6, 0x13b4, 0x405d, 0x91, 0x0b, 0x29, 0x93, 0x67, 0xe8, 0x23, 0x4c):
                'NVDIMM Control Region',
            (0x91af0530, 0x5d86, 0x470e, 0xa6, 0xb0, 0x0a, 0x2d, 0xb9, 0x40, 0x82, 0x49):
                'NVDIMM Block Data Window Region',
            (0x77ab535a, 0x45fc, 0x624b, 0x55, 0x60, 0xf7, 0xb2, 0x81, 0xd1, 0xf9, 0x6e):
                'RAM Disk supporting a Virtual Disk Region - Volitile',
            (0x3d5abd30, 0x4175, 0x87ce, 0x6d, 0x64, 0xd2, 0xad, 0xe5, 0x23, 0xc4, 0xbb):
                'RAM Disk supporting a Virtual CD Region - Volitile',
            (0x5cea02c9, 0x4d07, 0x69d3, 0x26, 0x9f, 0x44, 0x96, 0xfb, 0xe0, 0x96, 0xf9):
                'RAM Disk supporting Virtual Disk Region - Persistent',
            (0x08018188, 0x42cd, 0xbb48, 0x10, 0x0f, 0x53, 0x87, 0xd5, 0x3d, 0xed, 0x3d):
                'RAM Disk supporting a Virtual CD Region - Persistent',
        }
        for guid, name in expected.items():
            with self.subTest(guid=guid):
                nfit, content = nfit_table(nfit_spa(guid=guid))
                nfit.parse(content)

                self.assertIn(name, str(nfit))

    def test_unknown_structure_type_is_skipped(self):
        nfit = NFIT(nfit_header(0))
        nfit.parse(struct.pack('<L', 0) + struct.pack('<HH', 9, 8) + b'\x00' * 4)
        rendered = str(nfit)

        self.assertIn('NVDIMM Firmware Interface Table ( NFIT )', rendered)
        self.assertNotIn('[Type', rendered)

    def test_region_mapping_structure_is_decoded(self):
        nfit, content = nfit_table(nfit_map())
        nfit.parse(content)
        rendered = str(nfit)

        self.assertIn('NVDIMM Region Mapping Structure [Type 1]', rendered)
        self.assertIn('NFIT Device Handle                                          : 0x11223344', rendered)
        self.assertIn('NVDIMM Region Size                                          : 0x0000000000001000', rendered)

    def test_interleave_structure_lists_every_line(self):
        nfit, content = nfit_table(nfit_interleave(lines=(0x10, 0x20, 0x30)))
        nfit.parse(content)
        rendered = str(nfit)

        self.assertIn('Interleave Structure [Type 2]', rendered)
        self.assertIn('Number of Lines Described                                   : 0x00000003 ( 3 )', rendered)
        self.assertIn('Line 1 Offset', rendered)
        self.assertIn('Line 3 Offset', rendered)

    def test_smbios_structure_is_not_decoded_further(self):
        nfit, content = nfit_table(nfit_smbios())
        nfit.parse(content)

        self.assertIn('SMBIOS Management Information Structure [Type 3]', str(nfit))
        self.assertIn('Unable to further at this time', str(nfit))

    def test_control_region_structure_is_decoded(self):
        nfit, content = nfit_table(nfit_control_region())
        nfit.parse(content)
        rendered = str(nfit)

        self.assertIn('NVDIMM Control Region Structure [Type 4]', rendered)
        self.assertIn('Vendor ID                                                   : 0x8086', rendered)
        self.assertIn('Serial Number                                               : 0xDEADBEEF', rendered)
        self.assertIn('Region Format Interface Code                                : 0x4321', rendered)
        self.assertIn('Number of Block Control Windows                             : 0x00000001', rendered)

    def test_control_region_reports_acpi_60_compliance(self):
        nfit, content = nfit_table(nfit_control_region(valid_fields=0))
        nfit.parse(content)

        self.assertIn('System is compliant with ACPI 6.0', str(nfit))

    def test_control_region_with_valid_manufacturing_fields(self):
        nfit, content = nfit_table(nfit_control_region(valid_fields=1))
        nfit.parse(content)
        rendered = str(nfit)

        self.assertNotIn('System is compliant with ACPI 6.0', rendered)
        self.assertIn('Manufacturing Date                                          : 0x2024', rendered)

    def test_block_data_window_structure_is_decoded(self):
        nfit, content = nfit_table(nfit_block_data_window())
        nfit.parse(content)
        rendered = str(nfit)

        self.assertIn('NVDIMM Block Data Region Structure [Type 5]', rendered)
        self.assertIn('Number of Block Data Windows                                : 0x0004 ( 4 )', rendered)

    def test_flush_hint_structure_lists_its_addresses(self):
        nfit, content = nfit_table(nfit_flush_hint(addresses=(0xFED10000,)))
        nfit.parse(content)
        rendered = str(nfit)

        self.assertIn('Flush Hint Address Structure [Type 6]', rendered)
        self.assertIn('Flush Hint Address 1', rendered)
        self.assertIn('0x00000000FED10000', rendered)

    def test_platform_capabilities_structure_is_decoded(self):
        nfit, content = nfit_table(nfit_platform_capabilities(capabilities=7))
        nfit.parse(content)
        rendered = str(nfit)

        self.assertIn('Platform Capabilities Structure [Type 7]', rendered)
        self.assertIn('Platform ensures the entire CPU store data path is flushed', rendered)
        self.assertIn('Platform provides mechanisms to automatically flush', rendered)
        self.assertIn('Platform supports mirroring multiple byte addressable', rendered)

    def test_platform_capabilities_without_any_capability_bits(self):
        nfit, content = nfit_table(nfit_platform_capabilities(capabilities=0))
        nfit.parse(content)
        rendered = str(nfit)

        self.assertIn('Platform does not ensure the entire CPU store data path', rendered)
        self.assertIn('This should be set to 1 - Platform does not support', rendered)
        self.assertIn('Platform does not support mirroring', rendered)

    def test_partial_platform_capabilities(self):
        nfit, content = nfit_table(nfit_platform_capabilities(capabilities=1))
        nfit.parse(content)

        self.assertIn('Platform does not provides mechanisms to automatically flush', str(nfit))

    def test_multiple_structures_are_walked_in_order(self):
        nfit, content = nfit_table(nfit_spa(), nfit_platform_capabilities())
        nfit.parse(content)
        rendered = str(nfit)

        self.assertIn('System Physical Address (SPA) Range Structure', rendered)
        self.assertIn('Platform Capabilities Structure [Type 7]', rendered)
        self.assertEqual(rendered.count('Length:                    72'), 2)


if __name__ == '__main__':
    unittest.main()
