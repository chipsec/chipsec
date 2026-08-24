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

"""
To execute: python[3] -m unittest tests.cfg.parsers.test_hob_parser
"""

import os
import struct
import unittest
import uuid
import xml.etree.ElementTree as ET
from types import SimpleNamespace

from chipsec.cfg.parsers.core_parsers import DevConfig
from chipsec.cfg.parsers.hob_parser import HOBParser, HOBCommands, HOB_IP_NAME, normalize_guid
from chipsec.cfg.parsers.ip.platform import Platform, Vendor
from chipsec.library.file import get_main_dir
from chipsec.library.uefi.hob import (
    EFI_HOB_TYPE_GUID_EXTENSION,
    EFI_HOB_TYPE_END_OF_HOB_LIST,
    walk_hob_list,
)
from chipsec.parsers import Stage


PCD_GUID = 'EA296D92-0B69-423C-8C28-33B4E0A91268'

HOB_XML = f"""
<configuration>
    <hob>
        <structure name="PEI_PCD_DATABASE" guid="{PCD_GUID}" desc="PEI PCD Database">
            <field name="Signature" type="guid" />
            <field name="BuildVersion" type="uint32" />
            <field name="SystemSkuId" type="uint64" />
            <field name="GuidTableCount" type="uint16" />
            <field name="Pad" type="bytes" size="6" />
        </structure>
    </hob>
</configuration>
"""


class TestHOBParser(unittest.TestCase):
    """Cover the HOB definition parser in chipsec.cfg.parsers.hob_parser."""

    def setUp(self):
        self.cfg = SimpleNamespace()
        self.parser = HOBParser(self.cfg)
        self.parser.startup()

    def _parse(self, xml_str):
        root = ET.fromstring(xml_str)
        for node in root.iter('structure'):
            self.parser.handle_structure(node, None)

    def test_startup_initializes_definition_store(self):
        self.assertEqual(self.cfg.HOB_DEFINITIONS, {})

    def test_stage_is_cust_support(self):
        self.assertEqual(self.parser.get_stage(), Stage.CUST_SUPPORT)

    def test_definition_is_stored_by_guid(self):
        self._parse(HOB_XML)
        self.assertIn(PCD_GUID, self.cfg.HOB_DEFINITIONS)
        self.assertEqual(self.cfg.HOB_DEFINITIONS[PCD_GUID].name, 'PEI_PCD_DATABASE')

    def test_declared_layout_is_packed(self):
        self._parse(HOB_XML)
        hob_def = self.cfg.HOB_DEFINITIONS[PCD_GUID]
        self.assertEqual(hob_def.fmt, '=16sIQH6s')
        self.assertEqual(hob_def.size, 16 + 4 + 8 + 2 + 6)

    def test_fields_are_register_style_bit_ranges(self):
        self._parse(HOB_XML)
        fields = self.cfg.HOB_DEFINITIONS[PCD_GUID].FIELDS
        self.assertEqual(fields['SIGNATURE']['bit'], 0)
        self.assertEqual(fields['SIGNATURE']['size'], 128)
        self.assertEqual(fields['BUILDVERSION']['bit'], 16 * 8)
        self.assertEqual(fields['BUILDVERSION']['size'], 32)
        self.assertEqual(fields['SYSTEMSKUID']['bit'], 20 * 8)
        self.assertEqual(fields['PAD']['bit'], 30 * 8)
        self.assertEqual(fields['PAD']['size'], 48)
        # Original case is preserved for reporting
        self.assertEqual(fields['BUILDVERSION']['name'], 'BuildVersion')

    def test_register_get_field_matches_definition(self):
        self._parse(HOB_XML)
        hob_def = self.cfg.HOB_DEFINITIONS[PCD_GUID]
        guid_bytes = uuid.UUID(PCD_GUID).bytes_le
        data = struct.pack('<16sIQH6s', guid_bytes, 0x0A, 0x1122334455667788, 0x33, b'\x00' * 6)
        reg = hob_def.create_register(data, address=0x1000)
        self.assertEqual(reg.get_field('BuildVersion'), 0x0A)
        self.assertEqual(reg.get_field('systemskuid'), 0x1122334455667788)
        self.assertTrue(reg.has_field('Pad'))
        self.assertFalse(reg.has_field('NotAField'))
        self.assertEqual(reg.get_field_value('Signature'), PCD_GUID)
        self.assertEqual(reg.get_field_bytes('Pad'), b'\x00' * 6)
        self.assertEqual(reg.address, 0x1000)

    def test_decode_returns_named_fields(self):
        self._parse(HOB_XML)
        hob_def = self.cfg.HOB_DEFINITIONS[PCD_GUID]
        guid_bytes = uuid.UUID(PCD_GUID).bytes_le
        data = struct.pack('<16sIQH6s', guid_bytes, 0x0A, 0x1122334455667788, 0x33, b'\x00' * 6)
        decoded = hob_def.decode(data)
        self.assertEqual(decoded['Signature'], PCD_GUID)
        self.assertEqual(decoded['BuildVersion'], 0x0A)
        self.assertEqual(decoded['SystemSkuId'], 0x1122334455667788)
        self.assertEqual(decoded['GuidTableCount'], 0x33)
        self.assertEqual(decoded['Pad'], b'\x00' * 6)

    def test_decode_allows_trailing_data(self):
        self._parse(HOB_XML)
        hob_def = self.cfg.HOB_DEFINITIONS[PCD_GUID]
        data = struct.pack('<16sIQH6s', b'\x00' * 16, 1, 2, 3, b'\x00' * 6) + b'\xAA' * 128
        self.assertIsNotNone(hob_def.decode(data))

    def test_decode_rejects_short_data(self):
        self._parse(HOB_XML)
        hob_def = self.cfg.HOB_DEFINITIONS[PCD_GUID]
        self.assertIsNone(hob_def.decode(b'\x00' * 8))

    def test_array_field_returns_list(self):
        self._parse("""
        <configuration>
            <hob>
                <structure name="ARRAY_HOB" guid="11111111-2222-3333-4444-555555555555">
                    <field name="Values" type="uint16" count="3" />
                </structure>
            </hob>
        </configuration>
        """)
        hob_def = self.cfg.HOB_DEFINITIONS['11111111-2222-3333-4444-555555555555']
        self.assertEqual(hob_def.fmt, '=3H')
        self.assertEqual(hob_def.decode(struct.pack('<3H', 1, 2, 3))['Values'], [1, 2, 3])

    def test_guid_array_returns_guid_list(self):
        self._parse("""
        <configuration>
            <hob>
                <structure name="GUID_ARRAY_HOB" guid="11111111-2222-3333-4444-555555555555">
                    <field name="Guids" type="guid" count="2" />
                </structure>
            </hob>
        </configuration>
        """)
        hob_def = self.cfg.HOB_DEFINITIONS['11111111-2222-3333-4444-555555555555']
        first = uuid.UUID('AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE')
        second = uuid.UUID('12345678-1234-5678-90AB-CDEF01234567')
        self.assertEqual(hob_def.fmt, '=16s16s')
        self.assertEqual(hob_def.size, 32)
        self.assertEqual(
            hob_def.decode(first.bytes_le + second.bytes_le)['Guids'],
            [str(first).upper(), str(second).upper()]
        )

    def test_signed_fields_are_two_complement(self):
        self._parse("""
        <configuration>
            <hob>
                <structure name="SIGNED_HOB" guid="22222222-2222-3333-4444-555555555555">
                    <field name="Signed" type="int32" />
                    <field name="Unsigned" type="uint32" />
                    <field name="SignedArray" type="int16" count="2" />
                </structure>
            </hob>
        </configuration>
        """)
        hob_def = self.cfg.HOB_DEFINITIONS['22222222-2222-3333-4444-555555555555']
        data = struct.pack('<iIhh', -2, 0xFFFFFFFE, -1, 5)
        decoded = hob_def.decode(data)
        self.assertEqual(decoded['Signed'], -2)
        self.assertEqual(decoded['Unsigned'], 0xFFFFFFFE)
        self.assertEqual(decoded['SignedArray'], [-1, 5])
        # The raw bitfield stays unsigned
        self.assertEqual(hob_def.create_register(data).get_field('Signed'), 0xFFFFFFFE)

    def test_negative_values_render_with_sign(self):
        self._parse("""
        <configuration>
            <hob>
                <structure name="SIGNED_HOB" guid="22222222-2222-3333-4444-555555555555">
                    <field name="Signed" type="int32" />
                </structure>
            </hob>
        </configuration>
        """)
        hob_def = self.cfg.HOB_DEFINITIONS['22222222-2222-3333-4444-555555555555']
        self.assertIn('= -0x2', str(hob_def.create_register(struct.pack('<i', -2))))

    def test_include_reference_is_ignored(self):
        self._parse('<configuration><hob><definition name="HOB" config="HOB.hob0.xml" /></hob></configuration>')
        self.assertEqual(self.cfg.HOB_DEFINITIONS, {})

    def test_unsupported_field_type_skips_definition(self):
        self._parse("""
        <configuration>
            <hob>
                <structure name="BAD_HOB" guid="99999999-2222-3333-4444-555555555555">
                    <field name="Value" type="uint128" />
                </structure>
            </hob>
        </configuration>
        """)
        self.assertEqual(self.cfg.HOB_DEFINITIONS, {})

    def test_bytes_field_without_size_skips_definition(self):
        self._parse("""
        <configuration>
            <hob>
                <structure name="BAD_HOB" guid="99999999-2222-3333-4444-555555555555">
                    <field name="Value" type="bytes" />
                </structure>
            </hob>
        </configuration>
        """)
        self.assertEqual(self.cfg.HOB_DEFINITIONS, {})

    def test_structure_without_guid_is_skipped(self):
        self._parse('<configuration><hob><structure name="NO_GUID" /></hob></configuration>')
        self.assertEqual(self.cfg.HOB_DEFINITIONS, {})

    def test_normalize_guid(self):
        self.assertEqual(normalize_guid('{ea296d92-0b69-423c-8c28-33b4e0a91268} '), PCD_GUID)


class TestHOBCommands(unittest.TestCase):
    """Cover the HOB definition lookup helper."""

    def setUp(self):
        self.cfg = SimpleNamespace()
        parser = HOBParser(self.cfg)
        parser.startup()
        root = ET.fromstring(HOB_XML)
        for node in root.iter('structure'):
            parser.handle_structure(node, None)
        self.commands = HOBCommands(self.cfg)

    def test_get_by_guid(self):
        hob_def = self.commands.get_by_guid(PCD_GUID.lower())
        assert hob_def is not None
        self.assertEqual(hob_def.name, 'PEI_PCD_DATABASE')

    def test_get_by_name(self):
        hob_def = self.commands.get_by_name('PEI_PCD_DATABASE')
        assert hob_def is not None
        self.assertEqual(hob_def.guid, PCD_GUID)

    def test_get_by_name_is_case_insensitive(self):
        hob_def = self.commands.get_by_name('pei_pcd_database')
        assert hob_def is not None
        self.assertEqual(hob_def.name, 'PEI_PCD_DATABASE')

    def test_get_definition_accepts_either(self):
        self.assertIsNotNone(self.commands.get_definition(PCD_GUID))
        self.assertIsNotNone(self.commands.get_definition('PEI_PCD_DATABASE'))
        self.assertIsNone(self.commands.get_definition('NOT_A_HOB'))

    def test_get_all(self):
        self.assertEqual(len(self.commands.get_all()), 1)


class TestHOBPlatformHierarchy(unittest.TestCase):
    """Cover publication of HOB definitions into the platform hierarchy."""

    def setUp(self):
        self.cfg = SimpleNamespace()
        self.cfg.platform = Platform()
        self.cfg.platform.add_vendor(Vendor('8086'))
        self.parser = HOBParser(self.cfg)
        self.parser.startup()
        stage_data = SimpleNamespace(vid_str='8086', dev_name='HOB')
        for node in ET.fromstring(HOB_XML).iter('structure'):
            self.parser.handle_structure(node, stage_data)

    def test_definition_is_reachable_by_full_name(self):
        reg = self.cfg.platform.get_register_from_fullname('8086.HOB.PEI_PCD_DATABASE')
        self.assertEqual(len(reg), 1)
        self.assertEqual(reg[0].name, 'PEI_PCD_DATABASE')
        self.assertEqual(reg[0].guid, PCD_GUID)

    def test_hob_ip_holds_the_definition_dict(self):
        ip = self.cfg.platform.get_vendor('8086').get_ip(HOB_IP_NAME)
        self.assertIs(ip.obj, self.cfg.HOB_DEFINITIONS)

    def test_definition_carries_vid_and_ip(self):
        hob_def = self.cfg.HOB_DEFINITIONS[PCD_GUID]
        self.assertEqual(hob_def.vid_str, '8086')
        self.assertEqual(hob_def.ip_name, 'HOB')

    def test_ip_name_comes_from_the_definition_entry(self):
        cfg = SimpleNamespace()
        cfg.platform = Platform()
        cfg.platform.add_vendor(Vendor('8086'))
        parser = HOBParser(cfg)
        parser.startup()
        for node in ET.fromstring(HOB_XML).iter('structure'):
            parser.handle_structure(node, SimpleNamespace(vid_str='8086', dev_name='PEIHOB'))
        reg = cfg.platform.get_register_from_fullname('8086.PEIHOB.PEI_PCD_DATABASE')
        self.assertEqual(len(reg), 1)

    def test_missing_vendor_is_not_fatal(self):
        cfg = SimpleNamespace()
        cfg.platform = Platform()
        parser = HOBParser(cfg)
        parser.startup()
        for node in ET.fromstring(HOB_XML).iter('structure'):
            parser.handle_structure(node, SimpleNamespace(vid_str='8086', dev_name='HOB'))
        self.assertIn(PCD_GUID, cfg.HOB_DEFINITIONS)


class TestTopLevelHobSection(unittest.TestCase):
    """Cover the <hob><definition .../></hob> include handled at the device stage."""

    def setUp(self):
        self.cfg = SimpleNamespace()
        self.cfg.HOB = {'8086': {}}
        self.cfg.platform = Platform()
        self.cfg.platform.add_vendor(Vendor('8086'))
        self.dev_config = DevConfig(self.cfg)
        self.stage_data = SimpleNamespace(
            vid_str='8086',
            xml_file=os.path.join(get_main_dir(), 'chipsec', 'cfg', '8086', 'arlh.xml'),
            dev_name=None)

    def _handle(self, xml_str):
        return self.dev_config.handle_hob(ET.fromstring(xml_str), self.stage_data)

    def test_definition_queues_its_config_file(self):
        out = self._handle('<hob><definition name="HOB" config="HOB.hob0.xml" /></hob>')
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].dev_name, 'HOB')
        self.assertTrue(out[0].xml_file.endswith(os.path.join('8086', 'HOB', 'hob0.xml')))

    def test_definition_creates_the_ip(self):
        self._handle('<hob><definition name="HOB" config="HOB.hob0.xml" /></hob>')
        self.assertIn('HOB', self.cfg.HOB['8086'])
        self.assertEqual(self.cfg.platform.get_vendor('8086').get_ip('HOB').obj.name, 'HOB')

    def test_multiple_definitions(self):
        out = self._handle('<hob>'
                           '<definition name="HOB" config="HOB.hob0.xml" />'
                           '<definition name="PCHHOB" config="HOB.hob1.xml" />'
                           '</hob>')
        self.assertEqual([cd.dev_name for cd in out], ['HOB', 'PCHHOB'])

    def test_definition_without_config_is_skipped(self):
        self.assertEqual(self._handle('<hob><definition name="HOB" /></hob>'), [])


class TestDecodeDuringWalk(unittest.TestCase):
    """Cover decoding of GUID extension HOBs while the HOB list is walked."""

    def setUp(self):
        self.cfg = SimpleNamespace()
        parser = HOBParser(self.cfg)
        parser.startup()
        for node in ET.fromstring(HOB_XML).iter('structure'):
            parser.handle_structure(node, SimpleNamespace(vid_str='8086'))
        self.commands = HOBCommands(self.cfg)
        self.payload = struct.pack('<16sIQH6s', uuid.UUID(PCD_GUID).bytes_le,
                                   0x0A, 0x1122334455667788, 0x33, b'\x00' * 6)

    def _build_hob_list(self, payload):
        guid_hob = struct.pack('<HHI16s', EFI_HOB_TYPE_GUID_EXTENSION,
                               8 + 16 + len(payload), 0, uuid.UUID(PCD_GUID).bytes_le) + payload
        end_hob = struct.pack('<HHI', EFI_HOB_TYPE_END_OF_HOB_LIST, 8, 0)
        return guid_hob + end_hob

    def test_matching_hob_is_decoded_during_walk(self):
        hobs, complete, _ = walk_hob_list(self._build_hob_list(self.payload), 0x1000, self.commands)
        self.assertTrue(complete)
        self.assertIsNotNone(hobs[0].register)
        self.assertEqual(hobs[0].register.name, 'PEI_PCD_DATABASE')
        self.assertEqual(hobs[0].register.get_field('BuildVersion'), 0x0A)
        self.assertEqual(hobs[0].register.address, 0x1000)

    def test_trailing_payload_data_is_allowed(self):
        hobs, _, _ = walk_hob_list(self._build_hob_list(self.payload + b'\xAA' * 64), 0, self.commands)
        self.assertEqual(hobs[0].register.get_field('GuidTableCount'), 0x33)

    def test_short_payload_is_not_decoded(self):
        hobs, _, _ = walk_hob_list(self._build_hob_list(self.payload[:8]), 0, self.commands)
        self.assertIsNone(hobs[0].register)

    def test_no_definitions_leaves_register_unset(self):
        hobs, _, _ = walk_hob_list(self._build_hob_list(self.payload), 0)
        self.assertIsNone(hobs[0].register)

    def test_undeclared_guid_leaves_register_unset(self):
        other = struct.pack('<HHI16s', EFI_HOB_TYPE_GUID_EXTENSION, 8 + 16 + 4,
                            0, uuid.UUID('AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE').bytes_le) + b'\x01\x02\x03\x04'
        hobs, _, _ = walk_hob_list(other, 0, self.commands)
        self.assertIsNone(hobs[0].register)

    def test_decoded_register_carries_its_scope(self):
        hobs, _, _ = walk_hob_list(self._build_hob_list(self.payload), 0x1000, self.commands)
        reg = hobs[0].register
        self.assertEqual(reg.vid_str, '8086')
        self.assertEqual(reg.ip_name, 'HOB')
        self.assertEqual(reg.name, 'PEI_PCD_DATABASE')


class TestShippedHobConfig(unittest.TestCase):
    """Validate the HOB definitions shipped under chipsec/cfg/8086/HOB."""

    def setUp(self):
        self.cfg = SimpleNamespace()
        self.parser = HOBParser(self.cfg)
        self.parser.startup()
        xml_file = os.path.join(get_main_dir(), 'chipsec', 'cfg', '8086', 'HOB', 'hob0.xml')
        for node in ET.parse(xml_file).getroot().iter('structure'):
            self.parser.handle_structure(node, None)

    def test_pcd_database_definition_size(self):
        hob_def = self.cfg.HOB_DEFINITIONS[PCD_GUID]
        self.assertEqual(hob_def.name, 'PEI_PCD_DATABASE')
        # Packed layout matches sizeof(PEI_PCD_DATABASE) on a 64-bit build
        self.assertEqual(hob_def.size, 80)


if __name__ == '__main__':
    unittest.main()
