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

import unittest
from unittest.mock import MagicMock, patch
from uuid import UUID

from chipsec.library.uefi import search
from chipsec.library.uefi.spi import EFI_SECTION, EFI_FILE

GUID_STR = '12345678-1234-1234-1234-123456789ABC'
OTHER_GUID_STR = 'AABBCCDD-1234-1234-1234-123456789ABC'


def make_section(image: bytes = b'', ui_string: str = '', parent_guid=None) -> EFI_SECTION:
    section = EFI_SECTION(0, 'PE32', 0x10, image, 0x4, len(image))
    section.ui_string = ui_string
    section.parentGuid = parent_guid
    return section


def make_file(image: bytes = b'', guid=None, ui_string: str = '') -> EFI_FILE:
    efi_file = EFI_FILE(0, guid, 0x07, 0, 0, 0, len(image), image, 0x18, False, 0)
    efi_file.ui_string = ui_string
    return efi_file


class SearchTestBase(unittest.TestCase):

    def setUp(self):
        self.log = MagicMock()


class TestCheckRulesName(SearchTestBase):
    """Cover the 'name' criterion of chipsec.library.uefi.search.check_rules."""

    def test_matching_ui_string(self):
        efi = make_section(ui_string='rootkitX.efi')
        rules = {'rule1': {'name': 'rootkitX.efi'}}
        self.assertTrue(search.check_rules(efi, rules, 'entry', self.log))

    def test_non_matching_ui_string(self):
        efi = make_section(ui_string='legit.efi')
        rules = {'rule1': {'name': 'rootkitX.efi'}}
        self.assertFalse(search.check_rules(efi, rules, 'entry', self.log))

    def test_empty_name_criterion_is_ignored(self):
        efi = make_section(ui_string='legit.efi')
        rules = {'rule1': {'name': ''}}
        self.assertTrue(search.check_rules(efi, rules, 'entry', self.log))

    def test_match_is_logged_with_qualified_rule_name(self):
        efi = make_section(ui_string='rootkitX.efi')
        search.check_rules(efi, {'rule1': {'name': 'rootkitX.efi'}}, 'UEFI_rootkitX', self.log)
        self.log.log_important.assert_called_once_with("match 'UEFI_rootkitX.rule1'")

    def test_logging_suppressed_when_blog_false(self):
        efi = make_section(ui_string='rootkitX.efi')
        search.check_rules(efi, {'rule1': {'name': 'rootkitX.efi'}}, 'entry', self.log, bLog=False)
        self.log.log_important.assert_not_called()


class TestCheckRulesGuid(SearchTestBase):
    """Cover the 'guid' criterion of chipsec.library.uefi.search.check_rules."""

    def test_section_matches_on_parent_guid(self):
        efi = make_section(parent_guid=UUID(GUID_STR))
        self.assertTrue(search.check_rules(efi, {'r': {'guid': GUID_STR}}, 'entry', self.log))

    def test_section_does_not_match_other_guid(self):
        efi = make_section(parent_guid=UUID(OTHER_GUID_STR))
        self.assertFalse(search.check_rules(efi, {'r': {'guid': GUID_STR}}, 'entry', self.log))

    def test_file_matches_on_own_guid(self):
        efi = make_file(guid=UUID(GUID_STR))
        self.assertTrue(search.check_rules(efi, {'r': {'guid': GUID_STR}}, 'entry', self.log))

    def test_string_guid_is_normalized_to_uuid_in_place(self):
        rules = {'r': {'guid': GUID_STR}}
        search.check_rules(make_section(parent_guid=UUID(GUID_STR)), rules, 'entry', self.log)
        self.assertEqual(rules['r']['guid'], UUID(GUID_STR))

    def test_guid_already_a_uuid_is_accepted(self):
        rules = {'r': {'guid': UUID(GUID_STR)}}
        self.assertTrue(search.check_rules(make_section(parent_guid=UUID(GUID_STR)), rules, 'entry', self.log))


class TestCheckRulesRegexp(SearchTestBase):
    """Cover the 'regexp' criterion of chipsec.library.uefi.search.check_rules."""

    def test_matching_byte_sequence(self):
        efi = make_section(image=b'padding IAMVULNERABLE padding')
        self.assertTrue(search.check_rules(efi, {'r': {'regexp': 'IAMVULNERABLE'}}, 'entry', self.log))

    def test_non_matching_byte_sequence(self):
        efi = make_section(image=b'nothing to see here')
        self.assertFalse(search.check_rules(efi, {'r': {'regexp': 'IAMVULNERABLE'}}, 'entry', self.log))

    def test_match_offset_is_reported(self):
        efi = make_section(image=b'AAAABBBB')
        search.check_rules(efi, {'r': {'regexp': 'BBBB'}}, 'entry', self.log)
        logged = ' '.join(str(call) for call in self.log.log.call_args_list)
        self.assertIn('offset 4h', logged)

    def test_regexp_metacharacters_are_honored(self):
        efi = make_section(image=b'version 1.2.3')
        self.assertTrue(search.check_rules(efi, {'r': {'regexp': 'version [0-9.]+'}}, 'entry', self.log))


class TestCheckRulesHashes(SearchTestBase):
    """Cover the md5/sha1/sha256 criteria of chipsec.library.uefi.search.check_rules."""

    def setUp(self):
        super().setUp()
        self.efi = make_section(image=b'firmware blob')
        self.efi.calc_hashes()

    def test_md5_match(self):
        self.assertTrue(search.check_rules(self.efi, {'r': {'md5': self.efi.MD5}}, 'entry', self.log))

    def test_sha1_match(self):
        self.assertTrue(search.check_rules(self.efi, {'r': {'sha1': self.efi.SHA1}}, 'entry', self.log))

    def test_sha256_match(self):
        self.assertTrue(search.check_rules(self.efi, {'r': {'sha256': self.efi.SHA256}}, 'entry', self.log))

    def test_hash_mismatch(self):
        self.assertFalse(search.check_rules(self.efi, {'r': {'md5': '00' * 16}}, 'entry', self.log))

    def test_all_hashes_must_match_within_one_rule(self):
        rule = {'md5': self.efi.MD5, 'sha1': '00' * 20}
        self.assertFalse(search.check_rules(self.efi, {'r': rule}, 'entry', self.log))


class TestCheckRulesCpuid(SearchTestBase):
    """Cover the 'cpuid' criterion of chipsec.library.uefi.search.check_rules."""

    def test_cpuid_in_list_matches(self):
        rules = {'r': {'cpuid': '906EA,A0653'}}
        self.assertTrue(search.check_rules(make_section(), rules, 'entry', self.log, cpuid=0xA0653))

    def test_cpuid_not_in_list_does_not_match(self):
        rules = {'r': {'cpuid': '906EA'}}
        self.assertFalse(search.check_rules(make_section(), rules, 'entry', self.log, cpuid=0xA0653))

    def test_cpuid_list_is_case_insensitive(self):
        rules = {'r': {'cpuid': 'a0653'}}
        self.assertTrue(search.check_rules(make_section(), rules, 'entry', self.log, cpuid=0xA0653))

    def test_unknown_platform_cpuid_matches_conservatively(self):
        rules = {'r': {'cpuid': '906EA'}}
        self.assertTrue(search.check_rules(make_section(), rules, 'entry', self.log, cpuid=None))


class TestCheckRulesCombination(SearchTestBase):
    """Cover the AND-within-rule / OR-across-rules semantics."""

    def test_criteria_within_a_rule_are_anded(self):
        efi = make_section(image=b'IAMVULNERABLE', ui_string='target.efi')
        rules = {'r': {'name': 'target.efi', 'regexp': 'NOTPRESENT'}}
        self.assertFalse(search.check_rules(efi, rules, 'entry', self.log))

    def test_all_criteria_satisfied_within_a_rule(self):
        efi = make_section(image=b'IAMVULNERABLE', ui_string='target.efi')
        rules = {'r': {'name': 'target.efi', 'regexp': 'IAMVULNERABLE'}}
        self.assertTrue(search.check_rules(efi, rules, 'entry', self.log))

    def test_rules_are_ored(self):
        efi = make_section(ui_string='target.efi')
        rules = {'r1': {'name': 'other.efi'}, 'r2': {'name': 'target.efi'}}
        self.assertTrue(search.check_rules(efi, rules, 'entry', self.log))

    def test_no_rules_does_not_match(self):
        self.assertFalse(search.check_rules(make_section(), {}, 'entry', self.log))

    def test_rule_without_criteria_matches_everything(self):
        self.assertTrue(search.check_rules(make_section(), {'r': {}}, 'entry', self.log))


class TestCheckMatchCriteria(SearchTestBase):
    """Cover chipsec.library.uefi.search.check_match_criteria."""

    def test_matching_entry_is_reported(self):
        efi = make_section(ui_string='rootkitX.efi')
        criteria = {'UEFI_rootkitX': {'match': {'r1': {'name': 'rootkitX.efi'}}}}
        self.assertTrue(search.check_match_criteria(efi, criteria, self.log))

    def test_non_matching_entry_is_not_reported(self):
        efi = make_section(ui_string='legit.efi')
        criteria = {'UEFI_rootkitX': {'match': {'r1': {'name': 'rootkitX.efi'}}}}
        self.assertFalse(search.check_match_criteria(efi, criteria, self.log))

    def test_description_is_logged_on_match(self):
        efi = make_section(ui_string='rootkitX.efi')
        criteria = {'UEFI_rootkitX': {'description': 'implant X', 'match': {'r1': {'name': 'rootkitX.efi'}}}}
        search.check_match_criteria(efi, criteria, self.log)
        logged = ' '.join(str(call) for call in self.log.log.call_args_list)
        self.assertIn('implant X', logged)

    def test_exclusion_suppresses_a_match(self):
        efi = make_section(image=b'patched', ui_string='rootkitX.efi')
        efi.calc_hashes()
        criteria = {
            'UEFI_rootkitX': {
                'match': {'r1': {'name': 'rootkitX.efi'}},
                'exclude': {'patched': {'md5': efi.MD5}},
            }
        }
        self.assertFalse(search.check_match_criteria(efi, criteria, self.log))

    def test_non_applicable_exclusion_keeps_the_match(self):
        efi = make_section(image=b'unpatched', ui_string='rootkitX.efi')
        efi.calc_hashes()
        criteria = {
            'UEFI_rootkitX': {
                'match': {'r1': {'name': 'rootkitX.efi'}},
                'exclude': {'patched': {'md5': '00' * 16}},
            }
        }
        self.assertTrue(search.check_match_criteria(efi, criteria, self.log))

    def test_exclusion_is_not_evaluated_without_a_match(self):
        efi = make_section(ui_string='legit.efi')
        criteria = {
            'UEFI_rootkitX': {
                'match': {'r1': {'name': 'rootkitX.efi'}},
                'exclude': {'patched': {}},
            }
        }
        self.assertFalse(search.check_match_criteria(efi, criteria, self.log))

    def test_entry_without_match_key_is_skipped(self):
        efi = make_section(ui_string='rootkitX.efi')
        self.assertFalse(search.check_match_criteria(efi, {'UEFI_rootkitX': {}}, self.log))

    def test_multiple_entries_are_ored(self):
        efi = make_section(ui_string='rootkitX.efi')
        criteria = {
            'entryA': {'match': {'r1': {'name': 'other.efi'}}},
            'entryB': {'match': {'r1': {'name': 'rootkitX.efi'}}},
        }
        self.assertTrue(search.check_match_criteria(efi, criteria, self.log))

    def test_cpuid_is_forwarded_to_the_rules(self):
        efi = make_section(ui_string='rootkitX.efi')
        criteria = {'entryA': {'match': {'r1': {'name': 'rootkitX.efi', 'cpuid': 'A0653'}}}}
        self.assertTrue(search.check_match_criteria(efi, criteria, self.log, cpuid=0xA0653))
        self.assertFalse(search.check_match_criteria(efi, criteria, self.log, cpuid=0x906EA))

    def test_default_logger_used_when_none_supplied(self):
        efi = make_section(ui_string='rootkitX.efi')
        criteria = {'entryA': {'match': {'r1': {'name': 'rootkitX.efi'}}}}
        with patch.object(search, 'logger') as mock_logger:
            self.assertTrue(search.check_match_criteria(efi, criteria, None))
        mock_logger.assert_called_once_with()


if __name__ == '__main__':
    unittest.main()
