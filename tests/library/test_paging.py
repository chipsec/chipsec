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
from unittest.mock import MagicMock

from chipsec.library import paging
from chipsec.library.exceptions import InvalidMemoryAddress

PAGE_SIZE = 0x1000
PRESENT = 0x1
WRITABLE = 0x2
USER = 0x4
BIG_PAGE = 0x80


class FakePhysicalMemory:
    """Backing store that serves 4KB pages of 64-bit page table entries."""

    def __init__(self):
        self.pages = {}
        self.writes = []
        self.raise_on_read = None

    def set_page(self, addr, entries):
        data = b''.join(struct.pack('<Q', entry) for entry in entries)
        self.pages[addr] = data.ljust(PAGE_SIZE, b'\x00')

    def read_physical_mem(self, addr, size):
        if self.raise_on_read is not None:
            raise self.raise_on_read
        return self.pages.get(addr, b'\x00' * PAGE_SIZE)[:size]

    def write_physical_mem(self, addr, size, buf):
        self.writes.append((addr, size, buf))


def fake_cs(memory=None):
    cs = MagicMock()
    cs.hals.memory = memory if memory is not None else FakePhysicalMemory()
    return cs


def four_level_memory():
    """A 4-level hierarchy mapping VA 0 to a 2MB page at PA 0x400000."""
    mem = FakePhysicalMemory()
    mem.set_page(0x1000, [0x2000 | PRESENT | WRITABLE])
    mem.set_page(0x2000, [0x3000 | PRESENT | WRITABLE])
    mem.set_page(0x3000, [0x400000 | PRESENT | WRITABLE | BIG_PAGE])
    return mem


def four_kb_memory():
    """A 4-level hierarchy mapping VA 0 to a 4KB page at PA 0x500000."""
    mem = FakePhysicalMemory()
    mem.set_page(0x1000, [0x2000 | PRESENT | WRITABLE])
    mem.set_page(0x2000, [0x3000 | PRESENT | WRITABLE])
    mem.set_page(0x3000, [0x4000 | PRESENT | WRITABLE])
    mem.set_page(0x4000, [0x500000 | PRESENT | WRITABLE])
    return mem


class TestTranslation(unittest.TestCase):
    """c_translation stores the virtual to physical map built while walking tables."""

    def setUp(self):
        self.translation = paging.c_translation()

    def test_empty_translation_is_an_identity_map(self):
        self.assertEqual(self.translation.get_translation(0x1234), 0x1234)

    def test_4kb_page_translation_preserves_the_page_offset(self):
        self.translation.add_page(0x1000, 0x500000, '4KB', 'RW')

        self.assertEqual(self.translation.get_translation(0x1123), 0x500123)

    def test_2mb_page_translation_preserves_the_page_offset(self):
        self.translation.add_page(0x200000, 0x400000, '2MB', 'RW')

        self.assertEqual(self.translation.get_translation(0x201234), 0x401234)

    def test_1gb_page_translation_preserves_the_page_offset(self):
        self.translation.add_page(0x40000000, 0x80000000, '1GB', 'RW')

        self.assertEqual(self.translation.get_translation(0x40000ABC), 0x80000ABC)

    def test_unmapped_address_has_no_translation(self):
        self.translation.add_page(0x1000, 0x500000, '4KB', 'RW')

        self.assertIsNone(self.translation.get_translation(0xDEAD0000))

    def test_unsupported_page_size_is_rejected(self):
        with self.assertRaises(Exception):
            self.translation.add_page(0x1000, 0x2000, '8KB', 'RW')

    def test_deleting_a_page_removes_its_translation(self):
        self.translation.add_page(0x1000, 0x500000, '4KB', 'RW')
        self.translation.add_page(0x2000, 0x600000, '4KB', 'RW')

        self.translation.del_page(0x1000)

        self.assertIsNone(self.translation.get_translation(0x1000))
        self.assertEqual(self.translation.get_translation(0x2000), 0x600000)

    def test_deleting_an_unknown_page_is_a_no_op(self):
        self.translation.del_page(0x1000)

        self.assertEqual(self.translation.translation, {})

    def test_pages_can_be_looked_up_by_physical_address(self):
        self.translation.add_page(0x1000, 0x500000, '4KB', 'RW')
        self.translation.add_page(0x2000, 0x600000, '4KB', 'RW')

        pages = self.translation.get_pages_by_physaddr(0x500ABC)

        self.assertEqual(len(pages), 1)
        self.assertEqual(pages[0]['addr'], 0x500000)

    def test_adjacent_pages_with_matching_attributes_are_merged(self):
        self.translation.add_page(0x1000, 0x500000, '4KB', 'RW')
        self.translation.add_page(0x2000, 0x501000, '4KB', 'RW')

        self.assertEqual(self.translation.get_mem_range(), [[0x500000, 0x502000, 'RW']])

    def test_adjacent_pages_with_different_attributes_stay_separate(self):
        self.translation.add_page(0x1000, 0x500000, '4KB', 'RW')
        self.translation.add_page(0x2000, 0x501000, '4KB', 'R')

        self.assertEqual(len(self.translation.get_mem_range()), 2)

    def test_attributes_can_be_ignored_when_merging(self):
        self.translation.add_page(0x1000, 0x500000, '4KB', 'RW')
        self.translation.add_page(0x2000, 0x501000, '4KB', 'R')

        self.assertEqual(self.translation.get_mem_range(noattr=True), [[0x500000, 0x502000, '']])

    def test_non_adjacent_pages_stay_separate(self):
        self.translation.add_page(0x1000, 0x500000, '4KB', 'RW')
        self.translation.add_page(0x2000, 0x900000, '4KB', 'RW')

        self.assertEqual(len(self.translation.get_mem_range()), 2)

    def test_address_space_is_the_total_of_all_mapped_ranges(self):
        self.translation.add_page(0x1000, 0x500000, '4KB', 'RW')
        self.translation.add_page(0x200000, 0x800000, '2MB', 'RW')

        self.assertEqual(self.translation.get_address_space(), paging.SIZE_4KB + paging.SIZE_2MB)

    def test_empty_translation_has_no_address_space(self):
        self.assertEqual(self.translation.get_address_space(), 0)

    def test_2mb_page_expands_into_512_4kb_pages(self):
        self.translation.add_page(0x200000, 0x400000, '2MB', 'RW')

        self.translation.expand_pages('2MB')

        self.assertEqual(len(self.translation.translation), 512)
        self.assertEqual(
            self.translation.translation[0x200000],
            {'addr': 0x400000, 'size': '4KB', 'attr': 'RW'})
        self.assertEqual(
            self.translation.translation[0x3FF000],
            {'addr': 0x5FF000, 'size': '4KB', 'attr': 'RW'})

    def test_1gb_page_expands_into_512_2mb_pages(self):
        self.translation.add_page(0x40000000, 0x80000000, '1GB', 'R')

        self.translation.expand_pages('1GB')

        self.assertEqual(len(self.translation.translation), 512)
        self.assertEqual(
            self.translation.translation[0x40000000],
            {'addr': 0x80000000, 'size': '2MB', 'attr': 'R'})
        self.assertEqual(
            self.translation.translation[0x7FE00000],
            {'addr': 0xBFE00000, 'size': '2MB', 'attr': 'R'})

    def test_expansion_leaves_other_page_sizes_unchanged(self):
        self.translation.add_page(0x1000, 0x500000, '4KB', 'RW')

        self.translation.expand_pages('2MB')

        self.assertEqual(
            self.translation.translation,
            {0x1000: {'addr': 0x500000, 'size': '4KB', 'attr': 'RW'}})

    def test_unsupported_expansion_size_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Unsupported page size'):
            self.translation.expand_pages('4KB')


class TestReverseTranslation(unittest.TestCase):
    """c_reverse_translation answers "which virtual pages map here?"."""

    def test_multiple_virtual_pages_can_share_one_physical_page(self):
        forward = {
            0x1000: {'addr': 0x500000, 'size': '4KB', 'attr': 'RW'},
            0x9000: {'addr': 0x500000, 'size': '4KB', 'attr': 'R'},
        }

        reverse = paging.c_reverse_translation(forward)

        virts = sorted(entry['addr'] for entry in reverse.get_reverse_translation(0x500000))
        self.assertEqual(virts, [0x1000, 0x9000])

    def test_lookup_is_aligned_to_the_containing_page(self):
        forward = {0x1000: {'addr': 0x500000, 'size': '4KB', 'attr': 'RW'}}

        reverse = paging.c_reverse_translation(forward)

        self.assertEqual(len(reverse.get_reverse_translation(0x500FFF)), 1)

    def test_unmapped_physical_address_yields_no_entries(self):
        reverse = paging.c_reverse_translation({})

        self.assertEqual(reverse.get_reverse_translation(0x500000), [])


class TestMemoryAccess(unittest.TestCase):
    """Page table reads go through the HAL, optionally via a second translation level."""

    def test_reads_are_delegated_to_the_memory_hal(self):
        mem = FakePhysicalMemory()
        mem.set_page(0x1000, [0xAABBCCDD])

        data = paging.c_paging_memory_access(fake_cs(mem)).readmem('test', 0x1000, 8)

        self.assertEqual(data, struct.pack('<Q', 0xAABBCCDD))

    def test_without_a_second_level_the_address_is_used_as_is(self):
        mem = FakePhysicalMemory()
        mem.set_page(0x1000, [0x1111])

        access = paging.c_paging_with_2nd_level_translation(fake_cs(mem))

        self.assertEqual(access.readmem('test', 0x1000, 8), struct.pack('<Q', 0x1111))

    def test_second_level_translation_redirects_the_read(self):
        mem = FakePhysicalMemory()
        mem.set_page(0x7000, [0x2222])
        access = paging.c_paging_with_2nd_level_translation(fake_cs(mem))
        access.translation_level2.add_page(0x1000, 0x7000, '4KB', 'RW')

        self.assertEqual(access.readmem('test', 0x1000, 8), struct.pack('<Q', 0x2222))

    def test_unmapped_guest_address_reads_nothing(self):
        access = paging.c_paging_with_2nd_level_translation(fake_cs())
        access.translation_level2.add_page(0x1000, 0x7000, '4KB', 'RW')

        self.assertEqual(access.readmem('test', 0xDEAD0000, 8), b'')


class TestPagingHelpers(unittest.TestCase):
    """Shared helpers used by every page table flavor."""

    def setUp(self):
        self.paging = paging.c_paging(fake_cs())

    def test_addresses_below_the_canonical_boundary_are_unchanged(self):
        self.assertEqual(self.paging.get_canonical(0x1000), 0x1000)

    def test_addresses_above_the_canonical_boundary_are_sign_extended(self):
        self.assertEqual(self.paging.get_canonical(1 << 47), 0xFFFF800000000000)

    def test_field_extraction_and_insertion_are_inverses(self):
        desc = {'mask': 0x1FF, 'offset': 30}

        self.assertEqual(self.paging.get_field(self.paging.set_field(0x123, desc), desc), 0x123)

    def test_field_extraction_masks_out_neighboring_bits(self):
        self.assertEqual(self.paging.get_field(0xFF, {'mask': 0xF, 'offset': 4}), 0xF)

    def test_uniform_pages_are_collapsed_to_a_single_entry(self):
        mem = FakePhysicalMemory()
        walker = paging.c_paging(fake_cs(mem))

        self.assertEqual(walker.read_entries('pml4', 0x1000), [0])

    def test_non_uniform_pages_return_every_entry(self):
        mem = FakePhysicalMemory()
        mem.set_page(0x1000, [1])
        walker = paging.c_paging(fake_cs(mem))

        self.assertEqual(len(walker.read_entries('pml4', 0x1000)), 512)

    def test_wide_entries_are_returned_as_pairs(self):
        mem = FakePhysicalMemory()
        mem.set_page(0x1000, [1, 2])
        walker = paging.c_paging(fake_cs(mem))

        entries = walker.read_entries('re', 0x1000, 16)

        self.assertEqual(len(entries), 256)
        self.assertEqual(entries[0], [1, 2])

    def test_base_class_cannot_walk_page_tables(self):
        with self.assertRaises(Exception):
            self.paging.read_page_tables(0x1000)


class TestConfigurationPersistence(unittest.TestCase):
    """Captured page tables can be saved and reloaded for offline analysis."""

    def setUp(self):
        handle, self.path = tempfile.mkstemp()
        os.close(handle)
        self.addCleanup(os.remove, self.path)

    def test_saved_state_is_restored_on_load(self):
        original = paging.c_paging(fake_cs())
        original.add_page(0x1000, 0x500000, '4KB', 'RW')
        original.translation_level2.add_page(0x2000, 0x600000, '4KB', 'R')
        original.pt = {0x1000: 'pml4'}
        original.save_configuration(self.path)

        restored = paging.c_paging(fake_cs())
        restored.load_configuration(self.path)

        self.assertEqual(restored.translation, original.translation)
        self.assertEqual(restored.translation_level2.translation, original.translation_level2.translation)
        self.assertEqual(restored.pt, original.pt)

    def test_corrupt_configuration_does_not_raise(self):
        with open(self.path, 'w') as handle:
            handle.write('not a python literal\n')

        restored = paging.c_paging(fake_cs())
        restored.load_configuration(self.path)

        self.assertEqual(restored.translation, {})


class TestFourLevelPageTables(unittest.TestCase):
    """The 4-level walker is the base for IA32e, EPT and VT-d second level tables."""

    def test_virtual_address_is_composed_from_the_table_indices(self):
        walker = paging.c_4level_page_tables(fake_cs())

        self.assertEqual(
            walker.get_virt_addr(1, 2, 3, 4),
            (1 << 39) | (2 << 30) | (3 << 21) | (4 << 12),
        )

    def test_presence_and_page_size_are_read_from_the_entry_flags(self):
        walker = paging.c_4level_page_tables(fake_cs())

        self.assertTrue(walker.is_present(PRESENT))
        self.assertFalse(walker.is_present(0))
        self.assertTrue(walker.is_bigpage(BIG_PAGE))
        self.assertFalse(walker.is_bigpage(PRESENT))

    def test_walking_records_every_table_page(self):
        walker = paging.c_4level_page_tables(fake_cs(four_level_memory()))

        walker.read_page_tables(0x1000)

        self.assertEqual(set(walker.pt), {0x1000, 0x2000, 0x3000})

    def test_walking_records_the_mapped_large_page(self):
        walker = paging.c_4level_page_tables(fake_cs(four_level_memory()))

        walker.read_page_tables(0x1000)

        self.assertEqual(walker.translation[0]['addr'], 0x400000)
        self.assertEqual(walker.translation[0]['size'], '2MB')

    def test_walking_descends_into_leaf_page_tables(self):
        walker = paging.c_4level_page_tables(fake_cs(four_kb_memory()))

        walker.read_page_tables(0x1000)

        self.assertEqual(walker.translation[0]['size'], '4KB')
        self.assertEqual(walker.translation[0]['addr'], 0x500000)

    def test_walking_replaces_the_results_of_a_previous_walk(self):
        walker = paging.c_4level_page_tables(fake_cs(four_level_memory()))

        walker.read_page_tables(0x1000)
        walker.read_page_tables(0x1000)

        self.assertEqual(len(walker.translation), 1)

    def test_lookup_of_a_large_page_keeps_the_offset_within_the_page(self):
        walker = paging.c_4level_page_tables(fake_cs(four_level_memory()))
        walker.read_page_tables(0x1000)

        entry = walker.read_entry_by_virt_addr(0x1234)

        self.assertEqual(entry['addr'], 0x401234)
        self.assertEqual(entry['size'], '2MB')

    def test_lookup_of_a_small_page_keeps_the_offset_within_the_page(self):
        walker = paging.c_4level_page_tables(fake_cs(four_kb_memory()))
        walker.read_page_tables(0x1000)

        entry = walker.read_entry_by_virt_addr(0x123)

        self.assertEqual(entry['addr'], 0x500123)
        self.assertEqual(entry['size'], '4KB')

    def test_lookup_of_an_unmapped_address_reports_no_mapping(self):
        walker = paging.c_4level_page_tables(fake_cs(four_level_memory()))
        walker.read_page_tables(0x1000)

        self.assertEqual(walker.read_entry_by_virt_addr(1 << 40), {'addr': 0, 'attr': '', 'size': ''})

    def test_lookup_before_a_walk_is_rejected(self):
        walker = paging.c_4level_page_tables(fake_cs())

        with self.assertRaises(Exception):
            walker.read_entry_by_virt_addr(0)

    def test_attributes_describe_write_and_privilege_bits(self):
        walker = paging.c_4level_page_tables(fake_cs())

        self.assertEqual(walker.get_attr(PRESENT), 'RS')
        self.assertEqual(walker.get_attr(PRESENT | WRITABLE | USER), 'WU')

    def test_status_report_records_a_successful_walk(self):
        walker = paging.c_4level_page_tables(fake_cs(four_level_memory()))

        walker.read_pt_and_show_status(self.id(), 'test', 0x1000)

        self.assertFalse(walker.failure)

    def test_status_report_clears_state_when_memory_is_unreadable(self):
        mem = four_level_memory()
        mem.raise_on_read = InvalidMemoryAddress('bad address')
        walker = paging.c_4level_page_tables(fake_cs(mem))

        walker.read_pt_and_show_status(self.id(), 'test', 0x1000)

        self.assertTrue(walker.failure)
        self.assertEqual(walker.translation, {})
        self.assertEqual(walker.pt, {})

    def test_misconfiguration_check_tolerates_page_table_pages_in_range(self):
        walker = paging.c_4level_page_tables(fake_cs(four_level_memory()))
        walker.read_page_tables(0x1000)

        walker.check_misconfig(list(walker.pt))


class TestIA32ePageTables(unittest.TestCase):

    def test_presence_and_size_use_the_architectural_bit_positions(self):
        walker = paging.c_ia32e_page_tables(fake_cs())

        self.assertTrue(walker.is_present(PRESENT))
        self.assertFalse(walker.is_present(BIG_PAGE))
        self.assertTrue(walker.is_bigpage(BIG_PAGE))

    def test_attributes_report_read_write_and_supervisor_user(self):
        walker = paging.c_ia32e_page_tables(fake_cs())

        self.assertEqual(walker.get_attr(PRESENT), 'R S')
        self.assertEqual(walker.get_attr(PRESENT | WRITABLE), 'W S')
        self.assertEqual(walker.get_attr(PRESENT | WRITABLE | USER), 'W U')

    def test_mapped_pages_are_labelled_with_the_virtual_address_name(self):
        walker = paging.c_ia32e_page_tables(fake_cs(four_level_memory()))

        walker.read_page_tables(0x1000)

        self.assertEqual(walker.translation[0]['attr'], 'W S')


class TestPAEPageTables(unittest.TestCase):

    def test_pae_tables_have_no_pml4_level(self):
        walker = paging.c_pae_page_tables(fake_cs())

        with self.assertRaises(Exception):
            walker.read_pml4(0x1000)

    def test_pae_only_addresses_two_pdpt_index_bits(self):
        walker = paging.c_pae_page_tables(fake_cs())

        self.assertEqual(walker.PDPT_INDX['mask'], 0x3)


class TestExtendedPageTables(unittest.TestCase):
    """EPT entries encode access rights and memory type instead of R/W/U."""

    def test_presence_is_driven_by_the_access_rights_field(self):
        walker = paging.c_extended_page_tables(fake_cs())

        self.assertTrue(walker.is_present(0x7))
        self.assertFalse(walker.is_present(0x8))

    def test_attributes_report_access_rights_and_memory_type(self):
        walker = paging.c_extended_page_tables(fake_cs())

        self.assertEqual(walker.get_attr(0x7 | (6 << 3)), 'XWR WB')
        self.assertEqual(walker.get_attr(0x1), '--R UC')

    def test_guest_physical_addresses_are_not_sign_extended(self):
        walker = paging.c_extended_page_tables(fake_cs())

        self.assertEqual(walker.get_canonical(1 << 47), 1 << 47)

    def test_remapping_a_1gb_entry_writes_back_a_new_entry(self):
        mem = FakePhysicalMemory()
        mem.set_page(0x1000, [0x2000 | 0x7])
        mem.set_page(0x2000, [0x3000 | 0x7])
        walker = paging.c_extended_page_tables(fake_cs(mem))
        walker.read_page_tables(0x1000)

        walker.map_bigpage_1G(0, 0)

        self.assertEqual(len(mem.writes), 1)
        addr, size, _buf = mem.writes[0]
        self.assertEqual((addr, size), (0x2000, 8))

    def test_remapping_before_a_walk_is_rejected(self):
        walker = paging.c_extended_page_tables(fake_cs())

        with self.assertRaises(Exception):
            walker.map_bigpage_1G(0, 0)


class TestVTdPageTables(unittest.TestCase):
    """VT-d adds root and context entry tables in front of the second level tables."""

    @staticmethod
    def _vtd_memory():
        mem = FakePhysicalMemory()
        mem.set_page(0x1000, [0x2000 | 0x1, 0x0])
        mem.set_page(0x2000, [0x3000 | 0x1, 0x0])
        return mem

    def test_root_entries_lead_to_context_pages(self):
        walker = paging.c_vtd_page_tables(fake_cs(self._vtd_memory()))

        walker.read_re(0x1000)

        self.assertIn(0x2000, walker.cpt)

    def test_present_context_entries_are_recorded_by_source_id(self):
        walker = paging.c_vtd_page_tables(fake_cs(self._vtd_memory()))

        walker.read_ce(0x2000, 0)

        self.assertIn(0, walker.context)

    def test_context_entries_register_their_translation_domain(self):
        walker = paging.c_vtd_page_tables(fake_cs(self._vtd_memory()))

        walker.read_ce(0x2000, 0)

        self.assertIn(0x3000, walker.domains)

    def test_absent_root_entries_are_skipped(self):
        walker = paging.c_vtd_page_tables(fake_cs(FakePhysicalMemory()))

        walker.read_re(0x1000)

        self.assertEqual(walker.cpt, {})

    def test_reading_the_context_writes_a_report_and_records_domains(self):
        handle, path = tempfile.mkstemp()
        os.close(handle)
        self.addCleanup(os.remove, path)
        walker = paging.c_vtd_page_tables(fake_cs(self._vtd_memory()))

        walker.read_vtd_context(path, 0x1000)

        self.assertIn(0x3000, walker.domains)
        self.assertIn(0, walker.context)

    def test_context_entry_is_printable(self):
        walker = paging.c_vtd_page_tables(fake_cs())

        walker.print_context_entry(0x0100, [0x3000 | 0x1, 0x0])


if __name__ == '__main__':
    unittest.main()
