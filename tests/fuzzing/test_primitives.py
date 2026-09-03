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

from chipsec.fuzzing.primitives import (
    bit_field,
    byte,
    delim,
    dword,
    group,
    qword,
    random_data,
    static,
    string,
    word,
)


def drain(primitive, limit: int = 10000) -> list:
    """Mutate until the primitive reports completion and collect every value."""
    values = []
    while primitive.mutate():
        values.append(primitive.value)
        if len(values) > limit:
            raise AssertionError(f'{type(primitive).__name__} never reported completion')
    return values


class TestPrimitiveMutationContract(unittest.TestCase):
    """Every primitive shares the same mutate/reset/exhaust lifecycle."""

    def test_mutation_count_matches_reported_number_of_mutations(self):
        primitive = delim(':')

        self.assertEqual(len(drain(primitive)), primitive.num_mutations())

    def test_mutation_stops_and_restores_the_original_value(self):
        primitive = delim(':')
        drain(primitive)

        self.assertFalse(primitive.mutate())
        self.assertTrue(primitive.fuzz_complete)
        self.assertEqual(primitive.value, primitive.original_value)

    def test_mutation_index_advances_once_per_mutation(self):
        primitive = delim(':')

        primitive.mutate()
        primitive.mutate()

        self.assertEqual(primitive.mutant_index, 2)

    def test_reset_returns_the_primitive_to_its_starting_state(self):
        primitive = delim(':')
        drain(primitive)

        primitive.reset()

        self.assertFalse(primitive.fuzz_complete)
        self.assertEqual(primitive.mutant_index, 0)
        self.assertEqual(primitive.value, primitive.original_value)
        self.assertTrue(primitive.mutate())

    def test_exhaust_skips_the_remaining_mutations(self):
        primitive = delim(':')
        primitive.mutate()

        remaining = primitive.exhaust()

        self.assertEqual(remaining, primitive.num_mutations() - 1)
        self.assertTrue(primitive.fuzz_complete)
        self.assertEqual(primitive.value, primitive.original_value)
        self.assertFalse(primitive.mutate())

    def test_disabling_fuzzing_suppresses_all_mutations(self):
        primitive = delim(':', fuzzable=False)

        self.assertFalse(primitive.mutate())
        self.assertEqual(primitive.value, ':')

    def test_render_reflects_the_current_value(self):
        primitive = delim(':')
        primitive.mutate()

        self.assertEqual(primitive.render(), primitive.value)


class TestDelim(unittest.TestCase):

    def test_library_repeats_the_delimiter(self):
        primitive = delim(':')

        values = drain(primitive)

        self.assertIn('::', values)
        self.assertIn('', values)

    def test_space_delimiter_adds_tab_substitutions(self):
        spaced = drain(delim(' '))
        colon = drain(delim(':'))

        self.assertGreater(len(spaced), len(colon))

    def test_empty_delimiter_has_no_repetition_cases(self):
        empty = delim('')
        colon = delim(':')

        self.assertLess(empty.num_mutations(), colon.num_mutations())

    def test_named_primitive_keeps_its_name(self):
        self.assertEqual(delim(':', name='separator').name, 'separator')


class TestGroup(unittest.TestCase):

    def test_group_steps_through_every_value_in_order(self):
        primitive = group('opcodes', ['a', 'b', 'c'])

        self.assertEqual(drain(primitive), ['a', 'b', 'c'])

    def test_group_reports_one_mutation_per_value(self):
        self.assertEqual(group('opcodes', ['a', 'b', 'c']).num_mutations(), 3)

    def test_group_falls_back_to_the_first_value_once_exhausted(self):
        primitive = group('opcodes', ['a', 'b'])
        drain(primitive)

        self.assertFalse(primitive.mutate())
        self.assertEqual(primitive.value, 'a')

    def test_group_rejects_non_string_values(self):
        with self.assertRaises(AssertionError):
            group('opcodes', ['a', 1])


class TestRandomData(unittest.TestCase):

    def test_default_mutation_budget_is_respected(self):
        primitive = random_data('seed', 1, 4, max_mutations=7)

        self.assertEqual(len(drain(primitive)), 7)

    def test_generated_values_are_raw_bytes_within_the_requested_range(self):
        primitive = random_data('seed', 3, 6, max_mutations=20)

        for value in drain(primitive):
            self.assertIsInstance(value, bytes)
            self.assertTrue(3 <= len(value) <= 6)

    def test_stepping_produces_deterministic_lengths(self):
        primitive = random_data('seed', 0, 10, step=5)

        lengths = [len(value) for value in drain(primitive)]

        self.assertEqual(lengths, [0, 5, 10])

    def test_stepping_overrides_the_mutation_budget(self):
        self.assertEqual(random_data('seed', 0, 10, max_mutations=99, step=5).num_mutations(), 3)

    def test_original_value_is_restored_after_exhaustion(self):
        primitive = random_data('seed', 1, 2, max_mutations=3)
        drain(primitive)

        self.assertFalse(primitive.mutate())
        self.assertEqual(primitive.value, 'seed')


class TestStatic(unittest.TestCase):

    def test_static_content_never_mutates(self):
        primitive = static(b'\x01\x02')

        self.assertFalse(primitive.mutate())
        self.assertEqual(primitive.num_mutations(), 0)
        self.assertEqual(primitive.value, b'\x01\x02')

    def test_static_renders_its_value_unchanged(self):
        self.assertEqual(static(b'\x01\x02').render(), b'\x01\x02')

    def test_static_is_marked_complete_from_the_start(self):
        self.assertTrue(static(b'').fuzz_complete)


class TestString(unittest.TestCase):

    def test_instances_reuse_the_global_fuzz_library(self):
        first = string('A')
        second = string('B')

        self.assertIs(first.string_fuzz_library, second.string_fuzz_library)
        self.assertIs(first.string_fuzz_library, string.fuzz_library)
        self.assertGreater(first.num_mutations(), len(first.this_library))

    def test_max_length_filter_does_not_modify_the_global_library(self):
        unconstrained = string('A')
        global_count = len(unconstrained.string_fuzz_library)

        constrained = string('A', max_len=32)

        self.assertEqual(len(string.fuzz_library), global_count)
        self.assertTrue(all(len(value) <= 32
                    for value in constrained.string_fuzz_library))
        self.assertTrue(any(len(value) > 32
                    for value in unconstrained.string_fuzz_library))

    def test_mutation_count_matches_reported_number_of_mutations(self):
        primitive = string('A')

        self.assertEqual(len(drain(primitive)), primitive.num_mutations())

    def test_mutations_include_repetitions_of_the_original_value(self):
        values = drain(string('A'))

        self.assertIn('AA', values)

    def test_render_encodes_using_the_configured_encoding(self):
        primitive = string('A', encoding='utf_16_le')

        self.assertEqual(primitive.render(), 'A'.encode('utf_16_le'))

    def test_render_falls_back_when_a_value_is_not_encodable(self):
        primitive = string('A')
        primitive.value = '\xfe'

        self.assertEqual(primitive.render(), b'\xfe')

    def test_fixed_size_strings_are_padded_to_the_requested_width(self):
        primitive = string('A', size=64, padding='\x00')

        primitive.mutate()

        self.assertEqual(len(primitive.value), 64)

    def test_disabling_fuzzing_suppresses_all_mutations(self):
        primitive = string('A', fuzzable=False)

        self.assertFalse(primitive.mutate())
        self.assertEqual(primitive.value, 'A')


class TestBitFieldEncoding(unittest.TestCase):
    """bit_field defines how every integer primitive is serialized."""

    def test_binary_render_is_little_endian_by_default(self):
        self.assertEqual(bit_field(0x1234, 16).render(), b'\x34\x12')

    def test_binary_render_honors_big_endian(self):
        self.assertEqual(bit_field(0x1234, 16, endian='>').render(), b'\x12\x34')

    def test_widths_are_padded_up_to_a_byte_boundary(self):
        rendered = bit_field(0xABC, 12, endian='>').render()

        self.assertEqual(len(rendered), 2)
        self.assertEqual(rendered, b'\x0a\xbc')

    def test_ascii_render_returns_the_decimal_representation(self):
        self.assertEqual(bit_field(42, 8, format='ascii').render(), '42')

    def test_ascii_render_of_a_signed_value_is_negative(self):
        self.assertEqual(bit_field(0xFF, 8, format='ascii', signed=True).render(), '-1')

    def test_binary_conversion_round_trips(self):
        primitive = bit_field(0, 16)

        self.assertEqual(primitive.to_decimal(primitive.to_binary(0xBEEF, 16)), 0xBEEF)

    def test_to_binary_uses_the_configured_width(self):
        self.assertEqual(bit_field(0, 8).to_binary(1), '00000001')


class TestBitFieldLibrary(unittest.TestCase):

    def test_smart_boundaries_stay_inside_the_representable_range(self):
        primitive = bit_field(0, 8)

        for value in drain(primitive):
            self.assertTrue(0 <= value < primitive.max_num)

    def test_full_range_enumerates_every_representable_value(self):
        primitive = bit_field(0, 4, full_range=True)

        self.assertEqual(primitive.num_mutations(), primitive.max_num)
        self.assertEqual(sorted(drain(primitive)), list(range(primitive.max_num)))

    def test_supplied_value_list_becomes_the_mutation_library(self):
        primitive = bit_field([1, 2, 3], 8)

        self.assertEqual(drain(primitive), [1, 2, 3])

    def test_value_list_is_cycled_when_rendering_without_mutation(self):
        primitive = bit_field([1, 2], 8)

        rendered = [primitive.render(), primitive.render(), primitive.render()]

        self.assertEqual(rendered, [b'\x01', b'\x02', b'\x01'])

    def test_non_numeric_values_are_rejected(self):
        with self.assertRaises(ValueError):
            bit_field('not-a-number', 8)

    def test_explicit_max_num_bounds_the_library(self):
        primitive = bit_field(0, 32, max_num=16)

        for value in drain(primitive):
            self.assertLess(value, 16)


class TestSizedIntegerPrimitives(unittest.TestCase):
    """byte/word/dword/qword are width-specialized bit_fields."""

    def test_widths(self):
        self.assertEqual(byte(0).width, 8)
        self.assertEqual(word(0).width, 16)
        self.assertEqual(dword(0).width, 32)
        self.assertEqual(qword(0).width, 64)

    def test_render_widths_match_the_declared_size(self):
        self.assertEqual(len(byte(0xFF).render()), 1)
        self.assertEqual(len(word(0xFFFF).render()), 2)
        self.assertEqual(len(dword(0xFFFFFFFF).render()), 4)
        self.assertEqual(len(qword(0xFFFFFFFFFFFFFFFF).render()), 8)

    def test_packed_input_is_unpacked_to_an_integer(self):
        self.assertEqual(byte(struct.pack('<B', 0xAB)).value, 0xAB)
        self.assertEqual(word(struct.pack('<H', 0xBEEF)).value, 0xBEEF)
        self.assertEqual(dword(struct.pack('<L', 0xDEADBEEF)).value, 0xDEADBEEF)
        self.assertEqual(qword(struct.pack('<Q', 0x1122334455667788)).value, 0x1122334455667788)

    def test_dword_round_trips_through_render(self):
        self.assertEqual(dword(0x12345678).render(), struct.pack('<L', 0x12345678))

    def test_type_identifiers_are_reported(self):
        self.assertEqual(
            [byte(0).s_type, word(0).s_type, dword(0).s_type, qword(0).s_type],
            ['byte', 'word', 'dword', 'qword'],
        )


if __name__ == '__main__':
    unittest.main()
