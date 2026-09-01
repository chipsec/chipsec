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

import io
import unittest
from unittest.mock import MagicMock, patch

from chipsec.library.intel import vmm_common


class TestHvHciv(unittest.TestCase):
    """Cover chipsec.library.intel.vmm_common.hv_hciv."""

    def test_call_code_occupies_low_16_bits(self):
        self.assertEqual(vmm_common.hv_hciv(0, 0, 0x1234), 0x1234)

    def test_fast_flag_is_bit_16(self):
        self.assertEqual(vmm_common.hv_hciv(0, 0, 0, 1), 0x10000)

    def test_rep_count_occupies_bits_32_to_43(self):
        self.assertEqual(vmm_common.hv_hciv(0, 0x2, 0), 0x2 << 32)

    def test_rep_start_occupies_bits_48_to_59(self):
        self.assertEqual(vmm_common.hv_hciv(0x3, 0, 0), 0x3 << 48)

    def test_fields_are_masked_to_their_widths(self):
        self.assertEqual(vmm_common.hv_hciv(0xFFFF, 0xFFFF, 0xFFFF, 0xFF),
                         (0xFFF << 48) + (0xFFF << 32) + (0x1 << 16) + 0xFFFF)

    def test_all_fields_combined(self):
        self.assertEqual(vmm_common.hv_hciv(1, 2, 3, 1), (1 << 48) + (2 << 32) + (1 << 16) + 3)


class TestUuid(unittest.TestCase):
    """Cover chipsec.library.intel.vmm_common.uuid."""

    def test_formats_little_endian_guid(self):
        raw = bytes.fromhex('78563412') + bytes.fromhex('3412') + bytes.fromhex('3412') + bytes.fromhex('56789ABCDEF01234')
        self.assertEqual(vmm_common.uuid(raw), '{12345678-1234-1234-5678-9ABCDEF01234}')

    def test_first_three_fields_are_byte_swapped(self):
        raw = bytes.fromhex('785634127856') + bytes(10)
        self.assertTrue(vmm_common.uuid(raw).startswith('{12345678-5678-'))

    def test_output_is_wrapped_in_braces(self):
        result = vmm_common.uuid(bytes(16))
        self.assertTrue(result.startswith('{') and result.endswith('}'))

    def test_requires_16_bytes(self):
        with self.assertRaises(Exception):
            vmm_common.uuid(bytes(15))


class TestOverwrite(unittest.TestCase):
    """Cover chipsec.library.intel.vmm_common.overwrite."""

    def test_replaces_in_place_without_changing_length(self):
        self.assertEqual(vmm_common.overwrite(b'AAAAAAAA', b'BB', 2), b'AABBAAAA')

    def test_at_offset_zero(self):
        self.assertEqual(vmm_common.overwrite(b'AAAA', b'B', 0), b'BAAA')

    def test_empty_replacement_is_a_no_op(self):
        self.assertEqual(vmm_common.overwrite(b'AAAA', b'', 2), b'AAAA')

    def test_replacement_past_the_end_extends_the_buffer(self):
        self.assertEqual(vmm_common.overwrite(b'AA', b'BBBB', 1), b'ABBBB')


class TestGetIntArg(unittest.TestCase):
    """Cover chipsec.library.intel.vmm_common.get_int_arg."""

    def test_decimal_string(self):
        self.assertEqual(vmm_common.get_int_arg('42'), 42)

    def test_hex_string(self):
        self.assertEqual(vmm_common.get_int_arg('0x10'), 16)

    def test_arithmetic_expression(self):
        self.assertEqual(vmm_common.get_int_arg('1 << 4'), 16)

    def test_invalid_argument_exits(self):
        with patch('sys.stdout', new=io.StringIO()) as out:
            with self.assertRaises(SystemExit):
                vmm_common.get_int_arg('not-a-number')
        self.assertIn('ERROR: Invalid parameter', out.getvalue())


class TestWeightedChoice(unittest.TestCase):
    """Cover chipsec.library.intel.vmm_common.weighted_choice."""

    CHOICES = [('a', 1.0), ('b', 2.0), ('c', 3.0)]

    def _choose(self, r):
        with patch('chipsec.library.intel.vmm_common.random.uniform', return_value=r):
            return vmm_common.weighted_choice(self.CHOICES)

    def test_low_draw_picks_first_choice(self):
        self.assertEqual(self._choose(0.5), 'a')

    def test_mid_draw_picks_second_choice(self):
        self.assertEqual(self._choose(2.5), 'b')

    def test_high_draw_picks_last_choice(self):
        self.assertEqual(self._choose(5.5), 'c')

    def test_draw_uses_total_weight_as_upper_bound(self):
        with patch('chipsec.library.intel.vmm_common.random.uniform', return_value=0.0) as mock_uniform:
            vmm_common.weighted_choice(self.CHOICES)
        mock_uniform.assert_called_once_with(0, 6.0)

    def test_zero_weight_choice_is_skipped(self):
        with patch('chipsec.library.intel.vmm_common.random.uniform', return_value=0.5):
            self.assertEqual(vmm_common.weighted_choice([('a', 0.0), ('b', 1.0)]), 'b')


class TestRandDd(unittest.TestCase):
    """Cover chipsec.library.intel.vmm_common.rand_dd."""

    def test_returns_four_bytes_per_dword(self):
        self.assertEqual(len(vmm_common.rand_dd(3, rndbytes=0, rndbits=0)), 12)

    def test_all_entries_are_byte_values(self):
        for value in vmm_common.rand_dd(4, rndbytes=0, rndbits=0):
            self.assertTrue(0 <= value <= 0xFF)

    def test_random_byte_injection_stays_within_the_buffer(self):
        buffer = vmm_common.rand_dd(2, rndbytes=4, rndbits=0)
        self.assertEqual(len(buffer), 8)

    def test_zero_dwords_returns_empty_buffer(self):
        self.assertEqual(vmm_common.rand_dd(0, rndbytes=0, rndbits=0), [])


class TestBaseModuleDebug(unittest.TestCase):
    """Cover the console helpers on chipsec.library.intel.vmm_common.BaseModuleDebug."""

    def setUp(self):
        patcher = patch('chipsec.module_common.BaseModule.__init__', return_value=None)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.module = vmm_common.BaseModuleDebug()
        self.module.prompt = 'test'

    def _capture(self, func, *args):
        with patch('sys.stdout', new=io.StringIO()) as out:
            func(*args)
        return out.getvalue()

    def test_defaults(self):
        module = vmm_common.BaseModuleDebug()
        self.assertFalse(module.debug)
        self.assertEqual(module.prompt, '')

    def test_msg_prefixes_the_prompt(self):
        self.assertEqual(self._capture(self.module.msg, 'hello'), '[test]  hello\n')

    def test_err_marks_the_message(self):
        self.assertEqual(self._capture(self.module.err, 'boom'), '[test]  **** ERROR: boom\n')

    def test_dbg_is_silent_when_debug_disabled(self):
        self.assertEqual(self._capture(self.module.dbg, 'noisy'), '')

    def test_dbg_prints_when_debug_enabled(self):
        self.module.debug = True
        self.assertEqual(self._capture(self.module.dbg, 'noisy'), '[test]  noisy\n')

    def test_fatal_exits(self):
        with patch('sys.stdout', new=io.StringIO()) as out:
            with self.assertRaises(SystemExit):
                self.module.fatal('unrecoverable')
        self.assertIn('**** FATAL: unrecoverable', out.getvalue())

    def test_hex_dumps_one_row_per_width(self):
        output = self._capture(self.module.hex, 'title', 'AB', 16)
        self.assertIn('41 42', output)
        self.assertIn('00000000:', output)

    def test_hex_without_title_still_dumps_data(self):
        output = self._capture(self.module.hex, '', 'A', 16)
        self.assertIn('41', output)

    def test_hex_inserts_a_separator_every_8_bytes(self):
        output = self._capture(self.module.hex, '', 'A' * 9, 16)
        self.assertIn('| ', output)

    def test_info_bitwise_reports_only_described_set_bits(self):
        output = self._capture(self.module.info_bitwise, 0b101, {0: 'first', 2: 'third'})
        self.assertIn('first', output)
        self.assertIn('third', output)

    def test_info_bitwise_on_zero_prints_nothing(self):
        self.assertEqual(self._capture(self.module.info_bitwise, 0, {0: 'first'}), '')


class TestSessionLogger(unittest.TestCase):
    """Cover chipsec.library.intel.vmm_common.session_logger."""

    def test_disabled_logger_does_not_open_a_file(self):
        with patch('builtins.open') as mock_open:
            logger = vmm_common.session_logger(False, 'details')
        mock_open.assert_not_called()
        self.assertFalse(logger.log)

    def test_disabled_logger_write_and_flush_are_no_ops(self):
        logger = vmm_common.session_logger(False, 'details')
        logger.write('ignored')
        logger.flush()
        logger.closefile()

    def test_enabled_logger_writes_to_terminal_and_file(self):
        with patch('builtins.open') as mock_open, patch('os.makedirs'):
            logger = vmm_common.session_logger(True, 'details')
        logger.terminal = MagicMock()
        logger.write('message')
        logger.terminal.write.assert_called_once_with('message')
        mock_open.return_value.write.assert_called_once_with('message')

    def test_enabled_logger_flush_reaches_both_sinks(self):
        with patch('builtins.open') as mock_open, patch('os.makedirs'):
            logger = vmm_common.session_logger(True, 'details')
        logger.terminal = MagicMock()
        logger.flush()
        logger.terminal.flush.assert_called_once_with()
        mock_open.return_value.flush.assert_called_once_with()

    def test_existing_log_directory_is_tolerated(self):
        with patch('builtins.open'), patch('os.makedirs', side_effect=OSError):
            logger = vmm_common.session_logger(True, 'details')
        self.assertTrue(logger.log)

    def test_closefile_restores_stdout(self):
        with patch('builtins.open') as mock_open, patch('os.makedirs'):
            logger = vmm_common.session_logger(True, 'details')
        logger.closefile()
        mock_open.return_value.close.assert_called_once_with()


if __name__ == '__main__':
    unittest.main()
