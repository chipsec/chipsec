# CHIPSEC: Platform Security Assessment Framework
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; Version 2.

"""Unit tests for CoreParserHelper config include path resolution."""

import os
import unittest
from unittest.mock import MagicMock

from chipsec.cfg.parsers.core_parser_helper import CoreParserHelper


class TestResolveConfigIncludePath(unittest.TestCase):
    """Tests for CoreParserHelper._resolve_config_include_path and helpers."""

    def setUp(self) -> None:
        self.helper = CoreParserHelper(MagicMock())
        # Use os.path.join so the same test file works on Windows and POSIX.
        self.vendor_root = os.path.join(os.sep, 'cfg', '8086')
        self.nested_xml = os.path.join(self.vendor_root, 'HOSTCTL', 'hostctl1.xml')
        self.root_xml = os.path.join(self.vendor_root, 'adl.xml')

    # _process_config_path

    def test_process_config_path_replaces_all_dots_except_extension(self) -> None:
        result = self.helper._process_config_path('MMIO.mmio0.xml')
        self.assertEqual(os.path.join('MMIO', 'mmio0.xml'), result)

    def test_process_config_path_handles_multi_segment_token(self) -> None:
        result = self.helper._process_config_path('A.B.C.xml')
        self.assertEqual(os.path.join('A', 'B', 'C.xml'), result)

    def test_process_config_path_plain_filename_unchanged(self) -> None:
        result = self.helper._process_config_path('mmio0.xml')
        self.assertEqual('mmio0.xml', result)

    # _is_vendor_scoped_include

    def test_is_vendor_scoped_true_for_dot_qualified_token(self) -> None:
        self.assertTrue(self.helper._is_vendor_scoped_include('MMIO.mmio0.xml'))

    def test_is_vendor_scoped_false_for_plain_filename(self) -> None:
        self.assertFalse(self.helper._is_vendor_scoped_include('mmio0.xml'))

    def test_is_vendor_scoped_false_for_path_with_separator(self) -> None:
        self.assertFalse(self.helper._is_vendor_scoped_include('MMIO/mmio0.xml'))
        self.assertFalse(self.helper._is_vendor_scoped_include('MMIO\\mmio0.xml'))

    def test_is_vendor_scoped_false_for_absolute_path(self) -> None:
        abs_path = os.path.join(os.sep, 'tmp', 'foo.xml')
        self.assertFalse(self.helper._is_vendor_scoped_include(abs_path))

    # _get_vendor_root_dir

    def test_get_vendor_root_dir_finds_matching_ancestor(self) -> None:
        result = self.helper._get_vendor_root_dir(self.nested_xml, '8086')
        self.assertEqual(self.vendor_root, result)

    def test_get_vendor_root_dir_match_is_case_insensitive(self) -> None:
        result = self.helper._get_vendor_root_dir(self.nested_xml, '8086')
        self.assertEqual(self.vendor_root, result)
        # vid_str provided in different casing should still match the directory.
        upper_xml = os.path.join(os.sep, 'cfg', '8086', 'sub', 'x.xml')
        self.assertEqual(
            os.path.join(os.sep, 'cfg', '8086'),
            self.helper._get_vendor_root_dir(upper_xml, '8086'),
        )

    def test_get_vendor_root_dir_returns_none_when_no_match(self) -> None:
        unrelated = os.path.join(os.sep, 'tmp', 'foo', 'bar.xml')
        self.assertIsNone(self.helper._get_vendor_root_dir(unrelated, '8086'))

    # resolve_config_include_path

    def test_resolve_vendor_scoped_include_from_nested_file_uses_vendor_root(self) -> None:
        """Regression: dot-qualified token from nested XML must resolve to vendor root."""
        result = self.helper.resolve_config_include_path(
            self.nested_xml, '8086', 'MMIO.mmio0.xml'
        )
        expected = os.path.join(self.vendor_root, 'MMIO', 'mmio0.xml')
        self.assertEqual(expected, result)

    def test_resolve_vendor_scoped_include_from_root_file_matches_vendor_root(self) -> None:
        result = self.helper.resolve_config_include_path(
            self.root_xml, '8086', 'MMIO.mmio0.xml'
        )
        expected = os.path.join(self.vendor_root, 'MMIO', 'mmio0.xml')
        self.assertEqual(expected, result)

    def test_resolve_plain_filename_stays_relative_to_current_xml(self) -> None:
        result = self.helper.resolve_config_include_path(
            self.nested_xml, '8086', 'sibling.xml'
        )
        expected = os.path.join(os.path.dirname(self.nested_xml), 'sibling.xml')
        self.assertEqual(expected, result)

    def test_resolve_path_token_with_separator_stays_relative_to_current_xml(self) -> None:
        result = self.helper.resolve_config_include_path(
            self.nested_xml, '8086', 'sub/child.xml'
        )
        expected = os.path.join(os.path.dirname(self.nested_xml), 'sub/child.xml')
        self.assertEqual(expected, result)

    def test_resolve_absolute_path_returned_as_is(self) -> None:
        abs_path = os.path.join(os.sep, 'tmp', 'foo.xml')
        result = self.helper.resolve_config_include_path(
            self.nested_xml, '8086', abs_path
        )
        self.assertEqual(abs_path, result)

    def test_resolve_falls_back_to_current_dir_when_vendor_root_not_found(self) -> None:
        unrelated = os.path.join(os.sep, 'tmp', 'foo', 'bar.xml')
        result = self.helper.resolve_config_include_path(
            unrelated, '8086', 'MMIO.mmio0.xml'
        )
        expected = os.path.join(os.path.dirname(unrelated), 'MMIO', 'mmio0.xml')
        self.assertEqual(expected, result)

    def test_resolve_multi_segment_vendor_scoped_include(self) -> None:
        result = self.helper.resolve_config_include_path(
            self.nested_xml, '8086', 'A.B.C.xml'
        )
        expected = os.path.join(self.vendor_root, 'A', 'B', 'C.xml')
        self.assertEqual(expected, result)


if __name__ == '__main__':
    unittest.main()
