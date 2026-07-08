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

import json
import os
import tempfile
import time
import unittest
import xml.etree.ElementTree as ET

from chipsec.library import result_deltas


class TestComputeResultDeltas(unittest.TestCase):
    """Cover the delta computation logic in result_deltas.compute_result_deltas."""

    def test_no_changes_returns_empty(self):
        prev = {'t1': {'result': 'Passed'}}
        cur = {'t1': {'result': 'Passed'}}
        self.assertEqual(result_deltas.compute_result_deltas(prev, cur), {})

    def test_changed_result_reported(self):
        prev = {'t1': {'result': 'Passed'}}
        cur = {'t1': {'result': 'Failed'}}
        self.assertEqual(
            result_deltas.compute_result_deltas(prev, cur),
            {'t1': {'previous': 'Passed', 'current': 'Failed'}})

    def test_new_test_only_in_current(self):
        deltas = result_deltas.compute_result_deltas({}, {'t2': {'result': 'Passed'}})
        self.assertEqual(deltas, {'t2': {'previous': '-------', 'current': 'Passed'}})

    def test_removed_test_only_in_previous(self):
        deltas = result_deltas.compute_result_deltas({'t3': {'result': 'Failed'}}, {})
        self.assertEqual(deltas, {'t3': {'previous': 'Failed', 'current': '-------'}})

    def test_malformed_entries_use_placeholder_and_match(self):
        # Both entries lack a 'result' key -> both fall back to the placeholder
        # and are considered equal, so no delta is produced.
        deltas = result_deltas.compute_result_deltas({'t': {}}, {'t': {}})
        self.assertEqual(deltas, {})

    def test_multiple_tests_mixed(self):
        prev = {'a': {'result': 'Passed'}, 'b': {'result': 'Passed'}}
        cur = {'a': {'result': 'Passed'}, 'b': {'result': 'Failed'}}
        self.assertEqual(
            result_deltas.compute_result_deltas(prev, cur),
            {'b': {'previous': 'Passed', 'current': 'Failed'}})


class TestGetJsonResults(unittest.TestCase):
    """Cover result_deltas.get_json_results file/parse handling."""

    def test_valid_json_file(self):
        data = {'t1': {'result': 'Passed'}}
        fileno, path = tempfile.mkstemp(suffix='.json')
        os.close(fileno)
        try:
            with open(path, 'w') as f:
                json.dump(data, f)
            self.assertEqual(result_deltas.get_json_results(path), data)
        finally:
            os.remove(path)

    def test_missing_file_returns_none(self):
        self.assertIsNone(result_deltas.get_json_results('nonexistent_delta_file_xyz.json'))

    def test_invalid_json_returns_none(self):
        fileno, path = tempfile.mkstemp(suffix='.json')
        os.close(fileno)
        try:
            with open(path, 'w') as f:
                f.write('{not valid json')
            self.assertIsNone(result_deltas.get_json_results(path))
        finally:
            os.remove(path)


class TestLogDeltas(unittest.TestCase):
    """Cover the JSON/XML delta serialization helpers."""

    def test_log_deltas_json_roundtrip(self):
        deltas = {'t1': {'previous': 'Passed', 'current': 'Failed'}}
        fileno, path = tempfile.mkstemp(suffix='.json')
        os.close(fileno)
        try:
            result_deltas.log_deltas_json(deltas, path)
            with open(path) as f:
                self.assertEqual(json.load(f), deltas)
        finally:
            os.remove(path)

    def test_log_deltas_xml_with_entries(self):
        deltas = {'t1': {'previous': 'Passed', 'current': 'Failed'}}
        fileno, path = tempfile.mkstemp(suffix='.xml')
        os.close(fileno)
        try:
            result_deltas.log_deltas_xml(deltas, path)
            root = ET.parse(path).getroot()
            self.assertEqual(root.tag, 'deltas')
            tests = root.findall('test')
            self.assertEqual(len(tests), 1)
            self.assertEqual(tests[0].text, 't1')
            self.assertEqual(tests[0].get('current'), 'Failed')
            self.assertEqual(tests[0].get('previous'), 'Passed')
        finally:
            os.remove(path)

    def test_log_deltas_xml_empty(self):
        fileno, path = tempfile.mkstemp(suffix='.xml')
        os.close(fileno)
        try:
            result_deltas.log_deltas_xml({}, path)
            root = ET.parse(path).getroot()
            self.assertEqual(root.tag, 'deltas')
            self.assertEqual(root.findall('test'), [])
        finally:
            os.remove(path)


class TestDisplayDeltas(unittest.TestCase):
    """Smoke test display_deltas across its branches (logging only)."""

    def test_display_with_deltas_runs(self):
        deltas = {'t1': {'previous': 'Passed', 'current': 'Failed'}}
        # Should not raise regardless of hide_time.
        result_deltas.display_deltas(deltas, hide_time=False, start_time=time.time())

    def test_display_without_deltas_runs(self):
        result_deltas.display_deltas({}, hide_time=True, start_time=time.time())


if __name__ == '__main__':
    unittest.main()
