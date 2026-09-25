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

"""Unit tests for the optional sha256_norm field of tools.uefi.scan_image.

scan_image is created without BaseModule.__init__, so no chipset or driver is
needed. The normalization itself is tested in tests/library/uefi; here it is
replaced by a stub so these tests only cover what the module does with it.
"""

import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from chipsec.library.returncode import ModuleResult
from chipsec.library.uefi.fv import EFI_SECTION, EFI_SECTION_PE32
from chipsec.modules.tools.uefi import scan_image as scan_image_mod
from chipsec.modules.tools.uefi.scan_image import scan_image

HEADER_SIZE = 4


def _make_section(payload: bytes, guid: str, name: str) -> EFI_SECTION:
    image = b'\x00' * HEADER_SIZE + payload
    sec = EFI_SECTION(0, 'S_PE32', EFI_SECTION_PE32, image, HEADER_SIZE, len(image))
    sec.calc_hashes(HEADER_SIZE)
    sec.parentGuid = guid
    sec.ui_string = name
    return sec


def _new_scan_image(include_norm: bool = False) -> scan_image:
    module = scan_image.__new__(scan_image)
    module.logger = MagicMock()
    module.efi_list = {}
    module.suspect_modules = {}
    module.duplicate_list = []
    module.include_norm = include_norm
    return module


class TestGenlistCallbackNorm(unittest.TestCase):

    def test_value_is_added_when_enabled(self):
        module = _new_scan_image(include_norm=True)
        sec = _make_section(b'payload-a', 'GUID-A', 'ModuleA')
        with patch.object(scan_image_mod, 'normalized_sha256', return_value='profile:sha256:ab') as norm:
            module.genlist_callback(sec)
        # the section type and the payload without its section header
        norm.assert_called_once_with(EFI_SECTION_PE32, b'payload-a')
        self.assertEqual(module.efi_list[sec.SHA256]['sha256_norm'], 'profile:sha256:ab')

    def test_nothing_is_computed_when_disabled(self):
        module = _new_scan_image(include_norm=False)
        sec = _make_section(b'payload-a', 'GUID-A', 'ModuleA')
        with patch.object(scan_image_mod, 'normalized_sha256') as norm:
            module.genlist_callback(sec)
        norm.assert_not_called()
        self.assertNotIn('sha256_norm', module.efi_list[sec.SHA256])

    def test_no_field_when_the_module_cannot_be_normalized(self):
        module = _new_scan_image(include_norm=True)
        sec = _make_section(b'payload-a', 'GUID-A', 'ModuleA')
        with patch.object(scan_image_mod, 'normalized_sha256', return_value=None):
            module.genlist_callback(sec)
        self.assertEqual(set(module.efi_list[sec.SHA256]), {'sha1', 'guid', 'name', 'type'})


class TestCheckListWithNorm(unittest.TestCase):
    """check keys on sha256 alone, so a list written with norm still works."""

    def _check(self, list_entries):
        module = _new_scan_image()
        module.image = b''
        module.image_file = 'synthetic'
        sections = [_make_section(b'payload-a', 'GUID-A', 'ModuleA'),
                    _make_section(b'payload-b', 'GUID-B', 'ModuleB')]

        def fake_search(_tree, callback, *_args, **_kwargs):
            for sec in sections:
                callback(sec)

        with tempfile.TemporaryDirectory() as tmp:
            json_pth = os.path.join(tmp, 'efilist.json')
            with open(json_pth, 'w', encoding='utf-8') as handle:
                json.dump(list_entries(sections), handle)
            with patch.object(scan_image_mod, 'build_efi_model', return_value=[]), \
                    patch.object(scan_image_mod, 'search_efi_tree', side_effect=fake_search):
                result = module.check_list(json_pth)
        return module, result

    def test_check_passes_on_a_list_with_norm(self):
        module, result = self._check(
            lambda sections: {s.SHA256: {'sha1': s.SHA1, 'sha256_norm': 'profile:sha256:ab'} for s in sections})
        self.assertEqual(result, ModuleResult.PASSED)
        self.assertEqual(len(module.suspect_modules), 0)

    def test_check_still_reports_a_module_missing_from_the_list(self):
        module, result = self._check(
            lambda sections: {sections[0].SHA256: {'sha256_norm': 'profile:sha256:ab'}})
        self.assertEqual(result, ModuleResult.WARNING)
        self.assertEqual(len(module.suspect_modules), 1)


class TestNormArgument(unittest.TestCase):
    """norm is the fourth argument, and only generate uses it."""

    def _run(self, argv):
        module = _new_scan_image()
        # run() reads the image right after parsing its arguments; stop it there
        with patch.object(scan_image_mod, 'read_file', side_effect=RuntimeError('stop')):
            try:
                module.run(argv)
            except RuntimeError:
                pass
        return module

    def test_fourth_argument_enables_it(self):
        self.assertTrue(self._run(['generate', 'efilist.json', 'uefi.rom', 'norm']).include_norm)

    def test_off_by_default(self):
        module = self._run(['generate', 'efilist.json', 'uefi.rom'])
        self.assertFalse(module.include_norm)
        module.logger.log_warning.assert_not_called()

    def test_file_named_norm_does_not_enable_it(self):
        self.assertFalse(self._run(['generate', 'norm', 'uefi.rom']).include_norm)
        self.assertFalse(self._run(['generate', 'efilist.json', 'norm']).include_norm)

    def test_ignored_with_a_warning_on_check(self):
        module = self._run(['check', 'efilist.json', 'uefi.rom', 'norm'])
        self.assertFalse(module.include_norm)
        module.logger.log_warning.assert_called_once()

    def test_other_commands_do_not_mention_it(self):
        with patch.object(scan_image, 'usage'):
            module = self._run(['help', 'a', 'b', 'norm'])
        self.assertFalse(module.include_norm)
        module.logger.log_warning.assert_not_called()

    def test_extra_arguments_are_reported(self):
        module = self._run(['generate', 'efilist.json', 'uefi.rom', 'norm', 'extra'])
        self.assertTrue(module.include_norm)
        module.logger.log_warning.assert_called_once()

    def test_unrecognized_fourth_argument_is_reported(self):
        module = self._run(['generate', 'efilist.json', 'uefi.rom', 'NORM'])
        self.assertFalse(module.include_norm)
        module.logger.log_warning.assert_called_once()


if __name__ == '__main__':
    unittest.main()
