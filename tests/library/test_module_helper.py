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

import os
import tempfile
import unittest
from unittest.mock import patch

from chipsec.library.module_helper import get_module_files


class TestModuleHelper(unittest.TestCase):

    def test_get_module_files_filters_modules(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            os.mkdir(os.path.join(temp_dir, 'nested'))
            module_file = os.path.join(temp_dir, 'module.py')
            sidekick_file = os.path.join(temp_dir, 'module_sidekick.py')
            init_file = os.path.join(temp_dir, '__init__.py')
            nested_file = os.path.join(temp_dir, 'nested', 'nested_module.py')
            text_file = os.path.join(temp_dir, 'README.txt')
            for path in (module_file, sidekick_file, init_file, nested_file, text_file):
                open(path, 'w').close()

            files = get_module_files(temp_dir, skip_sidekick=True)

        self.assertEqual(files, [module_file, nested_file])

    def test_get_module_files_can_skip_recursion(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            os.mkdir(os.path.join(temp_dir, 'nested'))
            module_file = os.path.join(temp_dir, 'module.py')
            nested_file = os.path.join(temp_dir, 'nested', 'nested_module.py')
            for path in (module_file, nested_file):
                open(path, 'w').close()

            files = get_module_files(temp_dir, recursive=False)

        self.assertEqual(files, [module_file])

    def test_get_module_files_skips_missing_paths(self):
        missing_path = os.path.join(tempfile.gettempdir(), 'chipsec_missing_module_path')

        self.assertEqual(get_module_files(missing_path), [])

    def test_get_module_files_skips_unreadable_paths(self):
        with patch('chipsec.library.module_helper.os.listdir', side_effect=OSError):
            self.assertEqual(get_module_files('unreadable'), [])

    def test_get_module_files_does_not_follow_directory_symlinks(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target_dir = os.path.join(temp_dir, 'target')
            symlink_dir = os.path.join(temp_dir, 'symlink')
            os.mkdir(target_dir)
            linked_file = os.path.join(target_dir, 'linked_module.py')
            open(linked_file, 'w').close()
            try:
                os.symlink(target_dir, symlink_dir, target_is_directory=True)
            except (AttributeError, NotImplementedError, OSError):
                self.skipTest('directory symlinks are not available')

            files = get_module_files(temp_dir)

        self.assertEqual(files, [linked_file])


if __name__ == '__main__':
    unittest.main()
