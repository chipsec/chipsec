# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2024, Intel Corporation
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
import fnmatch
from chipsec.library.logger import logger
from chipsec.library.file import get_module_dir
from typing import List


def get_module_files(from_path: str, recursive: bool = True, skip_sidekick: bool = False) -> List[str]:
    files = []
    root_path = os.path.abspath(from_path)

    def is_module_file(entry: str) -> bool:
        _, extension = os.path.splitext(entry)
        rules = (
            extension == '.py',
            entry != '__init__.py',
            not (skip_sidekick and fnmatch.fnmatch(entry, '*sidekick.py')),
        )
        return all(rules)

    def walk_path(path: str) -> None:
        try:
            entries = sorted(os.listdir(path), key=lambda entry: entry.lower())
        except OSError:
            return
        directories = []
        for entry in entries:
            entry_path = os.path.join(path, entry)
            if os.path.isdir(entry_path) and not os.path.islink(entry_path):
                directories.append(entry_path)
                continue
            if is_module_file(entry):
                files.append(entry_path)
        if recursive:
            for directory in directories:
                walk_path(directory)

    walk_path(root_path)
    return files


def enumerate_modules() -> List[str]:
    mod_path = get_module_dir()
    files = []
    for module_file in get_module_files(mod_path):
        dirname, modx = os.path.split(module_file)
        module_path = os.path.relpath(dirname, mod_path)
        module_path = module_path.replace('\\', '.').replace('/', '.')
        files.append(f'{module_path}.{modx[:-3]}')
    return files


def print_modules(module_list: List[str]) -> None:
    logger().log('Enumerating modules...')
    for module in module_list:
        logger().log(f'\t{module}')
