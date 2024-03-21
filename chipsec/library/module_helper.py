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

def enumerate_modules():
    mod_path = get_module_dir()
    tools_path = os.path.join(mod_path)
    files = []
    for dirname, _, mod_fnames in os.walk(os.path.abspath(tools_path)):
        for modx in mod_fnames:
            if fnmatch.fnmatch(modx, '*.py') and not fnmatch.fnmatch(modx, '__init__.py'):
                module_path = os.path.relpath(dirname, mod_path).replace("\\", ".").replace("/", ".")
                files.append(f'{module_path}.{modx[:-3]}')
    return files

def print_modules(module_list: List[str]) -> None:
    logger().log('Enumerating modules...')
    for module in module_list:
        logger().log(f'\t{module}')