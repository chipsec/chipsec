# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2023, Intel Corporation
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
import configparser
from typing import Any, List
from chipsec.library.file import get_main_dir
from chipsec.library.exceptions import CSConfigError


class NoDefault():
    pass


class Options(object):

    def __init__(self):
        options_path = os.path.join(get_main_dir(), 'chipsec', 'options')
        if not os.path.isdir(options_path):
            raise CSConfigError(f'Unable to locate configuration options: {options_path}')
        options_name = os.path.join(options_path, 'cmd_options.ini')
        self.config = configparser.ConfigParser()
        with open(options_name) as options_file:
            self.config.read_file(options_file)

    def get_section_data(self, section: str, key: str, default: Any = NoDefault) -> str:
        try:
            ret_data = self.config.get(section, key)
        except Exception as e:
            if default is NoDefault:
                raise e
            return default
        return ret_data

    def get_list_data(self, list_section: str, list_key: str, list_default: Any, list_separator: str = ',') -> List[Any]:
        raw_data = self.get_section_data(list_section, list_key, '').split(list_separator)
        data = [item.strip() for item in raw_data]
        return data if data[0] else list_default
