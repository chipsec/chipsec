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
from typing import Any
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

    def get_section_data(self, section, key, default: Any = NoDefault):
        try:
            ret_data = self.config.get(section, key)
        except Exception as e:
            if default is NoDefault:
                raise e
            return default
        return ret_data
