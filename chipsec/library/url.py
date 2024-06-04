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

"""
Library to build module URLs

"""

import os
import json
import re
from chipsec.library.file import get_main_dir


class url:
    def __init__(self):
        self.url_info = self.get_url_info()
        self.base_url = self.get_base_url()
        self.replace_find = self.url_info.get('replace_find', '')
        self.replace_with = self.url_info.get('replace_with', '')
        self.ends_with = self.url_info.get('ends_with', '')

    def get_url_info(self):
        with open(os.path.join(get_main_dir(), 'chipsec', 'library', 'url_format.json'), 'r') as url_file:
            return json.loads(url_file.read())

    def get_base_url(self):
        if 'base_url' not in self.url_info:
            raise Exception('Missing Base URL in url file')
        return self.url_info['base_url']

    def get_module_url(self, module_name: str) -> str:
        module_name = re.sub(self.replace_find, self.replace_with, module_name)
        module_url = f'{self.base_url}{module_name}{self.ends_with}'
        return module_url
