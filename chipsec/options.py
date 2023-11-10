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
import yaml
from fnmatch import fnmatch
from chipsec.file import read_file
from chipsec.file import get_main_dir
from chipsec.exceptions import CSConfigError
from chipsec.logger import logger


class Options(object):
    def __init__(self):
        self.sections = {}
        options_path = os.path.join(get_main_dir(), 'chipsec', 'options')
        if not os.path.isdir(options_path):
            raise CSConfigError('Unable to locate configuration options: {}'.format(options_path))
        options_files = [f.name for f in sorted(os.scandir(options_path), key=lambda x: x.name)
                        if fnmatch(f.name, '*.yaml')]
        for options in options_files:
            options_name = os.path.join(options_path, options)
            logger().log_debug('[*] Importing options: {}'.format(options_name))
            data = read_file(options_name)
            try:
                section = yaml.safe_load(data)
            except yaml.YAMLError:
                section = {}
            if section:
                self.sections.update(section)

    def get_sections(self):
        return self.sections.keys()

    def get_section_data(self, sect):
        return self.sections.get(sect, None)