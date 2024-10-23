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

from chipsec.parsers import BaseConfigHelper


class GenericConfig(BaseConfigHelper):
    def __init__(self, cfg_obj):
        super(GenericConfig, self).__init__(cfg_obj)
        self.name = cfg_obj['name']
        if 'config' in cfg_obj:
            self.config = cfg_obj['config']
        else:
            self.config = []

    def add_config(self, config):
        for cfg in config:
            if cfg not in self.config:
                self.config.append(cfg)
