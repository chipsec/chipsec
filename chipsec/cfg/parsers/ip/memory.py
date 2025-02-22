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

from chipsec.cfg.parsers.ip.generic import GenericConfig


class MemoryConfig(GenericConfig):
    def __init__(self, cfg_obj):
        super(MemoryConfig, self).__init__(cfg_obj)
        self.access = cfg_obj['access']
        self.address = cfg_obj['address']
        self.limit = cfg_obj['limit']

    def __str__(self) -> str:
        ret = f'name: {self.name}, access: {self.access}'
        ret += f', address: {self.address}, limit: {self.limit}'
        ret += f', config: {self.config}'
        return ret
