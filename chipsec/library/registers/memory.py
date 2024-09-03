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

'''
Main functionality to get the definition of IO registers
'''

from chipsec.library.registers.baseregister import BaseRegister

class Memory(BaseRegister):
    def __init__(self, cs):
        super(Memory, self).__init__(cs)

    def get_def(self, range_name):
        scope = self.cs.Cfg.get_scope(range_name)
        vid, range, _, _ = self.cs.Cfg.convert_internal_scope(scope, range_name)
        if range in self.cs.Cfg.MEMORY_RANGES[vid]:
            return self.cs.Cfg.MEMORY_RANGES[vid][range]
        else:
            return None