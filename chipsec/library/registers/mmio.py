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

class MMIO(BaseRegister):
    def __init__(self, cs):
        super(MMIO, self).__init__(cs)

    def get_def(self, bar_name):
        ret = None
        scope = self.cs.Cfg.get_scope(bar_name)
        vid, device, bar, _ = self.cs.Cfg.convert_internal_scope(scope, bar_name)
        if vid in self.cs.Cfg.MMIO_BARS and device in self.cs.Cfg.MMIO_BARS[vid]:
            if bar in self.cs.Cfg.MMIO_BARS[vid][device]:
                ret = self.cs.Cfg.MMIO_BARS[vid][device][bar]
        return ret