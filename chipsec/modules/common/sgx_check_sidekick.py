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

class SGX_Check_Sidekick():
    def __init__(self, cs):
        self.cs = cs
        self.sgx_global_en_defined = self.cs.register.has_field('IA32_FEATURE_CONTROL', 'SGX_GLOBAL_EN')

    def check_valid(self, tid) -> bool:
        if self.sgx_global_en_defined:
            sgx_global_en = self.cs.register.read_field('IA32_FEATURE_CONTROL', 'SGX_GLOBAL_EN', tid)
        else:
            sgx_global_en = True
        return sgx_global_en
