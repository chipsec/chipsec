#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2019-2021, Intel Corporation
#
#This program is free software; you can redistribute it and/or
#modify it under the terms of the GNU General Public License
#as published by the Free Software Foundation; Version 2.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with this program; if not, write to the Free Software
#Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
#Contact information:
#chipsec@intel.com
#

from chipsec.module_common import BaseModule, ModuleResult

class ModuleClass(BaseModule):
    def __init__(self):
        super(ModuleClass, self).__init__()

    def is_supported(self):
        return True

    def action(self):
        self.logger.log_passed_check("Module was successful")
        return ModuleResult.PASSED

    def run(self, module_argv):
        self.logger.start_test('Module Description')
        self.res = self.action()
        return self.res
