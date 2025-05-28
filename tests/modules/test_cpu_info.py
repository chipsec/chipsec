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

import unittest
from unittest.mock import Mock
from chipsec.modules.common.cpu.cpu_info import cpu_info


class TestCpuInfo(unittest.TestCase):
    def test_cpu_info_init(self):
        cpu_info_instance = cpu_info()
        self.assertIsInstance(cpu_info_instance, cpu_info)

    def test_cpu_info_is_supported_false(self):
        mock_self = Mock()
        mock_self.cs.register.has_field.return_value = False
        result = cpu_info.is_supported(mock_self)
        self.assertFalse(result)

    def test_cpu_info_is_supported_true(self):
        mock_self = Mock()
        mock_self.cs.register.has_field.return_value = True
        result = cpu_info.is_supported(mock_self)
        self.assertTrue(result)


if __name__ == '__main__':
    unittest.main()
