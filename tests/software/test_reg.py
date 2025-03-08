# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2017, Google
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
#

import unittest

from tests.software import mock_helper, util


class TestRegChipsecUtil(util.TestChipsecUtil):
    """Test the reg commands exposed by chipsec_utils."""

    def test_reg_read(self):
        self._chipsec_util("reg read 8086.HOSTCTL.VID")
        self._assertLogValue("VID", "0x8086")

    def test_reg_read_field(self):
        self._chipsec_util("reg read 8086.HOSTCTL.TOUUD LOCK")
        self._assertLogValue("TOUUD.LOCK", "0x0")

    def test_reg_read_field1(self):
        self._chipsec_util("reg read_field 8086.HOSTCTL.TOUUD LOCK")
        self._assertLogValue("TOUUD.LOCK", "0x0")

    def test_reg_get_control(self):
        self._chipsec_util("reg get_control TSEGBaseLock",
                           mock_helper.SPIHelper)
        self._assertLogValue("TSEGBaseLock", "0x0")


if __name__ == '__main__':
    unittest.main()
