# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2021, Intel Corporation
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

# -------------------------------------------------------------------------------
#
# CHIPSEC: Platform Hardware Security Assessment Framework
#
# -------------------------------------------------------------------------------

"""
CMOS memory specific functions (dump, read/write)

usage:
    >>> cmos.dump_low()
    >>> cmos.dump_high()
    >>> cmos.dump()
    >>> cmos.read_cmos_low( offset )
    >>> cmos.write_cmos_low( offset, value )
    >>> cmos.read_cmos_high( offset )
    >>> cmos.write_cmos_high( offset, value )
"""
from typing import List
from chipsec.hal import hal_base
import chipsec.library.logger

CMOS_ADDR_PORT_LOW = 0x70
CMOS_DATA_PORT_LOW = 0x71
CMOS_ADDR_PORT_HIGH = 0x72
CMOS_DATA_PORT_HIGH = 0x73


class CMOS(hal_base.HALBase):

    def __init__(self, cs):
        super(CMOS, self).__init__(cs)

    def read_cmos_high(self, offset: int) -> int:
        self.cs.hals.io.write(CMOS_ADDR_PORT_HIGH, offset, 1)
        return self.cs.hals.io.read(CMOS_DATA_PORT_HIGH, 1)

    def write_cmos_high(self, offset: int, value: int) -> None:
        self.cs.hals.io.write(CMOS_ADDR_PORT_HIGH, offset, 1)
        self.cs.hals.io.write(CMOS_DATA_PORT_HIGH, value, 1)

    def read_cmos_low(self, offset: int) -> int:
        self.cs.hals.io.write(CMOS_ADDR_PORT_LOW, 0x80 | offset, 1)
        return self.cs.hals.io.read(CMOS_DATA_PORT_LOW, 1)

    def write_cmos_low(self, offset: int, value: int) -> None:
        self.cs.hals.io.write(CMOS_ADDR_PORT_LOW, offset, 1)
        self.cs.hals.io.write(CMOS_DATA_PORT_LOW, value, 1)

    def dump_low(self) -> List[int]:
        cmos_buf = [0xFF] * 0x80
        orig = self.cs.hals.io.read(CMOS_ADDR_PORT_LOW, 1)
        for off in range(0x80):
            cmos_buf[off] = self.read_cmos_low(off)
        self.cs.hals.io.write(CMOS_ADDR_PORT_LOW, orig, 1)
        return cmos_buf

    def dump_high(self) -> List[int]:
        cmos_buf = [0xFF] * 0x80
        orig = self.cs.hals.io.read(CMOS_ADDR_PORT_HIGH, 1)
        for off in range(0x80):
            cmos_buf[off] = self.read_cmos_high(off)
        self.cs.hals.io.write(CMOS_ADDR_PORT_HIGH, orig, 1)
        return cmos_buf

    def dump(self) -> None:
        self.logger.log("Low CMOS memory contents:")
        chipsec.library.logger.pretty_print_hex_buffer(self.dump_low())
        self.logger.log("\nHigh CMOS memory contents:")
        chipsec.library.logger.pretty_print_hex_buffer(self.dump_high())


haldata = {"arch":[hal_base.HALBase.MfgIds.Any], 'name': {'cmos': "CMOS"}}
