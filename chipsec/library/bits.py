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

from typing import Optional

BIT0 = 0x0001
BIT1 = 0x0002
BIT2 = 0x0004
BIT3 = 0x0008
BIT4 = 0x0010
BIT5 = 0x0020
BIT6 = 0x0040
BIT7 = 0x0080
BIT8 = 0x0100
BIT9 = 0x0200
BIT10 = 0x0400
BIT11 = 0x0800
BIT12 = 0x1000
BIT13 = 0x2000
BIT14 = 0x4000
BIT15 = 0x8000
BIT16 = 0x00010000
BIT17 = 0x00020000
BIT18 = 0x00040000
BIT19 = 0x00080000
BIT20 = 0x00100000
BIT21 = 0x00200000
BIT22 = 0x00400000
BIT23 = 0x00800000
BIT24 = 0x01000000
BIT25 = 0x02000000
BIT26 = 0x04000000
BIT27 = 0x08000000
BIT28 = 0x10000000
BIT29 = 0x20000000
BIT30 = 0x40000000
BIT31 = 0x80000000
BIT32 = 0x100000000
BIT33 = 0x200000000
BIT34 = 0x400000000
BIT35 = 0x800000000
BIT36 = 0x1000000000
BIT37 = 0x2000000000
BIT38 = 0x4000000000
BIT39 = 0x8000000000
BIT40 = 0x10000000000
BIT41 = 0x20000000000
BIT42 = 0x40000000000
BIT43 = 0x80000000000
BIT44 = 0x100000000000
BIT45 = 0x200000000000
BIT46 = 0x400000000000
BIT47 = 0x800000000000
BIT48 = 0x1000000000000
BIT49 = 0x2000000000000
BIT50 = 0x4000000000000
BIT51 = 0x8000000000000
BIT52 = 0x10000000000000
BIT53 = 0x20000000000000
BIT54 = 0x40000000000000
BIT55 = 0x80000000000000
BIT56 = 0x100000000000000
BIT57 = 0x200000000000000
BIT58 = 0x400000000000000
BIT59 = 0x800000000000000
BIT60 = 0x1000000000000000
BIT61 = 0x2000000000000000
BIT62 = 0x4000000000000000
BIT63 = 0x8000000000000000

def make_mask(size: int, mask_start:Optional[int] = 0) -> int:
    mask = (1 << size) - 1
    mask <<= mask_start
    return mask

def bit(bit_num: int) -> int:
    return int(1 << bit_num)


def is_set(val: int, bit_mask: int) -> bool:
    return bool(val & bit_mask != 0)


def scan_single_bit_mask(bit_mask: int) -> Optional[int]:
    for bit_num in range(0, 7):
        if bit_mask >> bit_num == 1:
            return bit_num
    return None


def is_all_ones(value: int, size: int, width: int = 8) -> bool:
    mask = (1 << (size * width)) - 1
    return (mask == (mask & value))


def ones_complement(value: int, number_of_bits: int = 64) -> int:
    return ((1 << number_of_bits) - 1) ^ value


def get_bits(value: int, start: int, nbits: int) -> int:
    ret = value >> start
    ret &= (1 << nbits) - 1
    return ret

def set_bits(bit: int, size:int, initial_value:int, value: int) -> int:
    field_mask = make_mask(size)
    new_value = initial_value & ~(field_mask << bit)  # keep other fields
    new_value |= ((value & field_mask) << bit)
    return new_value