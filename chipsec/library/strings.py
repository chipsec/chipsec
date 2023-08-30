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

import string
from time import strftime
from typing import AnyStr, Iterable


def get_datetime_str() -> str:
    return strftime('%a%b%d%y-%H%M%S')


def bytestostring(mbytes: AnyStr) -> str:
    if isinstance(mbytes, bytes) or isinstance(mbytes, bytearray):
        return mbytes.decode("latin_1")
    else:
        return mbytes


def stringtobytes(mstr: AnyStr) -> bytes:
    if isinstance(mstr, str):
        return mstr.encode("latin_1")
    else:
        return mstr


def is_printable(seq: AnyStr) -> bool:
    return set(bytestostring(seq)).issubset(set(string.printable))


def is_hex(maybe_hex: Iterable) -> bool:
    return all(char in string.hexdigits for char in maybe_hex)
