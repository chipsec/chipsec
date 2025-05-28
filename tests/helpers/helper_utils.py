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
#

from struct import pack


class packer():
    def __init__(self, default_size_char='Q') -> None:
        self.size_char = default_size_char

    def custom_pack(self, num_of_chunks: int, expected_value: int, expected_value_index: int = 0) -> bytes:
        input = [0] * num_of_chunks
        input[expected_value_index] = expected_value
        return pack(f'{num_of_chunks}{self.size_char}', *input)

    def pack_pci(self, expected_value: int) -> bytes:
        return self.custom_pack(5, expected_value, 4)

    def pack_cpuinfo(self, expected_value: int) -> bytes:
        return self.custom_pack(4, expected_value, 0)

    def pack_ioport(self, expected_value: int) -> bytes:
        return self.custom_pack(3, expected_value, 2)
