# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2026, Intel Corporation
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

import struct
from typing import Optional


def build_rsdp(
        revision: int = 0,
        rsdt_address: int = 0,
        xsdt_address: Optional[int] = None,
        oem_id: bytes = b'INTEL ',
        signature: bytes = b'RSD PTR ',
        length: int = 36
) -> bytes:
    """Build an RSDP with valid legacy and, when present, extended checksums."""
    if xsdt_address is None:
        data = bytearray(struct.pack(
            '<8sB6sBI', signature, 0, oem_id, revision, rsdt_address))
        data[8] = (-sum(data)) & 0xFF
        return bytes(data)

    data = bytearray(struct.pack(
        '<8sB6sBIIQB3s', signature, 0, oem_id, revision,
        rsdt_address, length, xsdt_address, 0, b'\x00\x00\x00'))
    data[8] = (-sum(data[:20])) & 0xFF
    data[32] = (-sum(data[:length])) & 0xFF
    return bytes(data)
