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

"""
Register view of a GUID extension HOB payload.

The payload is held as a single integer so that each structure member declared in
XML becomes a normal register field: its 'bit' is the member's byte offset times
eight and its 'size' is the member's width in bits. This makes the standard field
accessors (get_field / has_field / get_field_mask) work directly on HOB data.

Two distinct byte orders are involved:
  - The payload is packed into the integer little-endian so that the first byte of
    the structure is the least significant one. That is what makes byte offset N
    map to bit N*8; it is a container encoding, not an interpretation of the data.
  - Individual members are reinterpreted using sys.byteorder, because the HOB list
    is read from the memory of the machine running CHIPSEC and is therefore stored
    in that machine's native order (matching the '=' prefix used for sizing).
"""

import sys
from typing import Any, Dict

from chipsec.cfg.parsers.registers.simple import SimpleRegister
from chipsec.library.uefi.common import EFI_GUID_STR

GUID_TYPE = 'guid'
BYTES_TYPE = 'bytes'
BOOLEAN_TYPE = 'boolean'

# Field types decoded as two's complement
SIGNED_TYPES = frozenset(['int8', 'int16', 'int32', 'int64'])

# Byte order the structure members are stored in (the host CHIPSEC is running on)
NATIVE_BYTE_ORDER = sys.byteorder


class HobRegister(SimpleRegister):
    """In-memory register whose fields are the members of a HOB structure.

    The value is a snapshot of the HOB payload taken while the HOB list was walked,
    so read()/get_field() report what was in memory at that time. write() and
    write_field() update only this snapshot; they do not write back to the HOB.
    """

    register_type = 'hob'

    def __init__(self, cfg_obj: Dict[str, Any]) -> None:
        super().__init__(cfg_obj)
        self.guid = cfg_obj.get('guid', '')
        self.vid_str = cfg_obj.get('vid_str', '')
        self.ip_name = cfg_obj.get('ip_name', '')
        self.address = cfg_obj.get('address', 0)

    def set_data(self, data: bytes) -> None:
        """Load a raw HOB payload; trailing data beyond the structure is ignored."""
        # 'little' packs the first byte into the least significant position, which is
        # what makes a member's byte offset usable directly as its field bit position.
        self.set_value(int.from_bytes(data[:self.size], 'little'))

    def get_field_bytes(self, field_name: str) -> bytes:
        """Get the raw bytes of a field, in the order they appear in memory."""
        field_name = field_name.upper()
        field_size = self.fields[field_name]['size'] // 8
        return self.get_field(field_name).to_bytes(field_size, 'little')

    def get_field_value(self, field_name: str) -> Any:
        """Get a field converted to its declared type (GUID string, bytes, bool, int or list)."""
        field_name = field_name.upper()
        field_attrs = self.fields[field_name]
        ftype = field_attrs.get('ftype', '')
        count = field_attrs.get('count', 1)
        raw = self.get_field_bytes(field_name)

        if ftype == GUID_TYPE:
            if count > 1:
                return [EFI_GUID_STR(raw[idx * 16:(idx + 1) * 16]) for idx in range(count)]
            return EFI_GUID_STR(raw)
        if ftype == BYTES_TYPE:
            return raw

        signed = ftype in SIGNED_TYPES
        if count > 1:
            elem_size = len(raw) // count
            values = [int.from_bytes(raw[idx * elem_size:(idx + 1) * elem_size],
                                     NATIVE_BYTE_ORDER, signed=signed)
                      for idx in range(count)]
            return [bool(v) for v in values] if ftype == BOOLEAN_TYPE else values

        value = int.from_bytes(raw, NATIVE_BYTE_ORDER, signed=signed)
        return bool(value) if ftype == BOOLEAN_TYPE else value

    def get_decoded(self) -> Dict[str, Any]:
        """Return all fields as a dict keyed by their declared (original case) names."""
        return {attrs.get('name', key): self.get_field_value(key) for key, attrs in self.fields.items()}

    def __str__(self) -> str:
        header = f'{self.name} {{{self.guid}}} (0x{self.size:X} bytes)'
        lines = [header]
        for key, attrs in self.fields.items():
            value = self.get_field_value(key)
            name = attrs.get('name', key)
            offset = attrs['bit'] // 8
            if isinstance(value, bool) or not isinstance(value, int):
                lines.append(f'    [0x{offset:02X}] {name:28} = {value}')
            elif value < 0:
                lines.append(f'    [0x{offset:02X}] {name:28} = -0x{-value:X}')
            else:
                lines.append(f'    [0x{offset:02X}] {name:28} = 0x{value:X}')
        return '\n'.join(lines)

    def __repr__(self) -> str:
        return f'HobRegister(name={self.name!r}, guid={self.guid!r}, size={self.size})'
