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
Simple in-memory register.

Provides a register object backed solely by an in-memory value. Useful for
decoding raw values (e.g. fields read from a flash descriptor or a buffer)
into named bitfields without any hardware access.
"""

from typing import Any, Dict

from chipsec.library.register import BaseConfigRegisterHelper


class SimpleRegister(BaseConfigRegisterHelper):
    """In-memory register with named bitfields.

    The register value lives entirely in ``self.value``. ``read()`` returns the
    current value and ``write()`` replaces it. All field decoding/encoding is
    inherited from ``BaseConfigRegisterHelper`` (``get_field`` / ``set_field``
    / ``read_field`` / ``write_field``).
    """

    def __init__(self, cfg_obj: Dict[str, Any]) -> None:
        super().__init__(cfg_obj)
        self.size = cfg_obj.get('size', 4)
        self.value = cfg_obj.get('value', self.default if self.default is not None else 0)

    def read(self) -> int:
        return self.value

    def write(self, value: int) -> None:
        self.set_value(value)

    def __repr__(self) -> str:
        val = f'0x{self.value:X}' if self.value is not None else 'None'
        return f'SimpleRegister(name={self.name!r}, size={self.size}, value={val})'
