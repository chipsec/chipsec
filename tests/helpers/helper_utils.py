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

import importlib.util
import os
import sys
from struct import pack
from types import SimpleNamespace
from typing import List
from unittest.mock import MagicMock, patch

POSIX_ONLY_MODULES = ('fcntl', 'resource')
POSIX_ONLY_OS_FUNCTIONS = ('chown', 'sched_getaffinity', 'sched_setaffinity')
# Linux values; Windows' mmap module lacks the MAP_* and PROT_* constants.
POSIX_MMAP = SimpleNamespace(PAGESIZE=0x1000, MAP_SHARED=0x01, MAP_PRIVATE=0x02, MAP_ANONYMOUS=0x20,
                             PROT_READ=0x1, PROT_WRITE=0x2, PROT_EXEC=0x4)


def stub_posix_only_modules() -> None:
    """Make POSIX-only modules importable on every OS so Linux helpers can be tested anywhere."""
    for name in POSIX_ONLY_MODULES:
        if sys.modules.get(name) is None and importlib.util.find_spec(name) is None:
            sys.modules[name] = MagicMock(name=name)


def stub_posix_only_os_functions() -> List:
    """Add missing POSIX-only os functions so tests can patch them; stop the returned patchers when done."""
    patchers = [patch.object(os, name, create=True) for name in POSIX_ONLY_OS_FUNCTIONS if not hasattr(os, name)]
    for patcher in patchers:
        patcher.start()
    return patchers


def fake_mmap_module() -> MagicMock:
    return MagicMock(name='mmap', **vars(POSIX_MMAP))


class packer():
    def __init__(self, default_size_char = 'Q') -> None:
        self.size_char = default_size_char


    def custom_pack(self, num_of_chunks: int, expected_value: int, expected_value_index:int = 0) -> bytes:
        input = [0] * num_of_chunks
        input[expected_value_index] = expected_value
        return pack(f'{num_of_chunks}{self.size_char}',*input)

    def pack_pci(self, expected_value: int) -> bytes:
        return self.custom_pack(5, expected_value, 4)

    def pack_cpuinfo(self, expected_value:int) -> bytes:
        return self.custom_pack(4, expected_value, 0)

    def pack_ioport(self, expected_value:int) -> bytes:
        return self.custom_pack(3, expected_value, 2)