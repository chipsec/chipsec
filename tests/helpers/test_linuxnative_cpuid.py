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


# To execute: python[3] -m unittest tests.helpers.test_linuxnative_cpuid

import mmap
import unittest
from unittest.mock import MagicMock, patch

import chipsec.helper.linuxnative.cpuid as cpuid_mod

MOD = 'chipsec.helper.linuxnative.cpuid'


def build_cpuid(machine='x86_64'):
    """Create a CPUID object whose executable page and function pointer are mocked out."""
    page = MagicMock()
    with patch(f'{MOD}.platform.machine', return_value=machine), \
            patch(f'{MOD}.mmap.mmap', return_value=page) as mmap_mmap, \
            patch(f'{MOD}.c_void_p') as c_void_p, \
            patch(f'{MOD}.addressof', return_value=0x1000) as addressof, \
            patch(f'{MOD}.CFUNCTYPE') as cfunctype:
        instance = cpuid_mod.CPUID()
    return instance, page, mmap_mmap, c_void_p, addressof, cfunctype


class CPUIDTest(unittest.TestCase):

    def test_unsupported_architecture(self):
        # __del__ is neutralized because the failed __init__ leaves no 'fp' attribute to drop.
        with patch.object(cpuid_mod.CPUID, '__del__', lambda self: None), \
                patch(f'{MOD}.platform.machine', return_value='armv7l'):
            with self.assertRaises(SystemError):
                cpuid_mod.CPUID()

    def test_init_writes_opcodes_into_executable_page(self):
        instance, page, mmap_mmap, c_void_p, addressof, cfunctype = build_cpuid()
        try:
            mmap_mmap.assert_called_once_with(-1, mmap.PAGESIZE, flags=mmap.MAP_PRIVATE,
                                              prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
            expected_code = cpuid_mod._POSIX_64_OPC if cpuid_mod.is_64bit else cpuid_mod._CDECL_32_OPC
            page.write.assert_called_once_with(expected_code)
            c_void_p.from_buffer.assert_called_once_with(page)
            addressof.assert_called_once_with(instance.fp)
            cfunctype.return_value.assert_called_once_with(0x1000)
            self.assertIs(instance.func_ptr, cfunctype.return_value.return_value)
        finally:
            instance.fp = MagicMock()

    def test_call_returns_register_values(self):
        instance, _page, _mmap, _c_void_p, _addressof, _cfunctype = build_cpuid()
        try:
            def fill(struct, eax, ecx):
                struct.eax = 0x000406F1
                struct.ebx = eax
                struct.ecx = ecx
                struct.edx = 0xBFEBFBFF

            instance.func_ptr = fill
            self.assertEqual(instance(0x1, 0x2), (0x000406F1, 0x1, 0x2, 0xBFEBFBFF))
        finally:
            instance.fp = MagicMock()

    def test_del_closes_page(self):
        instance, page, _mmap, _c_void_p, _addressof, _cfunctype = build_cpuid()
        instance.__del__()
        page.close.assert_called_once_with()
        self.assertFalse(hasattr(instance, 'fp'))
        # Restore the attribute so the interpreter's own finalization stays quiet.
        instance.fp = MagicMock()

    def test_cpuid_struct_fields(self):
        struct = cpuid_mod.CPUID_struct()
        struct.eax, struct.ebx, struct.ecx, struct.edx = 1, 2, 3, 4
        self.assertEqual((struct.eax, struct.ebx, struct.ecx, struct.edx), (1, 2, 3, 4))


if __name__ == '__main__':
    unittest.main()
