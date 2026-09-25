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


# To execute: python[3] -m unittest tests.helpers.test_linuxnative_legacy_pci

import mmap
import unittest
from unittest.mock import MagicMock, patch

import chipsec.helper.linuxnative.legacy_pci as legacy_pci
from chipsec.library.exceptions import OsHelperError

MOD = 'chipsec.helper.linuxnative.legacy_pci'


class PortsTest(unittest.TestCase):

    def setUp(self):
        self._saved_instance = legacy_pci.Ports.instance
        legacy_pci.Ports.instance = None

    def tearDown(self):
        legacy_pci.Ports.instance = self._saved_instance

    def _build_ports(self, iopl_result=0):
        in_page = MagicMock(name='in_page')
        out_page = MagicMock(name='out_page')
        patches = {
            'cdll': patch(f'{MOD}.CDLL'),
            'mmap': patch(f'{MOD}.mmap.mmap', side_effect=[in_page, out_page]),
            'c_void_p': patch(f'{MOD}.c_void_p'),
            'addressof': patch(f'{MOD}.addressof', side_effect=[0x1000, 0x2000]),
            'cfunctype': patch(f'{MOD}.CFUNCTYPE'),
        }
        started = {name: p.start() for name, p in patches.items()}
        self.addCleanup(lambda: [p.stop() for p in patches.values()])
        started['cdll'].return_value.iopl.return_value = iopl_result
        ports = legacy_pci.Ports() if iopl_result == 0 else None
        return ports, in_page, out_page, started

    def test_init_maps_executable_stubs(self):
        ports, in_page, out_page, started = self._build_ports()
        started['cdll'].assert_called_once_with('libc.so.6', use_errno=True)
        started['cdll'].return_value.iopl.assert_called_once_with(3)
        started['mmap'].assert_called_with(-1, mmap.PAGESIZE, flags=mmap.MAP_PRIVATE,
                                           prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
        in_page.write.assert_called_once_with(legacy_pci.IN_PORT)
        out_page.write.assert_called_once_with(legacy_pci.OUT_PORT)
        self.assertIs(ports.inl_addr, in_page)
        self.assertIs(ports.outl_addr, out_page)

    def test_init_without_io_privileges(self):
        with patch(f'{MOD}.CDLL') as cdll, patch(f'{MOD}.get_errno', return_value=1):
            cdll.return_value.iopl.return_value = -1
            with self.assertRaises(OsHelperError) as ctx:
                legacy_pci.Ports()
        self.assertIn('Unable to use I/O ports using iopl', str(ctx.exception))

    def test_inl_and_outl_delegate_to_stubs(self):
        ports, _in_page, _out_page, _started = self._build_ports()
        ports.inl_ptr = MagicMock(return_value=0x9A128086)
        ports.outl_ptr = MagicMock()
        self.assertEqual(ports.inl(0xCFC), 0x9A128086)
        ports.inl_ptr.assert_called_once_with(0xCFC)
        self.assertIsNone(ports.outl(0x1234, 0xCF8))
        ports.outl_ptr.assert_called_once_with(0x1234, 0xCF8)

    def test_get_instance_is_cached(self):
        ports, _in_page, _out_page, _started = self._build_ports()
        legacy_pci.Ports.instance = ports
        self.assertIs(legacy_pci.Ports.get_instance(), ports)
        self.assertIs(legacy_pci.Ports.get_instance(), ports)

    def test_get_instance_creates_singleton(self):
        with patch.object(legacy_pci.Ports, '__init__', return_value=None):
            created = legacy_pci.Ports.get_instance()
            self.assertIs(legacy_pci.Ports.get_instance(), created)


class LegacyPciTest(unittest.TestCase):

    def test_read_pci_config(self):
        ports = MagicMock()
        ports.inl.return_value = 0x9A128086
        with patch.object(legacy_pci.Ports, 'get_instance', return_value=ports):
            self.assertEqual(legacy_pci.LegacyPci.read_pci_config(0, 0x1F, 3, 0x40), 0x9A128086)
        ports.outl.assert_called_once_with(0x8000FB40, 0xCF8)
        ports.inl.assert_called_once_with(0xCFC)

    def test_write_pci_config(self):
        ports = MagicMock()
        with patch.object(legacy_pci.Ports, 'get_instance', return_value=ports):
            self.assertIsNone(legacy_pci.LegacyPci.write_pci_config(1, 2, 3, 0x10, 0xDEADBEEF))
        self.assertEqual(ports.outl.call_args_list[0][0], (0x80011310, 0xCF8))
        self.assertEqual(ports.outl.call_args_list[1][0], (0xDEADBEEF, 0xCFC))


if __name__ == '__main__':
    unittest.main()
