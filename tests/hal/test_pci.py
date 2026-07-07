# CHIPSEC: Platform Security Assessment Framework
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

import unittest

from unittest.mock import MagicMock, call
from chipsec.hal.common.pci import Pci
from chipsec.library.exceptions import CSReadError
from chipsec.library.register import ObjList, Register
from chipsec.cfg.parsers.ip.pci_device import PCIConfig
from chipsec.cfg.parsers.registers.pci import PCIRegisters


def _device_read_side_effect(vid, did, rid, regs=None):
    """Build a ``helper.read_pci_reg`` side_effect for a present PCI device.

    DIDVID is served from offset 0x0 (size 4), RID from offset 0x8 (size 1), and
    any additional register values from the optional ``regs`` mapping keyed by
    ``(offset, size)``. Unmapped reads return 0.
    """
    regs = regs or {}

    def _side_effect(bus, dev, fun, off, size):
        if off == 0x0 and size == 4:
            return (did << 16) | vid
        if off == 0x8 and size == 1:
            return rid
        return regs.get((off, size), 0)

    return _side_effect


class TestPCI(unittest.TestCase):
    def test_(self):
        mock_cs = MagicMock()
        vid = 0x8086
        did = 0x1234
        rid = 0xa
        mock_cs.helper.read_pci_reg.return_value = (did << 16) | vid
        pci_data = {'bus': 0, 'dev': 0, 'fun': 0, 'vid': vid, 'did': did,'rid': rid}
        pcilist = ObjList([PCIConfig(pci_data)])
        test_acpi = Pci(mock_cs)
        new_data = test_acpi.get_viddidrid_from_device_list(pcilist)
        self.assertEqual(len(new_data), 1)
        new_vid, new_did, new_rid, _ = new_data[0]
        self.assertEqual(new_vid, vid)
        self.assertEqual(new_did, did)
        self.assertEqual(new_rid, rid)


class TestPCIReadCache(unittest.TestCase):
    """Cover the active_devices caching semantics in Pci.read()."""

    def test_read_cache_miss_probes_and_populates(self):
        vid, did, rid = 0x8086, 0x1234, 0x0A
        mock_cs = MagicMock()
        mock_cs.helper.read_pci_reg.side_effect = _device_read_side_effect(
            vid, did, rid, {(0x10, 4): 0xDEADBEEF})
        pci = Pci(mock_cs)

        self.assertNotIn((0, 0, 0), pci.active_devices)
        value = pci.read(0, 0, 0, 0x10, 4)

        self.assertEqual(value, 0xDEADBEEF)
        # The device is now cached with (vid, did, rid).
        self.assertEqual(pci.active_devices[(0, 0, 0)], (vid, did, rid))
        # A cache miss probes DIDVID (0x0/4) and RID (0x8/1) before the value read.
        calls = mock_cs.helper.read_pci_reg.call_args_list
        self.assertIn(call(0, 0, 0, 0x0, 4), calls)
        self.assertIn(call(0, 0, 0, 0x8, 1), calls)
        self.assertIn(call(0, 0, 0, 0x10, 4), calls)

    def test_read_cache_hit_skips_availability_probe(self):
        mock_cs = MagicMock()
        mock_cs.helper.read_pci_reg.return_value = 0x1234
        pci = Pci(mock_cs)
        # Pre-seed the cache so the availability probe should be skipped.
        pci.active_devices[(0, 0, 0)] = (0x8086, 0x1234, 0x0A)

        value = pci.read(0, 0, 0, 0x10, 4)

        self.assertEqual(value, 0x1234)
        # Only the value read happens; no DIDVID/RID probe reads.
        mock_cs.helper.read_pci_reg.assert_called_once_with(0, 0, 0, 0x10, 4)

    def test_read_unavailable_bdf_raises_and_does_not_cache(self):
        mock_cs = MagicMock()
        mock_cs.helper.read_pci_reg.return_value = 0xFFFFFFFF
        pci = Pci(mock_cs)

        with self.assertRaises(CSReadError):
            pci.read(0, 0, 0, 0x10, 4)
        self.assertNotIn((0, 0, 0), pci.active_devices)

    def test_read_size8_combines_two_dwords(self):
        vid, did, rid = 0x8086, 0x1234, 0x0A
        mock_cs = MagicMock()
        mock_cs.helper.read_pci_reg.side_effect = _device_read_side_effect(
            vid, did, rid, {(0x20, 4): 0x11112222, (0x24, 4): 0x33334444})
        pci = Pci(mock_cs)

        value = pci.read(0, 0, 0, 0x20, 8)

        self.assertEqual(value, (0x33334444 << 32) | 0x11112222)
        calls = mock_cs.helper.read_pci_reg.call_args_list
        self.assertIn(call(0, 0, 0, 0x20, 4), calls)
        self.assertIn(call(0, 0, 0, 0x24, 4), calls)

    def test_read_invalid_size_raises_for_available_device(self):
        mock_cs = MagicMock()
        mock_cs.helper.read_pci_reg.return_value = 0x1234
        pci = Pci(mock_cs)
        pci.active_devices[(0, 0, 0)] = (0x8086, 0x1234, 0x0A)

        with self.assertRaises(CSReadError):
            pci.read(0, 0, 0, 0x10, 3)

    def test_read_word_and_byte_use_expected_size(self):
        vid, did, rid = 0x8086, 0x1234, 0x0A
        mock_cs = MagicMock()
        mock_cs.helper.read_pci_reg.side_effect = _device_read_side_effect(
            vid, did, rid, {(0x10, 2): 0xABCD, (0x12, 1): 0xEF})
        pci = Pci(mock_cs)

        self.assertEqual(pci.read_word(0, 0, 0, 0x10), 0xABCD)
        self.assertEqual(pci.read_byte(0, 0, 0, 0x12), 0xEF)
        calls = mock_cs.helper.read_pci_reg.call_args_list
        self.assertIn(call(0, 0, 0, 0x10, 2), calls)
        self.assertIn(call(0, 0, 0, 0x12, 1), calls)


class TestPCIEnumerateRefresh(unittest.TestCase):
    """Cover the refresh reuse semantics in Pci.enumerate_devices()."""

    def test_no_refresh_reuses_cache_without_reads(self):
        mock_cs = MagicMock()
        pci = Pci(mock_cs)
        pci.active_devices = {
            (0, 0, 0): (0x8086, 0x1234, 0x0A),
            (0, 0x1F, 0): (0x8086, 0x5678, 0x11),
        }

        result = pci.enumerate_devices(refresh=False)

        mock_cs.helper.read_pci_reg.assert_not_called()
        self.assertEqual(len(result), 2)
        self.assertIn((0, 0, 0, 0x8086, 0x1234, 0x0A), result)
        self.assertIn((0, 0x1F, 0, 0x8086, 0x5678, 0x11), result)

    def test_no_refresh_empty_cache_falls_back_to_scan(self):
        vid, did, rid = 0x8086, 0x1234, 0x0A
        mock_cs = MagicMock()
        mock_cs.helper.read_pci_reg.side_effect = _device_read_side_effect(vid, did, rid)
        pci = Pci(mock_cs)

        # Cache is empty, so refresh=False still scans the requested BDF.
        result = pci.enumerate_devices(bus=0, device=0, function=0, refresh=False)

        self.assertTrue(mock_cs.helper.read_pci_reg.called)
        self.assertEqual(result, [(0, 0, 0, vid, did, rid)])
        self.assertEqual(pci.active_devices[(0, 0, 0)], (vid, did, rid))

    def test_refresh_clears_stale_cache_and_rescans(self):
        vid, did, rid = 0x8086, 0x1234, 0x0A
        mock_cs = MagicMock()
        mock_cs.helper.read_pci_reg.side_effect = _device_read_side_effect(vid, did, rid)
        pci = Pci(mock_cs)
        # Stale entry that must be removed by a refreshing scan.
        pci.active_devices = {(1, 2, 3): (0x1, 0x2, 0x3)}

        result = pci.enumerate_devices(bus=0, device=0, function=0, refresh=True)

        self.assertNotIn((1, 2, 3), pci.active_devices)
        self.assertEqual(result, [(0, 0, 0, vid, did, rid)])
        self.assertEqual(pci.active_devices[(0, 0, 0)], (vid, did, rid))


class TestPCIWriteChunking(unittest.TestCase):
    """Cover the dword/word/byte chunking logic in Pci.write()."""

    def _make_pci(self):
        mock_cs = MagicMock()
        return Pci(mock_cs), mock_cs.helper.write_pci_reg

    def test_write_dword_single_chunk(self):
        pci, write_reg = self._make_pci()
        pci.write(0, 0, 0, 0x10, 4, 0xAABBCCDD)
        write_reg.assert_called_once_with(0, 0, 0, 0x10, 0xAABBCCDD, 4)

    def test_write_word_single_chunk(self):
        pci, write_reg = self._make_pci()
        pci.write(0, 0, 0, 0x10, 2, 0xABCD)
        write_reg.assert_called_once_with(0, 0, 0, 0x10, 0xABCD, 2)

    def test_write_byte_single_chunk(self):
        pci, write_reg = self._make_pci()
        pci.write(0, 0, 0, 0x10, 1, 0xAB)
        write_reg.assert_called_once_with(0, 0, 0, 0x10, 0xAB, 1)

    def test_write_qword_splits_into_two_dwords(self):
        pci, write_reg = self._make_pci()
        pci.write(0, 0, 0, 0x10, 8, 0x1122334455667788)
        self.assertEqual(write_reg.call_args_list, [
            call(0, 0, 0, 0x10, 0x55667788, 4),
            call(0, 0, 0, 0x14, 0x11223344, 4),
        ])

    def test_write_three_bytes_splits_into_word_then_byte(self):
        pci, write_reg = self._make_pci()
        pci.write(0, 0, 0, 0x10, 3, 0xAABBCC)
        self.assertEqual(write_reg.call_args_list, [
            call(0, 0, 0, 0x10, 0xBBCC, 2),
            call(0, 0, 0, 0x12, 0xAA, 1),
        ])

    def test_write_six_bytes_splits_into_dword_then_word(self):
        pci, write_reg = self._make_pci()
        pci.write(0, 0, 0, 0x10, 6, 0xAABBCCDDEEFF)
        self.assertEqual(write_reg.call_args_list, [
            call(0, 0, 0, 0x10, 0xCCDDEEFF, 4),
            call(0, 0, 0, 0x14, 0xAABB, 2),
        ])

    def test_write_helpers_delegate_with_correct_size(self):
        pci, write_reg = self._make_pci()
        pci.write_dword(0, 0, 0, 0x10, 0xAABBCCDD)
        pci.write_word(0, 0, 0, 0x20, 0xABCD)
        pci.write_byte(0, 0, 0, 0x30, 0xAB)
        self.assertEqual(write_reg.call_args_list, [
            call(0, 0, 0, 0x10, 0xAABBCCDD, 4),
            call(0, 0, 0, 0x20, 0xABCD, 2),
            call(0, 0, 0, 0x30, 0xAB, 1),
        ])
