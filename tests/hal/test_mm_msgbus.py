# CHIPSEC: Platform Security Assessment Framework
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; Version 2.
#

import unittest
from unittest.mock import MagicMock

from chipsec.hal.intel.mm_msgbus import MMMsgBus
from chipsec.library.exceptions import CSReadError


def _make_msgbus_with_hidden_p2sb():
    """MMMsgBus whose P2SB config access always fails because the device is hidden."""
    mock_cs = MagicMock()
    mock_cs.hals.pci.read.side_effect = CSReadError('PCI Device is not available (0:31.1)')
    msgbus = MMMsgBus(mock_cs)
    msgbus.logger = MagicMock()

    hide_reg = MagicMock(name='P2SBC', offset=0xE0, size=2)
    hide_reg.pci.bus, hide_reg.pci.dev, hide_reg.pci.fun = 0, 0x1F, 1
    hide_reg.has_field.return_value = True
    bar_reg = MagicMock(name='SBREG_BAR', offset=0x10, size=8)
    bar_reg.pci.bus, bar_reg.pci.dev, bar_reg.pci.fun = 0, 0x1F, 1
    mock_cs.Cfg.get_reglist.side_effect = lambda name: [bar_reg] if name.endswith('SBREG_BAR') else [hide_reg]
    return msgbus, mock_cs


class TestMMMsgBus(unittest.TestCase):
    def test_unhidden_mmio_failure_is_logged_and_p2sb_is_hidden(self):
        mock_cs = MagicMock()
        msgbus = MMMsgBus(mock_cs)
        msgbus.logger = MagicMock()
        msgbus._MMMsgBus__unhide_p2sb = MagicMock()
        msgbus._MMMsgBus__hide_p2sb = MagicMock()
        msgbus._MMMsgBus__read_sbreg_bar_direct = MagicMock(side_effect=RuntimeError('unmapped'))

        address = msgbus._MMMsgBus__get_sbreg_from_unhidden_mmio_bar()

        self.assertIsNone(address)
        msgbus.logger.log_hal.assert_any_call('Failed to read unhidden SBREG_BAR: unmapped')
        msgbus._MMMsgBus__unhide_p2sb.assert_called_once_with()
        msgbus._MMMsgBus__hide_p2sb.assert_called_once_with()

    def test_hide_p2sb_skips_when_device_not_visible(self):
        msgbus, mock_cs = _make_msgbus_with_hidden_p2sb()

        msgbus._MMMsgBus__hide_p2sb()  # must not raise

        mock_cs.hals.pci.write.assert_not_called()
        msgbus.logger.log_hal.assert_any_call('[mm_msgbus] P2SB at 00:1F.1 is not visible; skipping re-hide')

    def test_direct_read_failure_is_not_masked_by_rehide(self):
        msgbus, mock_cs = _make_msgbus_with_hidden_p2sb()

        address = msgbus._MMMsgBus__get_sbreg_from_unhidden_mmio_bar()

        # The direct-read error, not a re-hide error, is what gets logged.
        self.assertIsNone(address)
        logged = [c[0][0] for c in msgbus.logger.log_hal.call_args_list]
        failure = [m for m in logged if m.startswith('Failed to read unhidden SBREG_BAR:')]
        self.assertEqual(len(failure), 1)
        self.assertIn('still hidden after unhide attempt', failure[0])
        self.assertIn('00:1F.1', failure[0])
        mock_cs.hals.pci.write.assert_called_once()  # unhide only; no re-hide write

    def test_failed_discovery_is_not_repeated(self):
        msgbus = MMMsgBus(MagicMock())
        msgbus.logger = MagicMock()
        sources = ('get_sbreg_from_fixed_address', 'get_sbreg_from_mmio_bar', 'get_sbreg_from_hob',
                   'get_sbreg_from_acpi', 'get_sbreg_from_unhidden_mmio_bar')
        for name in sources:
            setattr(msgbus, f'_MMMsgBus__{name}', MagicMock(return_value=None))

        self.assertFalse(msgbus.is_enabled())
        self.assertFalse(msgbus.is_enabled())

        for name in sources:
            getattr(msgbus, f'_MMMsgBus__{name}').assert_called_once_with()

    def test_explicit_find_retries_discovery(self):
        msgbus = MMMsgBus(MagicMock())
        msgbus.logger = MagicMock()
        mmio_bar = MagicMock(side_effect=[None, 0xFD000000])
        msgbus._MMMsgBus__get_sbreg_from_mmio_bar = mmio_bar
        for name in ('get_sbreg_from_fixed_address', 'get_sbreg_from_hob', 'get_sbreg_from_acpi',
                     'get_sbreg_from_unhidden_mmio_bar'):
            setattr(msgbus, f'_MMMsgBus__{name}', MagicMock(return_value=None))

        self.assertIsNone(msgbus.get_sbreg_base_address())
        self.assertEqual(msgbus.find_sbreg_base_address(), 0xFD000000)
        self.assertEqual(msgbus.get_sbreg_base_address(), 0xFD000000)
        self.assertEqual(mmio_bar.call_count, 2)

    def test_fixed_address_has_first_priority(self):
        mock_cs = MagicMock()
        mock_cs.register.mmio.get_def.return_value.fixed_address = 0xE0000000
        msgbus = MMMsgBus(mock_cs)
        msgbus.logger = MagicMock()
        msgbus._MMMsgBus__get_sbreg_from_mmio_bar = MagicMock(return_value=0xFD000000)

        self.assertEqual(msgbus.get_sbreg_base_address(), 0xE0000000)
        self.assertTrue(msgbus.is_enabled())
        msgbus._MMMsgBus__get_sbreg_from_mmio_bar.assert_not_called()

    def test_missing_fixed_address_falls_through_to_mmio_bar(self):
        for bar in (None, MagicMock(fixed_address=None)):
            with self.subTest(bar=bar):
                mock_cs = MagicMock()
                mock_cs.register.mmio.get_def.return_value = bar
                msgbus = MMMsgBus(mock_cs)
                msgbus.logger = MagicMock()
                msgbus._MMMsgBus__get_sbreg_from_mmio_bar = MagicMock(return_value=0xFD000000)

                self.assertEqual(msgbus.get_sbreg_base_address(), 0xFD000000)

    def test_read_and_write_raise_cs_read_error_when_discovery_failed(self):
        mock_cs = MagicMock()
        msgbus = MMMsgBus(mock_cs)
        msgbus.logger = MagicMock()
        msgbus._sbreg_searched = True

        with self.assertRaisesRegex(CSReadError, 'port 0x2A register 0x0034'):
            msgbus.read(0x2A, 0x34)
        with self.assertRaisesRegex(CSReadError, 'port 0x2A register 0x0034'):
            msgbus.write(0x2A, 0x34, 0x1)

        mock_cs.hals.mmio.read_MMIO_reg_dword.assert_not_called()
        mock_cs.hals.mmio.write_MMIO_reg_dword.assert_not_called()

    def test_read_and_write_use_discovered_base(self):
        mock_cs = MagicMock()
        msgbus = MMMsgBus(mock_cs)
        msgbus._sbreg_base = 0xFD000000

        msgbus.read(0x2A, 0x34)
        msgbus.write(0x2A, 0x34, 0x1)

        mock_cs.hals.mmio.read_MMIO_reg_dword.assert_called_once_with(0xFD000000, 0x2A0034)
        mock_cs.hals.mmio.write_MMIO_reg_dword.assert_called_once_with(0xFD000000, 0x2A0034, 0x1)


if __name__ == '__main__':
    unittest.main()