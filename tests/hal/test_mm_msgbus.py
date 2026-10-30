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
        mock_cs.hals.mmio.get_MMIO_BAR_base_address.side_effect = RuntimeError('unmapped')
        msgbus = MMMsgBus(mock_cs)
        msgbus.logger = MagicMock()
        msgbus._MMMsgBus__unhide_p2sb = MagicMock()
        msgbus._MMMsgBus__hide_p2sb = MagicMock()

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
        mock_cs.hals.mmio.get_MMIO_BAR_base_address.side_effect = CSReadError('no bar')
        mock_cs.hals.hob.get_list_by_name.return_value = []

        with self.assertRaises(CSReadError) as ctx:
            msgbus.get_sbreg_base_address()

        # The error from the direct SBREG_BAR read survives the finally/re-hide,
        # and tells the user the unhide did not take effect.
        self.assertIn('still hidden after unhide attempt', str(ctx.exception))
        self.assertIn('00:1F.1', str(ctx.exception))


if __name__ == '__main__':
    unittest.main()