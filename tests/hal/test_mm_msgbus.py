# CHIPSEC: Platform Security Assessment Framework
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; Version 2.
#

import unittest
from unittest.mock import MagicMock

from chipsec.hal.intel.mm_msgbus import MMMsgBus


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


if __name__ == '__main__':
    unittest.main()