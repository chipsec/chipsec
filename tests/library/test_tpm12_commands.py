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
import unittest
from unittest.mock import patch

from chipsec.library import tpm12_commands


class Tpm12TestBase(unittest.TestCase):
    """Silences the HAL logger used by the command builders."""

    def setUp(self):
        patcher = patch('chipsec.library.tpm12_commands.logger')
        self.mock_logger = patcher.start()
        self.mock_logger.return_value.HAL = True
        self.addCleanup(patcher.stop)

    def unpack(self, command):
        return struct.unpack(tpm12_commands.COMMAND_FORMAT, command)


class TestCommandLayout(Tpm12TestBase):
    """Cover the shared wire format of the TPM 1.2 command blobs."""

    def test_command_format_is_22_bytes(self):
        self.assertEqual(struct.calcsize(tpm12_commands.COMMAND_FORMAT), 22)

    def test_every_command_uses_the_rqu_command_tag(self):
        builders = (
            tpm12_commands.pcrread(0),
            tpm12_commands.nvread(1, 0, 4),
            tpm12_commands.startup(1),
            tpm12_commands.continueselftest(),
            tpm12_commands.getcap(0x1A, 0, 0),
            tpm12_commands.forceclear(),
        )
        for command, _ in builders:
            self.assertEqual(self.unpack(command)[0], tpm12_commands.TPM_TAG_RQU_COMMAND)

    def test_returned_size_is_the_size_field_top_byte(self):
        _, size = tpm12_commands.pcrread(0)
        self.assertEqual(size, 0x0E000000 >> 0x18)


class TestPcrRead(Tpm12TestBase):
    """Cover chipsec.library.tpm12_commands.pcrread."""

    def test_valid_pcr_builds_command(self):
        command, size = tpm12_commands.pcrread(5)
        tag, size_field, ordinal, pcr, pad1, pad2 = self.unpack(command)
        self.assertEqual(ordinal, tpm12_commands.TPM_ORD_PCRREAD)
        self.assertEqual(pcr, tpm12_commands.PCR[5])
        self.assertEqual((size_field, pad1, pad2), (0x0E000000, 0, 0))
        self.assertEqual(size, 14)

    def test_pcr_zero_is_valid(self):
        command, size = tpm12_commands.pcrread(0)
        self.assertEqual(self.unpack(command)[3], 0)
        self.assertEqual(size, 14)

    def test_out_of_range_pcr_returns_empty_command(self):
        self.assertEqual(tpm12_commands.pcrread(31), (b'', 0))

    def test_out_of_range_pcr_logs_when_hal_enabled(self):
        tpm12_commands.pcrread(31)
        self.mock_logger.return_value.log_bad.assert_called_once()

    def test_out_of_range_pcr_is_silent_when_hal_disabled(self):
        self.mock_logger.return_value.HAL = False
        self.assertEqual(tpm12_commands.pcrread(31), (b'', 0))
        self.mock_logger.return_value.log_bad.assert_not_called()


class TestNvRead(Tpm12TestBase):
    """Cover chipsec.library.tpm12_commands.nvread."""

    def test_builds_command_from_index_offset_size(self):
        command, size = tpm12_commands.nvread(0x1000, 0x10, 0x20)
        tag, size_field, ordinal, index, offset, length = self.unpack(command)
        self.assertEqual(ordinal, tpm12_commands.TPM_ORD_NV_READVALUE)
        self.assertEqual((index, offset, length), (0x1000, 0x10, 0x20))
        self.assertEqual(size_field, 0x18000000)
        self.assertEqual(size, 24)

    def test_wrong_argument_count_returns_empty_command(self):
        self.assertEqual(tpm12_commands.nvread(0x1000), (b'', 0))
        self.mock_logger.return_value.log_hal.assert_called_once()

    def test_no_arguments_returns_empty_command(self):
        self.assertEqual(tpm12_commands.nvread(), (b'', 0))


class TestStartup(Tpm12TestBase):
    """Cover chipsec.library.tpm12_commands.startup."""

    def test_each_documented_startup_type(self):
        for startup_type in (1, 2, 3):
            command, size = tpm12_commands.startup(startup_type)
            _, _, ordinal, value, _, _ = self.unpack(command)
            self.assertEqual(ordinal, tpm12_commands.TPM_ORD_STARTUP)
            self.assertEqual(value, tpm12_commands.STARTUP[startup_type])
            self.assertEqual(size, 14)

    def test_unknown_startup_type_returns_empty_command(self):
        self.assertEqual(tpm12_commands.startup(4), (b'', 0))
        self.mock_logger.return_value.log_hal.assert_called_once()

    def test_missing_argument_is_handled(self):
        self.assertEqual(tpm12_commands.startup(), (b'', 0))


class TestGetCap(Tpm12TestBase):
    """Cover chipsec.library.tpm12_commands.getcap."""

    def test_builds_command_from_cap_area_and_subcap(self):
        command, size = tpm12_commands.getcap(0x06000000, 0x04000000, 0x08000000)
        _, size_field, ordinal, cap_area, subcap_size, subcap = self.unpack(command)
        self.assertEqual(ordinal, tpm12_commands.TPM_ORD_GETCAPABILITY)
        self.assertEqual((cap_area, subcap_size, subcap), (0x06000000, 0x04000000, 0x08000000))
        self.assertEqual(size_field, 0x18000000)
        self.assertEqual(size, 24)

    def test_wrong_argument_count_returns_empty_command(self):
        self.assertEqual(tpm12_commands.getcap(0x06000000), (b'', 0))
        self.mock_logger.return_value.log_hal.assert_called_once()


class TestFixedCommands(Tpm12TestBase):
    """Cover the TPM 1.2 commands that take no parameters."""

    def test_continueselftest(self):
        command, size = tpm12_commands.continueselftest()
        _, size_field, ordinal, a, b, c = self.unpack(command)
        self.assertEqual(ordinal, tpm12_commands.TPM_ORD_CONTINUESELFTEST)
        self.assertEqual((size_field, a, b, c), (0x0A000000, 0, 0, 0))
        self.assertEqual(size, 10)

    def test_forceclear(self):
        command, size = tpm12_commands.forceclear()
        _, size_field, ordinal, a, b, c = self.unpack(command)
        self.assertEqual(ordinal, tpm12_commands.TPM_ORD_FORCECLEAR)
        self.assertEqual((size_field, a, b, c), (0x0A000000, 0, 0, 0))
        self.assertEqual(size, 10)

    def test_extra_arguments_are_ignored(self):
        self.assertEqual(tpm12_commands.forceclear('unused'), tpm12_commands.forceclear())


if __name__ == '__main__':
    unittest.main()
