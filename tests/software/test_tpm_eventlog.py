# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2017, Google
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

import os
import struct
import tempfile
import unittest

from tests.software import util


class TestTpmEventLogChipsecUtil(util.TestChipsecUtil):
    """Test the tpm commands exposed by chipsec_utils."""

    def _tpm12_event(self, pcr_index, event_type, digest, event):
        _fmt = "II20sI"
        event_size = len(event)
        header = struct.pack(_fmt, pcr_index, event_type, digest, event_size)
        return header + event

    def _parse_eventlog(self, events):
        fileno, binary_event_log = tempfile.mkstemp()
        for event in events:
            os.write(fileno, event)
        os.close(fileno)
        self._chipsec_util("tpm parse_log {}".format(binary_event_log))
        os.remove(binary_event_log)

    def test_tpm_eventlog_basic(self):
        empty_event = self._tpm12_event(0x0, 0x0, b"\x00" * 20, b"")
        self._parse_eventlog([empty_event])
        self.assertIn(b"EV_PREBOOT_CERT", self.log)

    def test_tpm_eventlog_firmware_blob(self):
        data = struct.pack("QL", 0xABABABABFEFEFEFE, 0x12345678)
        blob_event = self._tpm12_event(0x0, 0x80000008, b"\x00" * 20, data)
        self._parse_eventlog([blob_event])
        self.assertIn(b"EV_EFI_PLATFORM_FIRMWARE_BLOB", self.log)
        self._assertLogValue("base", "0xababababfefefefe")
        self._assertLogValue("length", "0x12345678")


if __name__ == '__main__':
    unittest.main()
