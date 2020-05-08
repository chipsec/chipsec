# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2017, Google Inc
# Copyright (c) 2019-2020, Intel Corporation
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

"""
Trusted Platform Module Event Log

Based on the following specifications:

TCG EFI Platform Specification For TPM Family 1.1 or 1.2
https://trustedcomputinggroup.org/wp-content/uploads/TCG_EFI_Platform_1_22_Final\_-v15.pdf

TCG PC Client Specific Implementation Specification for Conventional BIOS", version 1.21
https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientImplementation_1-21_1_00.pdf

TCG EFI Protocol Specification, Family "2.0"
https://trustedcomputinggroup.org/wp-content/uploads/EFI-Protocol-Specification-rev13-160330final.pdf

TCG PC Client Platform Firmware Profile Specification
https://trustedcomputinggroup.org/wp-content/uploads/PC-ClientSpecific_Platform_Profile_for_TPM_2p0_Systems_v51.pdf
"""

import binascii
import struct

from chipsec.logger import logger


class TcgPcrEvent(object):
    """An Event (TPM 1.2 format) as recorded in the SML."""

    _header_fmt = "II20sI"
    _header_size = struct.calcsize(_header_fmt)

    def __init__(self, pcr_index, event_type, digest, event_size, event):
        self.pcr_index = pcr_index
        self.event_type = event_type
        name = SML_EVENT_TYPE.get(self.event_type)
        if isinstance(name, str):
            self.event_type_name = name
        self.digest = digest
        self.event_size = event_size
        self.event = event

    @classmethod
    def parse(cls, log):
        """Try to read an event from the log.

        Args:
            log (file-like): Log where the event is stored.

        Returns:
            An instance of the created event. If a subclass
            exists for such event_type, an object of this class
            is returned. Otherwise, a TcgPcrEvent is returned.
        """
        header = log.read(cls._header_size)
        if not header:
            return
        fields = struct.unpack(cls._header_fmt, header)
        pcr_index, event_type, digest, event_size = fields
        event = log.read(event_size)
        if len(event) != event_size:
            logger().warn("[tpm_eventlog] event data length "
                                 "does not match the expected size")
        name = SML_EVENT_TYPE.get(event_type)
        kls = cls if isinstance(name, str) else name
        return kls(pcr_index, event_type, digest, event_size, event)

    def __str__(self):
        if self.event_type_name:
            t = self.event_type_name
        else:
            t = "(0x{:x}".format(self.event_type)
        _str = "PCR: {:d}\ttype: {}\tsize: 0x{:x}\tdigest: {}"
        return _str.format(self.pcr_index, t.ljust(EVENT_TYPE_MAX_LENGTH),
                       self.event_size, binascii.hexlify(self.digest))


class SCRTMVersion(TcgPcrEvent):
    def __init__(self, *args):
        super(SCRTMVersion, self).__init__(*args)
        self.event_type_name = "EV_S_CRTM_VERSION"
        self.version = self.event

    def __str__(self):
        _str = super(SCRTMVersion, self).__str__()
        try:
            _str += "\n\t+ version: {}".format(self.version.decode("utf-16"))
        except:
            if logger().HAL: logger().warn("[tpm_eventlog] CRTM Version is not "
                                 "a valid string")
        return _str


class EFIFirmwareBlob(TcgPcrEvent):
    # Although [4] 9.2.5 mentions UNIT64 for the length, [1] 7.7 uses
    # a UINTN. Use a native unsigned long to cover the most general case.
    _event_fmt = "@QL"

    def __init__(self, *args):
        super(EFIFirmwareBlob, self).__init__(*args)
        self.event_type_name = "EV_EFI_PLATFORM_FIRMWARE_BLOB"
        base, length = struct.unpack(self._event_fmt, self.event)
        self.base = base
        self.length = length


    def __str__(self):
        _str = super(EFIFirmwareBlob, self).__str__()
        _str += "\n\t+ base: 0x{:x}\tlength: 0x{:x}".format(self.base, self.length)
        return _str


SML_EVENT_TYPE = {
        # From reference [2]
        0x0: "EV_PREBOOT_CERT",
        0x1: "EV_POST_CODE",
        0x2: "EV_UNUSED",
        0x3: "EV_NO_ACTION",
        0x4: "EV_SEPARATOR",
        0x5: "EV_ACTION",
        0x6: "EV_EVENT_TAG",
        0x7: "EV_S_CRTM_CONTENTS",
        0x8: SCRTMVersion,
        0x9: "EV_CPU_MICROCODE",
        0xA: "EV_PLATFORM_CONFIG_FLAGS",
        0xB: "EV_TABLE_OF_DEVICES",
        0xC: "EV_COMPACT_HASH",
        0xD: "EV_IPL",
        0xE: "EV_IPL_PARTITION_DATA",
        0xF: "EV_NONHOST_CODE",
        0x10: "EV_NONHOST_CONFIG",
        0x11: "EV_NONHOST_INFO",
        0x12: "EV_OMIT_BOOT_DEVICE_EVENTS",

        # From reference [1]
        0x80000000: "EV_EFI_EVENT_BASE",
        0x80000001: "EV_EFI_VARIABLE_DRIVER_CONFIG",
        0x80000002: "EV_EFI_VARIABLE_BOOT",
        0x80000003: "EV_EFI_BOOT_SERVICES_APPLICATION",
        0x80000004: "EV_EFI_BOOT_SERVICES_DRIVER",
        0x80000005: "EV_EFI_RUNTIME_SERVICES_DRIVER",
        0x80000006: "EV_EFI_GPT_EVENT",
        0x80000007: "EV_EFI_ACTION",
        0x80000008: EFIFirmwareBlob,
        0x80000009: "EV_EFI_HANDOFF_TABLES",
        0x800000E0: "EV_EFI_VARIABLE_AUTHORITY"
}

EVENT_TYPE_MAX_LENGTH = max([len(v) for v in SML_EVENT_TYPE.values()
                             if isinstance(v, str)])


class PcrLogParser(object):
    """Iterator over the events of a log."""

    def __init__(self, log):
        self.log = log

    def __iter__(self):
        return self

    def __next__(self):
        event = TcgPcrEvent.parse(self.log)
        if not event:
            raise StopIteration()
        return event
    
    def next(self):
        return self.__next__()


def parse(log):
    """Simple wrapper around PcrLogParser."""
    for event in PcrLogParser(log):
        logger().log(event)
