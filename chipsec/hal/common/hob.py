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

"""
HAL component providing access to the PI Hand-Off Block (HOB) list

The HOB list is published in the EFI Configuration Table under the gEfiHobListGuid
(EFI_HOB_LIST_GUID) vendor table entry and is only available while the HOB list is
still resident in memory (i.e. when running in the EFI environment).
"""

from typing import Tuple, List, Dict, Optional

from chipsec.hal import hal_base
from chipsec.cfg.parsers.hob_parser import HOBCommands, HobDefinition
from chipsec.library.exceptions import PlatformConfigError
from chipsec.library.register import ObjList
from chipsec.library.uefi.hob import EFI_HOB_LIST_GUID, EFI_HOB_HANDOFF_INFO_TABLE_SIZE, MAX_HOB_LIST_SIZE, EFI_HOB_TYPE_GUID_EXTENSION
from chipsec.library.uefi.hob import Hob, parse_phit, walk_hob_list

# Size of each incremental physical memory read while walking the HOB list (64KB)
HOB_READ_CHUNK_SIZE = 0x10000

# Decoded fields that hold a GUID, searched when filtering the list by GUID
HOB_GUID_FIELDS = ('GUID', 'FvName_GUID', 'FileName_GUID', 'Owner_GUID')


class HOB(hal_base.HALBase):

    def __init__(self, cs):
        super(HOB, self).__init__(cs)
        self.hobs:List[Hob] = []
        self.hob_pa = 0
        self.complete = False
        self.found = False
        self.definitions = HOBCommands(cs.Cfg)
        self.get_HOB_list()

    def find_HOB_list(self) -> bool:
        """
        Locate the physical address of the PI HOB list and store it in self.hob_pa.

        The HOB list is published in the EFI Configuration Table under the
        gEfiHobListGuid (EFI_HOB_LIST_GUID) vendor table entry.

        Returns:
            True if the HOB list address was found, False otherwise (self.hob_pa is
            set to 0 when not found).
        """
        (found, _, ect, _) = self.cs.hals.uefi.find_EFI_Configuration_Table()
        if not found or ect is None:
            self.logger.log_hal('[hob] Could not find EFI Configuration Table; unable to locate HOB list')
            self.hob_pa = 0
            return False
        self.hob_pa = ect.VendorTables.get(EFI_HOB_LIST_GUID, 0)
        if not self.hob_pa:
            self.logger.log_hal(f'[hob] HOB list GUID {{{EFI_HOB_LIST_GUID}}} not present in Configuration Table')
            self.hob_pa = 0
            return False
        self.logger.log_hal(f'[hob] HOB list located at PA 0x{self.hob_pa:016X}')
        return True

    def read_HOB_list(self) -> Tuple[bool, bytes]:
        """
        Read the entire HOB list from physical memory.

        The HOB list is walked incrementally (following each HOB's self-describing
        length) until the END_OF_HOB_LIST HOB is reached. The PHIT's EfiEndOfHobList
        field is intentionally NOT used to compute the size: when the HOB list has
        been relocated (e.g. by the DXE core), EfiEndOfHobList still references the
        original PEI location and does not match the address published in the
        Configuration Table.

        Returns:
            (found, hob_list_buffer) where hob_list_buffer is empty if the list could
            not be located or does not start with a valid PHIT.
        """
        found = self.find_HOB_list()
        if not found:
            return (False, b'')

        # Validate that the data at hob_pa starts with a PHIT (HANDOFF) HOB.
        hdr_buf = self.cs.hals.memory.read_physical_mem(self.hob_pa, EFI_HOB_HANDOFF_INFO_TABLE_SIZE)
        phit = parse_phit(hdr_buf)
        if phit is None:
            self.logger.log_error(f'[hob] Data at 0x{self.hob_pa:016X} does not start with a valid PHIT HOB')
            return (False, b'')
        self.logger.log_hal(str(phit))

        # Walk the list in chunks until END_OF_HOB_LIST is found.
        hob_buf = bytearray(hdr_buf)
        while len(hob_buf) < MAX_HOB_LIST_SIZE:
            chunk = self.cs.hals.memory.read_physical_mem(self.hob_pa + len(hob_buf), HOB_READ_CHUNK_SIZE)
            if not chunk:
                break
            hob_buf += chunk
            _, complete, consumed = walk_hob_list(hob_buf, self.hob_pa)
            if complete:
                del hob_buf[consumed:]
                break
            if len(chunk) < HOB_READ_CHUNK_SIZE:
                # Could not read a full chunk; no more memory to consume.
                break

        self.logger.log_hal(f'[hob] Read HOB list: 0x{self.hob_pa:016X}-0x{self.hob_pa + len(hob_buf):016X} (0x{len(hob_buf):X} bytes)')
        return (True, bytes(hob_buf))

    def get_HOB_list(self) -> Tuple[bool, int, List[Hob]]:
        """
        Locate, read, and parse the PI HOB list into self.hobs.

        GUID extension HOBs with a declared definition are decoded into register
        objects while the list is walked, and the decoded instances are published
        into the platform hierarchy under the IP named by their <definition> entry.

        Returns:
            (found, hob_list_pa, list_of_Hob)
        """
        (self.found, hob_buf) = self.read_HOB_list()
        self.hobs = []
        self.complete = False
        if self.found:
            (self.hobs, self.complete, _) = walk_hob_list(hob_buf, self.hob_pa, self.definitions)
            if not self.complete:
                self.logger.log_hal('[hob] HOB list did not terminate with an END_OF_HOB_LIST HOB (possibly truncated)')
            self._publish_decoded_registers()
        return (self.found, self.hob_pa, self.hobs)

    def _publish_decoded_registers(self) -> None:
        """Add decoded HOB registers to the platform hierarchy as VID.<IP>.NAME."""
        instances: Dict[str, int] = {}
        for hob in self.hobs:
            reg = hob.register
            if reg is None:
                continue
            # The first decoded HOB replaces the definition placeholder (instance None)
            count = instances.get(reg.name, 0)
            reg.instance = None if count == 0 else count
            instances[reg.name] = count + 1
            try:
                vendor = self.cs.Cfg.platform.get_vendor(reg.vid_str)
                vendor.get_ip(reg.ip_name).add_register(reg.name.upper(), [reg])
            except PlatformConfigError:
                self.logger.log_hal(f'[hob] Could not publish {reg.name} under {reg.vid_str}.{reg.ip_name}')

    def dump_HOB_list(self, hob_type: Optional[int] = None, guid: Optional[str] = None) -> None:
        """
        Log the HOB list, optionally limited to a HOB type and/or a GUID.

        Args:
            hob_type: EFI_HOB_TYPE value to report, or None for every type.
            guid: Full or partial GUID to report, or None for every GUID.
        """
        if not self.found:
            self.logger.log('[hob] HOB list not found')
            return
        hobs = self.filter_HOBs(hob_type, guid)
        self.logger.log(f'[hob] HOB list at 0x{self.hob_pa:016X} ({len(self.hobs):d} HOBs, '
                        f'{"complete" if self.complete else "INCOMPLETE"}){self._filter_str(hob_type, guid)}:')
        for hob in hobs:
            self.logger.log(str(hob))

    def _filter_str(self, hob_type: Optional[int], guid: Optional[str]) -> str:
        """Describe an active filter for log headers."""
        parts = []
        if hob_type is not None:
            parts.append(f'type=0x{hob_type:04X}')
        if guid:
            parts.append(f'guid~{guid}')
        return f' matching {", ".join(parts)}' if parts else ''

    def filter_HOBs(self, hob_type: Optional[int] = None, guid: Optional[str] = None) -> List[Hob]:
        """
        Select HOBs matching an optional type and/or GUID.

        Args:
            hob_type: EFI_HOB_TYPE value to match, or None to match every type.
            guid: Full or partial GUID string matched (case-insensitively) against the
                GUID-valued fields of each HOB, or None to match every HOB.

        Returns:
            A list of matching HOBs, in HOB list order.
        """
        if not self.found:
            return []
        hobs = self.hobs
        if hob_type is not None:
            hobs = [hob for hob in hobs if hob.HobType == hob_type]
        if guid:
            pattern = guid.strip().strip('{}').upper()
            hobs = [hob for hob in hobs if self._matches_guid(hob, pattern)]
        return hobs

    def _matches_guid(self, hob: Hob, pattern: str) -> bool:
        """Check a HOB's GUID-valued fields for a full or partial GUID match."""
        for field in HOB_GUID_FIELDS:
            value = hob.fields.get(field)
            if value and isinstance(value, str) and pattern in value.upper():
                return True
        return False

    def search_HOBs_by_type(self, hob_type: int) -> List[Hob]:
        """
        Search the HOB list for HOBs of a specific type.

        Args:
            hob_type: The EFI_HOB_TYPE value to search for.

        Returns:
            A list of HOBs matching the specified type.
        """
        if not self.found:
            return []
        return [hob for hob in self.hobs if hob.HobType == hob_type]

    def search_guid_ext_HOBs(self, guid: str) -> List[Hob]:
        """
        Search the HOB list for GUID extension HOBs with a specific GUID.

        Args:
            guid: The GUID to search for, matched exactly and case-sensitively
                against the HOB's GUID field. Use filter_HOBs() for partial matches.

        Returns:
            A list of GUID extension HOBs whose GUID is the requested GUID.
        """
        guidexthobs = self.search_HOBs_by_type(EFI_HOB_TYPE_GUID_EXTENSION)
        return [hob for hob in guidexthobs if guid == hob.fields.get('GUID')]

    def get_HOB_definition(self, name_or_guid: str) -> Optional[HobDefinition]:
        """
        Get an XML-declared HOB definition by name or GUID.

        Args:
            name_or_guid: Definition name (e.g. 'PEI_PCD_DATABASE') or its GUID.

        Returns:
            The HobDefinition, or None if no definition has been declared.
        """
        return self.definitions.get_definition(name_or_guid)

    def decode_HOB(self, hob: Hob) -> Optional[Dict[str, object]]:
        """
        Get the decoded fields of a HOB that was matched to a declared definition.

        Args:
            hob: A HOB from the parsed list.

        Returns:
            A dict of field name -> value, or None if the HOB was not decoded.
        """
        return hob.register.get_decoded() if hob.register is not None else None

    def get_list_by_name(self, name: str) -> ObjList:
        """
        Get the decoded register objects for a declared definition.

        Args:
            name: Definition name declared in XML ('PEI_PCD_DATABASE') or a scoped
                register name ('HOB.PEI_PCD_DATABASE' or '8086.HOB.PEI_PCD_DATABASE').
                Any leading scope is matched against the register's IP and vendor.

        Returns:
            An ObjList of HobRegister objects, one per matching HOB in the list, so
            the standard register list helpers (read, get_field, filter_*) apply.
        """
        parts = name.upper().split('.')
        reg_name = parts[-1]
        ip_name = parts[-2] if len(parts) >= 2 else ''
        vid_str = parts[-3] if len(parts) >= 3 else ''
        registers = ObjList()
        for hob in self.hobs:
            reg = hob.register
            if reg is None or reg.name.upper() != reg_name:
                continue
            if ip_name and reg.ip_name.upper() != ip_name:
                continue
            if vid_str and reg.vid_str.upper() != vid_str:
                continue
            registers.append(reg)
        return registers

    def decode_HOBs_by_name(self, name: str) -> List[Dict[str, object]]:
        """
        Decode every HOB in the list matching a declared definition.

        Args:
            name: Definition name declared in XML ('PEI_PCD_DATABASE') or a scoped
                register name ('8086.HOB.PEI_PCD_DATABASE').

        Returns:
            A list of decoded field dicts, one per matching HOB.
        """
        registers = self.get_list_by_name(name)
        if not registers and self.definitions.get_by_name(name.split('.')[-1]) is None:
            self.logger.log_hal(f'[hob] No HOB definition declared for {name}')
        return [reg.get_decoded() for reg in registers]


haldata = {"arch": [hal_base.HALBase.MfgIds.Any], 'name': {'hob': "HOB"}}
