# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2021, Intel Corporation
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


# -------------------------------------------------------------------------------
#
# CHIPSEC: Platform Hardware Security Assessment Framework
#
# -------------------------------------------------------------------------------

"""
UEFI image search auxillary functionality

usage:
   >>> chipsec.hal.uefi_search.check_match_criteria(efi_module, match_criteria, self.logger)
"""

import re
from uuid import UUID
from typing import Dict, Callable, Optional, Any

from chipsec.library import defines
from chipsec.hal.spi_uefi import EFI_SECTION
from chipsec.library.logger import logger

#
# - EFI binaries are searched according to criteria defined by "match" rules.
# - EFI binaries matching exclusion criteria defined by "exclude" rules are excluded from matching.
#
# Format of the matching rules (any field can be empty or missing):
# - Individual rules are OR'ed
# - criteria within a given rule are AND'ed
#
# Example:
#
#  "UEFI_rootkitX": {
#    "description": "yet another UEFI implant X",
#    "match": {
#      "rktX_rule1" : { "guid": "12345678-XXXX-XXXX-XXXX-XXXXXXXXXXXX" },
#      "rktX_rule2" : { "name": "rootkitX.efi" }
#    }
#  }
#
# Above UEFI_rootkitX example results in a match if the following EFI binary is found:
# - with GUID "12345678-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
# OR
# - with Name "rootkitX.efi"
#
#
#  "UEFI_vulnerabilityX": {
#    "description": "yet another UEFI vulnerability X",
#    "match": {
#      "vulnX_rule1": { "guid": "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX", "regexp": "IAMVULNERABLE" },
#      "vulnX_rule2": { "md5": "aabbccddeeffgghhiijjkkllmmnnoopp", "sha1": "aabbccddeeffgghhiijjkkllmmnnooppqqrrsstt" }
#    },
#    "exclude": {
#      "vulnX_patched": { "md5": "HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH", "sha1": "HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH" }
#    }
#  }
#
# Above UEFI_vulnerabilityX example results in a match if the following EFI binary is found:
# - with GUID "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX" AND contains a byte sequence matching regular expression "IAMVULNERABLE"
# OR
# - with MD5 hash "aabbccddeeffgghhiijjkkllmmnnoopp" AND SHA-1 hash "aabbccddeeffgghhiijjkkllmmnnooppqqrrsstt"
# Unless it's a EFI binary:
# - with MD5 hash "HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH" AND SHA-1 hash "HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH"
#
#
# "UEFI_vulnerabilityY": {
#     "description": "Something else to be scared of!",
#     "match": {
#       "vulnY_rule1": {"guid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "cpuid": "12345,abcde" }
#     }
#   }
#
# Above UEFI_vulnerabilityY example results in a match if the following EFI binary is found:
# - with GUID "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" AND if the binary is dumped from a live system, check's the system's CPUID to see if it matches one in the list "12345,abcde"
#
MATCH_NAME = 0x1
MATCH_GUID = (0x1 << 1)
MATCH_REGEXP = (0x1 << 2)
MATCH_HASH_MD5 = (0x1 << 3)
MATCH_HASH_SHA1 = (0x1 << 4)
MATCH_HASH_SHA256 = (0x1 << 5)
MATCH_CPUID = (0x1 << 6)


def check_rules(efi: EFI_SECTION, rules: Dict[str, Any], entry_name: str, _log: Callable, bLog: bool = True, cpuid: Optional[str] = None) -> bool:
    bfound = False
    for name, rule in rules.items():
        what = None
        cpuidwhat = None
        offset = 0
        match_mask = 0x00000000
        match_result = 0x00000000
        fname = f'{entry_name}.{name}'
        #
        # Determine which criteria are defined in the current rule
        #
        if ('name' in rule) and (rule['name'] != ''):
            match_mask |= MATCH_NAME
        if ('guid' in rule) and (rule['guid'] != ''):
            match_mask |= MATCH_GUID
            if type(rule['guid']) == str:
                rule['guid'] = UUID(rule['guid'])
        if ('regexp' in rule) and (rule['regexp'] != ''):
            match_mask |= MATCH_REGEXP
        if ('md5' in rule) and (rule['md5'] != ''):
            match_mask |= MATCH_HASH_MD5
        if ('sha1' in rule) and (rule['sha1'] != ''):
            match_mask |= MATCH_HASH_SHA1
        if ('sha256' in rule) and (rule['sha256'] != ''):
            match_mask |= MATCH_HASH_SHA256
        if ('cpuid' in rule) and (rule['cpuid'] != ''):
            match_mask |= MATCH_CPUID
        #
        # Check criteria defined in the current rule against the current EFI module
        #
        if (match_mask & MATCH_NAME) == MATCH_NAME:
            if efi.ui_string == rule['name']:
                match_result |= MATCH_NAME
        if (match_mask & MATCH_GUID) == MATCH_GUID:
            if (type(efi) is EFI_SECTION and efi.parentGuid == rule['guid']) or \
               (efi.Guid == rule['guid']):
                match_result |= MATCH_GUID
        if (match_mask & MATCH_REGEXP) == MATCH_REGEXP:
            m = re.compile(bytes(rule['regexp'], 'utf-8')).search(efi.Image)
            if m:
                match_result |= MATCH_REGEXP
                _str = m.group(0)
                hexver = _str.hex()
                printver = f" ('{_str}')" if defines.is_printable(_str) else ''
                what = f"bytes '{hexver}'{printver}"
                offset = m.start()
        if (match_mask & MATCH_HASH_MD5) == MATCH_HASH_MD5:
            if efi.MD5 == rule['md5']:
                match_result |= MATCH_HASH_MD5
        if (match_mask & MATCH_HASH_SHA1) == MATCH_HASH_SHA1:
            if efi.SHA1 == rule['sha1']:
                match_result |= MATCH_HASH_SHA1
        if (match_mask & MATCH_HASH_SHA256) == MATCH_HASH_SHA256:
            if efi.SHA256 == rule['sha256']:
                match_result |= MATCH_HASH_SHA256
        if (match_mask & MATCH_CPUID) == MATCH_CPUID:
            if cpuid is None:
                cpuidwhat = f"Unable to identify platform. Check system's CPUID and compare it against list:\n\t\t{rule['cpuid']}"
                match_result |= MATCH_CPUID
            else:
                cpuids = rule['cpuid'].upper().split(',')
                if f'{cpuid:X}' in cpuids:
                    cpuidwhat = f'{cpuid:X}'
                    match_result |= MATCH_CPUID

        brule_match = ((match_result & match_mask) == match_mask)
        if brule_match and bLog:
            _log.log_important(f"match '{fname}'")
            if (match_result & MATCH_NAME) == MATCH_NAME:
                _log.log(f"\tname  : '{rule['name']}'")
            if (match_result & MATCH_GUID) == MATCH_GUID:
                _log.log(f"\tGUID  : {{{rule['guid']}}}")
            if (match_result & MATCH_REGEXP) == MATCH_REGEXP:
                _log.log(f"\tregexp: bytes '{what}' at offset {offset:X}h")
            if (match_result & MATCH_HASH_MD5) == MATCH_HASH_MD5:
                _log.log(f"\tMD5   : {rule['md5']}")
            if (match_result & MATCH_HASH_SHA1) == MATCH_HASH_SHA1:
                _log.log(f"\tSHA1  : {rule['sha1']}")
            if (match_result & MATCH_HASH_SHA256) == MATCH_HASH_SHA256:
                _log.log(f"\tSHA256: {rule['sha256']}")
            if (match_result & MATCH_CPUID) == MATCH_CPUID:
                _log.log(f"\tCPUID: {cpuidwhat}")
        #
        # Rules are OR'ed unless matching rule is explicitly excluded from match
        #
        bfound = bfound or brule_match

    return bfound


def check_match_criteria(efi: EFI_SECTION, criteria: Dict[str, Dict[str, Dict[str, str]]], _log: Callable, cpuid: Optional[str] = None) -> bool:
    bfound = False
    if _log is None:
        _log = logger()
    _log.log(f'[uefi] Checking {efi.name()}')
    for k in criteria.keys():
        entry = criteria[k]
        # Check if the EFI binary is a match
        if 'match' in entry:
            bmatch = check_rules(efi, entry['match'], k, _log, cpuid=cpuid)
            if bmatch:
                _log.log_important(f"found EFI binary matching '{k}'")
                if 'description' in entry:
                    _log.log(f"    {entry['description']}")
                _log.log(str(efi))
                # Check if the matched binary should be excluded
                # There's no point in checking a binary against exclusions if it wasn't a match
                if 'exclude' in entry:
                    if check_rules(efi, entry['exclude'], f'{k}.exclude', _log, cpuid=cpuid):
                        _log.log_important(f"matched EFI binary is excluded from '{k}'. Skipping...")
                        continue
            # we are here if the matched binary wasn't excluded
            # the binary is a final match if it matches either of search entries
            bfound = bfound or bmatch

    return bfound
