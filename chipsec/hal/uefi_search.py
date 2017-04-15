#!/usr/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2016, Intel Corporation
# 
#This program is free software; you can redistribute it and/or
#modify it under the terms of the GNU General Public License
#as published by the Free Software Foundation; Version 2.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with this program; if not, write to the Free Software
#Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
#Contact information:
#chipsec@intel.com
#



# -------------------------------------------------------------------------------
#
# CHIPSEC: Platform Hardware Security Assessment Framework
#
# -------------------------------------------------------------------------------

"""
UEFI image search auxilliary functionality

usage:
   >>> chipsec.hal.uefi_search.check_match_criteria(efi_module, match_criteria, self.logger)
"""

__version__ = '1.0'

import re
import binascii

from chipsec import defines
from chipsec.hal.spi_uefi import *

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
#      "rktX_rule1" : { "guid": "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX" },
#      "rktX_rule2" : { "name": "rootkitX.efi" }
#    }
#  },
#
#  "UEFI_vulnerabilityX": {
#    "description": "yet another UEFI vulnerability X",
#    "match": {
#      "vulnX_rule1": { "guid": "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX", "regexp": "IAMVULNERABLE" },
#      "vulnX_rule2": { "md5": "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", "sha1": "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" }
#    },
#    "exclude": {
#      "vulnX_patched": { "md5": "HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH", "sha1": "HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH" }
#    }
#  }
#
# Above example results in a match if the following EFI binary is found:
# - with GUID "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
# OR
# - with name "module0" AND contains a byte sequence matching regular expression "blah"
# OR
# - with MD5 hash "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" AND SHA-1 hash "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
# Unless it's a EFI binary:
# - with MD5 hash "HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH" AND SHA-1 hash "HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH"
#
MATCH_NAME        = 0x1
MATCH_GUID        = (0x1 << 1)
MATCH_REGEXP      = (0x1 << 2)
MATCH_HASH_MD5    = (0x1 << 3)
MATCH_HASH_SHA1   = (0x1 << 4)
MATCH_HASH_SHA256 = (0x1 << 5)

def check_rules( efi, rules, entry_name, _log, bLog=True ):
    bfound = False
    for rule_name in rules.keys():
        what = None
        offset = 0
        match_mask   = 0x00000000
        match_result = 0x00000000
        fname = "%s.%s" % (entry_name,rule_name)
        rule = rules[rule_name]
        #
        # Determine which criteria are defined in the current rule
        #
        if ('name'   in rule) and (rule['name']   != ''): match_mask |= MATCH_NAME
        if ('guid'   in rule) and (rule['guid']   != ''): match_mask |= MATCH_GUID
        if ('regexp' in rule) and (rule['regexp'] != ''): match_mask |= MATCH_REGEXP
        if ('md5'    in rule) and (rule['md5']    != ''): match_mask |= MATCH_HASH_MD5
        if ('sha1'   in rule) and (rule['sha1']   != ''): match_mask |= MATCH_HASH_SHA1
        if ('sha256' in rule) and (rule['sha256'] != ''): match_mask |= MATCH_HASH_SHA256
        #
        # Check criteria defined in the current rule against the current EFI module
        #
        if (match_mask & MATCH_NAME) == MATCH_NAME:
            if efi.ui_string == rule['name']: match_result |= MATCH_NAME
        if (match_mask & MATCH_GUID) == MATCH_GUID:
            if (type(efi) is EFI_SECTION and efi.parentGuid == rule['guid']) or \
               (efi.Guid == rule['guid']): match_result |= MATCH_GUID
        if (match_mask & MATCH_REGEXP) == MATCH_REGEXP:
            m = re.compile(rule['regexp']).search( efi.Image )
            if m:
                match_result |= MATCH_REGEXP
                _str = m.group(0)
                what = "bytes '%s'%s" % (binascii.hexlify(_str), " ('%s')" % _str if defines.is_printable(_str) else '')
                offset = m.start()
        if (match_mask & MATCH_HASH_MD5) == MATCH_HASH_MD5:
            if efi.MD5 == rule['md5']: match_result |= MATCH_HASH_MD5
        if (match_mask & MATCH_HASH_SHA1) == MATCH_HASH_SHA1:
            if efi.SHA1 == rule['sha1']: match_result |= MATCH_HASH_SHA1
        if (match_mask & MATCH_HASH_SHA256) == MATCH_HASH_SHA256:
            if efi.SHA256 == rule['sha256']: match_result |= MATCH_HASH_SHA256

        brule_match = ((match_result & match_mask) == match_mask)
        if brule_match and bLog:
            _log.log_important( "match '%s'" % fname )
            if (match_result & MATCH_NAME       ) == MATCH_NAME       : _log.log( "    name  : '%s'" % rule['name'] )
            if (match_result & MATCH_GUID       ) == MATCH_GUID       : _log.log( "    GUID  : {%s}" % rule['guid'] )
            if (match_result & MATCH_REGEXP     ) == MATCH_REGEXP     : _log.log( "    regexp: bytes '%s' at offset %Xh" % (what,offset) )
            if (match_result & MATCH_HASH_MD5   ) == MATCH_HASH_MD5   : _log.log( "    MD5   : %s" % rule['md5'] )
            if (match_result & MATCH_HASH_SHA1  ) == MATCH_HASH_SHA1  : _log.log( "    SHA1  : %s" % rule['sha1'] )
            if (match_result & MATCH_HASH_SHA256) == MATCH_HASH_SHA256: _log.log( "    SHA256: %s" % rule['sha256'] )
        #
        # Rules are OR'ed unless matching rule is explicitly excluded from match
        #
        bfound = bfound or brule_match

    return bfound

def check_match_criteria(efi, criteria, _log):
    bfound = False
    if _log is None: _log = logger()
    _log.log("[uefi] checking %s" % efi.name())
    for k in criteria.keys():
        entry = criteria[k]
        # Check if the EFI binary is a match
        if 'match' in entry:
            bmatch = check_rules(efi, entry['match'], k, _log)
            if bmatch:
                _log.log_important("found EFI binary matching '%s'" % k)
                if 'description' in entry: _log.log("    %s" % entry['description'])
                _log.log(efi)
                # Check if the matched binary should be excluded
                # There's no point in checking a binary against exclusions if it wasn't a match
                if 'exclude' in entry:
                    if check_rules(efi, entry['exclude'], "%s.exclude" % k, _log):
                        _log.log_important("matched EFI binary is excluded from '%s'. Skipping..." % k)
                        continue
            # we are here if the matched binary wasn't excluded
            # the binary is a final match if it matches either of search entries
            bfound = bfound or bmatch

    return bfound
