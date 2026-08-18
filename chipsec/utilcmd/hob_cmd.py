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
The hob command provides access to the PI Hand-Off Block (HOB) list.

The HOB list is only resident in memory while running in the EFI environment.

Both list and dump accept optional filters: a HOB type (EFI_HOB_TYPE value) and a
full or partial GUID matched against the GUID fields of each HOB.

The read subcommand reports every HOB matching an XML-declared definition, decoded
into its named fields.

>>> chipsec_util hob list [<type>] [<guid>]
>>> chipsec_util hob dump [<type>] [<guid>]
>>> chipsec_util hob read <register>

HOB types (EFI_HOB_TYPE):

    0x0001  HANDOFF (PHIT)          0x0008  FV2
    0x0002  MEMORY_ALLOCATION       0x0009  LOAD_PEIM_UNUSED
    0x0003  RESOURCE_DESCRIPTOR     0x000A  UEFI_CAPSULE
    0x0004  GUID_EXTENSION          0x000B  FV3
    0x0005  FV                      0xFFFE  UNUSED
    0x0006  CPU                     0xFFFF  END_OF_HOB_LIST
    0x0007  MEMORY_POOL

Examples:

>>> chipsec_util hob list
>>> chipsec_util hob list 0x4
>>> chipsec_util hob list 0x4 EA296D92-0B69-423C-8C28-33B4E0A91268
>>> chipsec_util hob list 0 EA296D92
>>> chipsec_util hob dump
>>> chipsec_util hob dump 0x5
>>> chipsec_util hob read 8086.HOB.PEI_PCD_DATABASE
>>> chipsec_util hob read PEI_PCD_DATABASE
"""

import os
from argparse import ArgumentParser

from chipsec.command import BaseCommand, toLoad
from chipsec.library.file import write_file


# PI Hand-Off Block (HOB) list
class HOBCommand(BaseCommand):

    hob_type = None     # optional EFI_HOB_TYPE filter, set by parse_arguments
    guid = None         # optional full or partial GUID filter, set by parse_arguments
    register = ''       # register name to read, set by parse_arguments

    def requirements(self) -> toLoad:
        return toLoad.All

    def parse_arguments(self) -> None:
        parser = ArgumentParser(prog='chipsec_util hob', usage=__doc__)
        subparsers = parser.add_subparsers()

        # list command args
        parser_list = subparsers.add_parser('list')
        self._add_filter_args(parser_list)
        parser_list.set_defaults(func=self.hob_list)

        # dump command args
        parser_dump = subparsers.add_parser('dump')
        self._add_filter_args(parser_dump)
        parser_dump.set_defaults(func=self.hob_dump)

        # read command args
        parser_read = subparsers.add_parser('read')
        parser_read.add_argument('register', type=str,
                                 help='HOB definition name, optionally scoped (e.g. 8086.HOB.PEI_PCD_DATABASE)')
        parser_read.set_defaults(func=self.hob_read)

        parser.parse_args(self.argv, namespace=self)

    def _add_filter_args(self, subparser) -> None:
        subparser.add_argument('hob_type', type=lambda x: int(x, 0), nargs='?', default=None,
                               help='EFI_HOB_TYPE value to filter on (e.g. 0x4)')
        subparser.add_argument('guid', type=str, nargs='?', default=None,
                               help='full or partial GUID to filter on')

    def _check_efi(self) -> None:
        if not self.cs.os_helper.is_efi():
            self.logger.log_warning("[CHIPSEC] Not running in EFI environment. Not all HOBs may be available.")

    def hob_list(self) -> None:
        self._check_efi()
        self.logger.log("[CHIPSEC] Searching memory for and dumping EFI HOB list (this may take a minute)..\n")
        self.cs.hals.hob.dump_HOB_list(self.hob_type, self.guid)

    def hob_read(self) -> None:
        self._check_efi()
        hob_hal = self.cs.hals.hob
        registers = hob_hal.get_list_by_name(self.register)
        if not registers:
            if hob_hal.get_HOB_definition(self.register.split('.')[-1]) is None:
                self.logger.log_important(f"[CHIPSEC] No HOB definition declared for '{self.register}'. Exit..")
            else:
                self.logger.log_important(f"[CHIPSEC] No HOBs found matching '{self.register}'. Exit..")
            return
        self.logger.log(f"[CHIPSEC] Found {len(registers):d} HOB(s) matching '{self.register}':\n")
        for reg in registers:
            self.logger.log(f'[0x{reg.address:016X}]')
            self.logger.log(str(reg))
            self.logger.log('')

    def hob_dump(self) -> None:
        self._check_efi()
        self.logger.log("[CHIPSEC] Searching memory for and dumping EFI HOB list (this may take a minute)..")
        hob_hal = self.cs.hals.hob
        if not hob_hal.found:
            self.logger.log_important("[CHIPSEC] Could not locate the EFI HOB list. Exit..")
            return
        hobs = hob_hal.filter_HOBs(self.hob_type, self.guid)
        if not hobs:
            self.logger.log_important("[CHIPSEC] No HOBs matched the requested filter. Exit..")
            return
        _orig_logname = self.logger.LOG_FILE_NAME
        hob_pth = 'efi_hobs.dir'
        try:
            self.logger.set_log_file('efi_hobs.lst', False)
            os.makedirs(hob_pth, exist_ok=True)
            self.logger.log(f'[hob] HOB list at 0x{hob_hal.hob_pa:016X} ({len(hobs):d} HOBs):')
            for idx, hob in enumerate(hobs):
                self.logger.log(str(hob))
                safe_name = ''.join(c if c.isalnum() else '_' for c in hob.type_name)
                hob_fname = os.path.join(hob_pth, f'hob_{idx:04d}_0x{hob.HobType:04X}_{safe_name}_0x{hob.address:016X}.bin')
                write_file(hob_fname, hob.raw)
        finally:
            self.logger.set_log_file(_orig_logname)
        self.logger.log("[CHIPSEC] HOBs are in efi_hobs.lst log and efi_hobs.dir directory")


commands = {'hob': HOBCommand}
