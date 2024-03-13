# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2017-2021, Intel Security
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
# Authors:
#   Yuriy Bulygin
#   Alex Bazhaniuk
#

"""
The module can generate a list of EFI executables from (U)EFI firmware file or
extracted from flash ROM, and then later check firmware image in flash ROM or
file against this list of expected executables

Usage:
  ``chipsec_main -m tools.uefi.scan_image [-a generate|check,<json>,<fw_image>]``
    - ``generate``	Generates a list of EFI executable binaries from the UEFI
                        firmware image (default)
    - ``check``		Decodes UEFI firmware image and checks all EFI executable
                        binaries against a specified list
    - ``json``		JSON file with configuration of allowed list EFI
                        executables (default = ``efilist.json``)
    - ``fw_image``	Full file path to UEFI firmware image. If not specified,
                        the module will dump firmware image directly from ROM

Examples:

>>> chipsec_main -m tools.uefi.scan_image

Creates a list of EFI executable binaries in ``efilist.json`` from the firmware
image extracted from ROM

>>> chipsec_main -i -n -m tools.uefi.scan_image -a generate,efilist.json,uefi.rom

Creates a list of EFI executable binaries in ``efilist.json`` from ``uefi.rom``
firmware binary

>>> chipsec_main -i -n -m tools.uefi.scan_image -a check,efilist.json,uefi.rom

Decodes ``uefi.rom`` UEFI firmware image binary and checks all EFI executables
in it against a list defined in ``efilist.json``

.. note::
    - ``-i`` and ``-n`` arguments can be used when specifying firmware file
      because the module doesn't depend on the platform and doesn't need kernel driver
"""

import json
import os

from chipsec.module_common import BaseModule, MTAG_BIOS
from chipsec.library.returncode import ModuleResult

from chipsec.hal.uefi import UEFI
from chipsec.hal.spi import SPI, BIOS
from chipsec.hal.uefi_fv import EFI_MODULE, EFI_SECTION, SECTION_NAMES, EFI_SECTION_PE32
from chipsec.hal.spi_uefi import build_efi_model, search_efi_tree, EFIModuleType, UUIDEncoder
from chipsec.library.file import write_file, read_file

TAGS = [MTAG_BIOS]

DEF_FWIMAGE_FILE = 'fw.bin'
DEF_EFILIST_FILE = 'efilist.json'


class scan_image(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)
        self.uefi = UEFI(self.cs)
        self.image = None
        self.efi_list = {}
        self.suspect_modules = {}
        self.duplicate_list = []

    def is_supported(self):
        return True

    #
    # callbacks to uefi_search.check_match_criteria
    #
    def genlist_callback(self, efi_module: EFI_MODULE) -> None:
        md = {}
        if type(efi_module) == EFI_SECTION:
            if efi_module.SHA256:
                md["sha1"] = efi_module.SHA1
            if efi_module.parentGuid:
                md["guid"] = efi_module.parentGuid
            if efi_module.ui_string:
                md["name"] = efi_module.ui_string
            if efi_module.Name and efi_module.Name != SECTION_NAMES[EFI_SECTION_PE32]:
                md["type"] = efi_module.Name
            if efi_module.SHA256 in self.efi_list.keys():
                self.duplicate_list.append(efi_module.SHA256)
            else:
                self.efi_list[efi_module.SHA256] = md
        else:
            pass

    #
    # Generates new list of EFI executable binaries
    #
    def generate_efilist(self, json_pth: str) -> int:
        self.logger.log("[*] Generating a list of EFI executables from firmware image...")
        efi_tree = build_efi_model(self.image, None)
        search_efi_tree(efi_tree, self.genlist_callback, EFIModuleType.SECTION_EXE, True)
        self.logger.log(f'[*] Found {len(self.efi_list):d} EFI executables in UEFI firmware image \'{self.image_file}\'')
        self.logger.log(f'[*] Found {len(self.duplicate_list)} duplicate executables')
        self.logger.log_verbose(f'\t{chr(10).join(i for i in self.duplicate_list)}')
        self.logger.log(f'[*] Creating JSON file \'{json_pth}\'...')
        write_file(f'{json_pth}', json.dumps(self.efi_list, indent=2, separators=(',', ': '), cls=UUIDEncoder))
        return ModuleResult.PASSED

    #
    # Checks EFI executable binaries against allowed list
    #
    def check_list(self, json_pth: str) -> int:
        with open(json_pth) as data_file:
            self.efilist = json.load(data_file)

        self.logger.log(f'[*] Checking EFI executables against the list \'{json_pth}\'')

        # parse the UEFI firmware image and look for EFI modules matching list
        # - match only executable EFI sections (PE/COFF, TE)
        # - find all occurrences of matching EFI modules
        efi_tree = build_efi_model(self.image, None)
        search_efi_tree(efi_tree, self.genlist_callback, EFIModuleType.SECTION_EXE, True)
        self.logger.log(f'[*] Found {len(self.efi_list):d} EFI executables in UEFI firmware image \'{self.image_file}\'')

        for m in self.efi_list:
            if not (m in self.efilist):
                self.suspect_modules[m] = self.efi_list[m]
                guid = self.efi_list[m]["guid"] if 'guid' in self.efi_list[m] else '?'
                name = self.efi_list[m]["name"] if 'name' in self.efi_list[m] else '<unknown>'
                sha1 = self.efi_list[m]["sha1"] if 'sha1' in self.efi_list[m] else ''
                self.logger.log_important(f'Found EFI executable not in the list:\n    {m} (sha256)\n    {sha1} (sha1)\n    {{{guid}}}\n    {name}')

        if len(self.suspect_modules) > 0:
            self.logger.log_warning(f'Found {len(self.suspect_modules):d} EFI executables not in the list \'{json_pth}\'')
            return ModuleResult.WARNING
        else:
            self.logger.log_passed(f'All EFI executables match the list \'{json_pth}\'')
            return ModuleResult.PASSED

    def usage(self):
        self.logger.log(__doc__.replace('`', ''))

    def run(self, module_argv):
        self.logger.start_test("Simple list generation/checking for (U)EFI firmware")

        self.res = ModuleResult.NOTAPPLICABLE

        op = module_argv[0] if len(module_argv) > 0 else 'generate'

        if op in ['generate', 'check']:

            if len(module_argv) <= 2:
                self.usage()
                return self.res
            elif len(module_argv) > 2:
                json_file = module_argv[1]
                image_file = module_argv[2]
                self.logger.log(f'[*] Reading firmware from \'{image_file}\'...')
            else:
                image_file = DEF_FWIMAGE_FILE
                json_file = DEF_EFILIST_FILE
                self.spi = SPI(self.cs)
                (base, limit, _) = self.spi.get_SPI_region(BIOS)
                image_size = limit + 1 - base
                self.logger.log(f'[*] Dumping firmware image from ROM to \'{image_file}\': 0x{image_size:08X} bytes at [0x{base:08X}:0x{limit:08X}]')
                self.spi.read_spi_to_file(base, image_size, image_file)

            self.image_file = image_file
            self.image = read_file(image_file)
            json_pth = os.path.abspath(json_file)

            if op == 'generate':
                if os.path.exists(json_pth):
                    self.logger.log_error(f'JSON file \'{json_file}\' already exists. Exiting...')
                    self.res = ModuleResult.ERROR
                else:
                    self.res = self.generate_efilist(json_pth)
            elif op == 'check':
                if not os.path.exists(json_pth):
                    self.logger.log_error(f'JSON file \'{json_file}\' doesn\'t exist. Exiting...')
                    self.res = ModuleResult.ERROR
                else:
                    self.res = self.check_list(json_pth)

        elif op == 'help':
            self.usage()
        else:
            self.logger.log_error("Unrecognized command-line argument to the module")
            self.usage()

        return self.res
