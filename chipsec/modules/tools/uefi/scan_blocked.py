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


"""
This module checks current contents of UEFI firmware ROM or specified firmware image for blocked EFI binaries
which can be EFI firmware volumes, EFI executable binaries (PEI modules, DXE drivers..) or EFI sections.
The module can find EFI binaries by their UI names, EFI GUIDs, MD5/SHA-1/SHA-256 hashes
or contents matching specified regular expressions.

Important! This module can only detect what it knows about from its config file.
If a bad or vulnerable binary is not detected then its 'signature' needs to be added to the config.

Usage:
  ``chipsec_main.py -i -m tools.uefi.scan_blocked [-a <fw_image>,<blockedlist>]``
    - ``fw_image``	Full file path to UEFI firmware image. If not specified, the module will dump firmware image directly from ROM
    - ``blockedlist``	JSON file with configuration of blocked EFI binaries (default = ``blockedlist.json``). Config file should be located in the same directory as this module

Examples:

    >>> chipsec_main.py -m tools.uefi.scan_blocked

Dumps UEFI firmware image from flash memory device, decodes it and checks for blocked EFI modules defined in the default config ``blockedlist.json``

    >>> chipsec_main.py -i --no_driver -m tools.uefi.scan_blocked -a uefi.rom,blockedlist.json

Decodes ``uefi.rom`` binary with UEFI firmware image and checks for blocked EFI modules defined in ``blockedlist.json`` config

.. note::
    - ``-i`` and ``--no_driver`` arguments can be used in this case because the test does not depend on the platform
      and no kernel driver is required when firmware image is specified

"""

import json
import os

from chipsec.module_common import BaseModule, MTAG_BIOS
from chipsec.library.returncode import ModuleResult
from chipsec.hal.spi_uefi import search_efi_tree, build_efi_model, EFIModuleType
from chipsec.hal.uefi import UEFI
from chipsec.hal.spi import SPI, BIOS
from chipsec.hal.uefi_search import check_match_criteria
from chipsec.library.file import read_file, get_main_dir

TAGS = [MTAG_BIOS]

DEF_FWIMAGE_FILE = 'fw.bin'


class scan_blocked(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)

        self.uefi = UEFI(self.cs)
        self.cfg_name = 'blockedlist.json'
        self.image = None
        self.efi_blockedlist = None
        self.cpuid = None

    def is_supported(self):
        return True

    def blockedlist_callback(self, efi_module):
        return check_match_criteria(efi_module, self.efi_blockedlist, self.logger, self.cpuid)

    def check_blockedlist(self):
        res = ModuleResult.PASSED

        self.logger.log(f'[*] Searching for EFI binaries that match criteria from \'{self.cfg_name}\':')
        for k in self.efi_blockedlist.keys():
            entry = self.efi_blockedlist[k]
            self.logger.log(f'    {k:16} - {entry["description"] if "description" in entry else ""}')

        # parse the UEFI firmware image and look for EFI modules matching the block-list
        efi_tree = build_efi_model(self.image, None)

        match_types = EFIModuleType.SECTION_EXE
        matching_modules = search_efi_tree(efi_tree, self.blockedlist_callback, match_types)
        found = len(matching_modules) > 0
        self.logger.log('')
        if found:
            res = ModuleResult.WARNING
            self.result.setStatusBit(self.result.status.VERIFY)
            self.logger.log_warning("Blocked EFI binary found in the UEFI firmware image")
        else:
            self.logger.log_passed("Didn't find any blocked EFI binary")
        return res

    def usage(self):
        self.logger.log(__doc__.replace('`', ''))

    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------

    def run(self, module_argv):
        self.logger.start_test("Check for blocked EFI binaries in UEFI firmware")

        self.usage()

        image_file = DEF_FWIMAGE_FILE
        if len(module_argv) == 0:
            # Read firmware image directly from SPI flash memory
            self.spi = SPI(self.cs)
            (base, limit, _) = self.spi.get_SPI_region(BIOS)
            image_size = limit + 1 - base
            self.logger.log(f'[*] Dumping FW image from ROM to {image_file}: 0x{base:08X} bytes at [0x{limit:08X}:0x{image_size:08X}]')
            self.logger.log("[*] This may take a few minutes (instead, use 'chipsec_util spi dump')...")
            self.spi.read_spi_to_file(base, image_size, image_file)
            self.cpuid = self.cs.get_cpuid()
        elif len(module_argv) > 0:
            # Use provided firmware image
            image_file = module_argv[0]
            self.logger.log(f'[*] Reading FW image from file: {image_file}')

        self.image = read_file(image_file)

        if not self.image:
            if len(module_argv) == 0:
                self.logger.log_important('Unable to read SPI and generate FW image. Access may be blocked.')
            self.logger.log_error('No FW image file to read.  Exiting!')
            self.result.setStatusBit(self.result.status.UNSUPPORTED_FEATURE)
            return self.result.getReturnCode(ModuleResult.ERROR)

        # Load JSON config with blocked EFI modules
        if len(module_argv) > 1:
            self.cfg_name = module_argv[1]
        cfg_pth = os.path.join(get_main_dir(), "chipsec/modules/tools/uefi", self.cfg_name)
        with open(cfg_pth, 'r') as blockedlist_json:
            self.efi_blockedlist = json.load(blockedlist_json)

        self.res = self.check_blockedlist()
        return self.result.getReturnCode(self.res)

