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


"""
This module checks current contents of UEFI firmware ROM or specified firmware image for black-listed EFI binaries
which can be EFI firmware volumes, EFI executable binaries (PEI modules, DXE drivers..) or EFI sections.
The module can find EFI binaries by their UI names, EFI GUIDs, MD5/SHA-1/SHA-256 hashes
or contents matching specified regular expressions.

Important! This module can only detect what it knows about from its config file.
If a bad or vulnerable binary is not detected then its 'signature' needs to be added to the config.

Usage:
  ``chipsec_main.py -i -m tools.uefi.blacklist [-a <fw_image>,<blacklist>]``
    - ``fw_image``	Full file path to UEFI firmware image. If not specified, the module will dump firmware image directly from ROM
    - ``blacklist``	JSON file with configuration of black-listed EFI binaries (default = ``blacklist.json``). Config file should be located in the same directory as this module
    
Examples:

>>> chipsec_main.py -m tools.uefi.blacklist 

Dumps UEFI firmware image from flash memory device, decodes it and checks for black-listed EFI modules defined in the default config ``blacklist.json``

>>> chipsec_main.py -i --no_driver -m tools.uefi.blacklist -a uefi.rom,blacklist.json

Decodes ``uefi.rom`` binary with UEFI firmware image and checks for black-listed EFI modules defined in ``blacklist.json`` config

Note: ``-i`` and ``--no_driver`` arguments can be used in this case because the test does not depend on the platform and no kernel driver is required when firmware image is specified
"""
import json

from chipsec.module_common import *

from chipsec.hal import spi_uefi
import chipsec.hal.uefi
import chipsec.hal.spi
import chipsec.hal.uefi_search

TAGS = [MTAG_BIOS]

DEF_FWIMAGE_FILE = 'fw.bin'

USAGE_TEXT = '''
Usage:

    chipsec_main.py -i -m tools.uefi.blacklist [-a <fw_image>,<blacklist>]

      fw_image  : Full file path to UEFI firmware image
                  If not specified, the module will dump firmware image directly from ROM
      blacklist : JSON file with configuration of black-listed EFI binaries (default = blacklist.json)
                  Config file should be located in the same directory as this module
    
Examples:

    chipsec_main.py -m tools.uefi.blacklist 

      Dumps UEFI firmware image from flash memory device, decodes it and
      checks for black-listed EFI modules defined in the default config 'blacklist.json'

    chipsec_main.py -i --no_driver -m tools.uefi.blacklist -a uefi.rom,blacklist.json

      Decodes 'uefi.rom' binary with UEFI firmware image and
      checks for black-listed EFI modules defined in 'blacklist.json' config

Important! This module can only detect what it knows about from its config file.
If a bad or vulnerable binary is not detected then its 'signature' needs to be added to the config.
'''

class blacklist(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)
        self.uefi = chipsec.hal.uefi.UEFI( self.cs )
        self.cfg_name = 'blacklist.json'
        self.image = None
        self.efi_blacklist = None

    def is_supported(self):
        return True

    def blacklist_callback(self, efi_module):
        return chipsec.hal.uefi_search.check_match_criteria(efi_module, self.efi_blacklist, self.logger)

    def check_blacklist( self ):
        res = ModuleResult.PASSED

        self.logger.log( "[*] searching for EFI binaries that match criteria from '%s':" % self.cfg_name )
        for k in self.efi_blacklist.keys():
            entry = self.efi_blacklist[k]
            self.logger.log( "    %-16s - %s" % (k,entry['description'] if 'description' in entry else '') )
            #if 'match' in entry:
            #    for c in entry['match'].keys(): self.logger.log( "[*]   %s" % entry['match'][c] )
            #if 'exclude' in entry:
            #    self.logger.log( "[*]   excluding binaries:" )
            #    for c in entry['exclude']: self.logger.log( "[*]   %s" % entry['exclude'][c] )

        # parse the UEFI firmware image and look for EFI modules matching the balck-list
        efi_tree = spi_uefi.build_efi_model(self.uefi, self.image, None)
        #match_types = (spi_uefi.EFIModuleType.SECTION_EXE|spi_uefi.EFIModuleType.FILE)
        match_types = spi_uefi.EFIModuleType.SECTION_EXE
        matching_modules = spi_uefi.search_efi_tree(efi_tree, self.blacklist_callback, match_types)
        found = len(matching_modules) > 0
        self.logger.log( '' )
        if found:
            res = ModuleResult.WARNING
            self.logger.log_warn_check("Black-listed EFI binary found in the UEFI firmware image")
        else:
            self.logger.log_passed_check("Didn't find any black-listed EFI binary")
        return res

    def usage(self):
        self.logger.log( USAGE_TEXT )


    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run( self, module_argv ):
        self.logger.start_test( "Check for black-listed EFI binaries in UEFI firmware" )

        self.usage()

        image_file = DEF_FWIMAGE_FILE
        if len(module_argv) == 0:
            # Read firmware image directly from SPI flash memory
            self.spi = chipsec.hal.spi.SPI( self.cs )
            (base,limit,freg) = self.spi.get_SPI_region( chipsec.hal.spi.BIOS )
            image_size = limit + 1 - base
            self.logger.log( "[*] dumping FW image from ROM to %s: 0x%08X bytes at [0x%08X:0x%08X]" % (image_file,base,limit,image_size) )
            self.logger.log( "[*] this may take a few minutes (instead, use 'chipsec_util spi dump')..." )
            self.spi.read_spi_to_file( base, image_size, image_file )
        elif len(module_argv) > 0:
            # Use provided firmware image 
            image_file = module_argv[0]
            self.logger.log( "[*] reading FW image from file: %s" % image_file )

        self.image = chipsec.file.read_file( image_file )

        # Load JSON config with black-listed EFI modules
        if len(module_argv) > 1: self.cfg_name = module_argv[1]
        cfg_pth = os.path.join( os.path.dirname(os.path.realpath(__file__)), self.cfg_name )
        with open(cfg_pth, 'r') as blacklist_json:
             self.efi_blacklist = json.load( blacklist_json )

        return self.check_blacklist()


