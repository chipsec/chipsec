#!/usr/local/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2014, Intel Corporation
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




## \addtogroup standalone
#chipsec_util uefi
#------
#~~~
#chipsec_util uefi var-list [output_file] [infcls]
#chipsec_util uefi var-read|var-write|var-delete <name> <GUID> <efi_variable_file>
#chipsec_util uefi nvram[-auth] <fw_type> [rom_file]
#chipsec_util uefi keys <keyvar_file>
#''
#    Examples:
#''
#        chipsec_util uefi var-list nvram.bin
#        chipsec_util uefi var-read db D719B2CB-3D3A-4596-A3BC-DAD00E67656F db.bin
#        chipsec_util uefi var-write db D719B2CB-3D3A-4596-A3BC-DAD00E67656F db.bin
#        chipsec_util uefi var-delete db D719B2CB-3D3A-4596-A3BC-DAD00E67656F
#        chipsec_util uefi nvram fwtype bios.rom
#        chipsec_util uefi nvram-auth fwtype bios.rom
#        chipsec_util uefi decode uefi.bin fwtype
#        chipsec_util uefi keys db.bin
#~~~
__version__ = '1.0'

import os
import sys
import time

import chipsec_util
from chipsec_util import chipsec_util_commands, _cs

from chipsec.logger     import *
from chipsec.file       import *

from chipsec.hal.uefi          import *
from chipsec.hal.spi_uefi      import *
#from chipsec.hal.uefi_platform import fw_types

#_cs  = cs()
_uefi = UEFI( _cs.helper )


usage = "chipsec_util uefi var-list\n" + \
        "chipsec_util uefi var-read|var-write|var-delete <name> <GUID> <efi_variable_file>\n" + \
        "chipsec_util uefi nvram[-auth] <fw_type> [rom_file]\n" + \
        "                  <fw_type> should be in [ %s ]\n" % (" | ".join( ["%s" % t for t in fw_types])) + \
        "chipsec_util uefi keys <keyvar_file>\n" + \
        "                  <keyvar_file> should be one of the following EFI variables\n" + \
        "                  [ %s ]\n" % (" | ".join( ["%s" % var for var in SECURE_BOOT_VARIABLES])) + \
        "Examples:\n" + \
        "  chipsec_util uefi var-list\n" + \
        "  chipsec_util uefi var-read db D719B2CB-3D3A-4596-A3BC-DAD00E67656F db.bin\n" + \
        "  chipsec_util uefi var-write db D719B2CB-3D3A-4596-A3BC-DAD00E67656F db.bin\n" + \
        "  chipsec_util uefi var-delete db D719B2CB-3D3A-4596-A3BC-DAD00E67656F\n" + \
        "  chipsec_util uefi nvram fwtype bios.rom\n" + \
        "  chipsec_util uefi nvram-auth fwtype bios.rom\n" + \
        "  chipsec_util uefi decode uefi.bin fwtype\n" + \
        "  chipsec_util uefi keys db.bin\n\n"

chipsec_util.global_usage += usage


# ###################################################################
#
# Unified Extensible Firmware Interface (UEFI)
#
# ###################################################################
def uefi(argv):

    if 3 > len(argv):
      print usage
      return

    op = argv[2]
    t = time.time()

    filename = None
    if ( 'var-read' == op ):

      if (4 < len(argv)):
         name = argv[3]
         guid = argv[4]
      if (5 < len(argv)):
         filename = argv[5]
      logger().log( "[CHIPSEC] Reading EFI variable Name='%s' GUID={%s} from '%s' via Variable API.." % (name, guid, filename) )
      var = _uefi.get_EFI_variable( name, guid, filename )

    elif ( 'var-write' == op ):

      if (5 < len(argv)):
         name = argv[3]
         guid = argv[4]
         filename = argv[5]
      else:
         print usage
         return
      logger().log( "[CHIPSEC] Writing EFI variable Name='%s' GUID={%s} from '%s' via Variable API.." % (name, guid, filename) )
      status = _uefi.set_EFI_variable_from_file( name, guid, filename )
      if status:
          logger().log( "[CHIPSEC] set_EFI_variable return SUCCESS status" )
      else:
          logger().error( "set_EFI_variable wasn't able to modify variable" )

    elif ( 'var-delete' == op ):

      if (4 < len(argv)):
         name = argv[3]
         guid = argv[4]
      else:
         print usage
         return
      logger().log( "[CHIPSEC] Deleting EFI variable Name='%s' GUID={%s} via Variable API.." % (name, guid) )
      status = _uefi.delete_EFI_variable( name, guid )
      if status: logger().log( "[CHIPSEC] delete_EFI_variable return SUCCESS status" )
      else:      logger().error( "delete_EFI_variable wasn't able to delete variable" )

    elif ( 'var-list' == op ):

      #infcls = 2
      #if (3 < len(argv)): filename = argv[3]
      #if (4 < len(argv)): infcls = int(argv[4],16)
      logger().log( "[CHIPSEC] Enumerating all EFI variables via OS specific EFI Variable API.." )
      efi_vars = _uefi.list_EFI_variables()
      if efi_vars is None:
          logger().log( "[CHIPSEC] Could not enumerate EFI Variables (Legacy OS?). Exit.." )
          return

      logger().log( "[CHIPSEC] Decoding EFI Variables.." )
      _orig_logname = logger().LOG_FILE_NAME
      logger().set_log_file( 'efi_variables.lst' )
      #print_sorted_EFI_variables( efi_vars )
      nvram_pth = 'efi_variables.dir'
      if not os.path.exists( nvram_pth ): os.makedirs( nvram_pth )
      decode_EFI_variables( efi_vars, nvram_pth )
      logger().set_log_file( _orig_logname )

      #efi_vars = _uefi.list_EFI_variables( infcls, filename )
      #_orig_logname = logger().LOG_FILE_NAME
      #logger().set_log_file( (filename + '.nv.lst') )
      #_uefi.parse_EFI_variables( filename, efi_vars, False, FWType.EFI_FW_TYPE_WIN )
      #logger().set_log_file( _orig_logname )

    elif ( 'nvram' == op or 'nvram-auth' == op ):

      authvars = ('nvram-auth' == op)
      efi_nvram_format = argv[3]
      if (4 == len(argv)):
         logger().log( "[CHIPSEC] Extracting EFI Variables directly in SPI ROM.." )
         try:
            _cs.init( True )
            _spi = SPI( _cs )
         except UnknownChipsetError, msg:
            print ("ERROR: Unknown chipset vendor (%s)" % str(msg))
            raise
         except SpiRuntimeError, msg:
            print ("ERROR: SPI initialization error" % str(msg))
            raise

         (bios_base,bios_limit,freg) = _spi.get_SPI_region( BIOS )
         bios_size = bios_limit - bios_base + 1
         logger().log( "[CHIPSEC] Reading BIOS: base = 0x%08X, limit = 0x%08X, size = 0x%08X" % (bios_base,bios_limit,bios_size) )
         rom = _spi.read_spi( bios_base, bios_size )
         _cs.stop( True )
         del _spi
      elif (5 == len(argv)):
         romfilename = argv[4]
         logger().log( "[CHIPSEC] Extracting EFI Variables from ROM file '%s'" % romfilename )
         rom = read_file( romfilename )

      _orig_logname = logger().LOG_FILE_NAME
      logger().set_log_file( (romfilename + '.nv.lst') )
      _uefi.parse_EFI_variables( romfilename, rom, authvars, efi_nvram_format )
      logger().set_log_file( _orig_logname )

    elif ( 'decode' == op):

      if (4 < len(argv)):
         filename = argv[3]
         fwtype = argv[4]
      else:
         print usage
         return
      logger().log( "[CHIPSEC] Parsing EFI volumes from '%s'.." % filename )
      _orig_logname = logger().LOG_FILE_NAME
      logger().set_log_file( filename + '.efi_fv.log' )
      cur_dir = _cs.helper.getcwd()
      decode_uefi_region(_uefi, cur_dir, filename, fwtype)
      logger().set_log_file( _orig_logname )

    elif ( 'keys' == op):

      if (3 < len(argv)):
         var_filename = argv[ 3 ]
      else:
         print usage
         return
      logger().log( "[CHIPSEC] Parsing EFI variable from '%s'.." % var_filename )
      parse_efivar_file( var_filename )

    logger().log( "[CHIPSEC] (uefi) time elapsed %.3f" % (time.time()-t) )


chipsec_util_commands['uefi'] = {'func' : uefi,    'start_driver' : False }

