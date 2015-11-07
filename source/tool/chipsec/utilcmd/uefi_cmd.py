#!/usr/local/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2015, Intel Corporation
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
The uefi command provides access to UEFI variables, both on the live system and in a SPI flash image file.
"""

__version__ = '1.0'

import os
import sys
import time

import chipsec_util

from chipsec.logger     import *
from chipsec.file       import *

from chipsec.hal.uefi          import *
from chipsec.hal.spi_uefi      import *

_uefi = UEFI( chipsec_util._cs )


# Unified Extensible Firmware Interface (UEFI)
def uefi(argv):
    """
    >>> chipsec_util uefi var-list
    >>> chipsec_util uefi var-find <name>|<GUID>
    >>> chipsec_util uefi var-read|var-write|var-delete <name> <GUID> <efi_variable_file>
    >>> chipsec_util uefi nvram[-auth] <fw_type> [rom_file]
    >>> chipsec_util uefi tables
    >>> chipsec_util uefi s3bootscript [script_address]
    >>> chipsec_util uefi assemble <GUID> freeform none|lzma|tiano <raw_file> <uefi_file>
    >>> chipsec_util uefi insert_before|insert_after|replace|remove <GUID> <bios_rom> <modified_bios_rom> <uefi_file>

    For a list of fw types run:

    >>> chipsec_util uefi types
    
    Examples:

    >>> chipsec_util uefi var-list
    >>> chipsec_util uefi var-find PK
    >>> chipsec_util uefi var-read db D719B2CB-3D3A-4596-A3BC-DAD00E67656F db.bin
    >>> chipsec_util uefi var-write db D719B2CB-3D3A-4596-A3BC-DAD00E67656F db.bin
    >>> chipsec_util uefi var-delete db D719B2CB-3D3A-4596-A3BC-DAD00E67656F
    >>> chipsec_util uefi nvram fwtype bios.rom
    >>> chipsec_util uefi nvram-auth fwtype bios.rom
    >>> chipsec_util uefi decode uefi.bin fwtype
    >>> chipsec_util uefi keys db.bin
    >>> chipsec_util uefi tables
    >>> chipsec_util uefi s3bootscript
    >>> chipsec_util uefi assemble AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE freeform lzma uefi_file.raw uefi_file.bin
    >>> chipsec_util uefi replace  AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE bios.bin modified_bios.bin uefi_file.bin
    """
       
    if 3 > len(argv):
        print uefi.__doc__
        return
    
    if argv[2] == "types":
        print "\n<fw_type> should be in [ %s ]\n" % (" | ".join( ["%s" % t for t in fw_types])) + \
        "chipsec_util uefi keys <keyvar_file>\n" + \
        "                  <keyvar_file> should be one of the following EFI variables\n" + \
        "                  [ %s ]\n" % (" | ".join( ["%s" % var for var in SECURE_BOOT_KEY_VARIABLES]))
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
        logger().log( "[CHIPSEC] Reading EFI variable Name='%s' GUID={%s} to '%s' via Variable API.." % (name, guid, filename) )
        var = _uefi.get_EFI_variable( name, guid, filename )

    elif ( 'var-write' == op ):

        if (5 < len(argv)):
            name = argv[3]
            guid = argv[4]
            filename = argv[5]
        else:
            print uefi.__doc__
            return
        logger().log( "[CHIPSEC] writing EFI variable Name='%s' GUID={%s} from '%s' via Variable API.." % (name, guid, filename) )
        status = _uefi.set_EFI_variable_from_file( name, guid, filename )
        logger().log("[CHIPSEC] status: %s" % chipsec.hal.uefi_common.EFI_STATUS_DICT[status])
        if status == 0:
            logger().log( "[CHIPSEC] set_EFI_variable return SUCCESS status" )
        else:
            logger().error( "set_EFI_variable wasn't able to modify variable" )

    elif ( 'var-delete' == op ):

        if (4 < len(argv)):
            name = argv[3]
            guid = argv[4]
        else:
            print uefi.__doc__
            return
        logger().log( "[CHIPSEC] Deleting EFI variable Name='%s' GUID={%s} via Variable API.." % (name, guid) )
        status = _uefi.delete_EFI_variable( name, guid )
        logger().log("Returned %s" % chipsec.hal.uefi_common.EFI_STATUS_DICT[status])
        if status == 0: logger().log( "[CHIPSEC] delete_EFI_variable return SUCCESS status" )
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

        logger().log( "[CHIPSEC] Variables are in efi_variables.lst log and efi_variables.dir directory" )

    elif ( 'var-find' == op ):

        _vars = _uefi.list_EFI_variables()
        if _vars is None:
            logger().log_warning( 'Could not enumerate UEFI variables (non-UEFI OS?)' )
            return

        _input_var = argv[3]
        if ('-' in _input_var):
            logger().log( "[*] Searching for UEFI variable with GUID {%s}.." % _input_var )
            for name in _vars:
                n = 0
                for (off, buf, hdr, data, guid, attrs) in _vars[name]:
                    if _input_var == guid:
                        var_fname = '%s_%s_%s_%d.bin' % (name,guid,get_attr_string(attrs).strip(),n)
                        logger().log_good( "Found UEFI variable %s:%s. Dumped to '%s'" % (guid,name,var_fname) )
                        write_file( var_fname, data )
                    n += 1
        else:
            logger().log( "[*] Searching for UEFI variable with name %s.." % _input_var )
            for name,_v in _vars.iteritems():
                n = 0
                for (off, buf, hdr, data, guid, attrs) in _v:
                    if _input_var == name:
                        var_fname = '%s_%s_%s_%d.bin' % (name,guid,get_attr_string(attrs).strip(),n)
                        logger().log_good( "Found UEFI variable %s:%s. Dumped to '%s'" % (guid,name,var_fname) )
                        write_file( var_fname, data )
                    n += 1

    elif ( 'nvram' == op or 'nvram-auth' == op ):

        authvars = ('nvram-auth' == op)
        efi_nvram_format = argv[3]
        if (4 == len(argv)):
            logger().log( "[CHIPSEC] Extracting EFI Variables directly in SPI ROM.." )
            try:
                chipsec_util._cs.init( True )
                _spi = SPI( chipsec_util._cs )
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
            chipsec_util._cs.stop( True )
            del _spi
        elif (5 == len(argv)):
            romfilename = argv[4]
            logger().log( "[CHIPSEC] Extracting EFI Variables from ROM file '%s'" % romfilename )
            rom = read_file( romfilename )

        _orig_logname = logger().LOG_FILE_NAME
        logger().set_log_file( (romfilename + '.nv.lst') )
        _uefi.parse_EFI_variables( romfilename, rom, authvars, efi_nvram_format )
        logger().set_log_file( _orig_logname )

    elif ( 'decode' == op ):

        if (4 < len(argv)):
            filename = argv[3]
            fwtype = argv[4]
        else:
            print uefi.__doc__
            return
        logger().log( "[CHIPSEC] Parsing EFI volumes from '%s'.." % filename )
        _orig_logname = logger().LOG_FILE_NAME
        logger().set_log_file( filename + '.efi_fv.log' )
        cur_dir = chipsec_util._cs.helper.getcwd()
        decode_uefi_region(_uefi, cur_dir, filename, fwtype)
        logger().set_log_file( _orig_logname )

    elif ( 'keys' == op ):

        if (3 < len(argv)):
            var_filename = argv[ 3 ]
        else:
            print uefi.__doc__
            return
        logger().log( "[CHIPSEC] Parsing EFI variable from '%s'.." % var_filename )
        parse_efivar_file( var_filename )

    elif ( 'tables' == op ):
        logger().log( "[CHIPSEC] Searching memory for and dumping EFI tables (this may take a minute)..\n" )
        _uefi.dump_EFI_tables()

    elif ( 's3bootscript' == op ):
        logger().log( "[CHIPSEC] Searching for and parsing S3 resume bootscripts.." )
        if len(argv) > 3:
            bootscript_pa = int(argv[3],16)
            logger().log( '[*] Reading S3 boot-script from memory at 0x%016X..' % bootscript_pa )
            script_all = chipsec_util._cs.mem.read_physical_mem( bootscript_pa, 0x100000 )
            logger().log( '[*] Decoding S3 boot-script opcodes..' )
            script_entries = chipsec.hal.uefi.parse_script( script_all, True )               
        else:
            (bootscript_PAs,parsed_scripts) = _uefi.get_s3_bootscript( True )

    elif op in ['insert_before', 'insert_after', 'replace']:

        if len(argv) < 7:
            print uefi.__doc__
            return

        (guid, rom_file, new_file, efi_file) = argv[3:7]

        commands = {
            'insert_before' :  CMD_UEFI_FILE_INSERT_BEFORE,
            'insert_after'  :  CMD_UEFI_FILE_INSERT_AFTER,
            'replace'       :  CMD_UEFI_FILE_REPLACE
        }

        if get_guid_bin(guid) == '':
            print '*** Error *** Invalid GUID: %s' % guid
            return

        if not os.path.isfile(rom_file):
            print '*** Error *** File doesn\'t exist: %s' % rom_file
            return

        if not os.path.isfile(efi_file):
            print '*** Error *** File doesn\'t exist: %s' % efi_file
            return

        rom_image = chipsec.file.read_file(rom_file)
        efi_image = chipsec.file.read_file(efi_file)
        new_image = modify_uefi_region(rom_image, commands[op], guid, efi_image)
        chipsec.file.write_file(new_file, new_image)

    elif op == 'remove':

        if len(argv) < 6:
            print uefi.__doc__
            return

        (guid, rom_file, new_file) = argv[3:6]

        if get_guid_bin(guid) == '':
            print '*** Error *** Invalid GUID: %s' % guid
            return

        if not os.path.isfile(rom_file):
            print '*** Error *** File doesn\'t exist: %s' % rom_file
            return

        rom_image = chipsec.file.read_file(rom_file)
        new_image = modify_uefi_region(rom_image, CMD_UEFI_FILE_REMOVE, guid)
        chipsec.file.write_file(new_file, new_image)

    elif op == 'assemble':

        compression = {'none': 0, 'tiano': 1, 'lzma': 2}

        if len(argv) < 8:
            print uefi.__doc__
            return

        (guid, file_type, comp, raw_file, efi_file) = argv[3:8]

        if get_guid_bin(guid) == '':
            print '*** Error *** Invalid GUID: %s' % guid
            return

        if not os.path.isfile(raw_file):
            print '*** Error *** File doesn\'t exist: %s' % raw_file
            return

        if comp not in compression:
            print '*** Error *** Unknown compression: %s' % comp
            return

        compression_type = compression[comp]

        if file_type == 'freeform':
            raw_image  = chipsec.file.read_file(raw_file)
            wrap_image = assemble_uefi_raw(raw_image)
            if compression_type > 0:
                comp_image = compress_image(_uefi, wrap_image, compression_type)
                wrap_image = assemble_uefi_section(comp_image, len(wrap_image), compression_type)
            uefi_image = assemble_uefi_file(guid, wrap_image)
            chipsec.file.write_file(efi_file, uefi_image)
        else:
            print '*** Error *** Unknow file type: %s' % file_type
            return

        logger().log( "[CHIPSEC]  UEFI file was successfully assembled! Binary file size: %d, compressed UEFI file size: %d" % (len(raw_image), len(uefi_image)) )

    else:
        logger().error( "Unknown uefi command '%s'" % op )
        print uefi.__doc__
        return

    logger().log( "[CHIPSEC] (uefi) time elapsed %.3f" % (time.time()-t) )

chipsec_util.commands['uefi'] = {'func' : uefi, 'start_driver' : True, 'help' : uefi.__doc__ }