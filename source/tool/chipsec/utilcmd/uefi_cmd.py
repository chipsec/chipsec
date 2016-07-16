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
import time

import chipsec_util

from chipsec.logger     import *
from chipsec.file       import *

from chipsec.hal.uefi          import *
from chipsec.hal.spi_uefi      import *

from chipsec.command    import BaseCommand


# Unified Extensible Firmware Interface (UEFI)
class UEFICommand(BaseCommand):
    """
    >>> chipsec_util uefi types
    >>> chipsec_util uefi var-list
    >>> chipsec_util uefi var-find <name>|<GUID>
    >>> chipsec_util uefi var-read|var-write|var-delete <name> <GUID> <efi_variable_file>
    >>> chipsec_util uefi decode <rom_file> [fwtype]
    >>> chipsec_util uefi nvram[-auth] <rom_file> [fwtype]
    >>> chipsec_util uefi keys <keyvar_file>
    >>> chipsec_util uefi tables
    >>> chipsec_util uefi s3bootscript [script_address]
    >>> chipsec_util uefi assemble <GUID> freeform none|lzma|tiano <raw_file> <uefi_file>
    >>> chipsec_util uefi insert_before|insert_after|replace|remove <GUID> <rom> <new_rom> <uefi_file>
    
    Examples:

    >>> chipsec_util uefi types
    >>> chipsec_util uefi var-list
    >>> chipsec_util uefi var-find PK
    >>> chipsec_util uefi var-read db D719B2CB-3D3A-4596-A3BC-DAD00E67656F db.bin
    >>> chipsec_util uefi var-write db D719B2CB-3D3A-4596-A3BC-DAD00E67656F db.bin
    >>> chipsec_util uefi var-delete db D719B2CB-3D3A-4596-A3BC-DAD00E67656F
    >>> chipsec_util uefi decode uefi.rom
    >>> chipsec_util uefi nvram uefi.rom vss_auth
    >>> chipsec_util uefi keys db.bin
    >>> chipsec_util uefi tables
    >>> chipsec_util uefi s3bootscript
    >>> chipsec_util uefi assemble AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE freeform lzma uefi.raw mydriver.efi
    >>> chipsec_util uefi replace  AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE bios.bin new_bios.bin mydriver.efi
    """

    def requires_driver(self):
        # No driver required when printing the util documentation
        if len(self.argv) < 3:
            return False
        return True

    def run(self):
        _uefi = UEFI( self.cs )
        if len(self.argv) < 3:
            print UEFICommand.__doc__
            return
        
        op       = self.argv[2]
        t        = time.time()
        filename = None

        if ( 'types' == op ):
            self.logger.log( "<fwtype> should be in [ %s ]" % (" | ".join( ["%s" % tp for tp in fw_types])) )

        elif ( 'var-read' == op ):
            if (4 < len(self.argv)):
                name = self.argv[3]
                guid = self.argv[4]
            if (5 < len(self.argv)):
                filename = self.argv[5]
            self.logger.log( "[CHIPSEC] Reading EFI variable Name='%s' GUID={%s} to '%s' via Variable API.." % (name, guid, filename) )
            var = _uefi.get_EFI_variable( name, guid, filename )

        elif ( 'var-write' == op ):

            if (5 < len(self.argv)):
                name = self.argv[3]
                guid = self.argv[4]
                filename = self.argv[5]
            else:
                print UEFICommand.__doc__
                return
            self.logger.log( "[CHIPSEC] writing EFI variable Name='%s' GUID={%s} from '%s' via Variable API.." % (name, guid, filename) )
            status = _uefi.set_EFI_variable_from_file( name, guid, filename )
            self.logger.log("[CHIPSEC] status: %s" % chipsec.hal.uefi_common.EFI_STATUS_DICT[status])
            if status == 0:
                self.logger.log( "[CHIPSEC] set_EFI_variable return SUCCESS status" )
            else:
                self.logger.error( "set_EFI_variable wasn't able to modify variable" )

        elif ( 'var-delete' == op ):

            if (4 < len(self.argv)):
                name = self.argv[3]
                guid = self.argv[4]
            else:
                print UEFICommand.__doc__
                return
            self.logger.log( "[CHIPSEC] Deleting EFI variable Name='%s' GUID={%s} via Variable API.." % (name, guid) )
            status = _uefi.delete_EFI_variable( name, guid )
            self.logger.log("Returned %s" % chipsec.hal.uefi_common.EFI_STATUS_DICT[status])
            if status == 0: self.logger.log( "[CHIPSEC] delete_EFI_variable return SUCCESS status" )
            else:      self.logger.error( "delete_EFI_variable wasn't able to delete variable" )

        elif ( 'var-list' == op ):

            #infcls = 2
            #if (3 < len(self.argv)): filename = self.argv[3]
            #if (4 < len(self.argv)): infcls = int(self.argv[4],16)
            self.logger.log( "[CHIPSEC] Enumerating all EFI variables via OS specific EFI Variable API.." )
            efi_vars = _uefi.list_EFI_variables()
            if efi_vars is None:
                self.logger.log( "[CHIPSEC] Could not enumerate EFI Variables (Legacy OS?). Exit.." )
                return

            self.logger.log( "[CHIPSEC] Decoding EFI Variables.." )
            _orig_logname = self.logger.LOG_FILE_NAME
            self.logger.set_log_file( 'efi_variables.lst' )
            #print_sorted_EFI_variables( efi_vars )
            nvram_pth = 'efi_variables.dir'
            if not os.path.exists( nvram_pth ): os.makedirs( nvram_pth )
            decode_EFI_variables( efi_vars, nvram_pth )
            self.logger.set_log_file( _orig_logname )

            #efi_vars = _uefi.list_EFI_variables( infcls, filename )
            #_orig_logname = self.logger.LOG_FILE_NAME
            #self.logger.set_log_file( (filename + '.nv.lst') )
            #_uefi.parse_EFI_variables( filename, efi_vars, False, FWType.EFI_FW_TYPE_WIN )
            #self.logger.set_log_file( _orig_logname )

            self.logger.log( "[CHIPSEC] Variables are in efi_variables.lst log and efi_variables.dir directory" )

        elif ( 'var-find' == op ):

            _vars = _uefi.list_EFI_variables()
            if _vars is None:
                self.logger.log_warning( 'Could not enumerate UEFI variables (non-UEFI OS?)' )
                return

            _input_var = self.argv[3]
            if ('-' in _input_var):
                self.logger.log( "[*] Searching for UEFI variable with GUID {%s}.." % _input_var )
                for name in _vars:
                    n = 0
                    for (off, buf, hdr, data, guid, attrs) in _vars[name]:
                        if _input_var == guid:
                            var_fname = '%s_%s_%s_%d.bin' % (name,guid,get_attr_string(attrs).strip(),n)
                            self.logger.log_good( "Found UEFI variable %s:%s. Dumped to '%s'" % (guid,name,var_fname) )
                            write_file( var_fname, data )
                        n += 1
            else:
                self.logger.log( "[*] Searching for UEFI variable with name %s.." % _input_var )
                for name,_v in _vars.iteritems():
                    n = 0
                    for (off, buf, hdr, data, guid, attrs) in _v:
                        if _input_var == name:
                            var_fname = '%s_%s_%s_%d.bin' % (name,guid,get_attr_string(attrs).strip(),n)
                            self.logger.log_good( "Found UEFI variable %s:%s. Dumped to '%s'" % (guid,name,var_fname) )
                            write_file( var_fname, data )
                        n += 1

        elif ( 'nvram' == op or 'nvram-auth' == op ):

            authvars = ('nvram-auth' == op)
            if len(self.argv) == 3:
                self.logger.log( "<fw_type> should be in [ %s ]\n" % (" | ".join( ["%s" % tp for tp in fw_types])) )
                return

            romfilename = self.argv[3]
            fwtype      = self.argv[4] if len(self.argv) == 5 else None
            self.logger.log( "[CHIPSEC] Extracting EFI Variables from ROM file '%s'" % romfilename )
            if not os.path.exists( romfilename ):
                self.logger.error( "Could not find file '%s'" % romfilename )
                return

            rom = read_file( romfilename )
            if fwtype is None:
                fwtype = identify_EFI_NVRAM( rom )
                if fwtype is None:
                    self.logger.error( "Could not automatically identify EFI NVRAM type" )
                    return
            elif fwtype not in fw_types:
                self.logger.error( "Unrecognized EFI NVRAM type '%s'" % fwtype )
                return

            _orig_logname = self.logger.LOG_FILE_NAME
            self.logger.set_log_file( (romfilename + '.nv.lst') )
            _uefi.parse_EFI_variables( romfilename, rom, authvars, fwtype )
            self.logger.set_log_file( _orig_logname )

        elif ( 'decode' == op ):

            if len(self.argv) < 4:
                print UEFICommand.__doc__
                return

            filename = self.argv[3]
            fwtype   = self.argv[4] if len(self.argv) > 4 else None
            if not os.path.exists( filename ):
                self.logger.error( "Could not find file '%s'" % filename )
                return

            self.logger.log( "[CHIPSEC] Parsing EFI volumes from '%s'.." % filename )
            _orig_logname = self.logger.LOG_FILE_NAME
            self.logger.set_log_file( filename + '.efi_fv.log' )
            cur_dir = self.cs.helper.getcwd()
            decode_uefi_region(_uefi, cur_dir, filename, fwtype)
            self.logger.set_log_file( _orig_logname )

        elif ( 'keys' == op ):

            if (3 < len(self.argv)):
                var_filename = self.argv[3]
                if not os.path.exists( var_filename ):
                    self.logger.error( "Could not find file '%s'" % var_filename )
                    return
            else:
                print UEFICommand.__doc__
                self.logger.log( "<keyvar_file> should contain one of the following EFI variables\n[ %s ]" % (" | ".join( ["%s" % var for var in SECURE_BOOT_KEY_VARIABLES]))  )
                return

            self.logger.log( "[CHIPSEC] Parsing EFI variable from '%s'.." % var_filename )
            parse_efivar_file( var_filename )

        elif ( 'tables' == op ):
            self.logger.log( "[CHIPSEC] Searching memory for and dumping EFI tables (this may take a minute)..\n" )
            _uefi.dump_EFI_tables()

        elif ( 's3bootscript' == op ):
            self.logger.log( "[CHIPSEC] Searching for and parsing S3 resume bootscripts.." )
            if len(self.argv) > 3:
                bootscript_pa = int(self.argv[3],16)
                self.logger.log( '[*] Reading S3 boot-script from memory at 0x%016X..' % bootscript_pa )
                script_all = self.cs.mem.read_physical_mem( bootscript_pa, 0x100000 )
                self.logger.log( '[*] Decoding S3 boot-script opcodes..' )
                script_entries = chipsec.hal.uefi.parse_script( script_all, True )               
            else:
                (bootscript_PAs,parsed_scripts) = _uefi.get_s3_bootscript( True )

        elif op in ['insert_before', 'insert_after', 'replace']:

            if len(self.argv) < 7:
                print UEFICommand.__doc__
                return

            (guid, rom_file, new_file, efi_file) = self.argv[3:7]

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

            if len(self.argv) < 6:
                print UEFICommand.__doc__
                return

            (guid, rom_file, new_file) = self.argv[3:6]

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

            if len(self.argv) < 8:
                print UEFICommand.__doc__
                return

            (guid, file_type, comp, raw_file, efi_file) = self.argv[3:8]

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

            self.logger.log( "[CHIPSEC]  UEFI file was successfully assembled! Binary file size: %d, compressed UEFI file size: %d" % (len(raw_image), len(uefi_image)) )

        else:
            self.logger.error( "Unknown uefi command '%s'" % op )
            print UEFICommand.__doc__
            return

        self.logger.log( "[CHIPSEC] (uefi) time elapsed %.3f" % (time.time()-t) )


commands = { 'uefi': UEFICommand }

