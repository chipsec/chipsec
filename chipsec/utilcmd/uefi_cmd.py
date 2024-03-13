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
The uefi command provides access to UEFI variables, both on the live system and in a SPI flash image file.

>>> chipsec_util uefi types
>>> chipsec_util uefi var-list
>>> chipsec_util uefi var-find <name>|<GUID>
>>> chipsec_util uefi var-read|var-write|var-delete <name> <GUID> <efi_variable_file>
>>> chipsec_util uefi decode <rom_file> [filetypes]
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
>>> chipsec_util uefi decode uefi.rom FV_MM
>>> chipsec_util uefi nvram uefi.rom vss_auth
>>> chipsec_util uefi keys db.bin
>>> chipsec_util uefi tables
>>> chipsec_util uefi s3bootscript
>>> chipsec_util uefi assemble AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE freeform lzma uefi.raw mydriver.efi
>>> chipsec_util uefi replace  AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE bios.bin new_bios.bin mydriver.efi
"""

import os
import uuid
from argparse import ArgumentParser

from chipsec.command import BaseCommand, toLoad
from chipsec.hal.uefi_common import EFI_STATUS_DICT, parse_efivar_file
from chipsec.library.file import write_file, read_file
from chipsec.hal.spi_uefi import decode_uefi_region, modify_uefi_region, compress_image, CMD_UEFI_FILE_REPLACE
from chipsec.hal.spi_uefi import CMD_UEFI_FILE_INSERT_AFTER, CMD_UEFI_FILE_INSERT_BEFORE, CMD_UEFI_FILE_REMOVE
from chipsec.hal.uefi import UEFI, decode_EFI_variables, get_attr_string, identify_EFI_NVRAM
from chipsec.hal.uefi import SECURE_BOOT_KEY_VARIABLES, parse_script, parse_EFI_variables
from chipsec.hal.uefi_fv import get_guid_bin, assemble_uefi_file, assemble_uefi_section, assemble_uefi_raw
from chipsec.hal.uefi_fv import FILE_TYPE_NAMES
from chipsec.hal.uefi_platform import fw_types


# Unified Extensible Firmware Interface (UEFI)
class UEFICommand(BaseCommand):

    def requirements(self) -> toLoad:
        if 'decode' in self.argv:
            return toLoad.Nil
        return toLoad.Driver

    def parse_arguments(self) -> None:
        parser = ArgumentParser(prog='chipsec_util uefi', usage=__doc__)
        subparsers = parser.add_subparsers()

        # var-read command args
        parser_var_read = subparsers.add_parser('var-read')
        parser_var_read.add_argument('name', type=str, help='name of variable to read')
        parser_var_read.add_argument('guid', type=str, help='guid of variable to read')
        parser_var_read.add_argument('filename', type=str, nargs='?', default=None, help='output file to store read variable contents to')
        parser_var_read.set_defaults(func=self.var_read)

        # var-write command args
        parser_var_write = subparsers.add_parser('var-write')
        parser_var_write.add_argument('name', type=str, help='name of variable to write')
        parser_var_write.add_argument('guid', type=str, help='guid of variable to write')
        parser_var_write.add_argument('filename', type=str, help='input file containing data to write to variable')
        parser_var_write.set_defaults(func=self.var_write)

        # var-delete command args
        parser_var_delete = subparsers.add_parser('var-delete')
        parser_var_delete.add_argument('name', type=str, help='name of variable to delete')
        parser_var_delete.add_argument('guid', type=str, help='guid of variable to delete')
        parser_var_delete.set_defaults(func=self.var_delete)

        # var-list command args
        parser_var_list = subparsers.add_parser('var-list')
        parser_var_list.set_defaults(func=self.var_list)

        # var-find command args
        parser_var_find = subparsers.add_parser('var-find')
        parser_var_find.add_argument('name_guid', type=str, help='name or guid of variable to find')
        parser_var_find.set_defaults(func=self.var_find)

        # nvram command args
        parser_nvram = subparsers.add_parser('nvram')
        parser_nvram.add_argument('romfilename', type=str, help='nvram image')
        parser_nvram.add_argument('fwtype', type=str, nargs='?', default=None)
        parser_nvram.set_defaults(func=self.nvram)

        # nvram-auth command args
        parser_nvram_auth = subparsers.add_parser('nvram-auth')
        parser_nvram_auth.add_argument('romfilename', type=str, help='nvram image')
        parser_nvram_auth.add_argument('fwtype', type=str, nargs='?', default=None)
        parser_nvram_auth.set_defaults(func=self.nvram_auth)

        # decode command args
        parser_decode = subparsers.add_parser('decode')
        parser_decode.add_argument('filename', type=str, help='bios image to decompress')
        parser_decode.add_argument('--fwtype', dest='fwtype', type=str, nargs='?', default=None)
        parser_decode.add_argument('filetypes', type=str, nargs='*', default=[], help=FILE_TYPE_NAMES.values())
        parser_decode.set_defaults(func=self.decode)

        # keys command args
        parser_keys = subparsers.add_parser('keys')
        parser_keys.add_argument('filename', type=str, help='name of file containing variables')
        parser_keys.set_defaults(func=self.keys)

        # tables command args
        parser_tables = subparsers.add_parser('tables')
        parser_tables.set_defaults(func=self.tables)

        # s3bootscript command args
        parser_bootscript = subparsers.add_parser('s3bootscript')
        parser_bootscript.set_defaults(func=self.s3bootscript)
        parser_bootscript.add_argument('bootscript_pa', type=lambda x: int(x, 0), nargs='?', help='')

        # insert-before command args
        parser_insert_before = subparsers.add_parser('insert-before')
        parser_insert_before.add_argument('guid', type=str, help='guid')
        parser_insert_before.add_argument('filename', type=str, help='')
        parser_insert_before.add_argument('new_file', type=str, help='')
        parser_insert_before.add_argument('efi_file', type=str, help='')
        parser_insert_before.set_defaults(func=self.insert_before)

        # insert-after command args
        parser_insert_after = subparsers.add_parser('insert-after')
        parser_insert_after.add_argument('guid', type=str, help='guid')
        parser_insert_after.add_argument('filename', type=str, help='')
        parser_insert_after.add_argument('new_file', type=str, help='')
        parser_insert_after.add_argument('efi_file', type=str, help='')
        parser_insert_after.set_defaults(func=self.insert_after)

        # replace command args
        parser_replace = subparsers.add_parser('replace')
        parser_replace.add_argument('guid', type=str, help='guid')
        parser_replace.add_argument('filename', type=str, help='')
        parser_replace.add_argument('new_file', type=str, help='')
        parser_replace.add_argument('efi_file', type=str, help='')
        parser_replace.set_defaults(func=self.replace)

        # remove command args
        parser_remove = subparsers.add_parser('remove')
        parser_remove.add_argument('guid', type=str, help='guid')
        parser_remove.add_argument('filename', type=str, help='')
        parser_remove.add_argument('new_file', type=str, help='')
        parser_remove.set_defaults(func=self.remove)

        # assemble command args
        parser_assemble = subparsers.add_parser('assemble')
        parser_assemble.add_argument('guid', type=str, help='guid')
        parser_assemble.add_argument('file_type', type=str, help='')
        parser_assemble.add_argument('comp', type=str, help='')
        parser_assemble.add_argument('raw_file', type=str, help='')
        parser_assemble.add_argument('efi_file', type=str, help='')
        parser_assemble.set_defaults(func=self.assemble)

        parser.parse_args(self.argv, namespace=self)

    def set_up(self) -> None:
        self._uefi = UEFI(self.cs)

    def var_read(self):
        self.logger.log("[CHIPSEC] Reading EFI variable Name='{}' GUID={{{}}} to '{}' via Variable API..".format(self.name, self.guid, self.filename))
        var = self._uefi.get_EFI_variable(self.name, self.guid, self.filename)

    def var_write(self):
        self.logger.log("[CHIPSEC] writing EFI variable Name='{}' GUID={{{}}} from '{}' via Variable API..".format(self.name, self.guid, self.filename))
        status = self._uefi.set_EFI_variable_from_file(self.name, self.guid, self.filename)
        self.logger.log("[CHIPSEC] status: {}".format(EFI_STATUS_DICT[status]))
        if status == 0:
            self.logger.log("[CHIPSEC] writing EFI variable was successful")
        else:
            self.logger.log_error("writing EFI variable failed")

    def var_delete(self):
        self.logger.log("[CHIPSEC] Deleting EFI variable Name='{}' GUID={{{}}} via Variable API..".format(self.name, self.guid))
        status = self._uefi.delete_EFI_variable(self.name, self.guid)
        self.logger.log("Returned {}".format(EFI_STATUS_DICT[status]))
        if status == 0:
            self.logger.log("[CHIPSEC] deleting EFI variable was successful")
        else:
            self.logger.log_error("deleting EFI variable failed")

    def var_list(self):
        self.logger.log("[CHIPSEC] Enumerating all EFI variables via OS specific EFI Variable API..")
        efi_vars = self._uefi.list_EFI_variables()
        if efi_vars is None:
            self.logger.log("[CHIPSEC] Could not enumerate EFI Variables (Legacy OS?). Exit..")
            return
        self.logger.log("[CHIPSEC] Decoding EFI Variables..")
        _orig_logname = self.logger.LOG_FILE_NAME
        self.logger.set_log_file('efi_variables.lst', False)
        nvram_pth = 'efi_variables.dir'
        if not os.path.exists(nvram_pth):
            os.makedirs(nvram_pth)
        decode_EFI_variables(efi_vars, nvram_pth)
        self.logger.set_log_file(_orig_logname)
        self.logger.log("[CHIPSEC] Variables are in efi_variables.lst log and efi_variables.dir directory")

    def var_find(self):
        _vars = self._uefi.list_EFI_variables()
        if _vars is None:
            self.logger.log_warning('Could not enumerate UEFI variables (non-UEFI OS?)')
            return
        is_guid = 0
        try:
            _input_var = str(uuid.UUID(self.name_guid))
            is_guid = 1
        except ValueError:
            _input_var = self.name_guid

        if is_guid:
            self.logger.log("[*] Searching for UEFI variable with GUID {{{}}}..".format(_input_var))
            for name in _vars:
                n = 0
                for (off, buf, hdr, data, guid, attrs) in _vars[name]:
                    if _input_var == guid:
                        var_fname = '{}_{}_{}_{:d}.bin'.format(name, guid, get_attr_string(attrs).strip(), n)
                        self.logger.log_good("Found UEFI variable {}:{}. Dumped to '{}'".format(guid, name, var_fname))
                        write_file(var_fname, data)
                    n += 1
        else:
            self.logger.log("[*] Searching for UEFI variable with name {}..".format(_input_var))
            name = _input_var
            if name in list(_vars.keys()):
                n = 0
                for (off, buf, hdr, data, guid, attrs) in _vars[name]:
                    var_fname = '{}_{}_{}_{:d}.bin'.format(name, guid, get_attr_string(attrs).strip(), n)
                    self.logger.log_good("Found UEFI variable {}:{}. Dumped to '{}'".format(guid, name, var_fname))
                    write_file(var_fname, data)
                    n += 1

    def nvram(self):
        authvars = 0
        rom = read_file(self.romfilename)
        if self.fwtype is None:
            self.fwtype = identify_EFI_NVRAM(rom)
            if self.fwtype is None:
                self.logger.log_error("Could not automatically identify EFI NVRAM type")
                return
        elif self.fwtype not in fw_types:
            self.logger.log_error("Unrecognized EFI NVRAM type '{}'".format(self.fwtype))
            return

        _orig_logname = self.logger.LOG_FILE_NAME
        self.logger.set_log_file( (self.romfilename + '.nv.lst'), False)
        parse_EFI_variables( self.romfilename, rom, authvars, self.fwtype )
        self.logger.set_log_file( _orig_logname )

    def nvram_auth(self):
        authvars = 1
        rom = read_file(self.romfilename)
        if self.fwtype is None:
            self.fwtype = identify_EFI_NVRAM(rom)
            if self.fwtype is None:
                self.logger.log_error("Could not automatically identify EFI NVRAM type")
                return
        elif self.fwtype not in fw_types:
            self.logger.log_error("Unrecognized EFI NVRAM type '{}'".format(self.fwtype))
            return

        _orig_logname = self.logger.LOG_FILE_NAME
        self.logger.set_log_file( (self.romfilename + '.nv.lst'), False)
        parse_EFI_variables( self.romfilename, rom, authvars, self.fwtype )
        self.logger.set_log_file( _orig_logname )

    def decode(self):
        if not os.path.exists(self.filename):
            self.logger.log_error("Could not find file '{}'".format(self.filename))
            return

        self.logger.log("[CHIPSEC] Parsing EFI volumes from '{}'..".format(self.filename))
        _orig_logname = self.logger.LOG_FILE_NAME
        self.logger.set_log_file(self.filename + '.UEFI.lst', False)
        cur_dir = self.cs.os_helper.getcwd()
        ftypes = []
        inv_filetypes = {v: k for k, v in FILE_TYPE_NAMES.items()}
        if self.filetypes:
            for mtype in self.filetypes:
                if mtype in inv_filetypes.keys():
                    if inv_filetypes[mtype] not in ftypes:
                        ftypes.append(inv_filetypes[mtype])
                    break
        decode_uefi_region(cur_dir, self.filename, self.fwtype, ftypes)
        self.logger.set_log_file( _orig_logname )

    def keys(self):
        if not os.path.exists(self.filename):
            self.logger.log_error("Could not find file '{}'".format(self.filename))
            return
        self.logger.log("<keyvar_file> should contain one of the following EFI variables\n[ %s ]" % (" | ".join(["%s" % var for var in SECURE_BOOT_KEY_VARIABLES])))
        self.logger.log("[CHIPSEC] Parsing EFI variable from '{}'..".format(self.filename))
        parse_efivar_file(self.filename)

    def tables(self):
        self.logger.log("[CHIPSEC] Searching memory for and dumping EFI tables (this may take a minute)..\n")
        self._uefi.dump_EFI_tables()

    def s3bootscript(self):
        self.logger.log("[CHIPSEC] Searching for and parsing S3 resume bootscripts..")
        if self.bootscript_pa is not None:
            self.logger.log('[*] Reading S3 boot-script from memory at 0x{:016X}..'.format(self.bootscript_pa))
            script_all = self.cs.mem.read_physical_mem(self.bootscript_pa, 0x100000)
            self.logger.log('[*] Decoding S3 boot-script opcodes..')
            script_entries = parse_script(script_all, True)
        else:
            (bootscript_PAs, parsed_scripts) = self._uefi.get_s3_bootscript(True)

    def insert_before(self):
        if get_guid_bin(self.guid) == '':
            print('*** Error *** Invalid GUID: {}'.format(self.guid))
            return

        if not os.path.isfile(self.rom_file):
            print('*** Error *** File doesn\'t exist: {}'.format(self.rom_file))
            return

        if not os.path.isfile(self.efi_file):
            print('*** Error *** File doesn\'t exist: {}'.format(self.efi_file))
            return

        rom_image = read_file(self.rom_file)
        efi_image = read_file(self.efi_file)
        new_image = modify_uefi_region(rom_image, CMD_UEFI_FILE_INSERT_BEFORE, self.guid, efi_image)
        write_file(self.new_file, new_image)

    def insert_after(self):
        if get_guid_bin(self.guid) == '':
            print('*** Error *** Invalid GUID: {}'.format(self.guid))
            return

        if not os.path.isfile(self.rom_file):
            print('*** Error *** File doesn\'t exist: {}'.format(self.rom_file))
            return

        if not os.path.isfile(self.efi_file):
            print('*** Error *** File doesn\'t exist: {}'.format(self.efi_file))
            return

        rom_image = read_file(self.rom_file)
        efi_image = read_file(self.efi_file)
        new_image = modify_uefi_region(rom_image, CMD_UEFI_FILE_INSERT_AFTER, self.guid, efi_image)
        write_file(self.new_file, new_image)

    def replace(self):
        if get_guid_bin(self.guid) == '':
            print('*** Error *** Invalid GUID: {}'.format(self.guid))
            return

        if not os.path.isfile(self.rom_file):
            print('*** Error *** File doesn\'t exist: {}'.format(self.rom_file))
            return

        if not os.path.isfile(self.efi_file):
            print('*** Error *** File doesn\'t exist: {}'.format(self.efi_file))
            return

        rom_image = read_file(self.rom_file)
        efi_image = read_file(self.efi_file)
        new_image = modify_uefi_region(rom_image, CMD_UEFI_FILE_REPLACE, self.guid, efi_image)
        write_file(self.new_file, new_image)

    def remove(self):
        if get_guid_bin(self.guid) == '':
            print('*** Error *** Invalid GUID: {}'.format(self.guid))
            return

        if not os.path.isfile(self.rom_file):
            print('*** Error *** File doesn\'t exist: {}'.format(self.rom_file))
            return

        rom_image = read_file(self.rom_file)
        new_image = modify_uefi_region(rom_image, CMD_UEFI_FILE_REMOVE, self.guid)
        write_file(self.new_file, new_image)

    def assemble(self):
        compression = {'none': 0, 'tiano': 1, 'lzma': 2}

        if get_guid_bin(self.guid) == '':
            print('*** Error *** Invalid GUID: {}'.format(self.guid))
            return

        if not os.path.isfile(self.raw_file):
            print('*** Error *** File doesn\'t exist: {}'.format(self.raw_file))
            return

        if self.comp not in compression:
            print('*** Error *** Unknown compression: {}'.format(self.comp))
            return

        compression_type = compression[self.comp]

        if self.file_type == 'freeform':
            raw_image = read_file(self.raw_file)
            wrap_image = assemble_uefi_raw(raw_image)
            if compression_type > 0:
                comp_image = compress_image(wrap_image, compression_type)
                wrap_image = assemble_uefi_section(comp_image, len(wrap_image), compression_type)
            uefi_image = assemble_uefi_file(self.guid, wrap_image)
            write_file(self.efi_file, uefi_image)
        else:
            print('*** Error *** Unknow file type: {}'.format(self.file_type))
            return

        self.logger.log("[CHIPSEC]  UEFI file was successfully assembled! Binary file size: {:d}, compressed UEFI file size: {:d}".format(len(raw_image), len(uefi_image)))


commands = {'uefi': UEFICommand}
