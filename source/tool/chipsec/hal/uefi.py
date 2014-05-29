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



# -------------------------------------------------------------------------------
#
# CHIPSEC: Platform Hardware Security Assessment Framework
# (c) 2010-2012 Intel Corporation
#
# -------------------------------------------------------------------------------
## \addtogroup hal
# chipsec/hal/uefi.py
# ============================
# Main UEFI component using platform specific and common UEFI functionality
#
#
#
__version__ = '1.0'

import struct
import sys

from collections import namedtuple
import collections

from chipsec.hal.uefi_common import *
from chipsec.hal.uefi_platform import *

from chipsec.logger import *
from chipsec.hal.mmio import *
from chipsec.hal.spi import *
from chipsec.file import *


EFI_VAR_NAME_PK         = 'PK'
EFI_VAR_NAME_KEK        = 'KEK'
EFI_VAR_NAME_db         = 'db'
EFI_VAR_NAME_dbx        = 'dbx'
EFI_VAR_NAME_SecureBoot = 'SecureBoot'
EFI_VAR_NAME_SetupMode  = 'SetupMode'
EFI_VAR_NAME_CustomMode = 'CustomMode'

EFI_VAR_GUID_SecureBoot = '8BE4DF61-93CA-11D2-AA0D-00E098032B8C'
EFI_VAR_GUID_db         = 'D719B2CB-3D3A-4596-A3BC-DAD00E67656F'

EFI_VARIABLE_DICT = {
EFI_VAR_NAME_PK        : EFI_VAR_GUID_SecureBoot,
EFI_VAR_NAME_KEK       : EFI_VAR_GUID_SecureBoot,
EFI_VAR_NAME_db        : EFI_VAR_GUID_db,
EFI_VAR_NAME_dbx       : EFI_VAR_GUID_db,
EFI_VAR_NAME_SecureBoot: EFI_VAR_GUID_SecureBoot,
EFI_VAR_NAME_SetupMode : EFI_VAR_GUID_SecureBoot,
EFI_VAR_NAME_CustomMode: EFI_VAR_GUID_SecureBoot
}


SECURE_BOOT_KEY_VARIABLES = (EFI_VAR_NAME_PK, EFI_VAR_NAME_KEK, EFI_VAR_NAME_db, EFI_VAR_NAME_dbx)
SECURE_BOOT_VARIABLES     = (EFI_VAR_NAME_SecureBoot, EFI_VAR_NAME_SetupMode, EFI_VAR_NAME_CustomMode) + SECURE_BOOT_KEY_VARIABLES
AUTHENTICATED_VARIABLES   = ('AuthVarKeyDatabase', 'certdb') + SECURE_BOOT_VARIABLES
SUPPORTED_EFI_VARIABLES   = ('BootOrder', 'Boot####', 'DriverOrder', 'Driver####') + AUTHENTICATED_VARIABLES


def get_attr_string( attr ):
    attr_str = ' '
    if IS_VARIABLE_ATTRIBUTE( attr, EFI_VARIABLE_NON_VOLATILE ):
        attr_str = attr_str + 'NV+'
    if IS_VARIABLE_ATTRIBUTE( attr, EFI_VARIABLE_BOOTSERVICE_ACCESS ):
        attr_str = attr_str + 'BS+'
    if IS_VARIABLE_ATTRIBUTE( attr, EFI_VARIABLE_RUNTIME_ACCESS ):
        attr_str = attr_str + 'RT+'
    if IS_VARIABLE_ATTRIBUTE( attr, EFI_VARIABLE_HARDWARE_ERROR_RECORD ):
        attr_str = attr_str + 'HER+'
    if IS_VARIABLE_ATTRIBUTE( attr, EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS ):
        attr_str = attr_str + 'AWS+'
    if IS_VARIABLE_ATTRIBUTE( attr, EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS ):
        attr_str = attr_str + 'TBAWS+'
    if IS_VARIABLE_ATTRIBUTE( attr, EFI_VARIABLE_APPEND_WRITE ):
        attr_str = attr_str + 'AW+'
    return attr_str[:-1].lstrip()



def print_efi_variable( offset, efi_var_buf, EFI_var_header, efi_var_name, efi_var_data, efi_var_guid, efi_var_attributes ):
        logger().log( '\n--------------------------------' )
        logger().log( 'EFI Variable (offset = 0x%x):' % offset )
        logger().log( '--------------------------------' )

        # Print Variable Name
        logger().log( 'Name      : %s' % efi_var_name )
        # Print Variable GUID
        logger().log( 'Guid      : %s' % efi_var_guid )

        # Print Variable State
        if EFI_var_header:
           if 'State' in EFI_var_header._fields:
              state = getattr(EFI_var_header, 'State')
              state_str = 'State     :'
              if IS_VARIABLE_STATE( state, VAR_IN_DELETED_TRANSITION ):
                 state_str = state_str + ' IN_DELETED_TRANSITION +'
              if IS_VARIABLE_STATE( state, VAR_DELETED ):
                 state_str = state_str + ' DELETED +'
              if IS_VARIABLE_STATE( state, VAR_ADDED ):
                 state_str = state_str + ' ADDED +'
              logger().log( state_str )
        
           # Print Variable Complete Header
           if logger().VERBOSE:
              if EFI_var_header.__str__:
                 logger().log( EFI_var_header )
              else:
                 logger().log( 'Decoded Header (%s):' % EFI_VAR_DICT[ self._FWType ]['name'] )
                 for attr in EFI_var_header._fields:
                    logger().log( '%s = %X' % ('{0:<16}'.format(attr), getattr(EFI_var_header, attr)) )
        
        attr_str = ('Attributes: 0x%X ( ' % efi_var_attributes) + get_attr_string( efi_var_attributes ) + ' )'
        logger().log( attr_str )
        
        # Print Variable Data
        logger().log( 'Data:' )
        print_buffer( efi_var_data )

        # Print Variable Full Contents
        if logger().VERBOSE:
           logger().log( 'Full Contents:' )
           print_buffer( efi_var_buf )


def print_sorted_EFI_variables( variables ):
    sorted_names = sorted(variables.keys())
    for name in sorted_names:
        for rec in variables[name]:
            #                   off,    buf,     hdr,         data,   guid,   attrs
            print_efi_variable( rec[0], rec[1], rec[2], name, rec[3], rec[4], rec[5] )

def decode_EFI_variables( efi_vars, nvram_pth ):
    # print decoded and sorted EFI variables into a log file
    print_sorted_EFI_variables( efi_vars )
    # write each EFI variable into its own binary file
    for name in efi_vars.keys():
        n = 0
        for (off, buf, hdr, data, guid, attrs) in efi_vars[name]:
            # efi_vars[name] = (off, buf, hdr, data, guid, attrs)
            attr_str = get_attr_string( attrs )
            var_fname = os.path.join( nvram_pth, '%s_%s_%s_%d.bin' % (name, guid, attr_str.strip(), n) )
            write_file( var_fname, data )
            #if name in SECURE_BOOT_VARIABLES:
            if name in AUTHENTICATED_VARIABLES:
                parse_efivar_file( var_fname, data )
            n = n+1


class UEFI:
    def __init__( self, helper ):
        self.helper = helper
        self._FWType = FWType.EFI_FW_TYPE_UEFI

    ######################################################################
    # FWType defines platform/BIOS dependent formats like 
    # format of EFI NVRAM, format of FV, etc.
    #
    # FWType chooses an element from the EFI_VAR_DICT Dictionary
    #
    # Default current platform type is EFI_FW_TYPE_UEFI
    ######################################################################

    def set_FWType( self, efi_nvram_format ):
        if efi_nvram_format in fw_types:
            self._FWType = efi_nvram_format


    ######################################################################
    # EFI NVRAM Parsing Functions
    ######################################################################

    def dump_EFI_variables_from_SPI( self ):
        return self.read_EFI_variables_from_SPI( 0, 0x800000 )

    def read_EFI_variables_from_SPI( self, BIOS_region_base, BIOS_region_size ):
        rom = spi.read_spi( BIOS_region_base, BIOS_region_size )
        efi_var_store = self.find_EFI_Variable_Store( rom )
        return self.read_EFI_NVRAM_variables( efi_var_store )

    def read_EFI_variables_from_file( self, filename ):
        rom = read_file( filename )
        efi_var_store = self.find_EFI_Variable_Store( rom )
        return self.read_EFI_NVRAM_variables( efi_var_store )

    def find_EFI_variable_store( self, rom_buffer ):
        if ( rom_buffer is None ):
            logger().error( 'rom_buffer is None' )
            return None
        # Meh..
        rom = "".join( rom_buffer )
        offset       = 0
        size         = len(rom_buffer)
        nvram_header = None

        if EFI_VAR_DICT[ self._FWType ]['func_getnvstore']:
           (offset, size, nvram_header) = EFI_VAR_DICT[ self._FWType ]['func_getnvstore']( rom )
           if (-1 == offset):
              logger().error( "'func_getnvstore' is defined but could not find EFI NVRAM. Exiting.." )
              return None
        else:
           logger().log( "[uefi] 'func_getnvstore' is not defined in EFI_VAR_DICT. Assuming start offset 0.." )

        if -1 == size: size = len(rom_buffer)
        nvram_buf = rom[ offset : offset + size ]

        if logger().UTIL_TRACE:
            logger().log( '[uefi] Found EFI NVRAM at offset 0x%08X' % offset )
            logger().log( """
==================================================================
NVRAM: EFI Variable Store
==================================================================""")
            if nvram_header: logger().log( nvram_header )
        return nvram_buf


    # @TODO: Do not use, will be removed
    def read_EFI_variables( self, efi_var_store, authvars ):
        if ( efi_var_store is None ):
           logger().error( 'efi_var_store is None' )
           return None
        variables = EFI_VAR_DICT[ self._FWType ]['func_getefivariables']( efi_var_store )
        if logger().UTIL_TRACE: print_sorted_EFI_variables( variables )
        return variables


    def parse_EFI_variables( self, fname, rom, authvars, _fw_type=None ):
        if _fw_type in fw_types:
           logger().log( "[uefi] Using FW type (NVRAM format): %s" % _fw_type )
           self.set_FWType( _fw_type )
        else:
           logger().error( "Unrecognized FW type (NVRAM format) '%s'.." % _fw_type )
           return False

        logger().log( "[uefi] Searching for NVRAM in the binary.." )
        efi_vars_store = self.find_EFI_variable_store( rom )
        if efi_vars_store:
           nvram_fname = fname + '.nvram.bin'
           write_file( nvram_fname, efi_vars_store )
           nvram_pth = fname + '.nvram.dir'
           if not os.path.exists( nvram_pth ):
               os.makedirs( nvram_pth )
           logger().log( "[uefi] Extracting EFI Variables in the NVRAM.." )
           efi_vars = EFI_VAR_DICT[ self._FWType ]['func_getefivariables']( efi_vars_store )
           decode_EFI_variables( efi_vars, nvram_pth )
        else:
           logger().error( "Did not find NVRAM" )
           return False

        return True


    ######################################################################
    # Runtime Variable API Functions
    ######################################################################

    def list_EFI_variables( self ):
        return self.helper.list_EFI_variables()

    def get_EFI_variable( self, name, guid, filename=None ):
        var = self.helper.get_EFI_variable( name, guid )
        if var:
           if filename: write_file( filename, var )
           if logger().UTIL_TRACE or logger().VERBOSE:
              logger().log( '[uefi] EFI variable:' )
              logger().log( 'Name: %s' % name )
              logger().log( 'GUID: %s' % guid )
              logger().log( 'Data:' )
              print_buffer( var )
        return var

    def set_EFI_variable( self, name, guid, var, attrs=None ):
        if logger().UTIL_TRACE or logger().VERBOSE:
           logger().log( '[uefi] Writing EFI variable:' )
           logger().log( 'Name: %s' % name )
           logger().log( 'GUID: %s' % guid )
           if attrs is not None: logger().log( 'Attributes: %s' % attrs )
           #print_buffer( var )
        return self.helper.set_EFI_variable( name, guid, var, attrs )

    def set_EFI_variable_from_file( self, name, guid, filename, attrs=None ):
        if filename is None:
           logger().error( 'File with EFI variable is not specified' )
           return False
        var = read_file( filename )
        return self.set_EFI_variable( name, guid, var, attrs )

    def delete_EFI_variable( self, name, guid, attrs=None ):
        if logger().UTIL_TRACE or logger().VERBOSE:
           logger().log( '[uefi] Deleting EFI variable:' )
           logger().log( 'Name: %s' % name )
           logger().log( 'GUID: %s' % guid )
           if attrs is not None: logger().log( 'Attributes: %s' % attrs )
        return self.helper.set_EFI_variable( name, guid, None, attrs )



