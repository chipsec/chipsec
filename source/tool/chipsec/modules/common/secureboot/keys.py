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




## \addtogroup modules
# __chipsec/modules/secureboot/keys.py__ - verify protections of Secure Boot key EFI variables


from chipsec.module_common import *

from chipsec.file          import *
from chipsec.hal.uefi      import *

# ############################################################
# SPECIFY PLATFORMS THIS MODULE IS APPLICABLE TO
# ############################################################
_MODULE_NAME = 'keys'
AVAILABLE_MODULES[ CHIPSET_ID_COMMON ].append( _MODULE_NAME )
TAGS = [MTAG_SECUREBOOT]


logger = logger()
_uefi  = UEFI( cs.helper )

SECURE = 0x1
INSECURE = 0x2
ERROR = 0x4

def check_EFI_variable_authentication( name, guid ):
    logger.log( "[*] Checking EFI variable %s {%s}.." % (name, guid) )
    orig_var = _uefi.get_EFI_variable( name, guid, None )
    if not orig_var:
        logger.log( "[*] EFI variable %s {%s} doesn't exist" % (name, guid) )
        return ERROR
    fname = name + '_' + guid + '.bin'
    if logger.VERBOSE: write_file( fname, orig_var )
    origvar_len = len(orig_var)
    mod_var = chr( ord(orig_var[0]) ^ 0xFF ) + orig_var[1:] 
    if origvar_len > 1: mod_var = mod_var[:origvar_len-1] + chr( ord(mod_var[origvar_len-1]) ^ 0xFF )
    if logger.VERBOSE: write_file( fname + '.mod', mod_var )
    status = _uefi.set_EFI_variable( name, guid, mod_var )
    if not status: logger.log( '[*] Writing EFI variable %s did not succeed. Verifying contents..' % name )
    new_var = _uefi.get_EFI_variable( name, guid, None )
    if logger.VERBOSE: write_file( fname + '.new', new_var )
    ok = (origvar_len == len(new_var))
    for i in range( origvar_len ):
        if not (new_var[i] == orig_var[i]):
            ok = INSECURE
            break
    if ok == INSECURE:
        logger.log_bad( "EFI variable %s is not protected! It has been modified. Restoring original contents.." % name )
        _uefi.set_EFI_variable( name, guid, orig_var )
    else:                                                                     
        logger.log_good( "Could not modify EFI variable %s {%s}" % (name, guid) )
    return ok

# checks authentication of Secure Boot EFI variables
def check_secureboot_key_variables():
    sts = 0
    sts |= check_EFI_variable_authentication( EFI_VAR_NAME_PK,         EFI_VARIABLE_DICT[EFI_VAR_NAME_PK]         )
    sts |= check_EFI_variable_authentication( EFI_VAR_NAME_KEK,        EFI_VARIABLE_DICT[EFI_VAR_NAME_KEK]        )
    sts |= check_EFI_variable_authentication( EFI_VAR_NAME_db,         EFI_VARIABLE_DICT[EFI_VAR_NAME_db]         )
    sts |= check_EFI_variable_authentication( EFI_VAR_NAME_dbx,        EFI_VARIABLE_DICT[EFI_VAR_NAME_dbx]        )
    sts |= check_EFI_variable_authentication( EFI_VAR_NAME_SecureBoot, EFI_VARIABLE_DICT[EFI_VAR_NAME_SecureBoot] )
    sts |= check_EFI_variable_authentication( EFI_VAR_NAME_SetupMode,  EFI_VARIABLE_DICT[EFI_VAR_NAME_SetupMode]  )
    #sts |= check_EFI_variable_authentication( EFI_VAR_NAME_CustomMode, EFI_VARIABLE_DICT[EFI_VAR_NAME_CustomMode] )
    if (sts & ERROR) != 0: logger.log_important( "Some Secure Boot variables don't exist" )

    ok = ((sts & INSECURE) == 0)
    logger.log('')
    if ok: logger.log_passed_check( 'All existing Secure Boot EFI variables seem to be protected' )
    else:  logger.log_failed_check( 'One or more Secure Boot variables are not protected' )
    return ok


# --------------------------------------------------------------------------
# run( module_argv )
# Required function: run here all tests from this module
# --------------------------------------------------------------------------
def run( module_argv ):
    #logger.VERBOSE = True
    logger.start_test( "Protection of Secure Boot Key and Configuraion EFI Variables" )
    if not (cs.helper.is_win8_or_greater() or cs.helper.is_linux()):
        logger.log_skipped_check( 'Currently this module can only run on Windows 8 or greater or Linux. Exiting..' )
        return ModuleResult.SKIPPED
    return check_secureboot_key_variables()
   
