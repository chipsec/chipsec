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
cs.add_available_module(_MODULE_NAME, 'COMMON')

TAGS = [MTAG_SECUREBOOT]

class keys(BaseModule):
    SECURE = 0x1
    INSECURE = 0x2
    ERROR = 0x4
    
    def __init__(self):
        BaseModule.__init__(self)
        self._uefi  = UEFI( self.cs.helper )
    
            
    
    def check_EFI_variable_authentication( self, name, guid ):
        self.logger.log( "[*] Checking EFI variable %s {%s}.." % (name, guid) )
        orig_var = self._uefi.get_EFI_variable( name, guid, None )
        if not orig_var:
            self.logger.log( "[*] EFI variable %s {%s} doesn't exist" % (name, guid) )
            return keys.ERROR
        fname = name + '_' + guid + '.bin'
        if self.logger.VERBOSE: write_file( fname, orig_var )
        origvar_len = len(orig_var)
        mod_var = chr( ord(orig_var[0]) ^ 0xFF ) + orig_var[1:] 
        if origvar_len > 1: mod_var = mod_var[:origvar_len-1] + chr( ord(mod_var[origvar_len-1]) ^ 0xFF )
        if self.logger.VERBOSE: write_file( fname + '.mod', mod_var )
        status = self._uefi.set_EFI_variable( name, guid, mod_var )
        if not status: self.logger.log( '[*] Writing EFI variable %s did not succeed. Verifying contents..' % name )
        new_var = self._uefi.get_EFI_variable( name, guid, None )
        if self.logger.VERBOSE: write_file( fname + '.new', new_var )
        ok = (origvar_len == len(new_var))
        for i in range( origvar_len ):
            if not (new_var[i] == orig_var[i]):
                ok = keys.INSECURE
                break
        if ok == keys.INSECURE:
            self.logger.log_bad( "EFI variable %s is not protected! It has been modified. Restoring original contents.." % name )
            self._uefi.set_EFI_variable( name, guid, orig_var )
        else:                                                                     
            self.logger.log_good( "Could not modify EFI variable %s {%s}" % (name, guid) )
        return ok
    
    # checks authentication of Secure Boot EFI variables
    def check_secureboot_key_variables(self):
        sts = 0
        sts |= self.check_EFI_variable_authentication( EFI_VAR_NAME_PK,         EFI_VARIABLE_DICT[EFI_VAR_NAME_PK]         )
        sts |= self.check_EFI_variable_authentication( EFI_VAR_NAME_KEK,        EFI_VARIABLE_DICT[EFI_VAR_NAME_KEK]        )
        sts |= self.check_EFI_variable_authentication( EFI_VAR_NAME_db,         EFI_VARIABLE_DICT[EFI_VAR_NAME_db]         )
        sts |= self.check_EFI_variable_authentication( EFI_VAR_NAME_dbx,        EFI_VARIABLE_DICT[EFI_VAR_NAME_dbx]        )
        sts |= self.check_EFI_variable_authentication( EFI_VAR_NAME_SecureBoot, EFI_VARIABLE_DICT[EFI_VAR_NAME_SecureBoot] )
        sts |= self.check_EFI_variable_authentication( EFI_VAR_NAME_SetupMode,  EFI_VARIABLE_DICT[EFI_VAR_NAME_SetupMode]  )
        #sts |= self.check_EFI_variable_authentication( EFI_VAR_NAME_CustomMode, EFI_VARIABLE_DICT[EFI_VAR_NAME_CustomMode] )
        if (sts & keys.ERROR) != 0: self.logger.log_important( "Some Secure Boot variables don't exist" )
    
        ok = ((sts & keys.INSECURE) == 0)
        self.logger.log('')
        if ok: self.logger.log_passed_check( 'All existing Secure Boot EFI variables seem to be protected' )
        else:  self.logger.log_failed_check( 'One or more Secure Boot variables are not protected' )
        return ok
    
    
    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run( self, module_argv ):
        #self.logger.VERBOSE = True
        self.logger.start_test( "Protection of Secure Boot Key and Configuraion EFI Variables" )
        if not (self.cs.helper.is_win8_or_greater() or self.cs.helper.is_linux()):
            self.logger.log_skipped_check( 'Currently this module can only run on Windows 8 or greater or Linux. Exiting..' )
            return ModuleResult.SKIPPED
        return self.check_secureboot_key_variables()
   
