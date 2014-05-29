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
# __chipsec/modules/secureboot/variables.py__ - verify that all EFI variables containing Secure Boot keys/databases are authenticated


from chipsec.module_common import *

from chipsec.file          import *
from chipsec.hal.uefi      import *

# ############################################################
# SPECIFY PLATFORMS THIS MODULE IS APPLICABLE TO
# ############################################################
_MODULE_NAME = 'variables'
cs.add_available_module(_MODULE_NAME, 'COMMON')
TAGS = [MTAG_SECUREBOOT]

class variables(BaseModule):
    
    def __init__(self):
        BaseModule.__init__(self)
        self._uefi  = UEFI( self.cs.helper )
    
    
    ## check_secureboot_variable_attributes
    # checks authentication attributes of Secure Boot EFI variables
    def check_secureboot_variable_attributes( self ):
        res = ModuleResult.PASSED
        error = False
        sbvars = self._uefi.list_EFI_variables()
        if sbvars is None:
            self.logger.log_error_check( 'Could not enumerate UEFI Variables from runtime (Legacy OS?)' )
            self.logger.log_important( "Note that the Secure Boot UEFI variables may still exist, OS just did not expose runtime UEFI Variable API to read them. You can extract Secure Boot variables directly from ROM file via 'chipsec_util.py uefi nvram bios.bin' command and verify their attributes" )
            return ModuleResult.ERROR
    
        for name in SECURE_BOOT_KEY_VARIABLES:
            if name in sbvars.keys() and sbvars[name] is not None:
                if len(sbvars[name]) > 1:
                    self.logger.log_failed_check( 'There should only one instance of Secure Boot variable %s exist' % name )
                    return ModuleResult.FAILED
                for (off, buf, hdr, data, guid, attrs) in sbvars[name]:
                    if   IS_VARIABLE_ATTRIBUTE( attrs, EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS ):
                        self.logger.log_good( 'Secure Boot variable %s is AUTHENTICATED_WRITE_ACCESS' % name )
                    elif IS_VARIABLE_ATTRIBUTE( attrs, EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS ):
                        self.logger.log_good( 'Secure Boot variable %s is TIME_BASED_AUTHENTICATED_WRITE_ACCESS' % name )
                    else:
                        res = ModuleResult.FAILED
                        self.logger.log_bad( 'Secure Boot variable %s is not authenticated' % name )
            else:
                self.logger.log_important('Secure Boot variable %s is not found!' % name )
                error = True
    
        if error: return ModuleResult.ERROR
        if   ModuleResult.PASSED == res: self.logger.log_passed_check( 'All Secure Boot EFI variables are authenticated' )
        elif ModuleResult.FAILED == res: self.logger.log_failed_check( 'Not all Secure Boot variables are authenticated' )
        return res
    
    
    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run( self,  module_argv ):
        self.logger.start_test( "Attributes of Secure Boot EFI Variables" )
        if not (self.cs.helper.is_win8_or_greater() or self.cs.helper.is_linux()):
            self.logger.log_skipped_check( 'Currently this module can only run on Windows 8 or higher or Linux. Exiting..' )
            return ModuleResult.SKIPPED
        return self.check_secureboot_variable_attributes()
