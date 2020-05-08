#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2020, Intel Corporation
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
`UEFI 2.4 spec Section 28 <http://uefi.org/>`_

Verify that all Secure Boot key/whitelist/blacklist UEFI variables are authenticated (BS+RT+AT)
and protected from unauthorized modification.

Use '-a modify' option for the module to also try to write/corrupt the variables.

"""


from chipsec.module_common import BaseModule, ModuleResult, MTAG_SECUREBOOT, OPT_MODIFY
from chipsec.hal.uefi import UEFI, SECURE_BOOT_VARIABLES, IS_VARIABLE_ATTRIBUTE, EFI_VAR_NAME_SecureBoot, SECURE_BOOT_KEY_VARIABLES
from chipsec.hal.uefi import EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS, EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS
from chipsec.hal.uefi_common import StatusCode

# ############################################################
# SPECIFY PLATFORMS THIS MODULE IS APPLICABLE TO
# ############################################################
_MODULE_NAME = 'variables'


TAGS = [MTAG_SECUREBOOT]


class variables(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)
        self._uefi  = UEFI( self.cs )

    def is_supported( self ):
        supported = self.cs.helper.EFI_supported()
        if not supported: self.logger.log_skipped_check( "OS does not support UEFI Runtime API" )
        return supported


    def can_modify( self, name, guid, data, attrs ):
        self.logger.log( "    > attempting to modify variable {}:{}".format(guid,name) )
        datalen = len(data)
        #print_buffer( data )

        baddata = chr( ord(data[0]) ^ 0xFF ) + data[1:]
        #if datalen > 1: baddata = baddata[:datalen-1] + chr( ord(baddata[datalen-1]) ^ 0xFF )
        status = self._uefi.set_EFI_variable( name, guid, baddata )
        if StatusCode.EFI_SUCCESS != status: self.logger.log( '    < modification of {} returned error 0x{:X}'.format(name,status) )
        else: self.logger.log( '    < modification of {} returned succees'.format(name) )

        self.logger.log( '    > checking variable {} contents after modification..'.format(name) )
        newdata = self._uefi.get_EFI_variable( name, guid )

        #print_buffer( newdata )
        #chipsec.file.write_file( name+'_'+guid+'.bin', data )
        #chipsec.file.write_file( name+'_'+guid+'.bin.bad', baddata )
        #chipsec.file.write_file( name+'_'+guid+'.bin.new', newdata )

        _changed = (data != newdata)
        if _changed:
            self.logger.log_bad( "EFI variable {} has been modified. Restoring original contents..".format(name) )
            self._uefi.set_EFI_variable( name, guid, data )
            # checking if restored correctly
            restoreddata = self._uefi.get_EFI_variable( name, guid )
            #print_buffer( restoreddata )
            if (restoreddata != data): self.logger.error( "Failed to restore contents of variable {} failed!".format(name) )
            else:                      self.logger.log( "    contents of variable {} have been restored".format(name) )
        else:
            self.logger.log_good( "Could not modify UEFI variable {}:{}".format(guid,name) )
        return _changed

    ## check_secureboot_variable_attributes
    # checks authentication attributes of Secure Boot EFI variables
    def check_secureboot_variable_attributes( self, do_modify ):
        res       = ModuleResult.ERROR
        not_found = 0
        not_auth  = 0
        not_wp    = 0
        is_secureboot_enabled = False

        sbvars = self._uefi.list_EFI_variables()
        if sbvars is None:
            self.logger.log_warn_check( 'Could not enumerate UEFI variables.' )
            return ModuleResult.SKIPPED

        for name in SECURE_BOOT_VARIABLES:

            if name in sbvars.keys() and sbvars[name] is not None:
                if len(sbvars[name]) > 1:
                    self.logger.log_failed_check( 'There should only be one instance of variable {}'.format(name) )
                    return ModuleResult.FAILED
                for (off, buf, hdr, data, guid, attrs) in sbvars[name]:
                    self.logger.log( "[*] Checking protections of UEFI variable {}:{}".format(guid,name) )

                    # check the status of Secure Boot
                    if EFI_VAR_NAME_SecureBoot == name:
                        is_secureboot_enabled = (data is not None and len(data) == 1 and ord(data) == 0x1)

                    #
                    # Verify if the Secure Boot key/database variable is authenticated
                    #
                    if name in SECURE_BOOT_KEY_VARIABLES:
                        if IS_VARIABLE_ATTRIBUTE( attrs, EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS ):
                            self.logger.log_good( 'Variable {}:{} is authenticated (AUTHENTICATED_WRITE_ACCESS)'.format(guid,name) )
                        elif IS_VARIABLE_ATTRIBUTE( attrs, EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS ):
                            self.logger.log_good( 'Variable {}:{} is authenticated (TIME_BASED_AUTHENTICATED_WRITE_ACCESS)'.format(guid,name) )
                        else:
                            not_auth += 1
                            self.logger.log_bad( 'Variable {}:{} is not authenticated'.format(guid,name) )

                    #
                    # Attempt to modify contents of the variables
                    #
                    if do_modify:
                        if self.can_modify( name, guid, data, attrs ): not_wp += 1

            else:
                not_found += 1
                self.logger.log_important( 'Secure Boot variable {} is not found'.format(name) )
                continue

        self.logger.log( '' )
        self.logger.log( '[*] Secure Boot appears to be {}abled'.format('en' if is_secureboot_enabled else 'dis') )

        if len(SECURE_BOOT_VARIABLES) == not_found:
            # None of Secure Boot variables were not found
            self.logger.log_skipped_check( 'None of required Secure Boot variables found. Secure Boot is not enabled' )
            return ModuleResult.SKIPPED
        else:
            # Some Secure Boot variables exist
            sb_vars_failed = (not_found > 0) or (not_auth > 0) or (not_wp > 0)
            if sb_vars_failed:
                if not_found > 0: self.logger.log_bad( "Some required Secure Boot variables are missing" )
                if not_auth  > 0: self.logger.log_bad( 'Some Secure Boot keying variables are not authenticated' )
                if not_wp    > 0: self.logger.log_bad( 'Some Secure Boot variables can be modified' )

                if is_secureboot_enabled:
                    self.logger.log_failed_check( 'Not all Secure Boot UEFI variables are protected' )
                    return ModuleResult.FAILED
                else:
                    self.logger.log_warn_check( 'Not all Secure Boot UEFI variables are protected' )
                    return ModuleResult.WARNING

            else:
                self.logger.log_passed_check( 'All Secure Boot UEFI variables are protected' )
                return ModuleResult.PASSED


    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run( self,  module_argv ):
        self.logger.start_test( "Attributes of Secure Boot EFI Variables" )
        do_modify = (len(module_argv) > 0 and module_argv[0] == OPT_MODIFY)
        return self.check_secureboot_variable_attributes( do_modify )
