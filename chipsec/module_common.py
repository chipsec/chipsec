#!/usr/bin/python
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
Common include file for modules
"""

import platform
import string
import sys
import os
from time import localtime, strftime

import chipsec.logger
import chipsec.chipset
import chipsec.defines

class ModuleResult:
    FAILED        = 0
    PASSED        = 1
    WARNING       = 2
    SKIPPED       = 3
    DEPRECATED    = 4
    INFORMATION   = 5
    NOTAPPLICABLE = 6
    ERROR         = -1


ModuleResultName = {
    ModuleResult.FAILED:        "Failed",
    ModuleResult.PASSED:        "Passed",
    ModuleResult.WARNING:       "Warning",
    ModuleResult.SKIPPED:       "Skipped",
    ModuleResult.DEPRECATED:    "Deprecated",
    ModuleResult.INFORMATION:   "Information",
    ModuleResult.ERROR:         "Error",
    ModuleResult.NOTAPPLICABLE: "NotApplicable"
}
def getModuleResultName(res):
    return ModuleResultName[res] if res in ModuleResultName else ModuleResultName[ModuleResult.ERROR]

class BaseModule(object):
    def __init__(self):
        self.cs = chipsec.chipset.cs()
        self.logger = chipsec.logger.logger()
        self.res = ModuleResult.PASSED

    def is_supported(self):
        """
        This method should be overwritten by the module returning True or False
        depending whether or not this module is supported in the currently running
        platform.
        To access the currently running platform use

        """
        return True

    def update_res(self, value):
        if self.res == ModuleResult.WARNING:
            if value == ModuleResult.FAILED \
            or value == ModuleResult.ERROR:
                self.res = value
        elif self.res == ModuleResult.FAILED:
            if value == ModuleResult.ERROR:
                self.res = value
        elif self.res == ModuleResult.INFORMATION:
            self.res = value
        else: # PASSED or SKIPPED or DEPRECATED or NOTAPPLICABLE
            self.res = value

    def run(self, module_argv):
        raise NotImplementedError('sub class should overwrite the run() method')


MTAG_BIOS       = "BIOS"
MTAG_SMM        = "SMM"
MTAG_SECUREBOOT = "SECUREBOOT"
MTAG_HWCONFIG   = "HWCONFIG"
MTAG_CPU        = "CPU"


##! [Available Tags]
MTAG_METAS = {
              MTAG_BIOS:       "System Firmware (BIOS/UEFI) Modules",
              MTAG_SMM:        "System Management Mode (SMM) Modules",
              MTAG_SECUREBOOT: "Secure Boot Modules",
              MTAG_HWCONFIG:   "Hardware Configuration Modules",
              MTAG_CPU:        "CPU Modules",
              }
##! [Available Tags]
MODULE_TAGS = dict( [(_tag, []) for _tag in MTAG_METAS])

#
# Common module command line options
#
OPT_MODIFY = 'modify'

#
# Python 2/3 compatible input
#
def cs_input(msg):
    if sys.version[0] == '2':
        return raw_input(msg)
    else:
        return input(msg)
