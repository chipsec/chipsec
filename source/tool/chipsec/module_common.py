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


## \addtogroup core
# __chipsec/module_common.py__ -- common include file for modules
#
#

import platform
import string
import sys
import os
from time import localtime, strftime

import chipsec.logger
import chipsec.chipset
cs = chipsec.chipset.cs()             #\TODO: remove
logger = chipsec.logger.logger()      #\TODO: remove
from chipsec.cfg.common      import * #\TODO: remove


class BaseModule( object ):
    def __init__(self):
        self.cs = chipsec.chipset.cs()
        self.logger = chipsec.logger.logger()

    # This method should be overwritten by the module returning True or False
    # depending wether or not this module is supported in the currently running
    # platform.
    # To access the currently running platform use
    #    self.cs.code
    def is_supported(self):
        raise NotImplementedError('sub class should overwrite this method')
    
    def run( self, module_argv ):
        raise NotImplementedError('sub class should overwrite this method')


MTAG_BIOS       = "BIOS"
MTAG_SMM        = "SMM"
MTAG_SECUREBOOT = "SECUREBOOT"
 


##! [Available Tags]
MTAG_METAS = {
              MTAG_BIOS:      "System firmware (BIOS/UEFI) specific tests", 
              MTAG_SMM:       "System Management Mode (SMM) specific tests",
              MTAG_SECUREBOOT: "Secure Boot specific tests",
              }
##! [Available Tags]
MODULE_TAGS = dict( [(_tag, []) for _tag in MTAG_METAS])


class ModuleResult:
    FAILED  = 0
    PASSED  = 1
    WARNING = 2
    SKIPPED = 3
    DEPRECATED = 4
    ERROR   = -1

