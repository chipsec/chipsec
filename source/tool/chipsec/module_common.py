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

from chipsec.logger  import *
from chipsec.chipset import *

#
# Instace of Chipset class to be used by all modules
#
cs = cs()

def init ():
    #
    # Import platform configuration defines in the following order:
    # 1. chipsec.cfg.common (imported in chipsec.chipset)
    # 2. chipsec.cfg.<platform>
    #
    #from chipsec.cfg.common import *
    if cs.code and '' != cs.code:
        try:
            exec 'from chipsec.cfg.' + cs.code + ' import *'
            logger().log_good( "imported platform specific configuration: chipsec.cfg.%s" % cs.code )
        except ImportError, msg:
            if logger().VERBOSE: logger().log( "[*] Couldn't import chipsec.cfg.%s" % cs.code )


#
# Instace of Logger class to be used by all modules
#
#logger = logger()

AVAILABLE_MODULES = dict( [(Chipset_Dictionary[ _did ]['id'], []) for _did in Chipset_Dictionary] )
AVAILABLE_MODULES[ CHIPSET_ID_COMMON ] = []

DISABLED_MODULES = dict( [(Chipset_Dictionary[ _did ]['id'], []) for _did in Chipset_Dictionary] )
DISABLED_MODULES[ CHIPSET_ID_COMMON ] = []


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

USER_MODULE_TAGS = []

class ModuleResult:
    FAILED  = 0
    PASSED  = 1
    WARNING = 2
    SKIPPED = 3
    ERROR   = -1

