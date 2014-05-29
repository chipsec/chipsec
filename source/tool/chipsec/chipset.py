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
# __chipsec/chipset.py__ -- Contains platform identification functions
#
#

__version__ = '1.0'

import sys
import collections

from chipsec.helper.oshelper import OsHelper, OsHelperError
from chipsec.hal.pci         import Pci
from chipsec.hal.physmem     import Memory
from chipsec.hal.msr         import Msr
from chipsec.hal.ucode       import Ucode
from chipsec.hal.io          import PortIO
from chipsec.hal.cpuid       import CpuID

from chipsec.cfg.common      import Cfg 
from chipsec.logger         import logger


#_importlib = True
#try:                import importlib
#except ImportError: _importlib = False

#


##################################################################################
# Functionality defining current chipset
##################################################################################
CHIPSET_ID_COMMON  = -1
CHIPSET_ID_UNKNOWN = 0

CHIPSET_ID_SNB     = 1
CHIPSET_ID_JKT     = 2
CHIPSET_ID_IVB     = 3
CHIPSET_ID_IVT     = 4
CHIPSET_ID_HSW     = 5
CHIPSET_ID_BYT     = 6

CHIPSET_CODE_COMMON  = 'COMMON'
CHIPSET_CODE_UNKNOWN = ''

CHIPSET_CODE_SNB     = 'SNB'
CHIPSET_CODE_JKT     = 'JKT'
CHIPSET_CODE_IVB     = 'IVB'
CHIPSET_CODE_IVT     = 'IVT'
CHIPSET_CODE_HSW     = 'HSW'
CHIPSET_CODE_BYT     = 'BYT'


VID_INTEL = 0x8086

# PCI 0/0/0 Device IDs
Chipset_Dictionary = {
# DID  : Data Dictionary

# 2nd Generation Core Processor Family (Sandy Bridge)
0x0100 : {'name' : 'Sandy Bridge',   'id' : CHIPSET_ID_SNB , 'code' : CHIPSET_CODE_SNB,  'longname' : 'Desktop 2nd Generation Core Processor (Sandy Bridge CPU / Cougar Point PCH)' },
0x0104 : {'name' : 'Sandy Bridge',   'id' : CHIPSET_ID_SNB , 'code' : CHIPSET_CODE_SNB,  'longname' : 'Mobile 2nd Generation Core Processor (Sandy Bridge CPU / Cougar Point PCH)' },
0x0108 : {'name' : 'Sandy Bridge',   'id' : CHIPSET_ID_SNB , 'code' : CHIPSET_CODE_SNB,  'longname' : 'Intel Xeon Processor E3-1200 (Sandy Bridge CPU, C200 Series PCH)' },

0x3C00 : {'name' : 'Jaketown',       'id' : CHIPSET_ID_JKT,  'code' : CHIPSET_CODE_JKT,  'longname' : 'Server 2nd Generation Core Processor (Jaketown CPU / Patsburg PCH)'},

# 3rd Generation Core Processor Family (Ivy Bridge)
0x0150 : {'name' : 'Ivy Bridge',     'id' : CHIPSET_ID_IVB , 'code' : CHIPSET_CODE_IVB,  'longname' : 'Desktop 3rd Generation Core Processor (Ivy Bridge CPU / Panther Point PCH)' },
0x0154 : {'name' : 'Ivy Bridge',     'id' : CHIPSET_ID_IVB , 'code' : CHIPSET_CODE_IVB,  'longname' : 'Mobile 3rd Generation Core Processor (Ivy Bridge CPU / Panther Point PCH)' },
0x0158 : {'name' : 'Ivy Bridge',     'id' : CHIPSET_ID_IVB , 'code' : CHIPSET_CODE_IVB,  'longname' : 'Intel Xeon Processor E3-1200 v2 (Ivy Bridge CPU, C200/C216 Series PCH)' },

0x0E00 : {'name' : 'Ivytown',        'id' : CHIPSET_ID_IVT,  'code' : CHIPSET_CODE_IVT,  'longname' : 'Server 3rd Generation Core Procesor (Ivytown CPU / Patsburg PCH)'},

# 4th Generation Core Processor Family (Haswell)
0x0C00 : {'name' : 'Haswell',        'id' : CHIPSET_ID_HSW , 'code' : CHIPSET_CODE_HSW,  'longname' : 'Desktop 4th Generation Core Processor (Haswell CPU / Lynx Point PCH)' },
0x0C04 : {'name' : 'Haswell',        'id' : CHIPSET_ID_HSW , 'code' : CHIPSET_CODE_HSW,  'longname' : 'Mobile 4th Generation Core Processor (Haswell M/H / Lynx Point PCH)' },
0x0C08 : {'name' : 'Haswell',        'id' : CHIPSET_ID_HSW , 'code' : CHIPSET_CODE_HSW,  'longname' : 'Intel Xeon Processor E3-1200 v3 (Haswell CPU, C220 Series PCH)' },
0x0A00 : {'name' : 'Haswell',        'id' : CHIPSET_ID_HSW , 'code' : CHIPSET_CODE_HSW,  'longname' : '4th Generation Core Processor (Haswell U/Y)' },
0x0A04 : {'name' : 'Haswell',        'id' : CHIPSET_ID_HSW , 'code' : CHIPSET_CODE_HSW,  'longname' : '4th Generation Core Processor (Haswell U/Y)' },
0x0A08 : {'name' : 'Haswell',        'id' : CHIPSET_ID_HSW , 'code' : CHIPSET_CODE_HSW,  'longname' : '4th Generation Core Processor (Haswell U/Y)' },

# Bay Trail SoC
0x0F00 : {'name' : 'Baytrail',       'id' : CHIPSET_ID_BYT , 'code' : CHIPSET_CODE_BYT,  'longname' : 'Bay Trail' },

}
try:
    from custom_chipsets import *
except :
    pass
 
Chipset_Code = dict( [(Chipset_Dictionary[ _did ]['code'], _did) for _did in Chipset_Dictionary] )

def print_supported_chipsets():
    codes_dict = collections.defaultdict(list)
    for _did in Chipset_Dictionary: codes_dict[ Chipset_Dictionary[ _did ]['code'] ].append( _did )
    logger().log( "\nSupported platforms:\n" )
    logger().log( "DID     | Name           | Code   | Long Name" )
    logger().log( "-------------------------------------------------------------------------------------" )
    for _code in sorted(codes_dict):    
        for _did in codes_dict[_code]:
            logger().log( " %-#6x | %-14s | %-6s | %-40s" % (_did, Chipset_Dictionary[_did]['name'], _code.lower(), Chipset_Dictionary[_did]['longname']) )


AVAILABLE_MODULES = dict( [(Chipset_Dictionary[ _did ]['id'], []) for _did in Chipset_Dictionary] )
AVAILABLE_MODULES[ CHIPSET_ID_COMMON ] = []

DISABLED_MODULES = dict( [(Chipset_Dictionary[ _did ]['id'], []) for _did in Chipset_Dictionary] )
DISABLED_MODULES[ CHIPSET_ID_COMMON ] = []


class UnknownChipsetError (RuntimeError):
    pass

class Chipset:

    def __init__(self, helper=None):
        if helper is None:
            self.helper = OsHelper()
        else:
            self.helper = helper

        self.vid        = 0
        self.did        = 0
        self.code       = CHIPSET_CODE_UNKNOWN
        self.longname   = "Unrecognized Platform"
        self.id         = CHIPSET_ID_UNKNOWN
        self.Cfg        = Cfg()

        #
        # Initializing 'basic primitive' HAL components
        # (HAL components directly using native OS helper functionality)
        #
        self.pci    	= Pci      ( self.helper )
        self.mem    	= Memory   ( self.helper )
        self.msr    	= Msr      ( self.helper )
        self.ucode  	= Ucode    ( self.helper )
        self.io     	= PortIO   ( self.helper )
        self.cpuid      = CpuID    ( self.helper )
        #
        # All HAL components which use above 'basic primitive' HAL components
        # should be instantiated in modules/utilcmd with an instance of chipset
        # Example of initializing second order HAL component (UEFI in uefi_cmd.py):
        # cs = cs()
        # self.uefi = UEFI( cs )
        #

    def init( self, platform_code, start_svc ):

        if start_svc: self.helper.start()

        if not platform_code:
            vid_did  = self.pci.read_dword( 0, 0, 0, 0 )
            self.vid = vid_did & 0xFFFF
            self.did = (vid_did >> 16) & 0xFFFF
            if VID_INTEL != self.vid: raise UnknownChipsetError, ('UnsupportedPlatform: Vendor ID = 0x%04X' % self.vid)
        else:
            if Chipset_Code.has_key( platform_code ): self.code = platform_code.lower()
            else: raise UnknownChipsetError, ('UnsupportedPlatform: code: %s' % platform_code)
            self.vid      = VID_INTEL
            self.did      = Chipset_Code[ platform_code ]

        if Chipset_Dictionary.has_key( self.did ):
            data_dict       = Chipset_Dictionary[ self.did ]
            self.code       = data_dict['code'].lower()
            self.longname   = data_dict['longname']
            self.id         = data_dict['id']
        else:
            raise UnknownChipsetError, ('UnsupportedPlatform: Device ID = 0x%04X' % self.did)
        self.init_cfg()
        
    def init_cfg(self):
        if self.code and '' != self.code:
            try:
                exec 'from chipsec.cfg.' + self.code + ' import *'
                logger().log_good( "imported platform specific configuration: chipsec.cfg.%s" % self.code )
                exec 'self.Cfg = ' +self.code + '()'
            except ImportError, msg:
                if logger().VERBOSE: logger().log( "[*] Couldn't import chipsec.cfg.%s\n%s" % ( self.code, str(msg) ) )


    def destroy( self, start_svc ):
        self.stop( start_svc )
        #self.helper.destroy()

    def stop( self, start_svc ):
        if start_svc:
            self.helper.stop()

    def get_chipset_id(self):
        return self.id

    def get_chipset_code(self):
        return self.code

    def get_chipset_name(self, id ):
        return self.longname


    def print_chipset(self):
        logger().log( "Platform: %s\n          VID: %04X\n          DID: %04X" % (self.longname, self.vid, self.did))
    
    def add_available_module(self, module_name, platform_code):
        chipset_id = CHIPSET_ID_UNKNOWN
        if Chipset_Code.has_key( platform_code ):
            chipset_id = Chipset_Dictionary[ Chipset_Code[ platform_code] ]['id']
        elif platform_code == CHIPSET_CODE_COMMON:
            chipset_id = CHIPSET_ID_COMMON
        AVAILABLE_MODULES[ chipset_id ].append( module_name )
        #print AVAILABLE_MODULES

from chipsec.helper.oshelper import helper
_chipset = Chipset( helper() )
def cs():
    return _chipset



