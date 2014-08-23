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
import os
import fnmatch
import re

from chipsec.helper.oshelper import OsHelper, OsHelperError
from chipsec.hal.pci         import Pci
from chipsec.hal.physmem     import Memory
from chipsec.hal.msr         import Msr
from chipsec.hal.ucode       import Ucode
from chipsec.hal.io          import PortIO
from chipsec.hal.cpuid       import CpuID
from chipsec.hal.mmio        import *

from chipsec.cfg.common      import Cfg 
from chipsec.logger         import logger

import chipsec.file

import importlib
#_importlib = True
#try:                import importlib
#except ImportError: _importlib = False

#


class RegisterType:
  PCICFG = 'pcicfg'
  MMCFG  = 'mmcfg'
  MMIO   = 'mmio'
  MSR    = 'msr'
  PORTIO = 'io'
  IOBAR  = 'iobar'


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
CHIPSET_ID_BDW     = 7
CHIPSET_ID_QRK     = 8
CHIPSET_ID_AVN     = 9

CHIPSET_CODE_COMMON  = 'COMMON'
CHIPSET_CODE_UNKNOWN = ''

CHIPSET_CODE_SNB     = 'SNB'
CHIPSET_CODE_JKT     = 'JKT'
CHIPSET_CODE_IVB     = 'IVB'
CHIPSET_CODE_IVT     = 'IVT'
CHIPSET_CODE_HSW     = 'HSW'
CHIPSET_CODE_BYT     = 'BYT'
CHIPSET_CODE_BDW     = 'BDW'
CHIPSET_CODE_QRK     = 'QRK'
CHIPSET_CODE_AVN     = 'AVN'

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

#
# Atom based SoC platforms
#

# Galileo Board
0x0958 : {'name' : 'Galileo ',       'id' : CHIPSET_ID_QRK , 'code' : CHIPSET_CODE_QRK,  'longname' : 'Intel Quark SoC X1000' },


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


def f_xml(self, x):
        XMLFILE_RE = re.compile("^\w+\.xml")
        return ( x.find('common') == -1 and XMLFILE_RE.match(x) )
def map_xmlname(self, x):
        return x.split('.')[0]



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
        # Examples:
        # - initializing SPI HAL component in a module:
        #   self.spi = SPI( self.cs )
        # - initializing second order UEFI HAL component in utilcmd extension:
        #   spi = SPI( chipsec_util._cs )
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
        

    #
    # @TODO: EXPERIMENTAL FEATURE
    # Load configuration from XML files in chipsec/cfg/
    #  
    def init_xml_configuration( self ):
        _cfg_path = os.path.join( chipsec.file.get_main_dir(), 'chipsec/cfg' )
        # Load chipsec/cfg/common.xml configuration XML file common for all platforms if it exists
        self.init_cfg_xml( os.path.join(_cfg_path,'common.xml'), self.code )
        # Load chipsec/cfg/<code>.xml configuration XML file if it exists for platform <code>
        if self.code and '' != self.code:
            self.init_cfg_xml( os.path.join(_cfg_path,('%s.xml'%self.code)), self.code )
        # Load configuration from all other XML files recursively (if any)
        for dirname, subdirs, xml_fnames in os.walk( _cfg_path ):
            for _xml in xml_fnames:
                if fnmatch.fnmatch( _xml, '*.xml' ) and not fnmatch.fnmatch( _xml, 'common.xml' ) and not (_xml in ['%s.xml' % c.lower() for c in Chipset_Code]):                
                    self.init_cfg_xml( os.path.join(dirname,_xml), self.code )
        self.Cfg.XML_CONFIG_LOADED = True


    def init_cfg_xml(self, fxml, code):
        import xml.etree.ElementTree as ET
        if not os.path.exists( fxml ): return
        logger().log( "[*] loading platform config from '%s'.." % fxml )
        tree = ET.parse( fxml )
        root = tree.getroot()
        for _cfg in root.iter('configuration'):
            if 'platform' not in _cfg.attrib:
                if logger().VERBOSE: logger().log_good( "found common platform config" )
            elif code == _cfg.attrib['platform'].lower():
                if logger().VERBOSE: logger().log_good( "found '%s' platform config" % code )
            else: continue
            if logger().VERBOSE: logger().log( "[*] loading MMIO BARs.." )
            for _mmio in _cfg.iter('mmio'):
                for _bar in _mmio.iter('bar'):
                    _name = _bar.attrib['name']
                    del _bar.attrib['name']
                    self.Cfg.MMIO_BARS[ _name ] = _bar.attrib
                    if logger().VERBOSE: logger().log( "    + %-16s: %s" % (_name, _bar.attrib) )
            if logger().VERBOSE: logger().log( "[*] loading I/O BARs.." )
            for _io in _cfg.iter('io'):
                for _bar in _io.iter('bar'):
                    _name = _bar.attrib['name']
                    del _bar.attrib['name']
                    self.Cfg.IO_BARS[ _name ] = _bar.attrib
                    if logger().VERBOSE: logger().log( "    + %-16s: %s" % (_name, _bar.attrib) )
            if logger().VERBOSE: logger().log( "[*] loading memory ranges.." )
            for _memory in _cfg.iter('memory'):
                for _range in _memory.iter('range'):
                    _name = _range.attrib['name']
                    del _range.attrib['name']
                    self.Cfg.MEMORY_RANGES[ _name ] = _range.attrib
                    if logger().VERBOSE: logger().log( "    + %-16s: %s" % (_name, _range.attrib) )
            if logger().VERBOSE: logger().log( "[*] loading configuration registers.." )
            for _registers in _cfg.iter('registers'):
                for _register in _registers.iter('register'):
                    _name = _register.attrib['name']
                    del _register.attrib['name']
                    reg_fields = {}
                    if _register.find('field') is not None:
                        for _field in _register.iter('field'):
                            _field_name = _field.attrib['name']
                            del _field.attrib['name']
                            reg_fields[ _field_name ] = _field.attrib
                        _register.attrib['FIELDS'] = reg_fields
                    self.Cfg.REGISTERS[ _name ] = _register.attrib
                    if logger().VERBOSE: logger().log( "    + %-16s: %s" % (_name, _register.attrib) )


    #
    # Load chipsec/cfg/<code>.py configuration file for platform <code>
    #
    def init_cfg(self):
        if self.code and '' != self.code:
            try:
                module_path = 'chipsec.cfg.' + self.code 
                module = importlib.import_module( module_path )
                logger().log_good( "imported platform specific configuration: chipsec.cfg.%s" % self.code )
                self.Cfg = getattr( module, self.code )()
            except ImportError, msg:
                if logger().VERBOSE: logger().log( "[*] Couldn't import chipsec.cfg.%s\n%s" % ( self.code, str(msg) ) )

        #
        # EXPERIMENTAL FEATURE
        #
        try:
            self.init_xml_configuration()
        except:
            pass


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


def is_register_defined( _cs, reg_name ):
    try:
        return (_cs.Cfg.REGISTERS[ reg_name ] is not None)
    except KeyError:
        if logger().VERBOSE: logger().warn( "'%s' register definition not found in XML config" % reg_name)
        return False

def read_register( _cs, reg_name ):
    reg = _cs.Cfg.REGISTERS[ reg_name ]
    rtype = reg['type']
    reg_value = 0
    if RegisterType.PCICFG == rtype:
        b = int(reg['bus'],16)
        d = int(reg['dev'],16)
        f = int(reg['fun'],16)
        o = int(reg['offset'],16)
        size = int(reg['size'],16)
        if   1 == size: reg_value = _cs.pci.read_byte ( b, d, f, o )
        elif 2 == size: reg_value = _cs.pci.read_word ( b, d, f, o )
        elif 4 == size: reg_value = _cs.pci.read_dword( b, d, f, o )
        elif 8 == size: reg_value = (_cs.pci.read_dword( b, d, f, o+4 ) << 32) | _cs.pci.read_dword( b, d, f, o )
    elif RegisterType.MMCFG == rtype:
        reg_value = mmio.read_mmcfg_reg( _cs, int(reg['bus'],16), int(reg['dev'],16), int(reg['fun'],16), int(reg['offset'],16), int(reg['size'],16) )
    elif RegisterType.MMIO == rtype:
        reg_value = mmio.read_MMIO_BAR_reg( _cs, reg['bar'], int(reg['offset'],16) )
    elif RegisterType.MSR == rtype:
        reg_value = _cs.msr.read_msr( int(reg['msr'],16) )
    elif RegisterType.PORT == rtype:
        port = int(reg['port'],16)
        size = int(reg['size'],16)
        reg_value = _cs.io._read_port( port, size )
    elif RegisterType.IOBAR == rtype:
        iobar = chipsec.hal.iobar( _cs )
        reg_value = iobar.read_IO_BAR_reg( _cs, reg['bar'], int(reg['offset'],16) )
    return reg_value

def write_register( _cs, reg_name, reg_value ):
    reg = _cs.Cfg.REGISTERS[ reg_name ]
    rtype = reg['type']
    if RegisterType.PCICFG == rtype:
        b = int(reg['bus'],16)
        d = int(reg['dev'],16)
        f = int(reg['fun'],16)
        o = int(reg['offset'],16)
        size = int(reg['size'],16)
        if   1 == size: _cs.pci.write_byte( b, d, f, o, reg_value )
        elif 2 == size: _cs.pci.write_word( b, d, f, o, reg_value )
        elif 4 == size: _cs.pci.write_dword( b, d, f, o, reg_value )
        elif 8 == size: 
            _cs.pci.write_dword( b, d, f, o, (reg_value & 0xFFFFFFFF) )
            _cs.pci.write_dword( b, d, f, o + 4, (reg_value>>32 & 0xFFFFFFFF) )
    elif RegisterType.MMCFG == rtype:
        mmio.write_mmcfg_reg( _cs, int(reg['bus'],16), int(reg['dev'],16), int(reg['fun'],16), int(reg['offset'],16), int(reg['size'],16), reg_value )
    elif RegisterType.MMIO == rtype:
        mmio.write_MMIO_BAR_reg( _cs, reg['bar'], int(reg['offset'],16), reg_value )
    elif RegisterType.MSR == rtype:
        _cs.msr.write_msr( int(reg['msr'],16), reg_value )
    elif RegisterType.PORT == rtype:
        port = int(reg['port'],16)
        size = int(reg['size'],16)
        _cs.io._write_port( port, reg_value, size )
    elif RegisterType.IOBAR == rtype:
        iobar = chipsec.hal.iobar( _cs )
        iobar.write_IO_BAR_reg( reg['bar'], int(reg['offset'],16), reg_value )


from chipsec.helper.oshelper import helper
_chipset = Chipset( helper() )
def cs():
    # if _chipset is None: _chipset = Chipset( helper() )
    return _chipset



