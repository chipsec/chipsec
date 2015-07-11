#!/usr/local/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2015, Intel Corporation
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

"""
Contains platform identification functions
"""

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
from chipsec.hal.cr          import CrRegs
from chipsec.hal.cpuid       import CpuID
#from chipsec.hal.mmio        import *

import chipsec.hal.mmio as mmio
import chipsec.hal.iobar as iobar 

from chipsec.cfg.common      import Cfg
from chipsec.logger          import logger

import chipsec.file

import importlib
import traceback
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
CHIPSET_ID_HSX     = 10

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
CHIPSET_CODE_HSX     = 'HSX'

CHIPSET_FAMILY_XEON  = [CHIPSET_ID_JKT,CHIPSET_ID_IVT,CHIPSET_ID_HSX]
CHIPSET_FAMILY_CORE  = [CHIPSET_ID_SNB,CHIPSET_ID_IVB,CHIPSET_ID_HSW,CHIPSET_ID_BDW]
CHIPSET_FAMILY_ATOM  = [CHIPSET_ID_BYT,CHIPSET_ID_AVN]
CHIPSET_FAMILY_QUARK = [CHIPSET_ID_QRK]


VID_INTEL = 0x8086

# PCI 0/0/0 Device IDs
Chipset_Dictionary = {
# DID  : Data Dictionary

# 2nd Generation Core Processor Family (Sandy Bridge)
0x0100 : {'name' : 'Sandy Bridge',   'id' : CHIPSET_ID_SNB , 'code' : CHIPSET_CODE_SNB,  'longname' : 'Desktop 2nd Generation Core Processor (Sandy Bridge CPU / Cougar Point PCH)' },
0x0104 : {'name' : 'Sandy Bridge',   'id' : CHIPSET_ID_SNB , 'code' : CHIPSET_CODE_SNB,  'longname' : 'Mobile 2nd Generation Core Processor (Sandy Bridge CPU / Cougar Point PCH)' },
0x0108 : {'name' : 'Sandy Bridge',   'id' : CHIPSET_ID_SNB , 'code' : CHIPSET_CODE_SNB,  'longname' : 'Intel Xeon Processor E3-1200 (Sandy Bridge CPU, C200 Series PCH)' },

# Xeon v1 Processor (Jaketown/Sandy Bridge - EP)
0x3C00 : {'name' : 'Jaketown',       'id' : CHIPSET_ID_JKT,  'code' : CHIPSET_CODE_JKT,  'longname' : 'Server 2nd Generation Core Processor (Jaketown CPU / Patsburg PCH)'},

# 3rd Generation Core Processor Family (Ivy Bridge)
0x0150 : {'name' : 'Ivy Bridge',     'id' : CHIPSET_ID_IVB , 'code' : CHIPSET_CODE_IVB,  'longname' : 'Desktop 3rd Generation Core Processor (Ivy Bridge CPU / Panther Point PCH)' },
0x0154 : {'name' : 'Ivy Bridge',     'id' : CHIPSET_ID_IVB , 'code' : CHIPSET_CODE_IVB,  'longname' : 'Mobile 3rd Generation Core Processor (Ivy Bridge CPU / Panther Point PCH)' },
0x0158 : {'name' : 'Ivy Bridge',     'id' : CHIPSET_ID_IVB , 'code' : CHIPSET_CODE_IVB,  'longname' : 'Intel Xeon Processor E3-1200 v2 (Ivy Bridge CPU, C200/C216 Series PCH)' },

# Xeon v2 Processor (Ivy Town/Ivy Bridge - EP)
0x0E00 : {'name' : 'Ivytown',        'id' : CHIPSET_ID_IVT,  'code' : CHIPSET_CODE_IVT,  'longname' : 'Server 3rd Generation Core Procesor (Ivytown CPU / Patsburg PCH)'},

# 4th Generation Core Processor Family (Haswell)
0x0C00 : {'name' : 'Haswell',        'id' : CHIPSET_ID_HSW , 'code' : CHIPSET_CODE_HSW,  'longname' : 'Desktop 4th Generation Core Processor (Haswell CPU / Lynx Point PCH)' },
0x0C04 : {'name' : 'Haswell',        'id' : CHIPSET_ID_HSW , 'code' : CHIPSET_CODE_HSW,  'longname' : 'Mobile 4th Generation Core Processor (Haswell M/H / Lynx Point PCH)' },
0x0C08 : {'name' : 'Haswell',        'id' : CHIPSET_ID_HSW , 'code' : CHIPSET_CODE_HSW,  'longname' : 'Intel Xeon Processor E3-1200 v3 (Haswell CPU, C220 Series PCH)' },
0x0D00 : {'name' : 'Haswell',        'id' : CHIPSET_ID_HSW , 'code' : CHIPSET_CODE_HSW,  'longname' : 'Desktop 4th Generation Core Processor (Haswell)' },
0x0D04 : {'name' : 'Haswell',        'id' : CHIPSET_ID_HSW , 'code' : CHIPSET_CODE_HSW,  'longname' : 'Mobile 4th Generation Core Processor (Haswell)' },
0x0D08 : {'name' : 'Haswell',        'id' : CHIPSET_ID_HSW , 'code' : CHIPSET_CODE_HSW,  'longname' : '4th Generation Core Processor (Haswell)' },
0x0A00 : {'name' : 'Haswell',        'id' : CHIPSET_ID_HSW , 'code' : CHIPSET_CODE_HSW,  'longname' : '4th Generation Core Processor (Haswell U/Y)' },
0x0A04 : {'name' : 'Haswell',        'id' : CHIPSET_ID_HSW , 'code' : CHIPSET_CODE_HSW,  'longname' : '4th Generation Core Processor (Haswell U/Y)' },
0x0A08 : {'name' : 'Haswell',        'id' : CHIPSET_ID_HSW , 'code' : CHIPSET_CODE_HSW,  'longname' : '4th Generation Core Processor (Haswell U/Y)' },

# 5th Generation Core Processor Family (Broadwell)
0x1600 : {'name' : 'Broadwell',      'id' : CHIPSET_ID_BDW , 'code' : 'BDW',  'longname' : 'Desktop 5th Generation Core Processor (Broadwell CPU / Wildcat Point PCH)' },
0x1604 : {'name' : 'Broadwell',      'id' : CHIPSET_ID_BDW , 'code' : 'BDW',  'longname' : 'Mobile 5th Generation Core Processor (Broadwell M/H / Wildcat Point PCH)' },

# Xeon v3 Processor (Haswell Server)
0x2F00 : {'name' : 'Haswell Server', 'id' : CHIPSET_ID_HSX,  'code' : CHIPSET_CODE_HSX,  'longname' : 'Server 4th Generation Core Processor (Haswell Server CPU / Wellsburg PCH)'},

# Bay Trail SoC
0x0F00 : {'name' : 'Baytrail',       'id' : CHIPSET_ID_BYT , 'code' : CHIPSET_CODE_BYT,  'longname' : 'Bay Trail' },

#
# Atom based SoC platforms
#
0x1F07 : {'name' : 'Avoton  ',       'id' : CHIPSET_ID_AVN , 'code' : CHIPSET_CODE_AVN,  'longname' : 'Intel Avoton' },
0x1F01 : {'name' : 'Avoton  ',       'id' : CHIPSET_ID_AVN , 'code' : CHIPSET_CODE_AVN,  'longname' : 'Intel Avoton' },

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

class DeviceNotFoundError (RuntimeError):
    pass

class Chipset:

    def __init__(self, helper=None):
        if logger().VERBOSE: logger().log("[Chipset] __init__")
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
        self.pci        = Pci      ( self )
        self.mem        = Memory   ( self )
        self.msr        = Msr      ( self )
        self.ucode      = Ucode    ( self )
        self.io         = PortIO   ( self )
        self.cr         = CrRegs   ( self )
        self.cpuid      = CpuID    ( self )
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

        _unknown_platform = False
        if start_svc: self.helper.start()

        if platform_code is None:
            vid_did  = self.pci.read_dword( 0, 0, 0, 0 )
            self.vid = vid_did & 0xFFFF
            self.did = (vid_did >> 16) & 0xFFFF
            if VID_INTEL != self.vid:
                _unknown_platform = True
        else:
            self.vid = VID_INTEL
            self.code = platform_code.lower()
            if Chipset_Code.has_key( platform_code ):
                self.did = Chipset_Code[ platform_code ]
            else:
                _unknown_platform = True
                self.did = 0xFFFF

        if Chipset_Dictionary.has_key( self.did ):
            data_dict       = Chipset_Dictionary[ self.did ]
            self.code       = data_dict['code'].lower()
            self.longname   = data_dict['longname']
            self.id         = data_dict['id']
        else:
            _unknown_platform = True
            self.longname   = 'UnknownPlatform'

        self.init_cfg()
        if _unknown_platform:
            msg = 'Unsupported Platform: VID = 0x%04X, DID = 0x%04X' % (self.vid,self.did)
            logger().error( msg )
            raise UnknownChipsetError, msg


    def destroy( self, start_svc ):
        self.stop( start_svc )
        #self.helper.destroy()

    def stop( self, start_svc ):
        if start_svc: self.helper.stop()

    def get_chipset_id(self):
        return self.id

    def get_chipset_code(self):
        return self.code

    def get_chipset_name(self, id ):
        return self.longname

    def print_chipset(self):
        logger().log( "[*] Platform: %s\n          VID: %04X\n          DID: %04X" % (self.longname, self.vid, self.did))


    ##################################################################################
    #
    # Loading platform configuration from XML files in chipsec/cfg/
    #
    ##################################################################################

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
        if logger().VERBOSE: logger().log( "[*] looking for platform config in '%s'.." % fxml )
        tree = ET.parse( fxml )
        root = tree.getroot()
        for _cfg in root.iter('configuration'):
            if 'platform' not in _cfg.attrib:
                if logger().HAL: logger().log( "[*] loading common platform config from '%s'.." % fxml )
            elif code == _cfg.attrib['platform'].lower():
                if logger().HAL: logger().log( "[*] loading '%s' platform config from '%s'.." % (code,fxml) )
            else: continue

            if logger().VERBOSE: logger().log( "[*] loading integrated devices/controllers.." )
            for _pci in _cfg.iter('pci'):
                for _device in _pci.iter('device'):
                    _name = _device.attrib['name']
                    del _device.attrib['name']
                    self.Cfg.CONFIG_PCI[ _name ] = _device.attrib
                    if logger().VERBOSE: logger().log( "    + %-16s: %s" % (_name, _device.attrib) )
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
                    if 'size' not in _register.attrib: _register.attrib['size'] = "0x4"
                    if 'desc' not in _register.attrib: _register.attrib['desc'] = ''
                    reg_fields = {}
                    if _register.find('field') is not None:
                        for _field in _register.iter('field'):
                            _field_name = _field.attrib['name']
                            del _field.attrib['name']
                            if 'desc' not in _field.attrib: _field.attrib['desc'] = ''
                            reg_fields[ _field_name ] = _field.attrib
                        _register.attrib['FIELDS'] = reg_fields
                    self.Cfg.REGISTERS[ _name ] = _register.attrib
                    if logger().VERBOSE: logger().log( "    + %-16s: %s" % (_name, _register.attrib) )
            if logger().VERBOSE: logger().log( "[*] loading controls.." )
            for _controls in _cfg.iter('controls'):
                for _control in _controls.iter('control'):
                    _name = _control.attrib['name']
                    del _control.attrib['name']
                    self.Cfg.CONTROLS[ _name ] = _control.attrib
                    if logger().VERBOSE: logger().log( "    + %-16s: %s" % (_name, _control.attrib) )

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
        # Initialize platform configuration from XML files
        #
        try:
            self.init_xml_configuration()
        except:
            if logger().VERBOSE: logger().log_bad(traceback.format_exc())
            pass


    ##################################################################################
    #
    # Functions which access configuration of integrated PCI devices (interfaces, controllers)
    # by device name (defined in XML configuration files)
    #
    ##################################################################################

    def get_device_BDF( self, device_name ):
        device = self.Cfg.CONFIG_PCI[ device_name ]
        if device is None or device == {}: raise DeviceNotFoundError, ('DeviceNotFound: %s' % device_name)
        b = int(device['bus'],16)
        d = int(device['dev'],16)
        f = int(device['fun'],16)
        return (b,d,f)

    def get_DeviceVendorID( self, device_name ):
        (b,d,f) = self.get_device_BDF( device_name )
        return self.pci.get_DIDVID( b, d, f )

    def is_device_enabled( self, device_name ):
        (b,d,f) = self.get_device_BDF( device_name )
        return self.pci.is_enabled( b, d, f )



class RegisterNotFoundError (RuntimeError):
    pass



##################################################################################
#
# Main functionality to read/write configuration registers
# based on their XML configuration
#
# is_register_defined
#   checks if register is defined in the XML config
# read_register/write_register
#   reads/writes configuration register (by name)
# get_register_field (set_register_field)
#   reads/writes the value of the field (by name) of configuration register (by register value)
# read_register_field (write_register_field)
#   reads/writes the value of the field (by name) of configuration register (by register name)
# register_has_field
#   checks if the register has specific field
# print_register
#   prints configuration register
# get_control/set_control
#   reads/writes some control field (by name) 
#
##################################################################################


def is_register_defined( _cs, reg_name ):
    try:
        return (_cs.Cfg.REGISTERS[ reg_name ] is not None)
    except KeyError:
        #if logger().VERBOSE: logger().error( "'%s' register definition not found in XML config" % reg_name)
        #raise RegisterNotFoundError, ('RegisterNotFound: %s' % reg_name)
        return False

def get_register_def( _cs, reg_name ):
    return _cs.Cfg.REGISTERS[ reg_name ]
        
def read_register( _cs, reg_name, cpu_thread=0 ):
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
        reg_value = mmio.read_MMIO_BAR_reg( _cs, reg['bar'], int(reg['offset'],16), int(reg['size'],16) )
    elif RegisterType.MSR == rtype:
        (eax, edx) = _cs.msr.read_msr( cpu_thread, int(reg['msr'],16) )
        reg_value = (edx << 32) | eax
    elif RegisterType.PORTIO == rtype:
        port = int(reg['port'],16)
        size = int(reg['size'],16)
        reg_value = _cs.io._read_port( port, size )
    elif RegisterType.IOBAR == rtype:
        iobar = chipsec.hal.iobar.iobar( _cs )
        reg_value = iobar.read_IO_BAR_reg( reg['bar'], int(reg['offset'],16), int(reg['size'],16) ) 
    return reg_value

def write_register( _cs, reg_name, reg_value, cpu_thread=0 ):
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
        mmio.write_MMIO_BAR_reg( _cs, reg['bar'], int(reg['offset'],16), reg_value, int(reg['size'],16) )
    elif RegisterType.MSR == rtype:
        eax = (reg_value & 0xFFFFFFFF)
        edx = ((reg_value >> 32) & 0xFFFFFFFF)
        _cs.msr.write_msr( cpu_thread, int(reg['msr'],16), eax, edx )
    elif RegisterType.PORT == rtype:
        port = int(reg['port'],16)
        size = int(reg['size'],16)
        _cs.io._write_port( port, reg_value, size )
    elif RegisterType.IOBAR == rtype:
        iobar = chipsec.hal.iobar( _cs )
        iobar.write_IO_BAR_reg( reg['bar'], int(reg['offset'],16), reg_value )

def read_register_dict( _cs, reg_name):
    reg_value = read_register( _cs, reg_name)
    reg_def = get_register_def( _cs, reg_name)
    result = reg_def
    result['value'] = reg_value
    for f in reg_def['FIELDS']:
        result['FIELDS'][f]['bit'] = field_bit = int(reg_def['FIELDS'][f]['bit'])
        result['FIELDS'][f]['size'] = field_size = int(reg_def['FIELDS'][f]['size'])
        field_mask = 0
        for i in range(field_size):
            field_mask = (field_mask << 1) | 1
        result['FIELDS'][f]['value'] = (reg_value >> field_bit) & field_mask
    return result

def get_register_field( _cs, reg_name, reg_value, field_name, preserve_field_position=False ):
    field_attrs = get_register_def( _cs, reg_name )['FIELDS'][field_name]
    field_bit   = int(field_attrs['bit'])
    field_mask  = (1 << int(field_attrs['size'])) - 1
    if preserve_field_position: return reg_value & (field_mask << field_bit)
    else:                       return (reg_value >> field_bit) & field_mask

def set_register_field( _cs, reg_name, reg_value, field_name, field_value ):
    field_attrs = get_register_def( _cs, reg_name )['FIELDS'][field_name]
    field_bit   = int(field_attrs['bit'])
    field_mask  = (1 << int(field_attrs['size'])) - 1
    reg_value &= ~(field_mask << field_bit)
    reg_value |= ((field_value & field_mask) << field_bit)
    return reg_value
    
# @TODO: add cpu_thread!
def read_register_field( _cs, reg_name, field_name, preserve_field_position=False ):
    reg_value = read_register( _cs, reg_name )
    return get_register_field( _cs, reg_name, reg_value, field_name, preserve_field_position )

def write_register_field( _cs, reg_name, field_name, field_value, cpu_thread=0 ):
    reg_value = read_register( _cs, reg_name, cpu_thread )
    reg_value_new = set_register_field( _cs, reg_name, reg_value, field_name, field_value )
    #logger().log("set register %s (0x%x) field %s = 0x%x ==> 0x%x" % (reg_name, reg_value, field_name, field_value, reg_value_new))
    return write_register( _cs, reg_name, reg_value_new, cpu_thread )

def register_has_field( _cs, reg_name, field_name ):
    reg_def = get_register_def( _cs, reg_name )
    return (field_name in reg_def['FIELDS'])

def _register_fields_str( reg_def, reg_val ):
    reg_fields_str = ''
    if 'FIELDS' in reg_def:
      reg_fields_str += '\n'
      # sort fields by their bit position in the register
      sorted_fields = sorted( reg_def['FIELDS'].items(), key=lambda field: int(field[1]['bit']) )
      for f in sorted_fields:
        field_attrs = f[1]
        field_bit = int(field_attrs['bit'])
        field_size = int(field_attrs['size'])
        field_mask = 0
        for i in range(field_size):
            field_mask = (field_mask << 1) | 1
        field_value = (reg_val >> field_bit) & field_mask
        field_desc = (' << ' + field_attrs['desc'] + ' ') if (field_attrs['desc'] != '') else ''
        reg_fields_str += ("    [%02d] %-16s = %X%s\n" % (field_bit,f[0],field_value,field_desc))

    if '' != reg_fields_str: reg_fields_str = reg_fields_str[:-1]
    return reg_fields_str

def print_register( _cs, reg_name, reg_val ):
    reg = _cs.Cfg.REGISTERS[ reg_name ]
    rtype = reg['type']
    reg_str = ''
    reg_val_str = ("0x%0" + ("%dX" % (int(reg['size'],16)*2))) % reg_val
    if RegisterType.PCICFG == rtype or RegisterType.MMCFG == rtype:
        b = int(reg['bus'],16)
        d = int(reg['dev'],16)
        f = int(reg['fun'],16)
        o = int(reg['offset'],16)
        mmcfg_off_str =  ''
        if RegisterType.MMCFG == rtype:
            mmcfg_off_str += ", MMCFG + 0x%X" % ((b*32*8 + d*8 + f) * 0x1000 + o)
        reg_str = "[*] %s = %s << %s (b:d.f %02d:%02d.%d + 0x%X%s)" % (reg_name, reg_val_str, reg['desc'], b, d, f, o, mmcfg_off_str)
    elif RegisterType.MMIO == rtype:
        reg_str = "[*] %s = %s << %s (%s + 0x%X)" % (reg_name, reg_val_str, reg['desc'], reg['bar'], int(reg['offset'],16))
    elif RegisterType.MSR == rtype:
        reg_str = "[*] %s = %s << %s (MSR 0x%X)" % (reg_name, reg_val_str, reg['desc'], int(reg['msr'],16))
    elif RegisterType.PORTIO == rtype:
        reg_str = "[*] %s = %s << %s (I/O port 0x%X)" % (reg_name, reg_val_str, reg['desc'], int(reg['port'],16))
    elif RegisterType.IOBAR == rtype:
        reg_str = "[*] %s = %s << %s (I/O %s + 0x%X)" % (reg_name, reg_val_str, reg['desc'], reg['bar'], int(reg['offset'],16))

    reg_str += _register_fields_str( reg, reg_val )
    logger().log( reg_str )
    return reg_str



def get_control( _cs, control_name, cpu_thread=0 ):
    control = _cs.Cfg.CONTROLS[ control_name ]
    reg     = control['register']
    field   = control['field']
    return chipsec.chipset.read_register_field( _cs, reg, field )    

def set_control( _cs, control_name, control_value, cpu_thread=0 ):
    control = _cs.Cfg.CONTROLS[ control_name ]
    reg     = control['register']
    field   = control['field']
    return chipsec.chipset.write_register_field( _cs, reg, field, control_value, cpu_thread )    

    
_chipset = None

def cs():
    global _chipset
    from chipsec.helper.oshelper import helper
    if _chipset is None: _chipset = Chipset( helper() )
    return _chipset
