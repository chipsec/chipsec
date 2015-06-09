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



"""
`Preventing & Detecting Xen Hypervisor Subversions <http://www.invisiblethingslab.com/resources/bh08/part2-full.pdf>`_ by Joanna Rutkowska & Rafal Wojtczuk

Check Memory Remapping Configuration
"""

from chipsec.module_common import *
import chipsec.chipset

_MODULE_NAME = 'remap'

TAGS = [MTAG_SMM,MTAG_HWCONFIG]


_REMAP_ADDR_MASK = 0x7FFFF00000
_TOLUD_MASK      = 0xFFFFF000

class remap(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)

    def is_supported(self):
        if self.cs.get_chipset_id() in chipsec.chipset.CHIPSET_FAMILY_CORE:
            return True
        return False

    def check_remap_config(self):
        self.logger.start_test( "Memory Remapping Configuration" )

        if not chipsec.chipset.is_register_defined( self.cs, 'PCI0.0.0_REMAPBASE'  ) or \
           not chipsec.chipset.is_register_defined( self.cs, 'PCI0.0.0_REMAPLIMIT' ) or \
           not chipsec.chipset.is_register_defined( self.cs, 'PCI0.0.0_TOUUD'      ) or \
           not chipsec.chipset.is_register_defined( self.cs, 'PCI0.0.0_TOLUD'      ) or \
           not chipsec.chipset.is_register_defined( self.cs, 'PCI0.0.0_TSEGMB'     ):
            self.logger.error( "Couldn't find definition of required registers (REMAP*, TOLUD, TOUUD, TSEGMB)" )
            return ModuleResult.ERROR

        remapbase  = chipsec.chipset.read_register( self.cs, 'PCI0.0.0_REMAPBASE' )
        remaplimit = chipsec.chipset.read_register( self.cs, 'PCI0.0.0_REMAPLIMIT' )
        touud      = chipsec.chipset.read_register( self.cs, 'PCI0.0.0_TOUUD' )
        tolud      = chipsec.chipset.read_register( self.cs, 'PCI0.0.0_TOLUD' )
        tsegmb     = chipsec.chipset.read_register( self.cs, 'PCI0.0.0_TSEGMB' )
        self.logger.log( "[*] Registers:" )
        self.logger.log( "[*]   TOUUD     : 0x%016X" % touud )
        self.logger.log( "[*]   REMAPLIMIT: 0x%016X" % remaplimit )
        self.logger.log( "[*]   REMAPBASE : 0x%016X" % remapbase )
        self.logger.log( "[*]   TOLUD     : 0x%08X" % tolud )
        self.logger.log( "[*]   TSEGMB    : 0x%08X\n" % tsegmb )

        remapbase_lock  = remapbase & 0x1
        remaplimit_lock = remaplimit & 0x1
        touud_lock      = touud & 0x1
        tolud_lock      = tolud & 0x1
        tsegmb_lock     = tsegmb & 0x1
        remapbase  &= _REMAP_ADDR_MASK
        remaplimit &= _REMAP_ADDR_MASK
        #remaplimit |= 0xFFFFF
        touud      &= _REMAP_ADDR_MASK
        tolud      &= _TOLUD_MASK
        tsegmb     &= _TOLUD_MASK
        self.logger.log( "[*] Memory Map:" )
        self.logger.log( "[*]   Top Of Upper Memory: 0x%016X" % touud )
        self.logger.log( "[*]   Remap Limit Address: 0x%016X" % (remaplimit|0xFFFFF) )
        self.logger.log( "[*]   Remap Base Address : 0x%016X" % remapbase )
        self.logger.log( "[*]   4GB                : 0x%016X" % self.cs.Cfg.BIT32 )
        self.logger.log( "[*]   Top Of Low Memory  : 0x%016X" % tolud )
        self.logger.log( "[*]   TSEG (SMRAM) Base  : 0x%016X\n" % tsegmb )

        remap_ok = True

        self.logger.log( "[*] checking memory remap configuration.." )
        if remapbase > remaplimit:
            self.logger.log( "[*]   Memory Remap is disabled" )
        else:
            self.logger.log( "[*]   Memory Remap is enabled" )
            remaplimit_addr = (remaplimit|0xFFFFF)
            ok = ((remaplimit_addr + 1) == touud)
            remap_ok = remap_ok and ok
            if ok: self.logger.log_good( "  Remap window configuration is correct: REMAPBASE <= REMAPLIMIT < TOUUD" )
            else:  self.logger.log_bad( "  Remap window configuration is not correct" )

        ok = (0 == tolud & self.cs.Cfg.ALIGNED_1MB)     and \
             (0 == touud & self.cs.Cfg.ALIGNED_1MB)     and \
             (0 == remapbase & self.cs.Cfg.ALIGNED_1MB) and \
             (0 == remaplimit & self.cs.Cfg.ALIGNED_1MB)
        remap_ok = remap_ok and ok
        if ok: self.logger.log_good( "  All addresses are 1MB aligned" )
        else:  self.logger.log_bad( "  Not all addresses are 1MB aligned" )

        self.logger.log( "[*] checking if memory remap configuration is locked.." )
        ok = (0 != touud_lock)
        remap_ok = remap_ok and ok
        if ok: self.logger.log_good( "  TOUUD is locked" )
        else:  self.logger.log_bad( "  TOUUD is not locked" )

        ok = (0 != tolud_lock)
        remap_ok = remap_ok and ok
        if ok: self.logger.log_good( "  TOLUD is locked" )
        else:  self.logger.log_bad( "  TOLUD is not locked" )

        ok = (0 != remapbase_lock) and (0 != remaplimit_lock)
        remap_ok = remap_ok and ok
        if ok: self.logger.log_good( "  REMAPBASE and REMAPLIMIT are locked" )
        else:  self.logger.log_bad( "  REMAPBASE and REMAPLIMIT are not locked" )

        self.logger.log('')
        if remap_ok: self.logger.log_passed_check( "Memory Remap is configured correctly and locked" )
        else:        self.logger.log_failed_check( "Memory Remap is not properly configured/locked. Remaping attack may be possible" )

        return remap_ok

    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run( self, module_argv ):
        return self.check_remap_config()
