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


#
## \addtogroup tools
# __chipsec/modules/tools/smm/smm_ptr.py__ - A tool to test SMI handlers for pointer validation vulnerabilies
#
# Usage: chipsec_main -m tools.smm.smm_ptr [ -a <fill_byte>,<size>,<config_file>,<address> ]
#        address	physical address of memory buffer to pass in GP regs to SMI handlers
#          ='smram'	pass address of SMRAM base (system may hang in this mode!)
#        config_file	path to a file describing interfaces to SMI handlers (template: smm_config.ini)
#        size		size of the memory buffer
#        fill_byte	byte to fill the memory buffer with
# 
# SMI configuration file should have the following format:
#
# Name=SW_SMI_Name
# desc=description
# SMI_code=SW_SMI_Code or *
# SMI_data=SW_SMI_Code or *
# RAX=Value_of_RAX or * or PTR or VAL
# RBX=Value_of_RBX or * or PTR or VAL
# RCX=Value_of_RCX or * or PTR or VAL
# RDX=Value_of_RDX or * or PTR or VAL
# RSI=Value_of_RSI or * or PTR or VAL
# RDI=Value_of_RDI or * or PTR or VAL
#
# Where:
# * = Don't Care (the module will replace * with 0x0)
# PTR = Physical address SMI handler will write to (the module will replace PTR with physical address provided as a command-line argument)
# VAL = Value SMI handler will write to PTR address (the module will replace VAL with hardcoded _FILL_VALUE_xx)
#

from chipsec.module_common import *
from chipsec.file import *

from chipsec.hal.interrupts import Interrupts
import chipsec.hal.uefi

#logger.VERBOSE = False

#################################################################
# Fuzzing configuration
#################################################################

#
# SMI handler may take a pointer/PA from (some offset of off) address passed in GPRs and write to it
# Treat contents at physical address passed in GPRs as pointers and check contents at that pointer
# If they changed, SMI handler might have modified them
#
# False - better performance, True - better coverage
MODE_SECOND_ORDER_BUFFER  = False

# False - better performance, True - better results tracking
DUMP_MEMORY_ON_DETECT  = True

# False - better performance, True - better results tracking
FLUSH_OUTPUT_ALWAYS    = True

# Default options
_FILL_VALUE_QWORD = 0x5A5A5A5A5A5A5A5A
_FILL_VALUE_BYTE  = 0x5A
_SMI_CODE_DATA    = 0x0
_MEM_FILL_VALUE   = chr(0x11)
_MEM_FILL_SIZE    = 0x500
_MAX_ALLOC_PA     = 0xFFFFFFFF

_pth = 'smm_ptr'

class smm_ptr(BaseModule):
    def __init__(self):
        BaseModule.__init__(self)
        self.interrupts = Interrupts( self.cs )
        self.is_check_memory = True
        
    def is_supported(self):
        return True
        

    def get_SMRAM( self ):
        msr_smrrbase = chipsec.chipset.read_register( self.cs, 'IA32_SMRR_PHYSBASE' )
        msr_smrrmask = chipsec.chipset.read_register( self.cs, 'IA32_SMRR_PHYSMASK' )
        smrrbase = chipsec.chipset.get_register_field( self.cs, 'IA32_SMRR_PHYSBASE', msr_smrrbase, 'PhysBase', True )
        smrrmask  = chipsec.chipset.get_register_field( self.cs, 'IA32_SMRR_PHYSMASK', msr_smrrmask, 'PhysMask', True )
        return (smrrbase,smrrmask)

    def fill_memory( self, _addr, _addr1, _fill_byte, _fill_size ):
        #
        # Fill in contents at PA = _addr with known pattern to check later if any SMI handler modifies them
        #
        self.logger.log( "[*] Filling in %d bytes at PA 0x%016X with '%c'.." % (_fill_size, _addr, _fill_byte) )
        self.cs.mem.write_physical_mem( _addr, _fill_size, _fill_byte*_MEM_FILL_SIZE )
        if MODE_SECOND_ORDER_BUFFER: 
            self.logger.log( "[*] Filling in %d bytes at PA 0x%016X with '%c'.." % (_fill_size, _addr1, _fill_byte) )
            self.cs.mem.write_physical_mem( _addr1, _fill_size, _fill_byte*_MEM_FILL_SIZE )
        return True

    def send_smi( self, smi_code, smi_data, name, desc, rax, rbx, rcx, rdx, rsi, rdi ):
        #
        # Invoke SW SMI#
        #
        self.logger.log( "[*] Sending SMI# 0x%02X (data = 0x%02X) %s (%s).." % (smi_code, smi_data, name, desc) )
        self.logger.log( "    RAX: 0x%016X (AX will be overwridden with values of SW SMI ports B2/B3)" % rax )
        self.logger.log( "    RBX: 0x%016X" % rbx )
        self.logger.log( "    RCX: 0x%016X" % rcx )
        self.logger.log( "    RDX: 0x%016X (DX will be overwridden with 0x00B2)" % rdx )
        self.logger.log( "    RSI: 0x%016X" % rsi )
        self.logger.log( "    RDI: 0x%016X" % rdi )
        self.interrupts.send_SW_SMI( smi_code, smi_data, rax, rbx, rcx, rdx, rsi, rdi )
        return True


    def check_memory( self, _addr, _addr1, _fill_byte, _fill_size ):
        #
        # Check if contents have changed at physical address passed in GPRs to SMI handler
        # If changed, SMI handler might have written to that address
        #
        _changed = False
        self.logger.log( "[*] Checking contents at PA 0x%016X.." % _addr )
        buf = self.cs.mem.read_physical_mem( _addr, _fill_size )
        i = 0
        for c in buf:
            if _fill_byte != c:
                _changed = True
                break
            i = i + 1
        if _changed:
            self.logger.log_important( "Detected: contents at PA 0x%016X (+ 0x%X) have changed" % (_addr,i) )
            if DUMP_MEMORY_ON_DETECT:
                _f = os.path.join( _pth, '%s_addr%X_after.dmp' % (name,_addr) )
                write_file( _f, buf )
        else: self.logger.log_good( "Contents at PA 0x%016X have not changed" % _addr )

        _changed1 = False
        if MODE_SECOND_ORDER_BUFFER:
            self.logger.log( "[*] Checking contents at PA 0x%016X.." % _addr1 )
            buf1 = self.cs.mem.read_physical_mem( _addr1, _fill_size )
            i = 0
            for c in buf1:
                if _fill_byte != c:
                    _changed1 = True
                    break
                i = i + 1
            if _changed1:
                self.logger.log_important( "Detected: contents at PA 0x%016X (+ 0x%X) have changed" % (_addr1,i) )
                if DUMP_MEMORY_ON_DETECT:
                    _f = os.path.join( _pth, '%s_addr%X_after.dmp' % (name,_addr1) )
                    write_file( _f, buf1 )
            else: self.logger.log_good( "Contents at PA 0x%016X have not changed" % _addr1 )

        return (_changed or _changed1)

    def run( self, module_argv ):
        self.logger.start_test( "A tool to test SMI handlers for pointer validation vulnerabilies" )
        self.logger.log( "Usage: chipsec_main -m tools.smm.smm_ptr [ -a <fill_byte>,<size>,<config_file>,<address> ]" )
        self.logger.log( "       address	physical address of memory buffer to pass in GP regs to SMI handlers" )
        self.logger.log( "         ='smram'	pass address of SMRAM base (system may hang in this mode!)" )
        self.logger.log( "       config_file	path to a file describing interfaces to SMI handlers (template: smm_config.ini)" )
        self.logger.log( "       size		size of the memory buffer" )
        self.logger.log( "       fill_byte	byte to fill the memory buffer with\n" )
        
        _smi_config_fname = 'chipsec/modules/tools/smm/smm_config.ini'
        _addr             = 0x0
        _wr_val           = _FILL_VALUE_BYTE

        _fill_byte = chr(int(module_argv[0],16)) if len(module_argv) > 0 else _MEM_FILL_VALUE
        _fill_size = int(module_argv[1],16)      if len(module_argv) > 1 else _MEM_FILL_SIZE

        if len(module_argv) > 2: _smi_config_fname = module_argv[2]
        if len(module_argv) > 3:
            if 'smram' == module_argv[3]:
                (smrrbase,smrrmask) = self.get_SMRAM()
                _addr = smrrbase & smrrmask
                self.is_check_memory = False
                self.logger.log( "[*] Using SMRAM base address (0x%016X) to pass to SMI handlers" % _addr )
            else:
                _addr = int(module_argv[3],16)
                self.logger.log( "[*] Using address from command-line (0x%016X) to pass to SMI handlers" % _addr )
        else:
            (va, _addr) = self.cs.mem.alloc_physical_mem( _fill_size, _MAX_ALLOC_PA )
            self.logger.log( "[*] Allocated new memory buffer (0x%016X) to pass to SMI handlers" % _addr )

        _b = ord(_fill_byte)
        _addr1 = 0xFFFFFFFFFFFFFFFF & ((_b<<24) | (_b<<16) | (_b<<8) | _b)

        #
        # @TODO: Need to check that SW/APMC SMI is enabled
        #

        self.logger.log( "[*] Configuration:" )
        self.logger.log( "    SMI config file          : %s" % _smi_config_fname )
        self.logger.log( "    Register default value   : 0x%016X" % _FILL_VALUE_QWORD )
        self.logger.log( "    Memory address           : 0x%016X (passed in GP regs to SMI)" % _addr )
        self.logger.log( "    Pointers within buffer?  : %s" % ('ON' if MODE_SECOND_ORDER_BUFFER else 'OFF') )
        if MODE_SECOND_ORDER_BUFFER: self.logger.log( "    Pointer (address) in memory buffer (32b): 0x%016X" % _addr1 )
        self.logger.log( "    Filling/checking memory? : %d" % self.is_check_memory )
        if self.is_check_memory:
            self.logger.log( "    Byte to fill with        : 0x%X" % _b )
            self.logger.log( "    Number of bytes to fill  : 0x%X" % _fill_size )

        #
        # Parse SMM config file describing SMI handlers and their call arguments
        # Then invoke SMI handlers
        #
        fcfg = open( _smi_config_fname, 'r' )
        keys = {}

        if DUMP_MEMORY_ON_DETECT and not os.path.exists( _pth ): os.makedirs( _pth )

        self.logger.set_always_flush( FLUSH_OUTPUT_ALWAYS )

        self.logger.log('')
        self.logger.log( "[*] Fuzzing SMI handlers defined in '%s'.." % _smi_config_fname )

        _failed = False
        for line in fcfg:
            if '' == line.strip():
                # Fill memory buffer if not in 'No Fill' mode
                if self.is_check_memory: self.fill_memory( _addr, _addr1, _fill_byte, _fill_size )
                # Invoke SW SMI handler
                self.send_smi( keys['smi_code'], keys['smi_data'], \
                               keys['name'], keys['desc'],         \
                               keys['rax'], keys['rbx'], keys['rcx'], keys['rdx'], keys['rsi'], keys['rdi'] )
                # Check memory buffer if not in 'No Fill' mode
                if self.is_check_memory: _failed = _failed or self.check_memory( _addr, _addr1, _fill_byte, _fill_size )
            else:
                name, var = line.strip().partition('=')[::2]
                _n = name.strip().lower()
                if   'name'     == _n or 'desc'     == _n: keys[ _n ] = var
                elif 'smi_code' == _n or 'smi_data' == _n: keys[ _n ] = int(var,16) if '*'!=var else _SMI_CODE_DATA
                else: keys[ _n ] = ( _addr if 'PTR'==var else (_wr_val if 'VAL'==var else int(var,16)) ) if '*'!=var else _FILL_VALUE_QWORD

        res = ModuleResult.FAILED if _failed else ModuleResult.PASSED
        return res
