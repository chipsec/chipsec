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
As described in `A New Class of Vulnerability in SMI Handlers of BIOS/UEFI Firmware <https://cansecwest.com/slides/2015/A%20New%20Class%20of%20Vulnin%20SMI%20-%20Andrew%20Furtak.pdf>`_ at CanSecWest 2015, the interface to SMI handlers may be used to pass pointer inputs to the SMI handler. If an SMI handler does not carefully check the value of this pointer input, it may read or write arbitrary memory. This module provides a tool to test SMI handlers for pointer such vulnerabilities.

**Usage**

``chipsec_main -m tools.smm.smm_ptr [ -a <mode>,<config_file>|<smic_start:smic_end>,<size>,<address> ]``

- ``mode``: SMI fuzzing mode

    * ``config`` = use SMI configuration file <config_file>
    
- ``size``: size of the memory buffer (in Hex)
- ``address``: physical address of memory buffer to pass in GP regs to SMI handlers (in Hex)

    * ``smram`` = option passes address of SMRAM base (system may hang in this mode!)

In 'config' mode, SMI configuration file should have the following format

::

    SMI_code=<SMI code> or *
    SMI_data=<SMI data> or *
    RAX=<value of RAX> or * or PTR or VAL
    RBX=<value of RBX> or * or PTR or VAL
    RCX=<value of RCX> or * or PTR or VAL
    RDX=<value of RDX> or * or PTR or VAL
    RSI=<value of RSI> or * or PTR or VAL
    RDI=<value of RDI> or * or PTR or VAL
    [PTR_OFFSET=<offset to pointer in the buffer>]
    [SIG=<signature>]
    [SIG_OFFSET=<offset to signature in the buffer>]
    [Name=<SMI name>]
    [Desc=<SMI description>]

Where

- ``[]``: optional line
- ``*``: Don't Care (the module will replace * with 0x0)
- ``PTR``: Physical address SMI handler will write to (the module will replace PTR with physical address provided as a command-line argument)
- ``VAL``: Value SMI handler will write to PTR address (the module will replace VAL with hardcoded _FILL_VALUE_xx)

"""

from chipsec.module_common import *
from chipsec.file import *

from chipsec.hal.interrupts import Interrupts
import chipsec.hal.uefi

#logger.VERBOSE = False

#################################################################
# Fuzzing configuration
#################################################################

#
# Logging option
#

# False - better performance, True - better results tracking
DUMP_MEMORY_ON_DETECT  = False
# False - better performance, True - better results tracking
FLUSH_OUTPUT_ALWAYS    = False
# makes sure SMI code is logged in case of a crash
FLUSH_OUTPUT_AFTER_SMI = True
# dump all registers in log before every SMI (True - large size of log file)
DUMP_GPRS_EVERY_SMI    = True

#
# SMI fuzzing options
#

# stop fuzzing after the first potential issue detected
FUZZ_BAIL_ON_1ST_DETECT   = True

#
# Pass the pointer to SMI handlers in all general-purpose registers
# rather than in one register
# True - faster, False - gives you specific GPR that the vulnerable SMI handler is consuming
#
PTR_IN_ALL_GPRS           = False

#
# SMI handler may take a pointer/PA from (some offset of off) address passed in GPRs and write to it
# Treat contents at physical address passed in GPRs as pointers and check contents at that pointer
# If they changed, SMI handler might have modified them
#
#MODE_SECOND_ORDER_BUFFER  = True
# Max offset of the pointer (physical address)
# of the 2nd order buffer written in the memory buffer passed to SMI
MAX_PTR_OFFSET_IN_BUFFER  = 0x20

# very obscure option, don't even try to understand
GPR_2ADDR = False


#
# Defaults
#
_FILL_VALUE_QWORD = 0x5A5A5A5A5A5A5A5A
_FILL_VALUE_BYTE  = 0x5A
_SMI_CODE_DATA    = 0x0
_MEM_FILL_VALUE   = chr(0x11)
_MEM_FILL_SIZE    = 0x500
_MAX_ALLOC_PA     = 0xFFFFFFFF
_DEFAULT_GPRS     = {'rax' : _FILL_VALUE_QWORD, 'rbx' : _FILL_VALUE_QWORD, 'rcx' : _FILL_VALUE_QWORD, 'rdx' : _FILL_VALUE_QWORD, 'rsi' : _FILL_VALUE_QWORD, 'rdi' : _FILL_VALUE_QWORD}

_pth = 'smm_ptr'


class BadSMIDetected (RuntimeError):
    pass

class smi_desc( object ):
    def __init__(self):
        self.smi_code      = None
        self.smi_data      = None
        self.name          = 'smi'
        self.desc          = ''
        self.gprs          = _DEFAULT_GPRS
        self.ptr_in_buffer = False
        self.ptr           = None
        self.ptr_offset    = 0
        self.sig           = None
        self.sig_offset    = 0

def DIFF( s, t, sz ):
    return [ pos for pos in range( sz ) if s[pos] != t[pos] ]

def FILL_BUFFER( _fill_byte, _fill_size, _ptr_in_buffer, _ptr, _ptr_offset, _sig, _sig_offset ):
    fill_buf = _fill_byte*_fill_size
    if _ptr_in_buffer and _ptr is not None: 
        fill_buf = fill_buf[ : _ptr_offset ] + struct.pack('=I',_ptr&0xFFFFFFFF) +  fill_buf[ _ptr_offset + 4 : ]
    if _sig is not None: 
        fill_buf = fill_buf[ : _sig_offset ] + _sig + fill_buf[ _sig_offset + len(_sig) : ]
    return fill_buf



class smm_ptr(BaseModule):
    def __init__(self):
        BaseModule.__init__(self)
        self.interrupts = Interrupts( self.cs )
        self.is_check_memory    = True
        self.test_ptr_in_buffer = False
        self.fill_byte = _MEM_FILL_VALUE
        self.fill_size = _MEM_FILL_SIZE
        
    def is_supported(self):
        return True
        

    def get_SMRAM( self ):
        smrrbase = chipsec.chipset.read_register_field( self.cs, 'IA32_SMRR_PHYSBASE', 'PhysBase', True )
        smrrmask  = chipsec.chipset.read_register_field( self.cs, 'IA32_SMRR_PHYSMASK', 'PhysMask', True )
        return (smrrbase,smrrmask)

    def fill_memory( self, _addr, is_ptr_in_buffer, _ptr, _ptr_offset, _sig, _sig_offset ):
        #
        # Fill in contents at PA = _addr with known pattern to check later if any SMI handler modifies them
        #
        fill_buf = FILL_BUFFER( self.fill_byte, self.fill_size, is_ptr_in_buffer, _ptr, _ptr_offset, _sig, _sig_offset )

        s = "[*] writing 0x%X bytes at 0x%016X" % (self.fill_size, _addr)
        if is_ptr_in_buffer: s += " -> PTR at +0x%X" % _ptr_offset
        if _sig is not None: s += " -> SIG at +0x%X" % _sig_offset
        self.logger.log( s )
        self.cs.mem.write_physical_mem( _addr, self.fill_size, fill_buf )

        if self.logger.VERBOSE:
             self.logger.log( "filling in contents at PA 0x%016X:" % _addr )
             chipsec.logger.print_buffer( fill_buf )

        if is_ptr_in_buffer and _ptr is not None: 
            self.logger.log( "[*] writing buffer at PA 0x%016X with 0x%X bytes '%c'" % (_ptr, self.fill_size, self.fill_byte) )
            self.cs.mem.write_physical_mem( _ptr, self.fill_size, self.fill_byte*self.fill_size )

        return True

    def send_smi( self, thread_id, smi_code, smi_data, name, desc, rax, rbx, rcx, rdx, rsi, rdi ):
        self.logger.log( "    > SMI %02X (data: %02X)" % (smi_code,smi_data) )
        if DUMP_GPRS_EVERY_SMI:
            self.logger.log( "      RAX: 0x%016X\n      RBX: 0x%016X\n      RCX: 0x%016X\n      RDX: 0x%016X\n      RSI: 0x%016X\n      RDI: 0x%016X" % (rax,rbx,rcx,rdx,rsi,rdi) )
        self.interrupts.send_SW_SMI( thread_id, smi_code, smi_data, rax, rbx, rcx, rdx, rsi, rdi )
        return True

    def check_memory( self, _addr, _smi_desc, fn, restore_contents=False ):
        _ptr = _smi_desc.ptr
        filler = self.fill_byte*self.fill_size
        #
        # Check if contents have changed at physical address passed in GPRs to SMI handler
        # If changed, SMI handler might have written to that address
        #
        self.logger.log( "    < checking buffers" )

        expected_buf = FILL_BUFFER( self.fill_byte, self.fill_size, _smi_desc.ptr_in_buffer, _smi_desc.ptr, _smi_desc.ptr_offset, _smi_desc.sig, _smi_desc.sig_offset )
        buf          = self.cs.mem.read_physical_mem( _addr, self.fill_size )
        differences  = DIFF( expected_buf, buf, self.fill_size )
        _changed     = (len(differences) > 0)

        if self.logger.VERBOSE:
             self.logger.log( "checking contents at PA 0x%016X:" % _addr )
             chipsec.logger.print_buffer( buf )
             self.logger.log( "expected contents:" )
             chipsec.logger.print_buffer( expected_buf )

        if _changed:
            self.logger.log( "    contents changed at 0x%016X +%s" % (_addr,differences) )
            if restore_contents:
                self.logger.log( "    restoring 0x%X bytes at 0x%016X" % (self.fill_size, _addr) )
                self.cs.mem.write_physical_mem( _addr, self.fill_size, expected_buf )
            if DUMP_MEMORY_ON_DETECT:
                _pth_smi = os.path.join( _pth, '%X_%s'% (_smi_desc.smi_code,_smi_desc.name)  )
                if not os.path.exists( _pth_smi ): os.makedirs( _pth_smi )
                _f = os.path.join( _pth_smi, fn + '.dmp'  )
                self.logger.log( "    dumping buffer to '%s'" % _f )
                write_file( _f, buf )

        _changed1    = False
        expected_buf = filler
        if _smi_desc.ptr_in_buffer and _ptr is not None:
            buf1         = self.cs.mem.read_physical_mem( _ptr, self.fill_size )
            differences1 = DIFF( expected_buf, buf1, self.fill_size )
            _changed1    = (len(differences1) > 0)

            if self.logger.VERBOSE:
                self.logger.log( "checking contents at PA 0x%016X:" % _ptr )
                chipsec.logger.print_buffer( buf1 )

            if _changed1:
                self.logger.log( "    contents changed at 0x%016X +%s" % (_ptr,differences1) )
                if restore_contents:
                    self.logger.log( "    restoring 0x%X bytes at PA 0x%016X" % (self.fill_size, _ptr) )
                    self.cs.mem.write_physical_mem( _ptr, self.fill_size, expected_buf )
                if DUMP_MEMORY_ON_DETECT:
                    _pth_smi = os.path.join( _pth, '%X_%s'% (_smi_desc.smi_code,_smi_desc.name)  )
                    if not os.path.exists( _pth_smi ): os.makedirs( _pth_smi )
                    _f = os.path.join( _pth_smi, fn + ('_ptr%X.dmp' % _smi_desc.ptr_offset)  )
                    self.logger.log( "    dumping buffer to '%s'" % _f )
                    write_file( _f, buf1 )

        return (_changed or _changed1)


    def smi_fuzz_iter( self, thread_id, _addr, _smi_desc, fill_contents=True, restore_contents=False ):
        #
        # Fill memory buffer if not in 'No Fill' mode
        #
        if self.is_check_memory and fill_contents:
            self.fill_memory( _addr, _smi_desc.ptr_in_buffer, _smi_desc.ptr, _smi_desc.ptr_offset, _smi_desc.sig, _smi_desc.sig_offset )
        #
        # Invoke SW SMI Handler
        #
        _rax = _smi_desc.gprs['rax']
        _rbx = _smi_desc.gprs['rbx']
        _rcx = _smi_desc.gprs['rcx']
        _rdx = _smi_desc.gprs['rdx']
        _rsi = _smi_desc.gprs['rsi']
        _rdi = _smi_desc.gprs['rdi']
        self.send_smi( thread_id, _smi_desc.smi_code, _smi_desc.smi_data, _smi_desc.name, _smi_desc.desc, _rax, _rbx, _rcx, _rdx, _rsi, _rdi )

        #
        # Check memory buffer if not in 'No Fill' mode
        #
        contents_changed = False
        if self.is_check_memory:
            fn = '%X-a%X_b%X_c%X_d%X_si%X_di%X' % (_smi_desc.smi_data,_rax,_rbx,_rcx,_rdx,_rsi,_rdi)
            contents_changed = self.check_memory( _addr, _smi_desc, fn, restore_contents )
            if contents_changed:
                msg = "DETECTED: SMI# %X data %X (rax=%X rbx=%X rcx=%X rdx=%X rsi=%X rdi=%X)" % (_smi_desc.smi_code,_smi_desc.smi_data,_rax,_rbx,_rcx,_rdx,_rsi,_rdi)
                self.logger.log_important( msg )     
                if FUZZ_BAIL_ON_1ST_DETECT: raise BadSMIDetected, msg

        if FLUSH_OUTPUT_AFTER_SMI: self.logger.flush()

        return contents_changed


    def test_config( self, thread_id, _smi_config_fname, _addr, _addr1 ):
        #
        # Parse SMM config file describing SMI handlers and their call arguments
        # Then invoke SMI handlers
        #
        fcfg = open( _smi_config_fname, 'r' )
        self.logger.log( "\n[*] >>> Testing SMI handlers defined in '%s'.." % _smi_config_fname )

        bad_ptr_cnt = 0
        _smi_desc = smi_desc()
        for line in fcfg:
            if '' == line.strip():
                self.logger.log( "\n[*] testing SMI# 0x%02X (data: 0x%02X) %s (%s)" % (_smi_desc.smi_code,_smi_desc.smi_data,_smi_desc.name,_smi_desc.desc) )
                if self.smi_fuzz_iter( thread_id, _addr, _smi_desc ): bad_ptr_cnt += 1
                _smi_desc = None
                _smi_desc = smi_desc()
            else:
                name, var = line.strip().partition('=')[::2]
                _n = name.strip().lower()
                if   'name'       == _n: _smi_desc.name       = var
                elif 'desc'       == _n: _smi_desc.desc       = var
                elif 'smi_code'   == _n: _smi_desc.smi_code   = int(var,16) if '*'!=var else _SMI_CODE_DATA
                elif 'smi_data'   == _n: _smi_desc.smi_data   = int(var,16) if '*'!=var else _SMI_CODE_DATA
                elif 'ptr_offset' == _n:
                    _smi_desc.ptr_in_buffer = True
                    _smi_desc.ptr_offset    = int(var,16)
                    _smi_desc.ptr           = _addr1
                elif 'sig'        == _n: _smi_desc.sig        = str( bytearray.fromhex( var ) )
                elif 'sig_offset' == _n: _smi_desc.sig_offset = int(var,16)
                else:                    _smi_desc.gprs[ _n ] = ( _addr if 'PTR'==var else (_FILL_VALUE_BYTE if 'VAL'==var else int(var,16)) ) if '*'!=var else _FILL_VALUE_QWORD

        return bad_ptr_cnt


    def run( self, module_argv ):
        self.logger.start_test( "A tool to test SMI handlers for pointer validation vulnerabilies" )
        self.logger.log( "Usage: chipsec_main -m tools.smm.smm_ptr [ -a <mode>,<config_file>|<smic_start:smic_end>,<size>,<address> ]" )
        self.logger.log( "  mode          SMI handlers testing mode" )
        self.logger.log( "    = config    use SMI configuration file <config_file>" )
        self.logger.log( "  size          size of the memory buffer (in Hex)" )
        self.logger.log( "  address       physical address of memory buffer to pass in GP regs to SMI handlers (in Hex)" )
        self.logger.log( "    = smram     pass address of SMRAM base (system may hang in this mode!)\n" )
        
        test_mode            = 'config'
        _smi_config_fname    = 'chipsec/modules/tools/smm/smm_config.ini'
        _addr                = None
        _addr1               = None
        thread_id            = 0x0

        global DUMP_GPRS_EVERY_SMI
        if len(module_argv) > 1:
            test_mode = module_argv[0].lower()
            if 'config' == test_mode:
                _smi_config_fname = module_argv[1]
            else:
                self.logger.error( "Unknown fuzzing mode '%s'" % module_argv[0] )
                return ModuleResult.ERROR

        if len(module_argv) > 2: self.fill_size = int(module_argv[2],16)
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
            (va, _addr) = self.cs.mem.alloc_physical_mem( self.fill_size, _MAX_ALLOC_PA )
            self.logger.log( "[*] Allocated memory buffer (to pass to SMI handlers)       : 0x%016X" % _addr )

        if self.is_check_memory:
            (va1, _addr1) = self.cs.mem.alloc_physical_mem( self.fill_size, _MAX_ALLOC_PA )
            self.logger.log( "[*] Allocated 2nd buffer (address will be in the 1st buffer): 0x%016X" % _addr1 )

        #
        # @TODO: Need to check that SW/APMC SMI is enabled
        #

        self.logger.log( "\n[*] Configuration" )
        self.logger.log( "    SMI testing mode          : %s" % test_mode )
        if 'config' == test_mode:
            self.logger.log( "    Config file           : %s" % _smi_config_fname )
        self.logger.log( "    Memory buffer pointer     : 0x%016X (address passed in GP regs to SMI)" % _addr )
        self.logger.log( "    Filling/checking memory?  : %s" % ('YES' if self.is_check_memory else 'NO'))
        if self.is_check_memory:
            self.logger.log( "      Second buffer pointer   : 0x%016X (address written to memory buffer)" % _addr1 )
            self.logger.log( "      Number of bytes to fill : 0x%X" % self.fill_size )
            self.logger.log( "      Byte to fill with       : 0x%X" % ord(self.fill_byte) )
        self.logger.log( "    Additional options (can be changed in the source code):" )
        self.logger.log( "      Passing pointer in all GP registers?   : %d" % PTR_IN_ALL_GPRS )
        self.logger.log( "      Default values of the registers        : 0x%016X" % _FILL_VALUE_QWORD )
        self.logger.log( "      Dump all register values every SMI     : %d" % DUMP_GPRS_EVERY_SMI )
        self.logger.log( "      Bail on first detection                : %d" % FUZZ_BAIL_ON_1ST_DETECT )

        self.logger.set_always_flush( FLUSH_OUTPUT_ALWAYS )
        if DUMP_MEMORY_ON_DETECT and not os.path.exists( _pth ): os.makedirs( _pth )

        bad_ptr_cnt = 0
        try:
            if 'config' == test_mode:
                bad_ptr_cnt = self.test_config( thread_id, _smi_config_fname, _addr, _addr1 )
        except BadSMIDetected, msg:
            bad_ptr_cnt = 1
            self.logger.log_important( "Potentially bad SMI detected! Stopped fuzing (see FUZZ_BAIL_ON_1ST_DETECT option)" )

        if bad_ptr_cnt > 0: self.logger.log_bad( "<<< Done: found %d potential occurrences of unchecked input pointers" % bad_ptr_cnt )
        else:               self.logger.log_good( "<<< Done: didn't find unchecked input pointers in tested SMI handlers" ) 

        res = ModuleResult.FAILED if (bad_ptr_cnt > 0) else ModuleResult.PASSED
        return res
