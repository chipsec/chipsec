# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2017, Intel Security
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; Version 2.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# Authors:
#   Yuriy Bulygin
#   Alex Bazhaniuk
#


"""
Experimental module that may help checking SMM firmware for MMIO BAR hijacking
vulnerabilities described in the following presentation:

`BARing the System: New vulnerabilities in Coreboot & UEFI based systems <http://www.intelsecurity.com/advanced-threat-research/content/data/REConBrussels2017_BARing_the_system.pdf>`_ by Intel Advanced Threat Research team at RECon Brussels 2017

Usage:
  ``chipsec_main -m tools.smm.rogue_mmio_bar [-a <smi_start:smi_end>,<b:d.f>]`` 
  
- ``smi_start:smi_end``: range of SMI codes (written to IO port 0xB2)
- ``b:d.f``: PCIe bus/device/function in b:d.f format (in hex)

Example:
    >>> chipsec_main.py -m tools.smm.rogue_mmio_bar -a 0x00:0x80
    >>> chipsec_main.py -m tools.smm.rogue_mmio_bar -a 0x00:0xFF,0:1C.0
"""

from chipsec.module_common import *

from chipsec import defines
from chipsec import file
from chipsec.hal import pci
from chipsec.hal.interrupts import Interrupts

#################################################################
# Testing configuration
#################################################################

FLUSH_OUTPUT_AFTER_SMI = False

_FILL_VALUE_QWORD   = 0x0000000000000000
_MEM_FILL_VALUE     = chr(0xFF)
MAX_MMIO_RANGE_SIZE = 0x10000 # 0x400000

SMI_CODE_LIMIT      = 0x0
SMI_DATA_LIMIT      = 0xF
SMI_FUNC_LIMIT      = 0xF


def DIFF( s, t, sz ):
    return [ pos for pos in range( sz ) if s[pos] != t[pos] ]

class rogue_mmio_bar(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)
        self._interrupts  = Interrupts( self.cs )

        # SMI code to be written to I/O port 0xB2
        self.smic_start   = 0x00
        self.smic_end     = SMI_CODE_LIMIT
        # SMI data to be written to I/O port 0xB3
        self.smid_start   = 0x00
        self.smid_end     = SMI_DATA_LIMIT
        # SMI handler "function" often supplied in ECX register
        self.smif_start   = 0x00
        self.smif_end     = SMI_FUNC_LIMIT
        # SMM communication buffer often supplied in EBX register
        self.comm         = 0x00

        self.reloc_mmio   = None
       

    def smi_mmio_range_fuzz(self, thread_id, b, d, f, bar_off, is64bit, bar, new_bar, base, size):

        # copy all registers from MMIO range to new location in memory
        # we do that once rather than before every SMI since we return after first change detected
        self.logger.log( "[*] copying BAR 0x%X > 0x%X" % (base,self.reloc_mmio) )
        orig_mmio = self.copy_bar(base, self.reloc_mmio, size)
        if self.logger.DEBUG:
            self.cs.mmio.dump_MMIO(base, size)
            file.write_file('mmio_mem.orig', orig_mmio)

        for smi_code in xrange(self.smic_start,self.smic_end+1):
            for smi_data in xrange(self.smid_start,self.smid_end+1):
                for ecx in xrange(self.smif_start,self.smif_end+1):
                    self.logger.log( "> SMI# %02X: data %02X, func (ECX) %X" % (smi_code,smi_data,ecx) )
                    if FLUSH_OUTPUT_AFTER_SMI: self.logger.flush()

                    # point MMIO range to new location (relocate MMIO range)
                    self.logger.log( "  relocating BAR 0x%X" % bar )
                    if not self.modify_bar(b, d, f, bar_off, is64bit, bar, new_bar): continue

                    # generate SW SMI
                    self._interrupts.send_SW_SMI(thread_id, smi_code, smi_data, _FILL_VALUE_QWORD, self.comm, ecx, _FILL_VALUE_QWORD, _FILL_VALUE_QWORD, _FILL_VALUE_QWORD)

                    # restore original location of MMIO range
                    self.restore_bar(b, d, f, bar_off, is64bit, bar)
                    self.logger.log( "  restored BAR with 0x%X" % bar )

                    # check the contents at the address range used to relocate MMIO BAR
                    buf = self.cs.mem.read_physical_mem( self.reloc_mmio, size )
                    diff = DIFF(orig_mmio, buf, size)
                    self.logger.log("  checking relocated MMIO")
                    if len(diff) > 0:
                        self.logger.log_important("changes found at 0x%X +%s" % (self.reloc_mmio, diff))
                        if self.logger.DEBUG: file.write_file('mmio_mem.new', buf)
                        return True
        return False


    def copy_bar(self, bar_base, bar_base_mem, size):
        for off in xrange(0,size,4):
            r = self.cs.mem.read_physical_mem_dword(bar_base + off)
            self.cs.mem.write_physical_mem_dword(bar_base_mem + off, r)
        return self.cs.mem.read_physical_mem(bar_base_mem, size)
    """
    def copy_bar_name(self, name, bar_base_mem):
        bar_regs = self.cs.mmio.read_MMIO_BAR(bar_name)
        size = len(bar_regs)
        off = 0
        for r in bar_regs:
            self.cs.mem.write_physical_mem_dword(bar_base_mem + off, r)
            off += 4
        return self.cs.mem.read_physical_mem(bar_base_mem, size)
    """

    def modify_bar(self, b, d, f, off, is64bit, bar, new_bar):
        # Modify MMIO BAR address
        if is64bit:
            #self.cs.pci.write_dword(b, d, f, off, 0x0)
            self.cs.pci.write_dword(b, d, f, off + pci.PCI_HDR_BAR_STEP, ((new_bar>>32)&0xFFFFFFFF))
        self.cs.pci.write_dword(b, d, f, off, (new_bar&0xFFFFFFFF))
        # Check that the MMIO BAR has been modified correctly. Restore original and skip if not
        l = self.cs.pci.read_dword(b, d, f, off)
        if l != (new_bar&0xFFFFFFFF):
            self.restore_bar(b, d, f, off, is64bit, bar)
            self.logger.log("  skipping (%X != %X)" % (l,new_bar))
            return False
        self.logger.log("  new BAR: 0x%X" % l)
        return True

    def restore_bar(self, b, d, f, off, is64bit, bar):
        if is64bit:
            #self.cs.pci.write_dword(b, d, f, off, 0x0)
            self.cs.pci.write_dword(b, d, f, off + pci.PCI_HDR_BAR_STEP, ((bar>>32)&0xFFFFFFFF))
        self.cs.pci.write_dword(b, d, f, off, (bar&0xFFFFFFFF))                        
        return True

    def run( self, module_argv ):
        self.logger.start_test( "experimental tool to help checking for SMM MMIO BAR issues" )

        pcie_devices = []

        if len(module_argv) > 0:
            smic_arr        = module_argv[0].split(':')
            self.smic_start = int(smic_arr[0],16)
            self.smic_end   = int(smic_arr[1],16)

        if len(module_argv) > 1:
            try:
                b,df = module_argv[1].split(':')
                d,f = df.split('.')
                pcie_devices = [ (int(b,16),int(d,16),int(f,16),0,0) ]
            except:
                self.logger.error("incorrect b:d.f format\nUsage:\nchipsec_main -m tools.smm.rogue_mmio_bar [-a <smi_start:smi_end>,<b:d.f>]")
        else:
            self.logger.log("[*] discovering PCIe devices..")
            pcie_devices = self.cs.pci.enumerate_devices()

        self.logger.log("[*] testing MMIO of PCIe devices:")
        for (b,d,f,_,_) in pcie_devices: self.logger.log("    %02X:%02X.%X" % (b,d,f))

        # allocate a page or SMM communication buffer (often supplied in EBX register)
        _, self.comm = self.cs.mem.alloc_physical_mem(0x1000, defines.BOUNDARY_4GB-1)
        #self.cs.mem.write_physical_mem( self.comm, 0x1000, chr(0)*0x1000 )

        # allocate range in physical memory (should cover all MMIO ranges including GTTMMADR)
        bsz = 2*MAX_MMIO_RANGE_SIZE
        (va, pa) = self.cs.mem.alloc_physical_mem( bsz, defines.BOUNDARY_4GB-1 )
        self.logger.log( "[*] allocated memory range : 0x%016X (0x%X bytes)" % (pa,bsz) )
        self.cs.mem.write_physical_mem(pa, bsz, _MEM_FILL_VALUE*bsz)
        # align at the MAX_MMIO_RANGE_SIZE boundary within allocated range
        self.reloc_mmio = pa & (~(MAX_MMIO_RANGE_SIZE-1))
        if self.reloc_mmio < pa: self.reloc_mmio += MAX_MMIO_RANGE_SIZE
        self.logger.log("[*] MMIO relocation address: 0x%016X\n" % self.reloc_mmio)
        
        for (b, d, f, vid, did) in pcie_devices:
            self.logger.log("[*] enumerating device %02X:%02X.%X MMIO BARs.." % (b, d, f))
            device_bars = self.cs.pci.get_device_bars(b, d, f, True)
            for (base, isMMIO, is64bit, bar_off, bar, size) in device_bars:
                if isMMIO and size <= MAX_MMIO_RANGE_SIZE:
                    self.logger.flush()
                    self.logger.log( "[*] found MMIO BAR +0x%02X (base 0x%016X, size 0x%X)" % (bar_off,base,size) )
                    new_bar = ((self.reloc_mmio & pci.PCI_HDR_BAR_BASE_MASK_MMIO64)|(bar & pci.PCI_HDR_BAR_CFGBITS_MASK))
                    if self.smi_mmio_range_fuzz(0, b, d, f, bar_off, is64bit, bar, new_bar, base, size):
                        return ModuleResult.FAILED

        return ModuleResult.PASSED
