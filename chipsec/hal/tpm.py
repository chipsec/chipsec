#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2016, Intel Corporation
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
Trusted Platform Module (TPM) HAL component

https://trustedcomputinggroup.org
"""

import struct
import sys
import time
from collections import namedtuple

from chipsec.logger import *
from chipsec.file import *

import chipsec.hal.tpm12_commands

class TpmRuntimeError (RuntimeError):
    pass

COMMANDREADY = 0x40
TPMGO = 0x20
HEADERSIZE = 0x0A
HEADERFORMAT = '>HII'
BEENSEIZED  = 0x10
REQUESTUSE  = 0x2
ACTIVELOCALITY = 0x20
DATAAVAIL = 0x10

TPM_DATAFIFO = 0x0024
TPM_STS = 0x0018
TPM_DIDVID = 0x0F00
TPM_ACCESS = 0x0000
TPM_RID = 0x0F04
TPM_INTCAP = 0x0014
TPM_INTENABLE = 0x0008

STATUS = {
  0x00:"Success",
  0x01:"ERROR: Authentication Failed",
  0x02:"ERROR: The index to a PCR, DIR or other register is incorrect",
  0x03:"ERROR: One or more parameter is bad",
  0x04:"ERROR: An operation completed successfully but the auditing of that operation failed",
  0x05:"ERROR: The clear disable flag is set and all clear operations now require physical access",
  0x06:"ERROR: The TPM is deactivated",
  0x07:"ERROR: The TPM is disabled",
  0x08:"ERROR: The target command has been disabled",
  0x09:"ERROR: The operation failed",
  0x0A:"ERROR: The ordinal was unknown or inconsistent",
  0x0B:"ERROR: The ability to install an owner is disabled",
  0x0C:"ERROR: The key handle can not be interpreted",
  0x0D:"ERROR: The key handle points to an invalid key",
  0x0E:"ERROR: Unacceptable encryption scheme",
  0x0F:"ERROR: Migration authorization failed",
  0x10:"ERROR: PCR information could not be interpreted",
  0x11:"ERROR: No room to load key",
  0x12:"ERROR: There is no SRK set",
  0x13:"ERROR: An encrypted blob is invalid or was not created by this TPM",
  0x14:"ERROR: There is already an Owner",
  0x15:"ERROR: The TPM has insufficient internal resources to perform the requested action",
  0x16:"ERROR: A random string was too short",
  0x17:"ERROR: The TPM does not have the space to perform the operation",
  0x18:"ERROR: The named PCR value does not match the current PCR value.",
  0x19:"ERROR: The paramSize argument to the command has the incorrect value",
  0x1A:"ERROR: There is no existing SHA-1 thread.",
  0x1B:"ERROR: The calculation is unable to proceed because the existing SHA-1 thread has already encountered an error",
  0x1C:"ERROR: Self-test has failed and the TPM has shut-down",
  0x1D:"ERROR: The authorization for the second key in a 2 key function failed authorization",
  0x1E:"ERROR: The tag value sent to for a command is invalid",
  0x1F:"ERROR: An IO error occurred transmitting information to the TPM",
  0x20:"ERROR: The encryption process had a problem",
  0x21:"ERROR: The decryption process did not complete",
  0x22:"ERROR: An invalid handle was used",
  0x23:"ERROR: The TPM does not a EK installed",
  0x24:"ERROR: The usage of a key is not allowed",
  0x25:"ERROR: The submitted entity type is not allowed",
  0x26:"ERROR: The command was received in the wrong sequence relative to TPM_Init and a subsequent TPM_Startup",
  0x27:"ERROR: Signed data cannot include additional DER information",
  0x28:"ERROR: The key properties in TPM_KEY_PARMs are not supported by this TPM",
  0x29:"ERROR: The migration properties of this key are incorrect",
  0x2A:"ERROR: The signature or encryption scheme for this key is incorrect or not permitted in this situation",
  0x2B:"ERROR: The size of the data (or blob) parameter is bad or inconsistent with the referenced key",
  0x2C:"ERROR: A parameter is bad",
  0x2D:"ERROR: Either the physicalPresence or physicalPresenceLock bits have the wrong value",
  0x2E:"ERROR: The TPM cannot perform this version of the capability",
  0x2F:"ERROR: The TPM does not allow for wrapped transport sessions",
  0x30:"ERROR: TPM audit construction failed and the underlying command was returning a failure code also",
  0x31:"ERROR: TPM audit construction failed and the underlying command was returning success",
  0x32:"ERROR: Attempt to reset a PCR register that does not have the resettable attribute",
  0x33:"ERROR: Attempt to reset a PCR register that requires locality and locality modifier not part of command transport",
  0x34:"ERROR: Make identity blob not properly typed",
  0x35:"ERROR: When saving context identified resource type does not match actual resource",
  0x36:"ERROR: The TPM is attempting to execute a command only available when in FIPS mode",
  0x37:"ERROR: The command is attempting to use an invalid family ID",
  0x38:"ERROR: The permission to manipulate the NV storage is not available",
  0x39:"ERROR: The operation requires a signed command",
  0x3A:"ERROR: Wrong operation to load an NV key",
  0x3B:"ERROR: NV_LoadKey blob requires both owner and blob authorization",
  0x3C:"ERROR: The NV area is locked and not writeable",
  0x3D:"ERROR: The locality is incorrect for the attempted operation",
  0x3E:"ERROR: The NV area is read only and can?t be written to",
  0x3F:"ERROR: There is no protection on the write to the NV area",
  0x40:"ERROR: The family count value does not match",
  0x41:"ERROR: The NV area has already been written to",
  0x42:"ERROR: The NV area attributes conflict",
  0x43:"ERROR: The structure tag and version are invalid or inconsistent",
  0x44:"ERROR: The key is under control of the TPM Owner and can only be evicted by the TPM Owner",
  0x45:"ERROR: The counter handle is incorrect",
  0x46:"ERROR: The write is not a complete write of the area",
  0x47:"ERROR: The gap between saved context counts is too large",
  0x48:"ERROR: The maximum number of NV writes without an owner has been exceeded",
  0x49:"ERROR: No operator AuthData value is set",
  0x4A:"ERROR: The resource pointed to by context is not loaded",
  0x4B:"ERROR: The delegate administration is locked",
  0x4C:"ERROR: Attempt to manage a family other then the delegated family",
  0x4D:"ERROR: Delegation table management not enabled",
  0x4E:"ERROR: There was a command executed outside of an exclusive transport session",
  0x4F:"ERROR: Attempt to context save a owner evict controlled key",
  0x50:"ERROR: The DAA command has no resources available to execute the command",
  0x51:"ERROR: The consistency check on DAA parameter inputData0 has failed",
  0x52:"ERROR: The consistency check on DAA parameter inputData1 has failed",
  0x53:"ERROR: The consistency check on DAA_issuerSettings has failed",
  0x54:"ERROR: The consistency check on DAA_tpmSpecific has failed",
  0x55:"ERROR: The atomic process indicated by the submitted DAA command is not the expected process",
  0x56:"ERROR: The issuer's validity check has detected an inconsistency",
  0x57:"ERROR: The consistency check on w has failed",
  0x58:"ERROR: The handle is incorrect",
  0x59:"ERROR: Delegation is not correct",
  0x5A:"ERROR: The context blob is invalid",
  0x5B:"ERROR: Too many contexts held by the TPM",
  0x5C:"ERROR: Migration authority signature validation failure",
  0x5D:"ERROR: Migration destination not authenticated",
  0x5E:"ERROR: Migration source incorrect",
  0x5F:"ERROR: Incorrect migration authority",
  0x60:"ERROR: TBD",
  0x61:"ERROR: Attempt to revoke the EK and the EK is not revocable",
  0x62:"ERROR: Bad signature of CMK ticket",
  0x63:"ERROR: There is no room in the context list for additional contexts",
  0x800:"NON-FATAL ERROR: The TPM is too busy to respond to the command immediately, but the command could be resubmitted at a later time",
  0x801:"NON-FATAL ERROR: TPM_ContinueSelfTest has not been run.",
  0x802:"NON-FATAL ERROR: The TPM is currently executing the actions of TPM_ContinueSelfTest because the ordinal required resources that have not been tested",
  0x803:"NON-FATAL ERROR: The TPM is defending against dictionary attacks and is in some time-out period." 
}

LOCALITY = {
  '0':0x0000,
  '1':0x1000,
  '2':0x2000,
  '3':0x3000,
  '4':0x4000
}

COMMANDS = {
  "pcrread"              : chipsec.hal.tpm12_commands.pcrread,
  "nvread"               : chipsec.hal.tpm12_commands.nvread,
  "startup"              : chipsec.hal.tpm12_commands.startup,
  "continueselftest"     : chipsec.hal.tpm12_commands.continueselftest,
  "forceclear"           : chipsec.hal.tpm12_commands.forceclear
}

class TPM_RESPONSE_HEADER( namedtuple('TPM_RESPONSE_HEADER', 'ResponseTag DataSize ReturnCode') ):
    __slots__ = ()
    def __str__(self):
        _str = """----------------------------------------------------------------
                     TPM response header
----------------------------------------------------------------
   Response TAG: 0x%x
   Data Size   : 0x%x
   Return Code : 0x%x
""" % ( self.ResponseTag, self.DataSize, self.ReturnCode  )
        _str += "\t"
        try:
            _str += STATUS[self.ReturnCode]
        except:
            _str += "Invalid return code"
        _str += "\n"
        return _str

class TPM():
    def __init__( self, cs ):
        self.cs = cs
        self.helper = cs.helper
        self.TPM_BASE = int(self.cs.Cfg.MEMORY_RANGES["TPM"]["address"], 16)

    def command( self, commandName, locality, command_argv ):
        """ 
        Send command to the TPM and receive data
        """
        try:
            Locality = LOCALITY[locality]
        except:
            logger().log_bad("Invalid locality value\n")
            return

        requestedUse = False
        
        #
        # Request locality use if needed
        #
        access_address = self.TPM_BASE | Locality | TPM_ACCESS 
        if self.helper.read_mmio_reg( access_address, 4 ) == BEENSEIZED:
            self.helper.write_mmio_reg( access_address, 4, REQUESTUSE )
            requestedUse = True
        
        #
        # Build command (big endian) and send/receive 
        #
        ( command, size ) = COMMANDS[commandName]( command_argv )
        self._send_command( Locality, command, size )
        
        ( header, data, header_blob, data_blob ) = self._read_response( Locality )
        logger().log( header )
        print_buffer( str(data_blob) )
        logger().log( '\n' )
        
        #
        # Release locality if needed
        #
        if requestedUse==True:
            self.helper.write_mmio_reg( access_address, 4, BEENSEIZED )
        self.helper.write_mmio_reg( access_address, 1, ACTIVELOCALITY )
    
    def _send_command( self, Locality, command, size ):
        """
        Send a command to the TPM using the locality specified
        """            
        count = 0
        
        datafifo_address = self.TPM_BASE | Locality | TPM_DATAFIFO
        sts_address = self.TPM_BASE | Locality| TPM_STS
        access_address = self.TPM_BASE | Locality| TPM_ACCESS
        
        self.helper.write_mmio_reg( access_address, 1, REQUESTUSE )
        #
        # Set status to command ready
        #
        sts_value = self.helper.read_mmio_reg( sts_address, 1 )       
        while ( 0 == ( sts_value & COMMANDREADY ) ):
            self.helper.write_mmio_reg( sts_address, 1, COMMANDREADY )
            sts_value = self.helper.read_mmio_reg( sts_address, 1 )        
 
        while count < size:
            sts_value = self.helper.read_mmio_reg( sts_address, 4 )
            burst_count = ( ( sts_value>>8 ) & 0xFFFFFF )
            burst_index = 0
            while ( burst_index < burst_count ) and ( count < size ):
                self.helper.write_mmio_reg( datafifo_address, 1, struct.unpack("=B", command[count])[0] )
                count += 1
                burst_index += 0x1
                
        self.helper.write_mmio_reg( sts_address, 1, TPMGO )
        
    def _read_response(self, Locality):
        """
        Read the TPM's response using the specified locality
        """     
        count = 0
        header = ""
        header_blob = bytearray()
        data = ""
        data_blob = bytearray()       
        #
        # Build FIFO address
        #            
        datafifo_address = self.TPM_BASE | Locality | TPM_DATAFIFO
        access_address = self.TPM_BASE | Locality| TPM_ACCESS        
        sts_address = self.TPM_BASE | Locality| TPM_STS

        sts_value = self.helper.read_mmio_reg( sts_address, 1 )
        data_avail = bin( sts_value & ( 1<<4 ) )[2]
        #
        # Read data available
        #        
        # watchdog?
        while data_avail == '0':
            sts_value = self.helper.read_mmio_reg( sts_address, 1 )
            self.helper.write_mmio_reg( sts_address, 1, DATAAVAIL )
            data_avail = bin( sts_value & ( 1<<4 ) )[2]
        
        while count < HEADERSIZE:
            sts_value = self.helper.read_mmio_reg( sts_address, 4 )
            burst_count = ( ( sts_value>>8 ) & 0xFFFFFF )
            burst_index = 0
            while ( burst_index < burst_count ) and ( count < HEADERSIZE ):
                header_blob.append(self.helper.read_mmio_reg( datafifo_address, 1 ))
                count += 1
                burst_index += 0x1

        header = TPM_RESPONSE_HEADER( *struct.unpack_from( HEADERFORMAT, header_blob ) )
        
        count = 0
        if header.DataSize > 10 and header.ReturnCode == 0:
            length = header.DataSize - HEADERSIZE
            while count < length:
                sts_value = self.helper.read_mmio_reg( sts_address, 4 )
                burst_count = ( ( sts_value>>8 ) & 0xFFFFFF )
                burst_index = 0
                while ( burst_index < burst_count ) and ( count < length ):
                    data_blob.append( self.helper.read_mmio_reg( datafifo_address, 1 ) )
                    count += 1
                    burst_index += 0x1
            
        return ( header, data, header_blob, data_blob )   
    
    def dump_access( self, locality ):
        """ 
        View the contents of the register used to gain ownership of the TPM
        """
        try:
            Locality = LOCALITY[locality]
        except:
            logger().log_bad("Invalid locality value\n")
            return
         
        access_address = self.TPM_BASE | Locality| TPM_ACCESS 
        access_value = self.helper.read_mmio_reg( access_address, 1 )

        logger().log( "================================================================" )
        logger().log( "                        TPM Access" )
        logger().log( "================================================================" )
        logger().log( "\ttpmRegValidSts  : 0x%s" % bin( access_value & ( 1<<7 ) )[2] )
        logger().log( "\treserved        : 0x%s" % bin( access_value & ( 1<<6 ) )[2] )
        logger().log( "\tactiveLocality  : 0x%s" % bin( access_value & ( 1<<5 ) )[2] )
        logger().log( "\tbeenSeized      : 0x%s" % bin( access_value & ( 1<<4 ) )[2] )
        logger().log( "\tSeize           : 0x%s" % bin( access_value & ( 1<<3 ) )[2] )
        logger().log( "\tpendingRequest  : 0x%s" % bin( access_value & ( 1<<2 ) )[2] )
        logger().log( "\trequestUse      : 0x%s" % bin( access_value & ( 1<<1 ) )[2] )
        logger().log( "\ttpmEstablishment: 0x%s" % bin( access_value & ( 1<<0 ) )[2] )
             
    def dump_status( self, locality ):
        """
        View general status details
        """
        try:
            Locality = LOCALITY[locality]
        except:
            logger().log_bad("Invalid locality value\n")
            return
         
        sts_address = self.TPM_BASE | Locality| TPM_STS 
        sts_value = self.helper.read_mmio_reg( sts_address, 4 )
        
        logger().log( "================================================================" )
        logger().log( "                         TPM Status" )
        logger().log( "================================================================" )
        logger().log( "\tburstCount   : 0x%x" % ( ( sts_value>>8 ) & 0xFFFFFF ) )
        logger().log( "\tstsValid     : 0x%s" % bin( sts_value & ( 1<<7 ) )[2] )
        logger().log( "\tcommandReady : 0x%s" % bin( sts_value & ( 1<<6 ) )[2] )
        logger().log( "\ttpmGo        : 0x%s" % bin( sts_value & ( 1<<5 ) )[2] )
        logger().log( "\tdataAvail    : 0x%s" % bin( sts_value & ( 1<<4 ) )[2] )
        logger().log( "\tExpect       : 0x%s" % bin( sts_value & ( 1<<3 ) )[2] )
        logger().log( "\tReserved     : 0x%s" % bin( sts_value & ( 1<<2 ) )[2] )
        logger().log( "\tresponseRetry: 0x%s" % bin( sts_value & ( 1<<1 ) )[2] )
        logger().log( "\tReserved     : 0x%s" % bin( sts_value & ( 1<<0 ) )[2] )

    def dump_didvid( self, locality ):
        """ 
        TPM's Vendor and Device ID
        """
        try:
            Locality = LOCALITY[locality]
        except:
            logger().log_bad("Invalid locality value\n")
            return
         
        didvid_address = self.TPM_BASE | Locality| TPM_DIDVID 
        didvid_value = self.helper.read_mmio_reg( didvid_address, 4 )
        
        logger().log( "================================================================" )
        logger().log( "                           TPM DID VID" )
        logger().log( "================================================================" )
        logger().log( "\tdid: 0x%x" % ( ( didvid_value>>16 ) & 0xFFFF ) )
        logger().log( "\tvid: 0x%x" % ( didvid_value & 0xFFFF) )
 
    def dump_rid( self, locality ):
        """ 
        TPM's Revision ID
        """
        try:
            Locality = LOCALITY[locality]
        except:
            logger().log_bad("Invalid locality value\n")
            return
         
        rid_address = self.TPM_BASE | Locality| TPM_RID 
        rid_value = self.helper.read_mmio_reg( rid_address, 1 )  
        
        logger().log( "================================================================" )
        logger().log( "                             TPM RID" )
        logger().log( "================================================================" )
        logger().log( "\trid: 0x%x" % rid_value )        
 
    def dump_intcap( self, locality ):
        """ 
        Provides information of which interrupts that particular TPM supports
        """
        try:
            Locality = LOCALITY[locality]
        except:
            logger().log_bad("Invalid locality value\n")
            return
         
        intcap_address = self.TPM_BASE | Locality| TPM_INTCAP
        intcap_value = self.helper.read_mmio_reg( intcap_address, 4 )

        logger().log( "================================================================" )
        logger().log( "                     TPM INTF CAPABILITY" )
        logger().log( "================================================================" )
        logger().log( "\tReserved                : 0x%x" % ( ( intcap_value>>8 ) & 0xFFFFFE ) )
        logger().log( "\tBurstCountStatic        : 0x%s" % bin( intcap_value & ( 1<<8 ) )[2] )
        logger().log( "\tCommandReadyIntSupport  : 0x%s" % bin( intcap_value & ( 1<<7 ) )[2] )
        logger().log( "\tInterruptEdgeFalling    : 0x%s" % bin( intcap_value & ( 1<<6 ) )[2] )
        logger().log( "\tInterruptEdgeRising     : 0x%s" % bin( intcap_value & ( 1<<5 ) )[2] )
        logger().log( "\tInterruptLevelLow       : 0x%s" % bin( intcap_value & ( 1<<4 ) )[2] )
        logger().log( "\tInterruptLevelHigh      : 0x%s" % bin( intcap_value & ( 1<<3 ) )[2] )
        logger().log( "\tLocalityChangeIntSupport: 0x%s" % bin( intcap_value & ( 1<<2 ) )[2] )
        logger().log( "\tstsValidIntSupport      : 0x%s" % bin( intcap_value & ( 1<<1 ) )[2] )
        logger().log( "\tdataAvailIntSupport     : 0x%s" % bin( intcap_value & ( 1<<0 ) )[2] )

    def dump_intenable( self, locality ):
        """ 
        View the contents of the register used to enable specific interrupts
        """
        polType = { 0:"High Level", 1:"Low Level", 2:"Rising edge", 3:"Failing edge" }
        
        try:
            Locality = LOCALITY[locality]
        except:
            logger().log_bad("Invalid locality value\n")
            return
         
        intenable_address = self.TPM_BASE | Locality| TPM_INTENABLE
        intenable_value = self.helper.read_mmio_reg( intenable_address, 4 )
        
        logger().log( "================================================================" )
        logger().log( "                         TPM INT ENABLE" )
        logger().log( "================================================================" )
        logger().log( "\tglobalIntEnable        : 0x%s" % bin( intenable_value & ( 1<<31 ) )[2] )
        logger().log( "\tReserved               : 0x%x" % ( (intenable_value>>8) & 0x7FFFFF00 ) )
        logger().log( "\tcommandReadyEnable     : 0x%s" % bin( intenable_value & ( 1<<7 ) )[2] )
        logger().log( "\tReserved               : 0x%x" % ( (intenable_value>>5) & 0x3  ) )
        type = ( ( intenable_value>>3 ) & 0x3 )
        logger().log( "\ttypePolarity           : 0x%x  %s" % ( type, polType[type] ) )
        logger().log( "\tlocalityChangeIntEnable: 0x%s" % bin( intenable_value & ( 1<<2 ) )[2] )
        logger().log( "\tstsValidIntEnable      : 0x%s" % bin( intenable_value & ( 1<<1 ) )[2] )
        logger().log( "\tdataAvailIntEnable     : 0x%s" % bin( intenable_value & ( 1<<0 ) )[2] )
