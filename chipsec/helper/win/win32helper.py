#!/usr/bin/python
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




# -------------------------------------------------------------------------------
#
# CHIPSEC: Platform Hardware Security Assessment Framework
# (c) 2010-2012 Intel Corporation
#
# -------------------------------------------------------------------------------

"""
Management and communication with Windows kernel mode driver which provides access to hardware resources

.. note:: 
    On Windows you need to install pywin32 Python extension corresponding to your Python version:
    http://sourceforge.net/projects/pywin32/
"""

__version__ = '1.0'

import os.path
import struct
import sys
import platform
import re
import errno
import traceback
import time
import shutil
from threading import Lock
from collections import namedtuple
from ctypes import *

import pywintypes
import win32service #win32serviceutil, win32api, win32con
import winerror
from win32file import FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OVERLAPPED, INVALID_HANDLE_VALUE
import win32api, win32process, win32security, win32file, win32serviceutil

from chipsec.helper.oshelper import Helper, OsHelperError, HWAccessViolationError, UnimplementedAPIError, UnimplementedNativeAPIError, get_tools_path
from chipsec.logger import logger, print_buffer
import chipsec.file
import chipsec.defines


class PCI_BDF(Structure):
    _fields_ = [("BUS",  c_ushort, 16),  # Bus
                ("DEV",  c_ushort, 16),  # Device
                ("FUNC", c_ushort, 16),  # Function
                ("OFF",  c_ushort, 16)]  # Offset

kernel32 = windll.kernel32


drv_hndl_error_msg = "Cannot open chipsec driver handle. Make sure chipsec driver is installed and started if you are using option -e (see README)"

DRIVER_FILE_NAME = "chipsec_hlpr.sys"
DEVICE_FILE      = "\\\\.\\chipsec_hlpr"
SERVICE_NAME     = "chipsec"
DISPLAY_NAME     = "CHIPSEC Service"

CHIPSEC_INSTALL_PATH = os.path.join(sys.prefix, "Lib\site-packages\chipsec")

# Status Codes
STATUS_PRIVILEGED_INSTRUCTION = 0xC0000096

# Defines for Win32 API Calls
GENERIC_READ    = 0x80000000
GENERIC_WRITE   = 0x40000000
OPEN_EXISTING   = 0x3

FILE_DEVICE_UNKNOWN = 0x00000022

METHOD_BUFFERED   = 0
METHOD_IN_DIRECT  = 1
METHOD_OUT_DIRECT = 2
METHOD_NEITHER    = 3

FILE_ANY_ACCESS     = 0
FILE_SPECIAL_ACCESS = (FILE_ANY_ACCESS)
FILE_READ_ACCESS    = ( 0x0001 )
FILE_WRITE_ACCESS   = ( 0x0002 )

def CTL_CODE( DeviceType, Function, Method, Access ):
    return ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method)

#
# chipsec driver IOCTL codes
#
CHIPSEC_CTL_ACCESS = (FILE_READ_ACCESS | FILE_WRITE_ACCESS)

CLOSE_DRIVER                   = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
READ_PCI_CFG_REGISTER          = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
WRITE_PCI_CFG_REGISTER         = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_READ_PHYSMEM             = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_WRITE_PHYSMEM            = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80a, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_LOAD_UCODE_PATCH         = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80b, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_WRMSR                    = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80c, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_RDMSR                    = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80d, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_READ_IO_PORT             = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80e, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_WRITE_IO_PORT            = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80f, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_GET_CPU_DESCRIPTOR_TABLE = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_SWSMI                    = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_ALLOC_PHYSMEM            = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x812, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_CPUID                    = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x813, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_HYPERCALL                = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x814, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_GET_PHYSADDR             = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x815, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_MAP_IO_SPACE             = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x816, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_FREE_PHYSMEM             = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x817, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_WRCR                     = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x818, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_RDCR                     = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x819, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_MSGBUS_SEND_MESSAGE      = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x820, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)

#
# NT Errors
#
# Defined in WinDDK\7600.16385.1\inc\api\ntstatus.h
#

#
# UEFI constants
#
# Default buffer size for EFI variables
#EFI_VAR_MAX_BUFFER_SIZE = 128*1024
EFI_VAR_MAX_BUFFER_SIZE = 1024*1024

attributes = {
  "EFI_VARIABLE_NON_VOLATILE"                          : 0x00000001,
  "EFI_VARIABLE_BOOTSERVICE_ACCESS"                    : 0x00000002,
  "EFI_VARIABLE_RUNTIME_ACCESS"                        : 0x00000004,
  "EFI_VARIABLE_HARDWARE_ERROR_RECORD"                 : 0x00000008,
  "EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS"            : 0x00000010,
  "EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS" : 0x00000020,
  "EFI_VARIABLE_APPEND_WRITE"                          : 0x00000040
}

PyLong_AsByteArray = pythonapi._PyLong_AsByteArray
PyLong_AsByteArray.argtypes = [py_object,
                               c_char_p,
                               c_size_t,
                               c_int,
                               c_int]

def packl_ctypes( lnum, bitlength ):
    length = (bitlength + 7)/8
    a = create_string_buffer( length )
    PyLong_AsByteArray(lnum, a, len(a), 1, 1) # 4th param is for endianness 0 - big, non 0 - little
    return a.raw

#
# Firmware Table Provider Signatures
#
FirmwareTableProviderSignature_ACPI = 0x41435049 # 'ACPI' - The ACPI firmware table provider
FirmwareTableProviderSignature_FIRM = 0x4649524D # 'FIRM' - The raw firmware table provider
FirmwareTableProviderSignature_RSMB = 0x52534D42 # 'RSMB' - The raw SMBIOS firmware table provider

FirmwareTableID_RSDT = 0x54445352
FirmwareTableID_XSDT = 0x54445358

#
# Windows 8 NtEnumerateSystemEnvironmentValuesEx (infcls = 2)
#
def guid_str(guid0, guid1, guid2, guid3):
    return ( "%08X-%04X-%04X-%04s-%06s" % (guid0, guid1, guid2, guid3[:2].encode('hex').upper(), guid3[-6::].encode('hex').upper()) )

class EFI_HDR_WIN( namedtuple('EFI_HDR_WIN', 'Size DataOffset DataSize Attributes guid0 guid1 guid2 guid3') ):
    __slots__ = ()
    def __str__(self):
        return """
Header (Windows)
----------------
VendorGuid= {%08X-%04X-%04X-%04s-%06s}
Size      = 0x%08X
DataOffset= 0x%08X
DataSize  = 0x%08X
Attributes= 0x%08X
""" % ( self.guid0, self.guid1, self.guid2, self.guid3[:2].encode('hex').upper(), self.guid3[-6::].encode('hex').upper(), self.Size, self.DataOffset, self.DataSize, self.Attributes )

def getEFIvariables_NtEnumerateSystemEnvironmentValuesEx2( nvram_buf ):
    start = 0
    buffer = nvram_buf
    bsize = len(buffer)
    header_fmt = "<IIIIIHH8s"
    header_size = struct.calcsize( header_fmt )
    variables = dict()
    off = 0
    while (off + header_size) < bsize:
        efi_var_hdr = EFI_HDR_WIN( *struct.unpack_from( header_fmt, buffer[ off : off + header_size ] ) )

        next_var_offset = off + efi_var_hdr.Size
        efi_var_buf     = buffer[ off : next_var_offset ]
        efi_var_data    = buffer[ off + efi_var_hdr.DataOffset : off + efi_var_hdr.DataOffset + efi_var_hdr.DataSize ]

        #efi_var_name = "".join( buffer[ start + header_size : start + efi_var_hdr.DataOffset ] ).decode('utf-16-le')
        str_fmt = "%ds" % (efi_var_hdr.DataOffset - header_size)
        s, = struct.unpack( str_fmt, buffer[ off + header_size : off + efi_var_hdr.DataOffset ] )
        efi_var_name = unicode(s, "utf-16-le", errors="replace").split(u'\u0000')[0]

        if efi_var_name not in variables.keys():
            variables[efi_var_name] = []
        #                                off, buf,         hdr,         data,         guid,                                                                                 attrs
        variables[efi_var_name].append( (off, efi_var_buf, efi_var_hdr, efi_var_data, guid_str(efi_var_hdr.guid0, efi_var_hdr.guid1, efi_var_hdr.guid2, efi_var_hdr.guid3), efi_var_hdr.Attributes) )

        if 0 == efi_var_hdr.Size: break
        off = next_var_offset

    return variables
#    return ( start, next_var_offset, efi_var_buf, efi_var_hdr, efi_var_name, efi_var_data, guid_str(efi_var_hdr.guid0, efi_var_hdr.guid1, efi_var_hdr.guid2, efi_var_hdr.guid3), efi_var_hdr.Attributes )



def _handle_winerror(fn, msg, hr):
    _handle_error( ("%s failed: %s (%d)" % (fn, msg, hr)), hr )
def _handle_error( err, hr=0 ):
    logger().error( err )
    raise OsHelperError( err, hr )


_tools = {
  chipsec.defines.ToolType.TIANO_COMPRESS: 'TianoCompress.exe',
  chipsec.defines.ToolType.LZMA_COMPRESS : 'LzmaCompress.exe'
}

class Win32Helper(Helper):

    def __init__(self):
        super(Win32Helper, self).__init__()
        import platform
        self.os_system  = platform.system()
        self.os_release = platform.release()
        self.os_version = platform.version()
        self.os_machine = platform.machine()
        self.os_uname   = platform.uname()
        if "windows" == self.os_system.lower():
            win_ver = "win7_" + self.os_machine.lower()
            if ("5" == self.os_release): win_ver = "winxp"
            if logger().HAL: logger().log( "[helper] OS: %s %s %s" % (self.os_system, self.os_release, self.os_version) )
            if logger().HAL: logger().log( "[helper] Using 'helper/win/%s' path for driver" % win_ver )

        self.use_existing_service = False

        self.driver_path    = None
        self.win_ver        = win_ver
        self.driver_handle  = None
        self.device_file    = pywintypes.Unicode(DEVICE_FILE)

        c_int_p = POINTER(c_int)

        # enable required SeSystemEnvironmentPrivilege privilege
        privilege = win32security.LookupPrivilegeValue( None, 'SeSystemEnvironmentPrivilege' )
        token = win32security.OpenProcessToken( win32process.GetCurrentProcess(), win32security.TOKEN_READ|win32security.TOKEN_ADJUST_PRIVILEGES )
        win32security.AdjustTokenPrivileges( token, False, [(privilege, win32security.SE_PRIVILEGE_ENABLED)] )
        win32api.CloseHandle( token )
        # import firmware variable API
        try:
            self.GetFirmwareEnvironmentVariable = kernel32.GetFirmwareEnvironmentVariableW
            self.GetFirmwareEnvironmentVariable.restype = c_int
            self.GetFirmwareEnvironmentVariable.argtypes = [c_wchar_p, c_wchar_p, c_void_p, c_int]
            self.SetFirmwareEnvironmentVariable = kernel32.SetFirmwareEnvironmentVariableW
            self.SetFirmwareEnvironmentVariable.restype = c_int
            self.SetFirmwareEnvironmentVariable.argtypes = [c_wchar_p, c_wchar_p, c_void_p, c_int]
        except AttributeError, msg:
            logger().warn( "G[S]etFirmwareEnvironmentVariableW function doesn't seem to exist" )
            pass

        try:
            self.NtEnumerateSystemEnvironmentValuesEx = windll.ntdll.NtEnumerateSystemEnvironmentValuesEx
            self.NtEnumerateSystemEnvironmentValuesEx.restype = c_int
            self.NtEnumerateSystemEnvironmentValuesEx.argtypes = [c_int, c_void_p, c_void_p]
        except AttributeError, msg:
            logger().warn( "NtEnumerateSystemEnvironmentValuesEx function doesn't seem to exist" )
            pass

        try:
            self.GetFirmwareEnvironmentVariableEx = kernel32.GetFirmwareEnvironmentVariableExW
            self.GetFirmwareEnvironmentVariableEx.restype = c_int
            self.GetFirmwareEnvironmentVariableEx.argtypes = [c_wchar_p, c_wchar_p, c_void_p, c_int, c_int_p]
            self.SetFirmwareEnvironmentVariableEx = kernel32.SetFirmwareEnvironmentVariableExW
            self.SetFirmwareEnvironmentVariableEx.restype = c_int
            self.SetFirmwareEnvironmentVariableEx.argtypes = [c_wchar_p, c_wchar_p, c_void_p, c_int, c_int]
        except AttributeError, msg:
            if logger().VERBOSE: logger().warn( "G[S]etFirmwareEnvironmentVariableExW function doesn't seem to exist" )
            pass

        try:
            self.GetSystemFirmwareTbl = kernel32.GetSystemFirmwareTable
            self.GetSystemFirmwareTbl.restype = c_int
            self.GetSystemFirmwareTbl.argtypes = [c_int, c_int, c_void_p, c_int]
        except AttributeError, msg:
            logger().warn( "GetSystemFirmwareTable function doesn't seem to exist" )
            pass
        
        try:
            self.EnumSystemFirmwareTbls = kernel32.EnumSystemFirmwareTables 
            self.EnumSystemFirmwareTbls.restype = c_int
            self.EnumSystemFirmwareTbls.argtypes = [c_int, c_void_p, c_int]
        except AttributeError, msg:
            logger().warn( "GetSystemFirmwareTable function doesn't seem to exist" )


    def __del__(self):
        if self.driver_handle:
            win32api.CloseHandle( self.driver_handle )
            self.driver_handle = None



###############################################################################################
# Driver/service management functions
###############################################################################################

    def show_warning(self):
        logger().log( "" )
        logger().warn( "*******************************************************************" )
        logger().warn( "Chipsec should only be used on test systems!" )
        logger().warn( "It should not be installed/deployed on production end-user systems." )
        logger().warn( "See WARNING.txt" )
        logger().warn( "*******************************************************************" )
        logger().log( "" )

    #
    # Create (register/install) chipsec service
    #           
    def create(self, start_driver):

        if not start_driver: return True
        self.show_warning()

        try:
            hscm = win32service.OpenSCManager( None, None, win32service.SC_MANAGER_ALL_ACCESS ) # SC_MANAGER_CREATE_SERVICE
        except win32service.error, (hr, fn, msg):
            handle_winerror(fn, msg, hr)

        if logger().VERBOSE: logger().log( "[helper] service control manager opened (handle = 0x%08x)" % hscm )

        driver_path = os.path.join( chipsec.file.get_main_dir(), "chipsec", "helper", "win", self.win_ver, DRIVER_FILE_NAME )
        if os.path.isfile( driver_path ):
            self.driver_path = driver_path
            if logger().VERBOSE: logger().log( "[helper] driver path: '%s'" % os.path.abspath(self.driver_path) )
        else:
            logger().error( "could not locate driver file '%.256s'" % driver_path )
            return False

        try:
            hs = win32service.CreateService(
                 hscm,
                 SERVICE_NAME,
                 DISPLAY_NAME,
                 (win32service.SERVICE_QUERY_STATUS|win32service.SERVICE_START|win32service.SERVICE_STOP),
                 win32service.SERVICE_KERNEL_DRIVER,
                 win32service.SERVICE_DEMAND_START,
                 win32service.SERVICE_ERROR_NORMAL,
                 os.path.abspath(driver_path),
                 None, 0, u"", None, None )
            if hs:
                if logger().VERBOSE: logger().log( "[helper] service '%s' created (handle = 0x%08x)" % (SERVICE_NAME,hs) )
        except win32service.error, (hr, fn, msg):
            if (winerror.ERROR_SERVICE_EXISTS == hr):
                if logger().VERBOSE: logger().log( "[helper] service '%s' already exists: %s (%d)" % (SERVICE_NAME, msg, hr) )
                try:
                    hs = win32service.OpenService( hscm, SERVICE_NAME, (win32service.SERVICE_QUERY_STATUS|win32service.SERVICE_START|win32service.SERVICE_STOP) ) # SERVICE_ALL_ACCESS
                except win32service.error, (hr, fn, msg):
                    handle_winerror(fn, msg, hr)
            else:
                handle_winerror(fn, msg, hr)

        finally:
            win32service.CloseServiceHandle( hs )
            win32service.CloseServiceHandle( hscm )

        return True

    #
    # Remove (detele/unregister/uninstall) chipsec service
    #
    def delete( self, start_driver ):
        if not start_driver: return True
        if self.use_existing_service: return True

        if win32serviceutil.QueryServiceStatus( SERVICE_NAME )[1] != win32service.SERVICE_STOPPED:
            logger().warn( "cannot delete service '%s' (not stopped)" % SERVICE_NAME )
            return False

        if logger().VERBOSE: logger().log( "[helper] deleting service '%s'..." % SERVICE_NAME )
        try:
            win32serviceutil.RemoveService( SERVICE_NAME )
            if logger().VERBOSE: logger().log( "[helper] service '%s' deleted" % SERVICE_NAME )
        except win32service.error, (hr, fn, msg):
            logger().warn( "RemoveService failed: %s (%d)" % (msg, hr) )
            return False

        return True

    #
    # Start chipsec service
    #           
    def start(self, start_driver, driver_exists=False):
        # we are in native API mode so not starting the service/driver
        if not start_driver: return True

        self.use_existing_service = (win32serviceutil.QueryServiceStatus( SERVICE_NAME )[1] == win32service.SERVICE_RUNNING)

        if self.use_existing_service:
            self.driver_loaded = True
            if logger().VERBOSE: logger().log( "[helper] service '%s' already running" % SERVICE_NAME )
            if logger().VERBOSE: logger().log( "[helper] trying to connect to existing '%s' service..." % SERVICE_NAME )
        else:
            #if self.use_existing_service:
            #    _handle_error( "connecting to existing '%s' service failed (service is not running)" % SERVICE_NAME )
            try:
                win32serviceutil.StartService( SERVICE_NAME )
                win32serviceutil.WaitForServiceStatus( SERVICE_NAME, win32service.SERVICE_RUNNING, 1 )
                self.driver_loaded = True
                if logger().VERBOSE: logger().log( "[helper] service '%s' started" % SERVICE_NAME )
            except pywintypes.error, (hr, fn, msg):
                _handle_error( "service '%s' didn't start: %s (%d)" % (SERVICE_NAME, msg, hr), hr )

        return True

    #
    # Stop chipsec service
    #           
    def stop( self, start_driver ):
        if not start_driver: return True
        if self.use_existing_service: return True

        if logger().VERBOSE: logger().log( "[helper] stopping service '%s'.." % SERVICE_NAME )
        try:
            win32api.CloseHandle( self.driver_handle )
            self.driver_handle = None
            win32serviceutil.StopService( SERVICE_NAME )
        except pywintypes.error, (hr, fn, msg):
            logger().error( "StopService failed: %s (%d)" % (msg, hr) )
            return False
        finally:
            self.driver_loaded = False

        try:
            win32serviceutil.WaitForServiceStatus( SERVICE_NAME, win32service.SERVICE_STOPPED, 1 )
            if logger().VERBOSE: logger().log( "[helper] service '%s' stopped" % SERVICE_NAME )
        except pywintypes.error, (hr, fn, msg):
            logger().warn( "service '%s' didn't stop: %s (%d)" % (SERVICE_NAME, msg, hr) )
            return False

        return True



    def get_driver_handle( self ):
        # This is bad but DeviceIoControl fails ocasionally if new device handle is not opened every time ;(
        if (self.driver_handle is not None) and (INVALID_HANDLE_VALUE != self.driver_handle):
            return self.driver_handle

        self.driver_handle = win32file.CreateFile( self.device_file, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, None, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, None )
        if (self.driver_handle is None) or (INVALID_HANDLE_VALUE == self.driver_handle):
            _handle_error( drv_hndl_error_msg, errno.ENXIO )
        else:
            if logger().VERBOSE: logger().log( "[helper] opened device '%.64s' (handle: %08x)" % (DEVICE_FILE, self.driver_handle) )
        return self.driver_handle

    def check_driver_handle( self ):
        if (0x6 == kernel32.GetLastError()):
            #kernel32.CloseHandle( self.driver_handle )
            win32api.CloseHandle( self.driver_handle )
            self.driver_handle = None
            self.get_driver_handle()
            logger().warn( "Invalid handle (wtf?): re-opened device '%.64s' (new handle: %08x)" % (self.device_file, self.driver_handle) )
            return False
        return True

    #
    # Auxiliary functions
    #
    def get_threads_count ( self ):
        sum = 0
        proc_group_count = (kernel32.GetActiveProcessorGroupCount() & 0xFFFF)
        for grp in range(proc_group_count):
            procs = kernel32.GetActiveProcessorCount( grp )
            sum = sum + procs
        return sum

    def getcwd( self ):
        return ("\\\\?\\" + os.getcwd())

    #
    # Generic IOCTL call function
    #
    def _ioctl( self, ioctl_code, in_buf, out_length ):

        if not self.driver_loaded:
           _handle_error("chipsec kernel driver is not loaded (in native API mode?)")

        out_buf = (c_char * out_length)()
        self.get_driver_handle()
        if logger().VERBOSE: print_buffer( in_buf )
        try:
            out_buf = win32file.DeviceIoControl( self.driver_handle, ioctl_code, in_buf, out_length, None )
        except pywintypes.error, _err:
            err_status = _err[0] + 0x100000000
            if STATUS_PRIVILEGED_INSTRUCTION == err_status:
                err_msg = "HW Access Violation: DeviceIoControl returned STATUS_PRIVILEGED_INSTRUCTION (0x%X)" % err_status
                logger().error( err_msg )
                raise HWAccessViolationError( err_msg, err_status )
            else:
                _handle_error( "HW Access Error: DeviceIoControl returned status 0x%X (%s)" % (err_status,_err[2]), err_status )

        return out_buf

###############################################################################################
# Actual driver IOCTL functions to access HW resources
###############################################################################################

    def read_phys_mem( self, phys_address_hi, phys_address_lo, length ):
        out_length = length
        out_buf = (c_char * out_length)()
        in_buf = struct.pack( '3I', phys_address_hi, phys_address_lo, length )
        out_buf = self._ioctl( IOCTL_READ_PHYSMEM, in_buf, out_length )
        return out_buf

    def native_read_phys_mem( self, phys_address_hi, phys_address_lo, length ):
        raise UnimplementedNativeAPIError( "native_read_phys_mem" )

    def write_phys_mem( self, phys_address_hi, phys_address_lo, length, buf ):
        in_length = length + 12
        out_buf = (c_char * 4)()
        in_buf = struct.pack( '3I', phys_address_hi, phys_address_lo, length ) + buf
        out_buf = self._ioctl( IOCTL_WRITE_PHYSMEM, in_buf, 4 )
        return out_buf

    def native_write_phys_mem( self, phys_address_hi, phys_address_lo, length, buf ):
        raise UnimplementedNativeAPIError( "native_write_phys_mem" )
    
    # @TODO: Temporarily the same as read_phys_mem for compatibility 
    def read_mmio_reg( self, phys_address, size ):
        out_size = size
        out_buf = (c_char * out_size)()
        in_buf = struct.pack( '3I', (phys_address>>32)&0xFFFFFFFF, phys_address&0xFFFFFFFF, size )
        out_buf = self._ioctl( IOCTL_READ_PHYSMEM, in_buf, out_size )
        if size == 8:
            value = struct.unpack( '=Q', out_buf )[0]
        elif size == 4:
            value = struct.unpack( '=I', out_buf )[0]
        elif size == 2:
            value = struct.unpack( '=H', out_buf )[0]
        elif size == 1:
            value = struct.unpack( '=B', out_buf )[0]
        else: value = 0
        return value
    def write_mmio_reg( self, phys_address, size, value ):
        if   size == 8: buf = struct.pack( '=Q', value )
        elif size == 4: buf = struct.pack( '=I', value&0xFFFFFFFF )
        elif size == 2: buf = struct.pack( '=H', value&0xFFFF )
        elif size == 1: buf = struct.pack( '=B', value&0xFF )
        else: return False
        return self.write_phys_mem( ((phys_address>>32)&0xFFFFFFFF), (phys_address&0xFFFFFFFF), size, buf )

    def alloc_phys_mem( self, length, max_pa ):
        (va, pa) = (0,0)
        in_length  = 12
        out_length = 16
        out_buf = (c_char * out_length)()
        in_buf = struct.pack( 'QI', max_pa, length )
        out_buf = self._ioctl( IOCTL_ALLOC_PHYSMEM, in_buf, out_length )
        (va, pa) = struct.unpack( '2Q', out_buf )
        return (va, pa)

    def va2pa( self, va ):
        error_code = 0
        in_length  = 8
        out_length = 8
        out_buf = (c_char * out_length)()
        in_buf = struct.pack( 'Q', va )
        out_buf = self._ioctl( IOCTL_GET_PHYSADDR, in_buf, out_length )
        pa = struct.unpack( 'Q', out_buf )[0]
        return (pa,error_code)

    #
    # HYPERCALL
    #
    def hypercall( self, rcx, rdx, r8, r9, r10, r11, rax, rbx, rdi, rsi, xmm_buffer ):
        if self.os_machine == 'AMD64':
            arg_type = 'Q'
            out_length = 8
        else:
            arg_type = 'I'
            out_length = 4
        out_buf = (c_char * out_length)()
        in_buf  = struct.pack( '<11' + arg_type, rcx, rdx, r8, r9, r10, r11, rax, rbx, rdi, rsi, xmm_buffer )
        out_buf = self._ioctl( IOCTL_HYPERCALL, in_buf, out_length )
        return struct.unpack( '<' + arg_type, out_buf )[0]

    #
    # MAP_IO_SPACE
    #
    def map_io_space( self, physical_address, length, cache_type ):
        out_length = 8
        out_buf = (c_char * out_length)()
        in_buf  = struct.pack( '<3Q', physical_address, length, cache_type )
        out_buf = self._ioctl( IOCTL_MAP_IO_SPACE, in_buf, out_length )
        virtual_address = struct.unpack( '<Q', out_buf )[0]
        return virtual_address

    #
    # FREE_PHYS_MEM
    #
    def free_phys_mem( self, physical_address ):
        out_length = 8
        out_buf = (c_char * out_length)()
        in_buf  = struct.pack( '<Q', physical_address )
        out_buf = self._ioctl( IOCTL_FREE_PHYSMEM, in_buf, out_length )
        return

    def read_msr( self, cpu_thread_id, msr_addr ):
        (eax,edx) = (0,0)
        out_length = 8
        out_buf = (c_char * out_length)()
        in_buf = struct.pack( '=BI', cpu_thread_id, msr_addr )
        out_buf = self._ioctl( IOCTL_RDMSR, in_buf, out_length )
        (eax, edx) = struct.unpack( '2I', out_buf )
        return (eax, edx)

    def write_msr( self, cpu_thread_id, msr_addr, eax, edx ):
        out_length = 0
        out_buf = (c_char * out_length)()
        in_buf = struct.pack( '=B3I', cpu_thread_id, msr_addr, eax, edx )
        out_buf = self._ioctl( IOCTL_WRMSR, in_buf, out_length )
        return

    def read_pci_reg( self, bus, device, function, address, size ):
        value = 0xFFFFFFFF
        bdf = PCI_BDF( bus&0xFFFF, device&0xFFFF, function&0xFFFF, address&0xFFFF )
        out_length = size
        out_buf = (c_char * out_length)()
        in_buf = struct.pack( '4HB', bdf.BUS, bdf.DEV, bdf.FUNC, bdf.OFF, size )
        out_buf = self._ioctl( READ_PCI_CFG_REGISTER, in_buf, out_length )
        if 1 == size:
            value = struct.unpack( 'B', out_buf )[0]
        elif 2 == size:
            value = struct.unpack( 'H', out_buf )[0]
        else:
            value = struct.unpack( 'I', out_buf )[0]
        return value

    def write_pci_reg( self, bus, device, function, address, value, size ):
        bdf = PCI_BDF( bus&0xFFFF, device&0xFFFF, function&0xFFFF, address&0xFFFF )
        out_length = 0
        out_buf = (c_char * out_length)()
        in_buf = struct.pack( '4HIB', bdf.BUS, bdf.DEV, bdf.FUNC, bdf.OFF, value, size )
        out_buf = self._ioctl( WRITE_PCI_CFG_REGISTER, in_buf, out_length )
        return True

    def load_ucode_update( self, cpu_thread_id, ucode_update_buf ):
        in_length = len(ucode_update_buf) + 3
        out_length = 0
        out_buf = (c_char * out_length)()
        in_buf = struct.pack( '=BH', cpu_thread_id, len(ucode_update_buf) ) + ucode_update_buf
        out_buf = self._ioctl( IOCTL_LOAD_UCODE_PATCH, in_buf, out_length )
        return True

    def read_io_port( self, io_port, size ):
        value =0
        in_buf = struct.pack( '=HB', io_port, size )
        out_buf = self._ioctl( IOCTL_READ_IO_PORT, in_buf, size )
        if 1 == size:
            value = struct.unpack( 'B', out_buf )[0]
        elif 2 == size:
            value = struct.unpack( 'H', out_buf )[0]
        else:
            value = struct.unpack( 'I', out_buf )[0]
        return value

    def write_io_port( self, io_port, value, size ):
        in_buf = struct.pack( '=HIB', io_port, value, size )
        out_buf = self._ioctl( IOCTL_WRITE_IO_PORT, in_buf, 0 )
        return True

    def read_cr(self, cpu_thread_id, cr_number):
        value = 0
        in_buf = struct.pack( '=HB', cr_number, cpu_thread_id )
        out_buf = self._ioctl( IOCTL_RDCR, in_buf, 8 )
        value, = struct.unpack( '=Q', out_buf )
        return value

    def write_cr(self, cpu_thread_id, cr_number, value):
        in_buf = struct.pack( '=HQB', cr_number, value )
        out_buf = self._ioctl( IOCTL_WRCR, in_buf, 0 )
        return True

    #
    # IDTR/GDTR/LDTR
    #
    def get_descriptor_table( self, cpu_thread_id, desc_table_code  ):
        in_buf = struct.pack( 'BB', cpu_thread_id, desc_table_code )
        out_buf = self._ioctl( IOCTL_GET_CPU_DESCRIPTOR_TABLE, in_buf, 18 )
        (limit,base,pa) = struct.unpack( '=HQQ', out_buf )
        return (limit,base,pa)


    #
    # EFI Variable API
    #
    def EFI_supported( self):
        # @TODO: use GetFirmwareType ?
        return ((self.GetFirmwareEnvironmentVariable is not None) or (self.GetFirmwareEnvironmentVariableEx is not None))

    def get_EFI_variable_full( self, name, guid, attrs=None ):
        status = 0 # EFI_SUCCESS
        efi_var = create_string_buffer( EFI_VAR_MAX_BUFFER_SIZE )
        if attrs is None:
            if self.GetFirmwareEnvironmentVariable is not None:
                if logger().HAL: logger().log( "[helper] -> GetFirmwareEnvironmentVariable( name='%s', GUID='%s' ).." % (name, "{%s}" % guid) )
                length = self.GetFirmwareEnvironmentVariable( name, "{%s}" % guid, efi_var, EFI_VAR_MAX_BUFFER_SIZE )
        else:
            if self.GetFirmwareEnvironmentVariableEx is not None:
                pattrs = c_int(attrs)
                if logger().HAL: logger().log( "[helper] -> GetFirmwareEnvironmentVariableEx( name='%s', GUID='%s', attrs = 0x%X ).." % (name, "{%s}" % guid, attrs) )
                length = self.GetFirmwareEnvironmentVariableEx( name, "{%s}" % guid, efi_var, EFI_VAR_MAX_BUFFER_SIZE, pattrs )
        if (0 == length) or (efi_var is None):
            status = kernel32.GetLastError()
            logger().error( 'GetFirmwareEnvironmentVariable[Ex] returned error: %s' % WinError() )
            efi_var_data = None
            #raise WinError(errno.EIO,"Unable to get EFI variable")
        else:
            efi_var_data = efi_var[:length]

        return (status, efi_var_data, attrs)

    def get_EFI_variable( self, name, guid, attrs=None ):
        (status, data, attributes) = self.get_EFI_variable_full( name, guid, attrs )
        return data

    def set_EFI_variable( self, name, guid, data, datasize, attrs ):
        var     = bytes(0) if data     is None else data
        var_len = len(var) if datasize is None else datasize

        if attrs is None:
            if self.SetFirmwareEnvironmentVariable is not None:
                if logger().HAL: logger().log( "[helper] -> SetFirmwareEnvironmentVariable( name='%s', GUID='%s', length=0x%X ).." % (name, "{%s}" % guid, var_len) )
                ntsts = self.SetFirmwareEnvironmentVariable( name, "{%s}" % guid, var, var_len )
        else:
            if self.SetFirmwareEnvironmentVariableEx is not None:
                if logger().HAL: logger().log( "[helper] -> SetFirmwareEnvironmentVariableEx( name='%s', GUID='%s', length=0x%X, length=0x%X ).." % (name, "{%s}" % guid, var_len, attrs) )
                ntsts = self.SetFirmwareEnvironmentVariableEx( name, "{%s}" % guid, var, var_len, attrs )
        if 0 != ntsts:
            status = 0 # EFI_SUCCESS
        else:
            status = kernel32.GetLastError()
            logger().error( 'SetFirmwareEnvironmentVariable[Ex] returned error: %s' % WinError() )
            #raise WinError(errno.EIO, "Unable to set EFI variable")
        return status

    def delete_EFI_variable(self, name, guid):
        return self.set_EFI_variable( name, guid, None, datasize=0, attrs=None )

    def list_EFI_variables( self, infcls=2 ):
        if logger().VERBOSE: logger().log( '[helper] -> NtEnumerateSystemEnvironmentValuesEx( infcls=%d )..' % infcls )
        efi_vars = create_string_buffer( EFI_VAR_MAX_BUFFER_SIZE )
        length = packl_ctypes( long(EFI_VAR_MAX_BUFFER_SIZE), 32 )
        status = self.NtEnumerateSystemEnvironmentValuesEx( infcls, efi_vars, length )
        status = ( ((1 << 32) - 1) & status)
        if (0xC0000023 == status):
            retlength, = struct.unpack("<I", length)
            efi_vars = create_string_buffer( retlength )
            status = self.NtEnumerateSystemEnvironmentValuesEx( infcls, efi_vars, length )
        elif (0xC0000002 == status):
            logger().warn( 'NtEnumerateSystemEnvironmentValuesEx was not found (NTSTATUS = 0xC0000002)' )
            logger().log( '[*] Your Windows does not expose UEFI Runtime Variable API. It was likely installed as legacy boot.\nTo use UEFI variable functions, chipsec needs to run in OS installed with UEFI boot (enable UEFI Boot in BIOS before installing OS)' )
            return None
        if 0 != status:
            logger().error( 'NtEnumerateSystemEnvironmentValuesEx failed (GetLastError = 0x%x)' % kernel32.GetLastError() )
            logger().error( '*** NTSTATUS: %08X' % ( ((1 << 32) - 1) & status) )
            raise WinError()
        if logger().VERBOSE: logger().log( '[helper] len(efi_vars) = 0x%X (should be 0x20000)' % len(efi_vars) )
        return getEFIvariables_NtEnumerateSystemEnvironmentValuesEx2( efi_vars )

    #
    # Interrupts
    #
    def send_sw_smi( self, cpu_thread_id, SMI_code_data, _rax, _rbx, _rcx, _rdx, _rsi, _rdi ):
        out_length = 0
        out_buf = (c_char * out_length)()
        out_size = c_ulong(out_length)
        in_buf = struct.pack( '=H6Q', SMI_code_data, _rax, _rbx, _rcx, _rdx, _rsi, _rdi )
        out_buf = self._ioctl( IOCTL_SWSMI, in_buf, out_length )
        return

    def _get_handle_for_pid( self, pid=0, ro=True ):
        if pid == 0:
            pHandle = win32process.GetCurrentProcess()
        else:
            flags = win32con.PROCESS_QUERY_INFORMATION
            if not ro:
                flags |= wn32con.PROCESS_SET_INFORMATION
            try:
                pHandle = win32api.OpenProcess(flags, 0, pid)
            except pywintypes.error, e:
                print "unable to open a process handle"
                raise ValueError, e
        return pHandle

    def set_affinity( self, value ):
        pHandle = self._get_handle_for_pid(0, False)
        current = win32process.GetProcessAffinityMask(pHandle)[0]
        try:
            win32process.SetProcessAffinityMask(pHandle, current)
        except win32process.error, e:
            print "unable to set process affinity"
            raise ValueError, e
        return current

    def get_affinity( self ):
        pHandle = self._get_handle_for_pid()
        try:
            return win32process.GetProcessAffinityMask(pHandle)[0]
        except win32process.error, e:
            print "unable to get the running cpu"
            raise ValueError, e
            
    #
    # CPUID
    #
    def cpuid( self, eax, ecx ):
        out_length = 16
        out_buf = (c_char * out_length)()
        in_buf = struct.pack( '=2I', eax, ecx )
        out_buf = self._ioctl( IOCTL_CPUID, in_buf, out_length )
        (eax, ebx, ecx, edx) = struct.unpack( '4I', out_buf )
        return (eax, ebx, ecx, edx)


    def get_ACPI_SDT( self ):
        sdt  = self.native_get_ACPI_table( 'XSDT' ) # FirmwareTableID_XSDT
        xsdt = sdt is not None
        if not xsdt:
            sdt = self.native_get_ACPI_table( 'RSDT' ) # FirmwareTableID_RSDT
        return sdt, xsdt

    def native_get_ACPI_table( self, table_name ):
        table_size = 36
        tBuffer = create_string_buffer( table_size )
        tbl = struct.unpack("<I", table_name)[0]
        retVal = self.GetSystemFirmwareTbl( FirmwareTableProviderSignature_ACPI, tbl, tBuffer, table_size )
        if retVal == 0: return None
        if retVal > table_size:
            table_size = retVal
            tBuffer    = create_string_buffer( table_size )
            retVal     = self.GetSystemFirmwareTbl( FirmwareTableProviderSignature_ACPI, tbl, tBuffer, table_size )
        return tBuffer[:retVal]

    # ACPI access is implemented through ACPI HAL rather than through kernel module
    def get_ACPI_table( self ):
        raise UnimplementedAPIError( "get_ACPI_table" )



    #
    # IOSF Message Bus access
    #

    def msgbus_send_read_message( self, mcr, mcrx ):
        logger().error( "[helper] Message Bus is not supported yet" )
        return None        

    def msgbus_send_write_message( self, mcr, mcrx, mdr ):
        logger().error( "[helper] Message Bus is not supported yet" )
        return None        

    def msgbus_send_message( self, mcr, mcrx, mdr=None ):
        logger().error( "[helper] Message Bus is not supported yet" )
        return None       

    def get_tool_path( self, tool_type ):
        tool_name, tool_pathdef = self.get_tool_info( tool_type )
        tool_path = tool_pathdef

        try:
            import pkg_resources
            tool_path = pkg_resources.resource_filename( '%s.%s' % (chipsec.file.TOOLS_DIR,self.os_system.lower()), tool_name )
        except ImportError:
            pass

        if not os.path.isfile( tool_path ):
            tool_path = os.path.join( tool_pathdef, tool_name )
            if not os.path.isfile( tool_path ): logger().error( "Couldn't find %s" % tool_path )

        return tool_path

    def get_compression_tool_path( self, compression_type ):
        return self.get_tool_path( compression_type )

    #
    # Decompress binary with OS specific tools
    #
    def decompress_file( self, CompressedFileName, OutputFileName, CompressionType ):
        import subprocess
        if (CompressionType == 0): # not compressed
          shutil.copyfile(CompressedFileName, OutputFileName)
        else:
          exe = self.get_compression_tool_path( CompressionType )
          if exe is None: return None 
          try:
            subprocess.call( [ exe, "-d", "-o", OutputFileName, CompressedFileName ], stdout=open(os.devnull, 'wb') )
          except BaseException, msg:
            logger().error( str(msg) )
            if logger().DEBUG: logger().log_bad( traceback.format_exc() )
            return None

        return chipsec.file.read_file( OutputFileName )


    #
    # File system
    #
    def get_tool_info( self, tool_type ):
        tool_name = _tools[ tool_type ] if tool_type in _tools else None
        tool_path = os.path.join( get_tools_path(), self.os_system.lower() )
        return tool_name,tool_path

#
# Get instance of this OS helper
#
def get_helper():
    return Win32Helper( )
