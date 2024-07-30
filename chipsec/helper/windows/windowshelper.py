# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2021, Intel Corporation
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
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
# Contact information:
# chipsec@intel.com
#

"""
Management and communication with Windows kernel mode driver which provides access to hardware resources

.. note::
    On Windows you need to install pywin32 Python extension corresponding to your Python version:
    http://sourceforge.net/projects/pywin32/
"""

import errno
import os.path
import platform
import pywintypes
import struct
import sys
import winerror
import win32service
import win32api, win32process, win32security, win32serviceutil, win32file
from collections import namedtuple
from ctypes import windll, Structure, pythonapi, py_object,  Array, POINTER
from ctypes import addressof, sizeof, create_string_buffer, WinError
from ctypes import c_ulong, c_ushort, c_char_p, c_size_t, c_int, c_uint32, c_wchar_p, c_void_p, c_char
from typing import Dict, List, Optional, Tuple, AnyStr, TYPE_CHECKING
from win32file import FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OVERLAPPED, INVALID_HANDLE_VALUE
from win32.lib import win32con
if TYPE_CHECKING:
    from pywintypes import PyHANDLE

from chipsec.library.exceptions import OsHelperError, HWAccessViolationError, UnimplementedAPIError
from chipsec.helper.basehelper import Helper
from chipsec.library.defines import stringtobytes, bytestostring
from chipsec.library.logger import logger
import chipsec.library.file
from chipsec.hal.uefi_common import EFI_GUID_STR


class PCI_BDF(Structure):
    _fields_ = [("BUS", c_ushort, 16),  # Bus
                ("DEV", c_ushort, 16),  # Device
                ("FUNC", c_ushort, 16),  # Function
                ("OFF", c_ushort, 16)]  # Offset


kernel32 = windll.kernel32


drv_hndl_error_msg = "Cannot open chipsec driver handle. Make sure chipsec driver is installed and started if you are using option -e (see README)"

DRIVER_FILE_PATHS = [os.path.join("C:\\", "Windows", "System32", "drivers"), os.path.join(chipsec.library.file.get_main_dir(), "chipsec", "helper", "windows", f'windows_{platform.machine().lower()}')]
DRIVER_FILE_NAME = "chipsec_hlpr.sys"
DEVICE_FILE = "\\\\.\\chipsec_hlpr"
SERVICE_NAME = "chipsec"
DISPLAY_NAME = "CHIPSEC Service"

CHIPSEC_INSTALL_PATH = os.path.join(sys.prefix, "Lib", "site-packages", "chipsec")

# Status Codes
STATUS_PRIVILEGED_INSTRUCTION = 0xC0000096

# Defines for Win32 API Calls
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 0x3

FILE_DEVICE_UNKNOWN = 0x00000022

METHOD_BUFFERED = 0
METHOD_IN_DIRECT = 1
METHOD_OUT_DIRECT = 2
METHOD_NEITHER = 3

FILE_ANY_ACCESS: int = 0
FILE_SPECIAL_ACCESS = (FILE_ANY_ACCESS)
FILE_READ_ACCESS = (0x0001)
FILE_WRITE_ACCESS = (0x0002)


def CTL_CODE(DeviceType: int, Function: int, Method: int, Access: int) -> int:
    return ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method)


#
# chipsec driver IOCTL codes
#
CHIPSEC_CTL_ACCESS: int = (FILE_READ_ACCESS | FILE_WRITE_ACCESS)

CLOSE_DRIVER: int = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
READ_PCI_CFG_REGISTER: int = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
WRITE_PCI_CFG_REGISTER: int = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_READ_PHYSMEM: int = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_WRITE_PHYSMEM: int = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80a, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_LOAD_UCODE_PATCH: int = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80b, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_WRMSR: int = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80c, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_RDMSR: int = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80d, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_READ_IO_PORT: int = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80e, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_WRITE_IO_PORT: int = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80f, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_GET_CPU_DESCRIPTOR_TABLE: int = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_SWSMI: int = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_ALLOC_PHYSMEM: int = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x812, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_CPUID: int = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x813, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_HYPERCALL: int = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x814, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_GET_PHYSADDR: int = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x815, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_MAP_IO_SPACE: int = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x816, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_FREE_PHYSMEM: int = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x817, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_WRCR: int = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x818, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_RDCR: int = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x819, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_MSGBUS_SEND_MESSAGE: int = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x81a, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_WRITE_MMIO: int = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x81b, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_READ_MMIO: int = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x81c, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)

#
# Format for IOCTL Structures
#
_pack = 'Q' if sys.maxsize > 2**32 else 'I'
_smi_msg_t_fmt = 7 * _pack

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
EFI_VAR_MAX_BUFFER_SIZE = 1024 * 1024

attributes: Dict[str, int] = {
    "EFI_VARIABLE_NON_VOLATILE": 0x00000001,
    "EFI_VARIABLE_BOOTSERVICE_ACCESS": 0x00000002,
    "EFI_VARIABLE_RUNTIME_ACCESS": 0x00000004,
    "EFI_VARIABLE_HARDWARE_ERROR_RECORD": 0x00000008,
    "EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS": 0x00000010,
    "EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS": 0x00000020,
    "EFI_VARIABLE_APPEND_WRITE": 0x00000040
}

PyLong_AsByteArray = pythonapi._PyLong_AsByteArray
PyLong_AsByteArray.argtypes = [py_object,
                               c_char_p,
                               c_size_t,
                               c_int,
                               c_int]


def packl_ctypes(lnum: int, bitlength: int) -> bytes:
    length = (bitlength + 7) // 8
    a = create_string_buffer(length)
    PyLong_AsByteArray(lnum, a, len(a), 1, 1)  # 4th param is for endianness 0 - big, non 0 - little
    return a.raw


#
# Firmware Table Provider Signatures
#
FirmwareTableProviderSignature_ACPI = 0x41435049  # 'ACPI' - The ACPI firmware table provider
FirmwareTableProviderSignature_FIRM = 0x4649524D  # 'FIRM' - The raw firmware table provider
FirmwareTableProviderSignature_RSMB = 0x52534D42  # 'RSMB' - The raw SMBIOS firmware table provider

FirmwareTableID_RSDT = 0x54445352
FirmwareTableID_XSDT = 0x54445358


class EFI_HDR_WIN(namedtuple('EFI_HDR_WIN', 'Size DataOffset DataSize Attributes guid')):
    __slots__ = ()

    def __str__(self) -> str:
        return f"""
Header (Windows)
----------------
VendorGuid= {{{EFI_GUID_STR(self.guid)}}}
Size      = 0x{self.Size:08X}
DataOffset= 0x{self.DataOffset:08X}
DataSize  = 0x{self.DataSize:08X}
Attributes= 0x{self.Attributes:08X}
"""


def getEFIvariables_NtEnumerateSystemEnvironmentValuesEx2(nvram_buf: bytes) -> Dict[str, List[Tuple[int, bytes, int, bytes, str, int]]]:
    start = 0
    buffer = nvram_buf
    bsize = len(buffer)
    header_fmt = "<IIII16s"
    header_size = struct.calcsize(header_fmt)
    variables = dict()
    off = 0
    while (off + header_size) < bsize:
        efi_var_hdr = EFI_HDR_WIN(*struct.unpack_from(header_fmt, buffer[off: off + header_size]))

        next_var_offset = off + efi_var_hdr.Size
        efi_var_buf = buffer[off: next_var_offset]
        efi_var_data = buffer[off + efi_var_hdr.DataOffset: off + efi_var_hdr.DataOffset + efi_var_hdr.DataSize]

        str_fmt = f'{efi_var_hdr.DataOffset - header_size:d}s'
        s, = struct.unpack(str_fmt, buffer[off + header_size: off + efi_var_hdr.DataOffset])
        efi_var_name = str(s, "utf-16-le", errors="replace").split(u'\u0000')[0]

        if efi_var_name not in variables.keys():
            variables[efi_var_name] = []
        #                                off, buf,         hdr,         data,         guid,                           attrs
        variables[efi_var_name].append((off, efi_var_buf, efi_var_hdr, efi_var_data, EFI_GUID_STR(efi_var_hdr.guid), efi_var_hdr.Attributes))

        if 0 == efi_var_hdr.Size:
            break
        off = next_var_offset

    return variables


def _handle_winerror(fn: str, msg: str, hr: int) -> None:
    _handle_error(f'{fn} failed: {msg} ({hr:d})', hr)


def _handle_error(err: str, hr: int = 0) -> None:
    if logger().DEBUG:
        logger().log_error(err)
    raise OsHelperError(err, hr)


class WindowsHelper(Helper):

    def __init__(self):
        super(WindowsHelper, self).__init__()

        self.os_system = platform.system()
        self.os_release = platform.release()
        self.os_version = platform.version()
        self.os_machine = platform.machine()
        self.os_uname = platform.uname()
        self.name = "WindowsHelper"
        win_ver = ""
        if "windows" == self.os_system.lower():
            win_ver = f"windows_{self.os_machine.lower()}"
            if ("5" == self.os_release):
                win_ver = "winxp"
            logger().log_debug(f'[helper] OS: {self.os_system} {self.os_release} {self.os_version}')

        self.use_existing_service = False

        self.win_ver = win_ver
        self.driver_handle = None
        self.device_file = str(DEVICE_FILE)

        c_int_p = POINTER(c_int)
        c_uint32_p = POINTER(c_uint32)

        # enable required SeSystemEnvironmentPrivilege privilege
        privilege = win32security.LookupPrivilegeValue(None, 'SeSystemEnvironmentPrivilege')
        token = win32security.OpenProcessToken(win32process.GetCurrentProcess(), win32security.TOKEN_READ | win32security.TOKEN_ADJUST_PRIVILEGES)
        win32security.AdjustTokenPrivileges(token, False, [(privilege, win32security.SE_PRIVILEGE_ENABLED)])
        win32api.CloseHandle(token)
        # import firmware variable API
        try:
            self.GetFirmwareEnvironmentVariable = kernel32.GetFirmwareEnvironmentVariableW
            self.GetFirmwareEnvironmentVariable.restype = c_int
            self.GetFirmwareEnvironmentVariable.argtypes = [c_wchar_p, c_wchar_p, c_void_p, c_int]
            self.SetFirmwareEnvironmentVariable = kernel32.SetFirmwareEnvironmentVariableW
            self.SetFirmwareEnvironmentVariable.restype = c_int
            self.SetFirmwareEnvironmentVariable.argtypes = [c_wchar_p, c_wchar_p, c_void_p, c_int]
        except AttributeError as msg:
            logger().log_warning("G[S]etFirmwareEnvironmentVariableW function doesn't seem to exist")

        try:
            self.NtEnumerateSystemEnvironmentValuesEx = windll.ntdll.NtEnumerateSystemEnvironmentValuesEx
            self.NtEnumerateSystemEnvironmentValuesEx.restype = c_int
            self.NtEnumerateSystemEnvironmentValuesEx.argtypes = [c_int, c_void_p, c_void_p]
        except AttributeError as msg:
            logger().log_warning("NtEnumerateSystemEnvironmentValuesEx function doesn't seem to exist")

        try:
            self.GetFirmwareEnvironmentVariableEx = kernel32.GetFirmwareEnvironmentVariableExW
            self.GetFirmwareEnvironmentVariableEx.restype = c_int
            self.GetFirmwareEnvironmentVariableEx.argtypes = [c_wchar_p, c_wchar_p, c_void_p, c_int, c_int_p]
            self.SetFirmwareEnvironmentVariableEx = kernel32.SetFirmwareEnvironmentVariableExW
            self.SetFirmwareEnvironmentVariableEx.restype = c_int
            self.SetFirmwareEnvironmentVariableEx.argtypes = [c_wchar_p, c_wchar_p, c_void_p, c_int, c_int]
        except AttributeError as msg:
            if logger().DEBUG:
                logger().log_warning("G[S]etFirmwareEnvironmentVariableExW function doesn't seem to exist")

        try:
            self.GetSystemFirmwareTbl = kernel32.GetSystemFirmwareTable
            self.GetSystemFirmwareTbl.restype = c_int
            self.GetSystemFirmwareTbl.argtypes = [c_int, c_int, c_void_p, c_int]
        except AttributeError as msg:
            logger().log_warning("GetSystemFirmwareTable function doesn't seem to exist")

        try:
            self.EnumSystemFirmwareTbls = kernel32.EnumSystemFirmwareTables
            self.EnumSystemFirmwareTbls.restype = c_int
            self.EnumSystemFirmwareTbls.argtypes = [c_int, c_void_p, c_int]
        except AttributeError as msg:
            logger().log_warning("GetSystemFirmwareTable function doesn't seem to exist")

        try:
            self.NtQuerySystemInformation = windll.ntdll.NtQuerySystemInformation
            self.NtQuerySystemInformation.restype = c_int
            self.NtQuerySystemInformation.argtypes = [c_uint32, c_void_p, c_uint32, c_uint32_p]
        except AttributeError as msg:
            logger().log_warning("NtQuerySystemInformation function doesn't seem to exist")

    def __del__(self):
        if self.driver_handle:
            win32api.CloseHandle(self.driver_handle)
            self.driver_handle = None


###############################################################################################
# Driver/service management functions
###############################################################################################


    def show_warning(self) -> None:
        logger().log("")
        logger().log_warning("*******************************************************************")
        logger().log_warning("Chipsec should only be used on test systems!")
        logger().log_warning("It should not be installed/deployed on production end-user systems.")
        logger().log_warning("See WARNING.txt")
        logger().log_warning("*******************************************************************")
        logger().log("")

    def create(self) -> bool:
        # check DRIVER_FILE_PATHS for the DRIVER_FILE_NAME
        self.driver_path = None
        for path in DRIVER_FILE_PATHS:
            driver_path = os.path.join(path, DRIVER_FILE_NAME)
            if os.path.isfile(driver_path):
                self.driver_path = driver_path
                logger().log_debug(f'[helper] Found driver in {driver_path}')
        if self.driver_path is None:
            logger().log_debug("[helper] CHIPSEC Windows Driver Not Found")
            raise Exception("CHIPSEC Windows Driver Not Found")

        self.show_warning()

        try:
            hscm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ALL_ACCESS)  # SC_MANAGER_CREATE_SERVICE
        except win32service.error as err:
            _handle_winerror(err.args[1], err.args[2], err.args[0])
        logger().log_debug(f'[helper] service control manager opened (handle = {hscm})')
        logger().log_debug(f"[helper] driver path: '{os.path.abspath(self.driver_path)}'")

        try:
            hs = win32service.CreateService(
                hscm,
                SERVICE_NAME,
                DISPLAY_NAME,
                (win32service.SERVICE_QUERY_STATUS | win32service.SERVICE_START | win32service.SERVICE_STOP),
                win32service.SERVICE_KERNEL_DRIVER,
                win32service.SERVICE_DEMAND_START,
                win32service.SERVICE_ERROR_NORMAL,
                os.path.abspath(self.driver_path),
                None, 0, u"", None, None)
            if hs:
                logger().log_debug(f"[helper] Service '{SERVICE_NAME}' created (handle = 0x{int(hs):08X})")
        except win32service.error as err:
            if (winerror.ERROR_SERVICE_EXISTS == err.args[0]):
                logger().log_debug(f"[helper] Service '{SERVICE_NAME}' already exists: {err.args[2]} ({err.args[0]:d})")
                try:
                    hs = win32service.OpenService(hscm, SERVICE_NAME, (win32service.SERVICE_QUERY_STATUS | win32service.SERVICE_START | win32service.SERVICE_STOP))  # SERVICE_ALL_ACCESS
                except win32service.error as _err:
                    _handle_winerror(_err.args[1], _err.args[2], _err.args[0])
            else:
                _handle_winerror(err.args[1], err.args[2], err.args[0])

        finally:
            win32service.CloseServiceHandle(hs)
            win32service.CloseServiceHandle(hscm)

        return True

    def start(self) -> bool:

        self.use_existing_service = (win32serviceutil.QueryServiceStatus(SERVICE_NAME)[1] == win32service.SERVICE_RUNNING)

        if self.use_existing_service:
            self.driver_loaded = True
            logger().log_debug(f"[helper] Service '{SERVICE_NAME}' already running")
            logger().log_debug(f"[helper] Trying to connect to existing '{SERVICE_NAME}' service...")
        else:
            try:
                win32serviceutil.StartService(SERVICE_NAME)
                win32serviceutil.WaitForServiceStatus(SERVICE_NAME, win32service.SERVICE_RUNNING, 1)
                self.driver_loaded = True
                logger().log_debug(f"[helper] service '{SERVICE_NAME}' started")
            except pywintypes.error as err:
                _handle_error(f"Service '{SERVICE_NAME}' didn't start: {err.args[2]} ({err.args[0]:d})", err.args[0])
        self.driverpath = win32serviceutil.LocateSpecificServiceExe(SERVICE_NAME)
        self.driverpath = f'({self.driverpath})'
        return True

    def stop(self) -> bool:
        if self.use_existing_service:
            return True

        logger().log_debug(f"[helper] Stopping service '{SERVICE_NAME}'...")
        try:
            win32api.CloseHandle(self.driver_handle)
            self.driver_handle = None
            win32serviceutil.StopService(SERVICE_NAME)
        except pywintypes.error as err:
            if logger().DEBUG:
                logger().log_error(f'StopService failed: {err.args[2]} ({err.args[0]:d})')
            return False
        finally:
            self.driver_loaded = False

        try:
            win32serviceutil.WaitForServiceStatus(SERVICE_NAME, win32service.SERVICE_STOPPED, 1)
            logger().log_debug(f"[helper] Service '{SERVICE_NAME}' stopped")
        except pywintypes.error as err:
            if logger().DEBUG:
                logger().log_warning(f"Service '{SERVICE_NAME}' didn't stop: {err.args[2]} ({err.args[0]:d})")
            return False

        return True

    def delete(self) -> bool:
        if self.use_existing_service:
            return True

        if win32serviceutil.QueryServiceStatus(SERVICE_NAME)[1] != win32service.SERVICE_STOPPED:
            logger().log_warning(f"Cannot delete service '{SERVICE_NAME}' (not stopped)")
            return False

        logger().log_debug(f"[helper] Deleting service '{SERVICE_NAME}'...")
        try:
            win32serviceutil.RemoveService(SERVICE_NAME)
            logger().log_debug(f"[helper] Service '{SERVICE_NAME}' deleted")
        except win32service.error as err:
            if logger().DEBUG:
                logger().log_warning(f"RemoveService failed: {err.args[2]} ({err.args[0]:d})")
            return False

        return True

    def _get_driver_handle(self) -> 'PyHANDLE':
        # This is bad but DeviceIoControl fails occasionally if new device handle is not opened every time ;(
        if (self.driver_handle is not None) and (INVALID_HANDLE_VALUE != self.driver_handle):
            return self.driver_handle
        self.driver_handle = win32file.CreateFile(self.device_file, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, None, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, None)
        if (self.driver_handle is None) or (INVALID_HANDLE_VALUE == self.driver_handle):
            _handle_error(drv_hndl_error_msg, errno.ENXIO)
        else:
            logger().log_debug(f"[helper] Opened device '{DEVICE_FILE:.64}' (handle: {int(self.driver_handle):08X})")
        return self.driver_handle

    def check_driver_handle(self) -> bool:
        if (0x6 == kernel32.GetLastError()):
            win32api.CloseHandle(self.driver_handle)
            self.driver_handle = None
            self._get_driver_handle()
            logger().log_warning(f"Invalid handle: re-opened device '{self.device_file:.64}' (new handle: {int(self.driver_handle):08X})")
            return False
        return True

    #
    # Auxiliary functions
    #
    def get_threads_count(self) -> int:
        sum = 0
        proc_group_count = (kernel32.GetActiveProcessorGroupCount() & 0xFFFF)
        for grp in range(proc_group_count):
            procs = kernel32.GetActiveProcessorCount(grp)
            sum = sum + procs
        return sum

    #
    # Generic IOCTL call function
    #
    def _ioctl(self, ioctl_code: int, in_buf: bytes, out_length: int) -> Array:

        if not self.driver_loaded:
            _handle_error("chipsec kernel driver is not loaded (in native API mode?)")

        out_buf = (c_char * out_length)()
        self._get_driver_handle()
        try:
            out_buf = win32file.DeviceIoControl(self.driver_handle, ioctl_code, in_buf, out_length, None)
        except pywintypes.error as _err:
            err_status = _err.args[0] + 0x100000000
            if STATUS_PRIVILEGED_INSTRUCTION == err_status:
                err_msg = f'HW Access Violation: DeviceIoControl returned STATUS_PRIVILEGED_INSTRUCTION (0x{err_status:X})'
                if logger().DEBUG:
                    logger().log_error(err_msg)
                raise HWAccessViolationError(err_msg, err_status)
            else:
                _handle_error(f'HW Access Error: DeviceIoControl returned status 0x{err_status:X} ({_err.args[2]})', err_status)

        return out_buf

###############################################################################################
# Actual driver IOCTL functions to access HW resources
###############################################################################################

    def read_phys_mem(self, phys_address: int, length: int) -> bytes:
        out_length = length
        hi = (phys_address >> 32) & 0xFFFFFFFF
        lo = phys_address & 0xFFFFFFFF
        in_buf = struct.pack('3I', hi, lo, length)
        out_buf = self._ioctl(IOCTL_READ_PHYSMEM, in_buf, out_length)
        return bytes(out_buf)

    def write_phys_mem(self, phys_address: int, length: int, buf: AnyStr) -> int:
        hi = (phys_address >> 32) & 0xFFFFFFFF
        lo = phys_address & 0xFFFFFFFF
        in_buf = struct.pack('3I', hi, lo, length) + stringtobytes(buf)
        out_buf = self._ioctl(IOCTL_WRITE_PHYSMEM, in_buf, 4)
        return int.from_bytes(out_buf, 'little')

    # @TODO: Temporarily the same as read_phys_mem for compatibility
    def read_mmio_reg(self, phys_address: int, size: int) -> int:
        out_size = size
        logger().log_debug(f'[helper] -> read_mmio_reg( phys_address=0x{phys_address:X}, size={size} )')
        in_buf = struct.pack('3I', (phys_address >> 32) & 0xFFFFFFFF, phys_address & 0xFFFFFFFF, size)
        out_buf = self._ioctl(IOCTL_READ_MMIO, in_buf, out_size)
        if size == 8:
            value = struct.unpack('=Q', out_buf)[0]
        elif size == 4:
            value = struct.unpack('=I', out_buf)[0]
        elif size == 2:
            value = struct.unpack('=H', out_buf)[0]
        elif size == 1:
            value = struct.unpack('=B', out_buf)[0]
        else:
            value = 0
        return value

    def write_mmio_reg(self, phys_address: int, size: int, value: int) -> int:
        if size == 8:
            buf = struct.pack('=Q', value)
        elif size == 4:
            buf = struct.pack('=I', value & 0xFFFFFFFF)
        elif size == 2:
            buf = struct.pack('=H', value & 0xFFFF)
        elif size == 1:
            buf = struct.pack('=B', value & 0xFF)
        else:
            return False
        in_buf = struct.pack('3I', ((phys_address >> 32) & 0xFFFFFFFF), (phys_address & 0xFFFFFFFF), size) + buf
        out_buf = self._ioctl(IOCTL_WRITE_MMIO, in_buf, 4)
        return int.from_bytes(out_buf, 'little')

    def alloc_phys_mem(self, length: int, max_pa: int) -> Tuple[int, int]:
        in_length = 12
        out_length = 16
        in_buf = struct.pack('QI', max_pa, length)
        out_buf = self._ioctl(IOCTL_ALLOC_PHYSMEM, in_buf, out_length)
        (va, pa) = struct.unpack('2Q', out_buf)
        return (va, pa)

    def va2pa(self, va: int) -> Tuple[int, int]:
        error_code = 0
        in_length = 8
        out_length = 8
        in_buf = struct.pack('Q', va)
        out_buf = self._ioctl(IOCTL_GET_PHYSADDR, in_buf, out_length)
        pa = struct.unpack('Q', out_buf)[0]
        return (pa, error_code)

    #
    # HYPERCALL
    #
    def hypercall(self, rcx, rdx, r8, r9, r10, r11, rax, rbx, rdi, rsi, xmm_buffer):
        if self.os_machine == 'AMD64':
            arg_type = 'Q'
            out_length = 8
        else:
            arg_type = 'I'
            out_length = 4
        in_buf = struct.pack(f'<11{arg_type}', rcx, rdx, r8, r9, r10, r11, rax, rbx, rdi, rsi, xmm_buffer)
        out_buf = self._ioctl(IOCTL_HYPERCALL, in_buf, out_length)
        return struct.unpack(f'<{arg_type}', out_buf)[0]

    #
    # MAP_IO_SPACE
    #
    def map_io_space(self, physical_address, length, cache_type):
        out_length = 8
        in_buf = struct.pack('<3Q', physical_address, length, cache_type)
        out_buf = self._ioctl(IOCTL_MAP_IO_SPACE, in_buf, out_length)
        virtual_address = struct.unpack('<Q', out_buf)[0]
        return virtual_address

    #
    # FREE_PHYS_MEM
    #
    def free_phys_mem(self, physical_address):
        out_length = 8
        in_buf = struct.pack('<Q', physical_address)
        out_buf = self._ioctl(IOCTL_FREE_PHYSMEM, in_buf, out_length)
        return

    def read_msr(self, cpu_thread_id: int, msr_addr: int) -> Tuple[int, int]:
        out_length = 8
        in_buf = struct.pack('=2I', cpu_thread_id, msr_addr)
        out_buf = self._ioctl(IOCTL_RDMSR, in_buf, out_length)
        (eax, edx) = struct.unpack('2I', out_buf)
        return (eax, edx)

    def write_msr(self, cpu_thread_id: int, msr_addr: int, eax: int, edx: int) -> int:
        out_length = 0
        in_buf = struct.pack('=4I', cpu_thread_id, msr_addr, eax, edx)
        self._ioctl(IOCTL_WRMSR, in_buf, out_length)
        return True

    def read_pci_reg(self, bus: int, device: int, function: int, address: int, size: int) -> int:
        bdf = PCI_BDF(bus & 0xFFFF, device & 0xFFFF, function & 0xFFFF, address & 0xFFFF)
        out_length = size
        in_buf = struct.pack('4HB', bdf.BUS, bdf.DEV, bdf.FUNC, bdf.OFF, size)
        out_buf = self._ioctl(READ_PCI_CFG_REGISTER, in_buf, out_length)
        if 1 == size:
            value = struct.unpack('B', out_buf)[0]
        elif 2 == size:
            value = struct.unpack('H', out_buf)[0]
        else:
            value = struct.unpack('I', out_buf)[0]
        return value

    def write_pci_reg(self, bus: int, device: int, function: int, address: int, value: int, size: int) -> int:
        bdf = PCI_BDF(bus & 0xFFFF, device & 0xFFFF, function & 0xFFFF, address & 0xFFFF)
        out_length = 0
        in_buf = struct.pack('4HIB', bdf.BUS, bdf.DEV, bdf.FUNC, bdf.OFF, value, size)
        self._ioctl(WRITE_PCI_CFG_REGISTER, in_buf, out_length)
        return True

    def load_ucode_update(self, cpu_thread_id: int, ucode_update_buf: bytes) -> bool:
        out_length = 0
        in_buf = struct.pack('=IH', cpu_thread_id, len(ucode_update_buf)) + ucode_update_buf
        self._ioctl(IOCTL_LOAD_UCODE_PATCH, in_buf, out_length)
        return True

    def read_io_port(self, io_port: int, size: int) -> int:
        value = 0
        in_buf = struct.pack('=HB', io_port, size)
        out_buf = self._ioctl(IOCTL_READ_IO_PORT, in_buf, size)
        if 1 == size:
            value = struct.unpack('B', out_buf)[0]
        elif 2 == size:
            value = struct.unpack('H', out_buf)[0]
        else:
            value = struct.unpack('I', out_buf)[0]
        return value

    def write_io_port(self, io_port: int, value: int, size: int) -> bool:
        in_buf = struct.pack('=HIB', io_port, value, size)
        self._ioctl(IOCTL_WRITE_IO_PORT, in_buf, 0)
        return True

    def read_cr(self, cpu_thread_id: int, cr_number: int) -> int:
        value = 0
        in_buf = struct.pack('=HI', cr_number, cpu_thread_id)
        out_buf = self._ioctl(IOCTL_RDCR, in_buf, 8)
        value, = struct.unpack('=Q', out_buf)
        return value

    def write_cr(self, cpu_thread_id: int, cr_number: int, value: int) -> int:
        in_buf = struct.pack('=HQI', cr_number, value, cpu_thread_id)
        self._ioctl(IOCTL_WRCR, in_buf, 0)
        return True

    #
    # IDTR/GDTR/LDTR
    #
    def get_descriptor_table(self, cpu_thread_id: int, desc_table_code: int) -> Tuple[int, int, int]:
        in_buf = struct.pack('IB', cpu_thread_id, desc_table_code)
        out_buf = self._ioctl(IOCTL_GET_CPU_DESCRIPTOR_TABLE, in_buf, 18)
        (limit, base, pa) = struct.unpack('=HQQ', out_buf)
        return (limit, base, pa)

    #
    # EFI Variable API
    #
    def EFI_supported(self) -> bool:
        # kern32.GetFirmwareEnvironmentVariable with garbage parameters will cause GetLastError() == 1 reliably on a legacy system
        if self.GetFirmwareEnvironmentVariable is not None:
            self.GetFirmwareEnvironmentVariable("", "{00000000-0000-0000-0000-000000000000}", 0, 0)
            return win32api.GetLastError() != 1
        elif self.GetFirmwareEnvironmentVariableEx is not None:
            self.GetFirmwareEnvironmentVariableEx("", "{00000000-0000-0000-0000-000000000000}", 0, 0)
            return win32api.GetLastError() != 1
        else:
            return False

    def get_EFI_variable_full(self, name: str, guid: str, attrs: Optional[int] = None) -> Tuple[int, Optional[bytes], int]:
        status = 0  # EFI_SUCCESS
        length = 0
        efi_var = create_string_buffer(EFI_VAR_MAX_BUFFER_SIZE)
        if attrs is None:
            if self.GetFirmwareEnvironmentVariable is not None:
                logger().log_debug(f"[helper] -> GetFirmwareEnvironmentVariable( name='{name}', GUID='{{{guid}}}' )...")
                length = self.GetFirmwareEnvironmentVariable(name, f'{{{guid}}}', efi_var, EFI_VAR_MAX_BUFFER_SIZE)
        else:
            if self.GetFirmwareEnvironmentVariableEx is not None:
                pattrs = c_int(attrs)
                logger().log_debug(f"[helper] -> GetFirmwareEnvironmentVariableEx( name='{name}', GUID='{{{guid}}}', attrs = 0x{attrs:X} )...")
                length = self.GetFirmwareEnvironmentVariableEx(name, f'{{{guid}}}', efi_var, EFI_VAR_MAX_BUFFER_SIZE, pattrs)
        if (0 == length) or (efi_var is None):
            status = kernel32.GetLastError()
            if logger().DEBUG:
                logger().log_error(f'GetFirmwareEnvironmentVariable[Ex] returned error: {WinError()}')
            efi_var_data = None
            #raise WinError(errno.EIO,"Unable to get EFI variable")
        else:
            efi_var_data = bytes(efi_var[:length])

        return (status, efi_var_data, attrs)

    def get_EFI_variable(self, name: str, guid: str, attrs: Optional[int] = None) -> Optional[bytes]:
        (status, data, attributes) = self.get_EFI_variable_full(name, guid, attrs)
        return data

    def set_EFI_variable(self, name: str, guid: str, buffer: bytes, buffer_size: Optional[int], attrs: Optional[int]) -> int:
        var = bytes(0) if buffer is None else buffer
        var_len = len(var) if buffer_size is None else buffer_size
        ntsts = 0
        if isinstance(attrs, (str, bytes)):
            attrs_data = f'{bytestostring(attrs):\x00<8}'[:8]
            attrs = struct.unpack("Q", stringtobytes(attrs_data))[0]

        if attrs is None:
            if self.SetFirmwareEnvironmentVariable is not None:
                logger().log_debug(f"[helper] -> SetFirmwareEnvironmentVariable( name='{name}', GUID='{{{guid}}}', length=0x{var_len:X} )...")
                ntsts = self.SetFirmwareEnvironmentVariable(name, f'{{{guid}}}', var, var_len)
        else:
            if self.SetFirmwareEnvironmentVariableEx is not None:
                logger().log_debug(f"[helper] -> SetFirmwareEnvironmentVariableEx( name='{name}', GUID='{{{guid}}}', length=0x{var_len:X}, attrs=0x{attrs:X} )...")
                ntsts = self.SetFirmwareEnvironmentVariableEx(name, f'{{{guid}}}', var, var_len, attrs)
        if 0 != ntsts:
            status = 0  # EFI_SUCCESS
        else:
            status = kernel32.GetLastError()
            if logger().DEBUG:
                logger().log_error(f'SetFirmwareEnvironmentVariable[Ex] returned error: {WinError()}')
        return status

    def delete_EFI_variable(self, name: str, guid: str) -> int:
        return self.set_EFI_variable(name, guid, None, buffer_size=0, attrs=None)

    def list_EFI_variables(self, infcls: int = 2) -> Optional[Dict[str, List[Tuple[int, bytes, int, bytes, str, int]]]]:
        logger().log_debug(f'[helper] -> NtEnumerateSystemEnvironmentValuesEx( infcls={infcls:d} )...')
        efi_vars = create_string_buffer(EFI_VAR_MAX_BUFFER_SIZE)
        length = packl_ctypes(EFI_VAR_MAX_BUFFER_SIZE, 32)
        status = self.NtEnumerateSystemEnvironmentValuesEx(infcls, efi_vars, length)
        status = (((1 << 32) - 1) & status)
        if (0xC0000023 == status):
            retlength, = struct.unpack("<I", length)
            efi_vars = create_string_buffer(retlength)
            status = self.NtEnumerateSystemEnvironmentValuesEx(infcls, efi_vars, length)
        elif (0xC0000002 == status):
            if logger().DEBUG:
                logger().log_warning('NtEnumerateSystemEnvironmentValuesEx was not found (NTSTATUS = 0xC0000002)')
            logger().log_debug('[*] Your Windows does not expose UEFI Runtime Variable API. It was likely installed as legacy boot.\nTo use UEFI variable functions, chipsec needs to run in OS installed with UEFI boot (enable UEFI Boot in BIOS before installing OS)')
            return None
        if 0 != status:
            lasterror = kernel32.GetLastError()
            if (0xC0000001 == status):  # ERROR_NOACCESS: Invalid access to memory location.  https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/18d8fbe8-a967-4f1c-ae50-99ca8e491d2d
                logger().log_warning('NtEnumerateSystemEnvironmentValuesEx was not successful')
                logger().log_debug(f'NTSTATUS = 0x{status:08X}, LastError = 0x{lasterror:X}')
                logger().log_warning('Looks like your version of Windows has restricted access to UEFI variables.\n\tTo use UEFI variable functions, chipsec needs to run in an older version of windows or in a different environment (Linux)')
                return None
            else:
                if logger().DEBUG:
                    logger().log_error(f'NtEnumerateSystemEnvironmentValuesEx failed (GetLastError = 0x{lasterror:X})')
                    logger().log_error(f'*** NTSTATUS: {status:08X}')
                raise WinError()
        logger().log_debug(f'[helper] len(efi_vars) = 0x{len(efi_vars):X} (should be 0x20000)')
        return getEFIvariables_NtEnumerateSystemEnvironmentValuesEx2(bytes(efi_vars))

    #
    # Interrupts
    #
    def send_sw_smi(self, cpu_thread_id: int, SMI_code_data: int, _rax: int, _rbx: int, _rcx: int, _rdx: int, _rsi: int, _rdi: int) -> Optional[Tuple[int, int, int, int, int, int, int]]:
        if (sys.maxsize < 2**32 and self.os_machine == 'AMD64') or (sys.maxsize > 2**32 and self.os_machine == 'i386'):
            logger().log(f"[helper] Python architecture must match OS architecture.  Run with {self.os_machine} architecture of python")
        out_length = struct.calcsize(_smi_msg_t_fmt)
        out_size = c_ulong(out_length)
        in_buf = struct.pack(_smi_msg_t_fmt, SMI_code_data, _rax, _rbx, _rcx, _rdx, _rsi, _rdi)
        out_buf = self._ioctl(IOCTL_SWSMI, in_buf, out_length)
        if out_buf:
            ret = struct.unpack(_smi_msg_t_fmt, out_buf)
        else:
            ret = None
        return ret

    def _get_handle_for_pid(self, pid: int = 0, ro: bool = True) -> int:
        if pid == 0:
            pHandle = win32process.GetCurrentProcess()
        else:
            flags = win32con.PROCESS_QUERY_INFORMATION
            if not ro:
                flags |= win32con.PROCESS_SET_INFORMATION
            try:
                pHandle = win32api.OpenProcess(flags, 0, pid)
            except pywintypes.error as e:
                print("unable to open a process handle")
                raise ValueError(e)
        return pHandle

    def set_affinity(self, value: int) -> Optional[int]:
        pHandle = self._get_handle_for_pid(0, False)
        current = win32process.GetProcessAffinityMask(pHandle)[0]
        try:
            win32process.SetProcessAffinityMask(pHandle, current)
        except win32process.error as e:
            print("unable to set process affinity")
            raise ValueError(e)
        return current

    def get_affinity(self) -> Optional[int]:
        pHandle = self._get_handle_for_pid()
        try:
            return win32process.GetProcessAffinityMask(pHandle)[0]
        except win32process.error as e:
            print("unable to get the running cpu")
            raise ValueError(e)

    #
    # CPUID
    #
    def cpuid(self, eax: int, ecx: int) -> Tuple[int, int, int, int]:
        out_length = 16
        in_buf = struct.pack('=2I', eax, ecx)
        out_buf = self._ioctl(IOCTL_CPUID, in_buf, out_length)
        (eax, ebx, ecx, edx) = struct.unpack('4I', out_buf)
        return (eax, ebx, ecx, edx)

    def enum_ACPI_tables(self) -> Optional[Array]:
        table_size = 36
        tBuffer = create_string_buffer(table_size)
        retVal = self.EnumSystemFirmwareTbls(FirmwareTableProviderSignature_ACPI, tBuffer, table_size)
        if retVal == 0:
            if logger().DEBUG:
                logger().log_error(f'EnumSystemFirmwareTbls() returned error: {WinError()}')
            return None
        if retVal > table_size:
            table_size = retVal
            tBuffer = create_string_buffer(table_size)
            retVal = self.EnumSystemFirmwareTbls(FirmwareTableProviderSignature_ACPI, tBuffer, table_size)
        tables_array = [tBuffer[i:i+4] for i in range(0, retVal, 4)]
        return tables_array

    # ACPI access is implemented through ACPI HAL rather than through kernel module
    def get_ACPI_table(self, table_name: str) -> Optional[Array]:
        table_size = 36
        tBuffer = create_string_buffer(table_size)
        tbl = struct.unpack("<I", bytes(table_name, 'ascii'))[0]
        retVal = self.GetSystemFirmwareTbl(FirmwareTableProviderSignature_ACPI, tbl, tBuffer, table_size)
        if retVal == 0:
            if logger().DEBUG:
                logger().log_error(f'GetSystemFirmwareTable({table_name}) returned error: {WinError()}')
            return None
        if retVal > table_size:
            table_size = retVal
            tBuffer = create_string_buffer(table_size)
            retVal = self.GetSystemFirmwareTbl(FirmwareTableProviderSignature_ACPI, tbl, tBuffer, table_size)
        return tBuffer[:retVal]

    #
    # IOSF Message Bus access
    #

    def msgbus_send_read_message(self, mcr, mcrx):
        raise UnimplementedAPIError("msgbus_send_read_message")

    def msgbus_send_write_message( self, mcr, mcrx, mdr):
        raise UnimplementedAPIError("msgbus_send_write_message")

    def msgbus_send_message(self, mcr, mcrx, mdr):
        raise UnimplementedAPIError("msgbus_send_message")

    #
    # Speculation control
    #
    def retpoline_enabled(self) -> bool:
        # See https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation
        speculation_control = c_uint32(0)
        SystemSpeculationControlInformation = 0xC9
        SpecCtrlRetpolineEnabled = 0x4000
        self.NtQuerySystemInformation(SystemSpeculationControlInformation, addressof(speculation_control), sizeof(speculation_control), None)
        return bool(speculation_control.value & SpecCtrlRetpolineEnabled)

#
# Get instance of this OS helper
#


def get_helper() -> WindowsHelper:
    return WindowsHelper()
