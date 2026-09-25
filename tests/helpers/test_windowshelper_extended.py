# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2025, Intel Corporation
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
#

# To execute: python[3] -m unittest tests.helpers.test_windowshelper_extended

import errno
import struct
import sys
import unittest
from unittest.mock import MagicMock, Mock, patch

from chipsec.library.exceptions import HWAccessViolationError, OsHelperError, UnimplementedAPIError

MOCKED_MODULES = ['pywintypes', 'win32service', 'windll', 'winerror', 'win32file', 'win32api',
                  'win32process', 'win32security', 'win32serviceutil', 'ctypes', 'win32.lib']

ERROR_SERVICE_EXISTS = 1073
SERVICE_STOPPED = 1
SERVICE_RUNNING = 4


class FakeWin32Error(Exception):
    """Stand in for ``win32service.error`` / ``pywintypes.error`` (hr, fn, msg)."""


class FakeBuffer:
    """Minimal stand in for a ``ctypes`` string buffer."""

    def __init__(self, data: bytes):
        self.raw = bytes(data)

    def __len__(self):
        return len(self.raw)

    def __getitem__(self, item):
        return self.raw[item]

    def __bytes__(self):
        return self.raw


def make_efi_var_blob(name: str, data: bytes, attributes: int, guid: bytes) -> bytes:
    """Build a single NtEnumerateSystemEnvironmentValuesEx variable record."""
    header_size = struct.calcsize('<IIII16s')
    name_bytes = name.encode('utf-16-le') + b'\x00\x00'
    data_offset = header_size + len(name_bytes)
    size = data_offset + len(data)
    return struct.pack('<IIII16s', size, data_offset, len(data), attributes, guid) + name_bytes + data


class WindowsHelperExtendedBase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls._saved_modules = {}
        for mod in MOCKED_MODULES:
            cls._saved_modules[mod] = sys.modules.get(mod)
            sys.modules[mod] = Mock()
        import chipsec.helper.windows.windowshelper as wh
        cls.wh = wh

    @classmethod
    def tearDownClass(cls):
        for mod in MOCKED_MODULES:
            saved = cls._saved_modules.get(mod)
            if saved is None:
                sys.modules.pop(mod, None)
            else:
                sys.modules[mod] = saved

    def setUp(self):
        unittest.TestCase.setUp(self)
        logger_patcher = patch.object(self.wh, 'logger')
        self.addCleanup(logger_patcher.stop)
        self.mock_logger = logger_patcher.start()
        self.log = self.mock_logger.return_value
        self.log.DEBUG = True

    def _patch(self, name, new=None, **kwargs):
        patcher = patch.object(self.wh, name, new) if new is not None else patch.object(self.wh, name, **kwargs)
        self.addCleanup(patcher.stop)
        return patcher.start()

    def _new_helper(self, system='windows', release='10', machine='AMD64'):
        wh = self.wh
        with patch.object(wh, 'platform') as mock_platform, \
                patch.object(wh, 'win32security'), \
                patch.object(wh, 'win32process'), \
                patch.object(wh, 'win32api'):
            mock_platform.system.return_value = system
            mock_platform.release.return_value = release
            mock_platform.version.return_value = '10.0.19045'
            mock_platform.machine.return_value = machine
            mock_platform.uname.return_value = (system, 'host', release, '', machine, '')
            return wh.WindowsHelper()


class TestWindowsHelperModuleFunctions(WindowsHelperExtendedBase):

    def test_ctl_code(self):
        # FILE_DEVICE_UNKNOWN 0x22, function 0x807, METHOD_BUFFERED, read|write access
        self.assertEqual(self.wh.CTL_CODE(0x22, 0x807, 0, 3), 0x22E01C)
        self.assertEqual(self.wh.READ_PCI_CFG_REGISTER, 0x22E01C)

    def test_packl_ctypes_sizes_buffer_from_bitlength(self):
        created = []

        def fake_create(length):
            created.append(length)
            return FakeBuffer(b'\x00' * length)

        self._patch('create_string_buffer', fake_create)
        mock_pylong = self._patch('PyLong_AsByteArray', MagicMock())
        result = self.wh.packl_ctypes(0x100000, 32)
        self.assertEqual(created, [4])
        self.assertEqual(result, b'\x00\x00\x00\x00')
        args = mock_pylong.call_args[0]
        self.assertEqual(args[0], 0x100000)
        self.assertEqual(args[2:], (4, 1, 1))

    def test_packl_ctypes_rounds_bitlength_up(self):
        self._patch('create_string_buffer', lambda length: FakeBuffer(b'\xFF' * length))
        self._patch('PyLong_AsByteArray', MagicMock())
        self.assertEqual(self.wh.packl_ctypes(0xFF, 9), b'\xFF\xFF')

    def test_efi_hdr_win_str(self):
        hdr = self.wh.EFI_HDR_WIN(Size=0x2A, DataOffset=0x26, DataSize=0x4,
                                  Attributes=0x7, guid=bytes(range(16)))
        text = str(hdr)
        self.assertIn('Header (Windows)', text)
        self.assertIn('Size      = 0x0000002A', text)
        self.assertIn('DataOffset= 0x00000026', text)
        self.assertIn('DataSize  = 0x00000004', text)
        self.assertIn('Attributes= 0x00000007', text)
        self.assertIn(self.wh.EFI_GUID_STR(bytes(range(16))), text)

    def test_get_efi_variables_parses_single_record(self):
        guid = bytes(range(16))
        blob = make_efi_var_blob('AB', b'\xDE\xAD\xBE\xEF', 0x7, guid)
        variables = self.wh.getEFIvariables_NtEnumerateSystemEnvironmentValuesEx2(blob)
        self.assertEqual(list(variables.keys()), ['AB'])
        (off, var_buf, hdr, data, guid_str, attrs) = variables['AB'][0]
        self.assertEqual(off, 0)
        self.assertEqual(var_buf, blob)
        self.assertEqual(hdr.Size, len(blob))
        self.assertEqual(hdr.DataOffset, 38)
        self.assertEqual(hdr.DataSize, 4)
        self.assertEqual(data, b'\xDE\xAD\xBE\xEF')
        self.assertEqual(attrs, 0x7)
        self.assertEqual(guid_str, self.wh.EFI_GUID_STR(guid))

    def test_get_efi_variables_parses_two_records(self):
        guid = bytes(range(16))
        blob = (make_efi_var_blob('AB', b'\x01\x02', 0x1, guid) +
                make_efi_var_blob('CD', b'\x03', 0x2, guid))
        variables = self.wh.getEFIvariables_NtEnumerateSystemEnvironmentValuesEx2(blob + b'\x00' * 8)
        self.assertEqual(sorted(variables.keys()), ['AB', 'CD'])
        self.assertEqual(variables['CD'][0][3], b'\x03')
        self.assertEqual(variables['CD'][0][0], len(make_efi_var_blob('AB', b'\x01\x02', 0x1, guid)))

    def test_get_efi_variables_stops_on_zero_size(self):
        guid = bytes(range(16))
        header_size = struct.calcsize('<IIII16s')
        terminator = struct.pack('<IIII16s', 0, header_size, 0, 0, guid)
        blob = make_efi_var_blob('AB', b'\x01', 0x1, guid) + terminator + b'\x00' * 64
        variables = self.wh.getEFIvariables_NtEnumerateSystemEnvironmentValuesEx2(blob)
        self.assertEqual(sorted(variables.keys()), ['', 'AB'])

    def test_get_efi_variables_empty_buffer(self):
        self.assertEqual(self.wh.getEFIvariables_NtEnumerateSystemEnvironmentValuesEx2(b''), {})

    def test_handle_error_raises_and_logs(self):
        with self.assertRaises(OsHelperError) as ctx:
            self.wh._handle_error('boom', 5)
        self.assertEqual(str(ctx.exception), 'boom')
        self.assertEqual(ctx.exception.errorcode, 5)
        self.log.log_error.assert_called_once_with('boom')

    def test_handle_error_without_debug_does_not_log(self):
        self.log.DEBUG = False
        self.assertRaises(OsHelperError, self.wh._handle_error, 'boom')
        self.log.log_error.assert_not_called()

    def test_handle_winerror_formats_message(self):
        with self.assertRaises(OsHelperError) as ctx:
            self.wh._handle_winerror('OpenSCManager', 'Access is denied.', 5)
        self.assertEqual(str(ctx.exception), 'OpenSCManager failed: Access is denied. (5)')
        self.assertEqual(ctx.exception.errorcode, 5)

    def test_get_helper_returns_windows_helper(self):
        wh = self.wh
        with patch.object(wh, 'platform') as mock_platform, \
                patch.object(wh, 'win32security'), \
                patch.object(wh, 'win32process'), \
                patch.object(wh, 'win32api'):
            mock_platform.system.return_value = 'Windows'
            mock_platform.release.return_value = '10'
            mock_platform.version.return_value = '10.0'
            mock_platform.machine.return_value = 'AMD64'
            mock_platform.uname.return_value = ()
            helper = wh.get_helper()
        self.assertIsInstance(helper, wh.WindowsHelper)
        self.assertEqual(helper.name, 'WindowsHelper')


class TestWindowsHelperInit(WindowsHelperExtendedBase):

    def test_win_ver_from_machine(self):
        helper = self._new_helper(machine='AMD64')
        self.assertEqual(helper.win_ver, 'windows_amd64')
        self.assertFalse(helper.use_existing_service)
        self.assertIsNone(helper.driver_handle)
        self.assertEqual(helper.device_file, self.wh.DEVICE_FILE)

    def test_win_ver_winxp(self):
        helper = self._new_helper(release='5')
        self.assertEqual(helper.win_ver, 'winxp')

    def test_win_ver_empty_on_non_windows(self):
        helper = self._new_helper(system='Linux')
        self.assertEqual(helper.win_ver, '')

    def test_missing_firmware_apis_log_warnings(self):
        self._patch('kernel32', Mock(spec=[]))
        self._patch('windll', Mock(spec=[]))
        helper = self._new_helper()
        warnings = [c.args[0] for c in self.log.log_warning.call_args_list]
        self.assertIn("G[S]etFirmwareEnvironmentVariableW function doesn't seem to exist", warnings)
        self.assertIn("NtEnumerateSystemEnvironmentValuesEx function doesn't seem to exist", warnings)
        self.assertIn("G[S]etFirmwareEnvironmentVariableExW function doesn't seem to exist", warnings)
        self.assertIn("GetSystemFirmwareTable function doesn't seem to exist", warnings)
        self.assertIn("NtQuerySystemInformation function doesn't seem to exist", warnings)
        self.assertFalse(hasattr(helper, 'GetFirmwareEnvironmentVariable'))

    def test_missing_firmware_apis_without_debug_skips_ex_warning(self):
        self.log.DEBUG = False
        self._patch('kernel32', Mock(spec=[]))
        self._patch('windll', Mock(spec=[]))
        self._new_helper()
        warnings = [c.args[0] for c in self.log.log_warning.call_args_list]
        self.assertNotIn("G[S]etFirmwareEnvironmentVariableExW function doesn't seem to exist", warnings)

    def test_del_closes_driver_handle(self):
        helper = self._new_helper()
        mock_api = self._patch('win32api', MagicMock())
        helper.driver_handle = 0x1234
        helper.__del__()
        mock_api.CloseHandle.assert_called_once_with(0x1234)
        self.assertIsNone(helper.driver_handle)

    def test_del_without_handle_is_noop(self):
        helper = self._new_helper()
        mock_api = self._patch('win32api', MagicMock())
        helper.driver_handle = None
        helper.__del__()
        mock_api.CloseHandle.assert_not_called()

    def test_show_warning(self):
        helper = self._new_helper()
        helper.show_warning()
        warnings = [c.args[0] for c in self.log.log_warning.call_args_list]
        self.assertIn('Chipsec should only be used on test systems!', warnings)
        self.assertIn('See WARNING.txt', warnings)


class TestWindowsHelperService(WindowsHelperExtendedBase):

    def setUp(self):
        WindowsHelperExtendedBase.setUp(self)
        self.helper = self._new_helper()
        self.win32service = self._patch('win32service', MagicMock())
        self.win32service.error = FakeWin32Error
        self.win32service.SERVICE_STOPPED = SERVICE_STOPPED
        self.win32service.SERVICE_RUNNING = SERVICE_RUNNING
        self.win32serviceutil = self._patch('win32serviceutil', MagicMock())
        self.win32api = self._patch('win32api', MagicMock())
        self.pywintypes = self._patch('pywintypes', MagicMock())
        self.pywintypes.error = FakeWin32Error
        self.winerror = self._patch('winerror', MagicMock())
        self.winerror.ERROR_SERVICE_EXISTS = ERROR_SERVICE_EXISTS

    # -- create -------------------------------------------------------------

    def test_create_success(self):
        self.win32service.OpenSCManager.return_value = 0x100
        self.win32service.CreateService.return_value = 0x200
        with patch('chipsec.helper.windows.windowshelper.os.path.isfile', return_value=True):
            self.assertTrue(self.helper.create())
        self.assertEqual(self.helper.driver_path,
                         self.wh.os.path.join(self.wh.DRIVER_FILE_PATHS[-1], self.wh.DRIVER_FILE_NAME))
        self.win32service.CloseServiceHandle.assert_any_call(0x200)
        self.win32service.CloseServiceHandle.assert_any_call(0x100)

    def test_create_driver_not_found(self):
        with patch('chipsec.helper.windows.windowshelper.os.path.isfile', return_value=False):
            with self.assertRaises(Exception) as ctx:
                self.helper.create()
        self.assertEqual(str(ctx.exception), 'CHIPSEC Windows Driver Not Found')
        self.assertIsNone(self.helper.driver_path)

    def test_create_open_scmanager_failure(self):
        self.win32service.OpenSCManager.side_effect = FakeWin32Error(5, 'OpenSCManager', 'Access is denied.')
        with patch('chipsec.helper.windows.windowshelper.os.path.isfile', return_value=True):
            with self.assertRaises(OsHelperError) as ctx:
                self.helper.create()
        self.assertEqual(str(ctx.exception), 'OpenSCManager failed: Access is denied. (5)')
        self.assertEqual(ctx.exception.errorcode, 5)

    def test_create_service_already_exists_opens_existing(self):
        self.win32service.OpenSCManager.return_value = 0x100
        self.win32service.CreateService.side_effect = FakeWin32Error(
            ERROR_SERVICE_EXISTS, 'CreateService', 'The specified service already exists.')
        self.win32service.OpenService.return_value = 0x300
        with patch('chipsec.helper.windows.windowshelper.os.path.isfile', return_value=True):
            self.assertTrue(self.helper.create())
        self.win32service.OpenService.assert_called_once()
        self.assertEqual(self.win32service.OpenService.call_args[0][1], self.wh.SERVICE_NAME)
        self.win32service.CloseServiceHandle.assert_any_call(0x300)

    def test_create_service_exists_but_open_fails(self):
        self.win32service.OpenSCManager.return_value = 0x100
        self.win32service.CreateService.side_effect = FakeWin32Error(
            ERROR_SERVICE_EXISTS, 'CreateService', 'exists')
        self.win32service.OpenService.side_effect = FakeWin32Error(5, 'OpenService', 'Access is denied.')
        with patch('chipsec.helper.windows.windowshelper.os.path.isfile', return_value=True):
            # The ``finally`` block dereferences the unassigned service handle
            with self.assertRaises(UnboundLocalError):
                self.helper.create()

    def test_create_service_other_error(self):
        self.win32service.OpenSCManager.return_value = 0x100
        self.win32service.CreateService.side_effect = FakeWin32Error(5, 'CreateService', 'Access is denied.')
        with patch('chipsec.helper.windows.windowshelper.os.path.isfile', return_value=True):
            with self.assertRaises(UnboundLocalError):
                self.helper.create()

    def test_create_service_handle_falsy_skips_debug_log(self):
        self.win32service.OpenSCManager.return_value = 0x100
        self.win32service.CreateService.return_value = 0
        with patch('chipsec.helper.windows.windowshelper.os.path.isfile', return_value=True):
            self.assertTrue(self.helper.create())

    # -- start --------------------------------------------------------------

    def test_start_with_existing_running_service(self):
        self.win32serviceutil.QueryServiceStatus.return_value = (16, SERVICE_RUNNING, 197, 0, 0, 0, 0)
        self.win32serviceutil.LocateSpecificServiceExe.return_value = 'C:\\drv.sys'
        self.assertTrue(self.helper.start())
        self.assertTrue(self.helper.use_existing_service)
        self.assertTrue(self.helper.driver_loaded)
        self.assertEqual(self.helper.driverpath, '(C:\\drv.sys)')
        self.win32serviceutil.StartService.assert_not_called()

    def test_start_starts_stopped_service(self):
        self.win32serviceutil.QueryServiceStatus.return_value = (16, SERVICE_STOPPED, 197, 0, 0, 0, 0)
        self.win32serviceutil.LocateSpecificServiceExe.return_value = 'C:\\drv.sys'
        self.assertTrue(self.helper.start())
        self.assertFalse(self.helper.use_existing_service)
        self.assertTrue(self.helper.driver_loaded)
        self.win32serviceutil.StartService.assert_called_once_with(self.wh.SERVICE_NAME)
        self.win32serviceutil.WaitForServiceStatus.assert_called_once_with(
            self.wh.SERVICE_NAME, SERVICE_RUNNING, 1)

    def test_start_failure_raises(self):
        self.win32serviceutil.QueryServiceStatus.return_value = (16, SERVICE_STOPPED, 197, 0, 0, 0, 0)
        self.win32serviceutil.StartService.side_effect = FakeWin32Error(2, 'StartService', 'Not found.')
        with self.assertRaises(OsHelperError) as ctx:
            self.helper.start()
        self.assertEqual(str(ctx.exception),
                         f"Service '{self.wh.SERVICE_NAME}' didn't start: Not found. (2)")
        self.assertEqual(ctx.exception.errorcode, 2)

    # -- stop ---------------------------------------------------------------

    def test_stop_with_existing_service_is_noop(self):
        self.helper.use_existing_service = True
        self.assertTrue(self.helper.stop())
        self.win32serviceutil.StopService.assert_not_called()

    def test_stop_success(self):
        self.helper.use_existing_service = False
        self.helper.driver_handle = 0x1234
        self.helper.driver_loaded = True
        self.assertTrue(self.helper.stop())
        self.win32api.CloseHandle.assert_called_once_with(0x1234)
        self.assertIsNone(self.helper.driver_handle)
        self.assertFalse(self.helper.driver_loaded)
        self.win32serviceutil.StopService.assert_called_once_with(self.wh.SERVICE_NAME)
        self.win32serviceutil.WaitForServiceStatus.assert_called_once_with(
            self.wh.SERVICE_NAME, SERVICE_STOPPED, 1)

    def test_stop_service_failure_returns_false(self):
        self.helper.use_existing_service = False
        self.helper.driver_loaded = True
        self.win32serviceutil.StopService.side_effect = FakeWin32Error(5, 'StopService', 'Access is denied.')
        self.assertFalse(self.helper.stop())
        self.assertFalse(self.helper.driver_loaded)
        self.log.log_error.assert_called_once_with('StopService failed: Access is denied. (5)')

    def test_stop_wait_failure_returns_false(self):
        self.helper.use_existing_service = False
        self.helper.driver_loaded = True
        self.win32serviceutil.WaitForServiceStatus.side_effect = FakeWin32Error(
            1053, 'Wait', 'The service did not respond.')
        self.assertFalse(self.helper.stop())
        self.log.log_warning.assert_called_once_with(
            f"Service '{self.wh.SERVICE_NAME}' didn't stop: The service did not respond. (1053)")

    # -- delete -------------------------------------------------------------

    def test_delete_with_existing_service_is_noop(self):
        self.helper.use_existing_service = True
        self.assertTrue(self.helper.delete())
        self.win32serviceutil.RemoveService.assert_not_called()

    def test_delete_success(self):
        self.helper.use_existing_service = False
        self.win32serviceutil.QueryServiceStatus.return_value = (16, SERVICE_STOPPED, 0, 0, 0, 0, 0)
        self.assertTrue(self.helper.delete())
        self.win32serviceutil.RemoveService.assert_called_once_with(self.wh.SERVICE_NAME)

    def test_delete_not_stopped_returns_false(self):
        self.helper.use_existing_service = False
        self.win32serviceutil.QueryServiceStatus.return_value = (16, SERVICE_RUNNING, 0, 0, 0, 0, 0)
        self.assertFalse(self.helper.delete())
        self.log.log_warning.assert_called_once_with(
            f"Cannot delete service '{self.wh.SERVICE_NAME}' (not stopped)")
        self.win32serviceutil.RemoveService.assert_not_called()

    def test_delete_remove_failure_returns_false(self):
        self.helper.use_existing_service = False
        self.win32serviceutil.QueryServiceStatus.return_value = (16, SERVICE_STOPPED, 0, 0, 0, 0, 0)
        self.win32serviceutil.RemoveService.side_effect = FakeWin32Error(5, 'RemoveService', 'Access is denied.')
        self.assertFalse(self.helper.delete())
        self.log.log_warning.assert_called_once_with('RemoveService failed: Access is denied. (5)')


class TestWindowsHelperDriverHandle(WindowsHelperExtendedBase):

    def setUp(self):
        WindowsHelperExtendedBase.setUp(self)
        self.helper = self._new_helper()
        self.win32file = self._patch('win32file', MagicMock())
        self.win32api = self._patch('win32api', MagicMock())
        self.kernel32 = self._patch('kernel32', MagicMock())
        self._patch('INVALID_HANDLE_VALUE', -1)
        self._patch('FILE_SHARE_READ', 1)
        self._patch('FILE_SHARE_WRITE', 2)
        self._patch('OPEN_EXISTING', 3)
        self._patch('FILE_ATTRIBUTE_NORMAL', 0x80)
        self._patch('FILE_FLAG_OVERLAPPED', 0x40000000)

    def test_get_driver_handle_reuses_open_handle(self):
        self.helper.driver_handle = 0x1234
        self.assertEqual(self.helper._get_driver_handle(), 0x1234)
        self.win32file.CreateFile.assert_not_called()

    def test_get_driver_handle_opens_device(self):
        self.win32file.CreateFile.return_value = 0x4321
        self.assertEqual(self.helper._get_driver_handle(), 0x4321)
        self.win32file.CreateFile.assert_called_once_with(
            self.helper.device_file, 3, 0, None, 3, 0x40000080, None)

    def test_get_driver_handle_invalid_raises(self):
        self.win32file.CreateFile.return_value = -1
        with self.assertRaises(OsHelperError) as ctx:
            self.helper._get_driver_handle()
        self.assertEqual(str(ctx.exception), self.wh.drv_hndl_error_msg)
        self.assertEqual(ctx.exception.errorcode, errno.ENXIO)

    def test_get_driver_handle_none_raises(self):
        self.win32file.CreateFile.return_value = None
        self.assertRaises(OsHelperError, self.helper._get_driver_handle)

    def test_check_driver_handle_ok(self):
        self.kernel32.GetLastError.return_value = 0
        self.assertTrue(self.helper.check_driver_handle())
        self.win32api.CloseHandle.assert_not_called()

    def test_check_driver_handle_reopens_on_invalid_handle(self):
        self.kernel32.GetLastError.return_value = 0x6
        self.helper.driver_handle = 0x1111
        self.win32file.CreateFile.return_value = 0x2222
        self.assertFalse(self.helper.check_driver_handle())
        self.win32api.CloseHandle.assert_called_once_with(0x1111)
        self.assertEqual(self.helper.driver_handle, 0x2222)
        self.log.log_warning.assert_called_once()

    def test_get_threads_count_sums_groups(self):
        self.kernel32.GetActiveProcessorGroupCount.return_value = 0x10003
        self.kernel32.GetActiveProcessorCount.side_effect = [4, 8, 16]
        self.assertEqual(self.helper.get_threads_count(), 28)
        self.assertEqual([c.args[0] for c in self.kernel32.GetActiveProcessorCount.call_args_list],
                         [0, 1, 2])


class TestWindowsHelperIoctl(WindowsHelperExtendedBase):

    def setUp(self):
        WindowsHelperExtendedBase.setUp(self)
        self.helper = self._new_helper()
        self.helper.driver_loaded = True
        self.helper.driver_handle = 0x1234
        self.win32file = self._patch('win32file', MagicMock())
        self._patch('INVALID_HANDLE_VALUE', -1)
        self._patch('c_char', type('c_char_stub', (object,), {'__mul__': lambda self, other: (lambda: b'')})())
        self.pywintypes = self._patch('pywintypes', MagicMock())
        self.pywintypes.error = FakeWin32Error

    def test_ioctl_requires_loaded_driver(self):
        self.helper.driver_loaded = False
        with self.assertRaises(OsHelperError) as ctx:
            self.helper._ioctl(self.wh.IOCTL_RDMSR, b'', 8)
        self.assertEqual(str(ctx.exception),
                         'chipsec kernel driver is not loaded (in native API mode?)')
        self.assertEqual(ctx.exception.errorcode, 0)

    def test_ioctl_passes_through_device_io_control(self):
        self.win32file.DeviceIoControl.return_value = b'\x01\x02'
        out = self.helper._ioctl(self.wh.IOCTL_RDMSR, b'\xAA', 2)
        self.assertEqual(out, b'\x01\x02')
        self.win32file.DeviceIoControl.assert_called_once_with(
            0x1234, self.wh.IOCTL_RDMSR, b'\xAA', 2, None)

    def test_ioctl_privileged_instruction_raises_hw_access_violation(self):
        err_arg = self.wh.STATUS_PRIVILEGED_INSTRUCTION - 0x100000000
        self.win32file.DeviceIoControl.side_effect = FakeWin32Error(err_arg, 'DeviceIoControl', 'privileged')
        with self.assertRaises(HWAccessViolationError) as ctx:
            self.helper._ioctl(self.wh.IOCTL_RDMSR, b'', 8)
        self.assertEqual(ctx.exception.errorcode, self.wh.STATUS_PRIVILEGED_INSTRUCTION)
        self.assertIn('STATUS_PRIVILEGED_INSTRUCTION', str(ctx.exception))

    def test_ioctl_other_error_raises_oshelper_error(self):
        self.win32file.DeviceIoControl.side_effect = FakeWin32Error(
            0xC0000005 - 0x100000000, 'DeviceIoControl', 'access violation')
        with self.assertRaises(OsHelperError) as ctx:
            self.helper._ioctl(self.wh.IOCTL_RDMSR, b'', 8)
        self.assertEqual(str(ctx.exception),
                         'HW Access Error: DeviceIoControl returned status 0xC0000005 (access violation)')
        self.assertEqual(ctx.exception.errorcode, 0xC0000005)


class TestWindowsHelperHwApi(WindowsHelperExtendedBase):
    """API surface tests that stub ``_ioctl`` and assert the packed request buffers."""

    def setUp(self):
        WindowsHelperExtendedBase.setUp(self)
        self.helper = self._new_helper()
        self.helper.driver_loaded = True
        ioctl_patcher = patch.object(self.helper, '_ioctl')
        self.addCleanup(ioctl_patcher.stop)
        self.ioctl = ioctl_patcher.start()

    def _ioctl_args(self):
        return self.ioctl.call_args[0]

    # -- MMIO ---------------------------------------------------------------

    def test_read_mmio_reg_qword(self):
        self.ioctl.return_value = struct.pack('=Q', 0x1122334455667788)
        self.assertEqual(self.helper.read_mmio_reg(0x1_FED0_0000, 8), 0x1122334455667788)
        self.assertEqual(self._ioctl_args(),
                         (self.wh.IOCTL_READ_MMIO, struct.pack('3I', 1, 0xFED00000, 8), 8))

    def test_read_mmio_reg_word(self):
        self.ioctl.return_value = struct.pack('=H', 0xBEEF)
        self.assertEqual(self.helper.read_mmio_reg(0xFED00000, 2), 0xBEEF)

    def test_read_mmio_reg_byte(self):
        self.ioctl.return_value = struct.pack('=B', 0xAB)
        self.assertEqual(self.helper.read_mmio_reg(0xFED00000, 1), 0xAB)

    def test_read_mmio_reg_invalid_size_returns_zero(self):
        self.ioctl.return_value = b'\x00\x00\x00'
        self.assertEqual(self.helper.read_mmio_reg(0xFED00000, 3), 0)

    def test_write_mmio_reg_qword(self):
        self.ioctl.return_value = b'\x01\x00\x00\x00'
        self.assertEqual(self.helper.write_mmio_reg(0xFED00000, 8, 0x1122334455667788), 1)
        self.assertEqual(self._ioctl_args(),
                         (self.wh.IOCTL_WRITE_MMIO,
                          struct.pack('3I', 0, 0xFED00000, 8) + struct.pack('=Q', 0x1122334455667788),
                          4))

    def test_write_mmio_reg_dword_masks_value(self):
        self.ioctl.return_value = b'\x00\x00\x00\x00'
        self.helper.write_mmio_reg(0xFED00000, 4, 0x1_DEADBEEF)
        self.assertEqual(self._ioctl_args()[1],
                         struct.pack('3I', 0, 0xFED00000, 4) + struct.pack('=I', 0xDEADBEEF))

    def test_write_mmio_reg_word_masks_value(self):
        self.ioctl.return_value = b'\x00\x00\x00\x00'
        self.helper.write_mmio_reg(0xFED00000, 2, 0xDEADBEEF)
        self.assertEqual(self._ioctl_args()[1],
                         struct.pack('3I', 0, 0xFED00000, 2) + struct.pack('=H', 0xBEEF))

    def test_write_mmio_reg_byte_masks_value(self):
        self.ioctl.return_value = b'\x00\x00\x00\x00'
        self.helper.write_mmio_reg(0xFED00000, 1, 0xDEADBEEF)
        self.assertEqual(self._ioctl_args()[1],
                         struct.pack('3I', 0, 0xFED00000, 1) + struct.pack('=B', 0xEF))

    def test_write_mmio_reg_invalid_size_returns_false(self):
        self.assertFalse(self.helper.write_mmio_reg(0xFED00000, 3, 0))
        self.ioctl.assert_not_called()

    # -- hypercall / map_io_space / free_phys_mem ---------------------------

    def test_hypercall_amd64(self):
        self.helper.os_machine = 'AMD64'
        self.ioctl.return_value = struct.pack('<Q', 0xFEEDFACECAFEBEEF)
        result = self.helper.hypercall(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11)
        self.assertEqual(result, 0xFEEDFACECAFEBEEF)
        self.assertEqual(self._ioctl_args(),
                         (self.wh.IOCTL_HYPERCALL,
                          struct.pack('<11Q', 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11), 8))

    def test_hypercall_x86(self):
        self.helper.os_machine = 'x86'
        self.ioctl.return_value = struct.pack('<I', 0xCAFEBEEF)
        result = self.helper.hypercall(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11)
        self.assertEqual(result, 0xCAFEBEEF)
        self.assertEqual(self._ioctl_args(),
                         (self.wh.IOCTL_HYPERCALL,
                          struct.pack('<11I', 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11), 4))

    def test_map_io_space(self):
        self.ioctl.return_value = struct.pack('<Q', 0xFFFFF80000000000)
        self.assertEqual(self.helper.map_io_space(0xFED00000, 0x1000, 0), 0xFFFFF80000000000)
        self.assertEqual(self._ioctl_args(),
                         (self.wh.IOCTL_MAP_IO_SPACE, struct.pack('<3Q', 0xFED00000, 0x1000, 0), 8))

    def test_free_phys_mem(self):
        self.ioctl.return_value = struct.pack('<Q', 0)
        self.assertIsNone(self.helper.free_phys_mem(0x16000000))
        self.assertEqual(self._ioctl_args(),
                         (self.wh.IOCTL_FREE_PHYSMEM, struct.pack('<Q', 0x16000000), 8))

    # -- SW SMI -------------------------------------------------------------

    def test_send_sw_smi_returns_unpacked_registers(self):
        self.helper.os_machine = 'AMD64'
        values = (0xDEAD, 1, 2, 3, 4, 5, 6)
        self.ioctl.return_value = struct.pack(self.wh._smi_msg_t_fmt, *values)
        self.assertEqual(self.helper.send_sw_smi(0, 0xDEAD, 1, 2, 3, 4, 5, 6), values)
        self.assertEqual(self._ioctl_args(),
                         (self.wh.IOCTL_SWSMI, struct.pack(self.wh._smi_msg_t_fmt, *values),
                          struct.calcsize(self.wh._smi_msg_t_fmt)))

    def test_send_sw_smi_empty_response_returns_none(self):
        self.helper.os_machine = 'AMD64'
        self.ioctl.return_value = b''
        self.assertIsNone(self.helper.send_sw_smi(0, 0, 0, 0, 0, 0, 0, 0))

    def test_send_sw_smi_architecture_mismatch_logs(self):
        self.helper.os_machine = 'i386'
        self.ioctl.return_value = b''
        self.helper.send_sw_smi(0, 0, 0, 0, 0, 0, 0, 0)
        self.log.log.assert_called_once_with(
            '[helper] Python architecture must match OS architecture.  Run with i386 architecture of python')


class TestWindowsHelperEfiVariables(WindowsHelperExtendedBase):

    def setUp(self):
        WindowsHelperExtendedBase.setUp(self)
        self.helper = self._new_helper()
        self.win32api = self._patch('win32api', MagicMock())
        self.kernel32 = self._patch('kernel32', MagicMock())
        self._patch('WinError', MagicMock(return_value='winerr'))
        self.buffers = {}
        self._patch('create_string_buffer', self._create_buffer)
        self.helper.GetFirmwareEnvironmentVariable = MagicMock()
        self.helper.GetFirmwareEnvironmentVariableEx = MagicMock()
        self.helper.SetFirmwareEnvironmentVariable = MagicMock()
        self.helper.SetFirmwareEnvironmentVariableEx = MagicMock()
        self.helper.NtEnumerateSystemEnvironmentValuesEx = MagicMock()

    def _create_buffer(self, size):
        return FakeBuffer(self.buffers.get(size, b'\x00' * size))

    # -- EFI_supported ------------------------------------------------------

    def test_efi_supported_true(self):
        self.win32api.GetLastError.return_value = 0
        self.assertTrue(self.helper.EFI_supported())
        self.helper.GetFirmwareEnvironmentVariable.assert_called_once_with(
            '', '{00000000-0000-0000-0000-000000000000}', 0, 0)

    def test_efi_supported_false_on_legacy(self):
        self.win32api.GetLastError.return_value = 1
        self.assertFalse(self.helper.EFI_supported())

    def test_efi_supported_falls_back_to_ex(self):
        self.helper.GetFirmwareEnvironmentVariable = None
        self.win32api.GetLastError.return_value = 0
        self.assertTrue(self.helper.EFI_supported())
        self.helper.GetFirmwareEnvironmentVariableEx.assert_called_once_with(
            '', '{00000000-0000-0000-0000-000000000000}', 0, 0)

    def test_efi_supported_no_api(self):
        self.helper.GetFirmwareEnvironmentVariable = None
        self.helper.GetFirmwareEnvironmentVariableEx = None
        self.assertFalse(self.helper.EFI_supported())

    # -- get_EFI_variable ---------------------------------------------------

    def test_get_efi_variable_full(self):
        self.buffers[self.wh.EFI_VAR_MAX_BUFFER_SIZE] = b'\x11\x22\x33\x44' + b'\x00' * 8
        self.helper.GetFirmwareEnvironmentVariable.return_value = 4
        (status, data, attrs) = self.helper.get_EFI_variable_full('Setup', '1-2-3')
        self.assertEqual(status, 0)
        self.assertEqual(data, b'\x11\x22\x33\x44')
        self.assertIsNone(attrs)
        call = self.helper.GetFirmwareEnvironmentVariable.call_args[0]
        self.assertEqual(call[0], 'Setup')
        self.assertEqual(call[1], '{1-2-3}')
        self.assertEqual(call[3], self.wh.EFI_VAR_MAX_BUFFER_SIZE)

    def test_get_efi_variable_full_with_attrs_uses_ex(self):
        self.buffers[self.wh.EFI_VAR_MAX_BUFFER_SIZE] = b'\xAA\xBB'
        self.helper.GetFirmwareEnvironmentVariableEx.return_value = 2
        (status, data, attrs) = self.helper.get_EFI_variable_full('Setup', '1-2-3', 0x7)
        self.assertEqual(status, 0)
        self.assertEqual(data, b'\xAA\xBB')
        self.assertEqual(attrs, 0x7)
        self.helper.GetFirmwareEnvironmentVariable.assert_not_called()

    def test_get_efi_variable_full_failure_returns_last_error(self):
        self.helper.GetFirmwareEnvironmentVariable.return_value = 0
        self.kernel32.GetLastError.return_value = 203
        (status, data, attrs) = self.helper.get_EFI_variable_full('Nope', '1-2-3')
        self.assertEqual(status, 203)
        self.assertIsNone(data)
        self.log.log_error.assert_called_once_with(
            'GetFirmwareEnvironmentVariable[Ex] returned error: winerr')

    def test_get_efi_variable_full_missing_api_returns_last_error(self):
        self.helper.GetFirmwareEnvironmentVariable = None
        self.kernel32.GetLastError.return_value = 1
        (status, data, _) = self.helper.get_EFI_variable_full('Nope', '1-2-3')
        self.assertEqual(status, 1)
        self.assertIsNone(data)

    def test_get_efi_variable_returns_data_only(self):
        self.buffers[self.wh.EFI_VAR_MAX_BUFFER_SIZE] = b'\x01\x02\x03'
        self.helper.GetFirmwareEnvironmentVariable.return_value = 3
        self.assertEqual(self.helper.get_EFI_variable('Setup', '1-2-3'), b'\x01\x02\x03')

    # -- set_EFI_variable ---------------------------------------------------

    def test_set_efi_variable_success(self):
        self.helper.SetFirmwareEnvironmentVariable.return_value = 1
        self.assertEqual(self.helper.set_EFI_variable('Setup', '1-2-3', b'\xAA\xBB', None, None), 0)
        self.helper.SetFirmwareEnvironmentVariable.assert_called_once_with(
            'Setup', '{1-2-3}', b'\xAA\xBB', 2)

    def test_set_efi_variable_failure_returns_last_error(self):
        self.helper.SetFirmwareEnvironmentVariable.return_value = 0
        self.kernel32.GetLastError.return_value = 5
        self.assertEqual(self.helper.set_EFI_variable('Setup', '1-2-3', b'\xAA', None, None), 5)
        self.log.log_error.assert_called_once_with(
            'SetFirmwareEnvironmentVariable[Ex] returned error: winerr')

    def test_set_efi_variable_with_attrs_uses_ex(self):
        self.helper.SetFirmwareEnvironmentVariableEx.return_value = 1
        self.assertEqual(self.helper.set_EFI_variable('Setup', '1-2-3', b'\xAA', 1, 0x7), 0)
        self.helper.SetFirmwareEnvironmentVariableEx.assert_called_once_with(
            'Setup', '{1-2-3}', b'\xAA', 1, 0x7)

    def test_set_efi_variable_string_attrs_are_unpacked(self):
        self.helper.SetFirmwareEnvironmentVariableEx.return_value = 1
        self.helper.set_EFI_variable('Setup', '1-2-3', b'\xAA', None, 'ABCD')
        expected_attrs = struct.unpack('Q', b'ABCD\x00\x00\x00\x00')[0]
        self.assertEqual(self.helper.SetFirmwareEnvironmentVariableEx.call_args[0][4], expected_attrs)

    def test_set_efi_variable_none_buffer_uses_empty_bytes(self):
        self.helper.SetFirmwareEnvironmentVariable.return_value = 1
        self.assertEqual(self.helper.set_EFI_variable('Setup', '1-2-3', None, None, None), 0)
        self.helper.SetFirmwareEnvironmentVariable.assert_called_once_with(
            'Setup', '{1-2-3}', b'', 0)

    def test_set_efi_variable_missing_api_returns_last_error(self):
        self.helper.SetFirmwareEnvironmentVariable = None
        self.kernel32.GetLastError.return_value = 1
        self.assertEqual(self.helper.set_EFI_variable('Setup', '1-2-3', b'\xAA', None, None), 1)

    def test_delete_efi_variable_writes_zero_length(self):
        self.helper.SetFirmwareEnvironmentVariable.return_value = 1
        self.assertEqual(self.helper.delete_EFI_variable('Setup', '1-2-3'), 0)
        self.helper.SetFirmwareEnvironmentVariable.assert_called_once_with(
            'Setup', '{1-2-3}', b'', 0)

    # -- list_EFI_variables -------------------------------------------------

    def test_list_efi_variables_success(self):
        guid = bytes(range(16))
        blob = make_efi_var_blob('AB', b'\xDE\xAD', 0x7, guid)
        self.buffers[self.wh.EFI_VAR_MAX_BUFFER_SIZE] = blob
        self.helper.NtEnumerateSystemEnvironmentValuesEx.return_value = 0
        variables = self.helper.list_EFI_variables()
        self.assertEqual(list(variables.keys()), ['AB'])
        self.assertEqual(variables['AB'][0][3], b'\xDE\xAD')
        self.assertEqual(self.helper.NtEnumerateSystemEnvironmentValuesEx.call_args[0][0], 2)

    def test_list_efi_variables_buffer_too_small_retries(self):
        guid = bytes(range(16))
        blob = make_efi_var_blob('AB', b'\x01', 0x1, guid)
        self.buffers[self.wh.EFI_VAR_MAX_BUFFER_SIZE] = b''
        self.buffers[4] = struct.pack('<I', len(blob))
        self.buffers[len(blob)] = blob
        self.helper.NtEnumerateSystemEnvironmentValuesEx.side_effect = [0xC0000023, 0]
        self._patch('PyLong_AsByteArray', MagicMock())
        variables = self.helper.list_EFI_variables()
        self.assertEqual(list(variables.keys()), ['AB'])
        self.assertEqual(self.helper.NtEnumerateSystemEnvironmentValuesEx.call_count, 2)

    def test_list_efi_variables_api_not_found(self):
        self.buffers[self.wh.EFI_VAR_MAX_BUFFER_SIZE] = b''
        self.helper.NtEnumerateSystemEnvironmentValuesEx.return_value = 0xC0000002
        self.assertIsNone(self.helper.list_EFI_variables())
        self.log.log_warning.assert_called_once_with(
            'NtEnumerateSystemEnvironmentValuesEx was not found (NTSTATUS = 0xC0000002)')

    def test_list_efi_variables_access_restricted(self):
        self.buffers[self.wh.EFI_VAR_MAX_BUFFER_SIZE] = b''
        self.helper.NtEnumerateSystemEnvironmentValuesEx.return_value = 0xC0000001
        self.kernel32.GetLastError.return_value = 5
        self.assertIsNone(self.helper.list_EFI_variables())
        warnings = [c.args[0] for c in self.log.log_warning.call_args_list]
        self.assertIn('NtEnumerateSystemEnvironmentValuesEx was not successful', warnings)

    def test_list_efi_variables_other_failure(self):
        self.buffers[self.wh.EFI_VAR_MAX_BUFFER_SIZE] = b''
        self.helper.NtEnumerateSystemEnvironmentValuesEx.return_value = 0xC0000005
        self.kernel32.GetLastError.return_value = 87
        self.assertIsNone(self.helper.list_EFI_variables())
        errors = [c.args[0] for c in self.log.log_error.call_args_list]
        self.assertIn('NtEnumerateSystemEnvironmentValuesEx failed (GetLastError = 0x57)', errors)
        self.assertIn('*** NTSTATUS: C0000005', errors)

    def test_list_efi_variables_negative_status_is_masked(self):
        self.buffers[self.wh.EFI_VAR_MAX_BUFFER_SIZE] = b''
        self.helper.NtEnumerateSystemEnvironmentValuesEx.return_value = -1073741822  # 0xC0000002
        self.assertIsNone(self.helper.list_EFI_variables())


class TestWindowsHelperProcessAffinity(WindowsHelperExtendedBase):

    def setUp(self):
        WindowsHelperExtendedBase.setUp(self)
        self.helper = self._new_helper()
        self.win32process = self._patch('win32process', MagicMock())
        self.win32process.error = FakeWin32Error
        self.win32api = self._patch('win32api', MagicMock())
        self.pywintypes = self._patch('pywintypes', MagicMock())
        self.pywintypes.error = FakeWin32Error
        win32con = Mock()
        win32con.PROCESS_QUERY_INFORMATION = 0x0400
        win32con.PROCESS_SET_INFORMATION = 0x0200
        self._patch('win32con', win32con)

    def test_get_handle_for_current_process(self):
        self.win32process.GetCurrentProcess.return_value = 0xFFFF
        self.assertEqual(self.helper._get_handle_for_pid(), 0xFFFF)
        self.win32api.OpenProcess.assert_not_called()

    def test_get_handle_for_pid_readonly(self):
        self.win32api.OpenProcess.return_value = 0x88
        self.assertEqual(self.helper._get_handle_for_pid(1234), 0x88)
        self.win32api.OpenProcess.assert_called_once_with(0x0400, 0, 1234)

    def test_get_handle_for_pid_readwrite(self):
        self.win32api.OpenProcess.return_value = 0x88
        self.helper._get_handle_for_pid(1234, ro=False)
        self.win32api.OpenProcess.assert_called_once_with(0x0600, 0, 1234)

    def test_get_handle_for_pid_failure_raises_value_error(self):
        self.win32api.OpenProcess.side_effect = FakeWin32Error(5, 'OpenProcess', 'denied')
        self.assertRaises(ValueError, self.helper._get_handle_for_pid, 1234)
        self.log.log.assert_called_once_with('unable to open a process handle')

    def test_set_affinity_returns_current_mask(self):
        self.win32process.GetProcessAffinityMask.return_value = (0xF, 0xFF)
        self.assertEqual(self.helper.set_affinity(0x1), 0xF)
        self.win32process.SetProcessAffinityMask.assert_called_once_with(
            self.win32process.GetCurrentProcess.return_value, 0xF)

    def test_set_affinity_failure_raises_value_error(self):
        self.win32process.GetProcessAffinityMask.return_value = (0xF, 0xFF)
        self.win32process.SetProcessAffinityMask.side_effect = FakeWin32Error(5, 'Set', 'denied')
        self.assertRaises(ValueError, self.helper.set_affinity, 0x1)
        self.log.log.assert_called_once_with('unable to set process affinity')

    def test_get_affinity_returns_mask(self):
        self.win32process.GetProcessAffinityMask.return_value = (0x3, 0xFF)
        self.assertEqual(self.helper.get_affinity(), 0x3)

    def test_get_affinity_failure_raises_value_error(self):
        self.win32process.GetProcessAffinityMask.side_effect = FakeWin32Error(5, 'Get', 'denied')
        self.assertRaises(ValueError, self.helper.get_affinity)
        self.log.log.assert_called_once_with('unable to get the running cpu')


class TestWindowsHelperAcpiTables(WindowsHelperExtendedBase):

    def setUp(self):
        WindowsHelperExtendedBase.setUp(self)
        self.helper = self._new_helper()
        self._patch('WinError', MagicMock(return_value='winerr'))
        self.sizes = []
        self._patch('create_string_buffer', self._create_buffer)
        self.helper.EnumSystemFirmwareTbls = MagicMock()
        self.helper.GetSystemFirmwareTbl = MagicMock()

    def _create_buffer(self, size):
        self.sizes.append(size)
        return FakeBuffer(bytes(i % 256 for i in range(size)))

    def test_enum_acpi_tables_single_pass(self):
        self.helper.EnumSystemFirmwareTbls.return_value = 8
        tables = self.helper.enum_ACPI_tables()
        self.assertEqual(tables, [bytes(range(0, 4)), bytes(range(4, 8))])
        self.assertEqual(self.sizes, [36])
        self.helper.EnumSystemFirmwareTbls.assert_called_once()
        self.assertEqual(self.helper.EnumSystemFirmwareTbls.call_args[0][0],
                         self.wh.FirmwareTableProviderSignature_ACPI)

    def test_enum_acpi_tables_grows_buffer(self):
        self.helper.EnumSystemFirmwareTbls.side_effect = [40, 40]
        tables = self.helper.enum_ACPI_tables()
        self.assertEqual(self.sizes, [36, 40])
        self.assertEqual(len(tables), 10)
        self.assertEqual(tables[-1], bytes(range(36, 40)))

    def test_enum_acpi_tables_failure_returns_none(self):
        self.helper.EnumSystemFirmwareTbls.return_value = 0
        self.assertIsNone(self.helper.enum_ACPI_tables())
        self.log.log_error.assert_called_once_with('EnumSystemFirmwareTbls() returned error: winerr')

    def test_get_acpi_table_single_pass(self):
        self.helper.GetSystemFirmwareTbl.return_value = 36
        table = self.helper.get_ACPI_table('RSDT')
        self.assertEqual(table, bytes(range(36)))
        self.assertEqual(self.helper.GetSystemFirmwareTbl.call_args[0][1],
                         struct.unpack('<I', b'RSDT')[0])

    def test_get_acpi_table_grows_buffer(self):
        self.helper.GetSystemFirmwareTbl.side_effect = [50, 50]
        table = self.helper.get_ACPI_table('XSDT')
        self.assertEqual(self.sizes, [36, 50])
        self.assertEqual(table, bytes(range(50)))

    def test_get_acpi_table_failure_returns_none(self):
        self.helper.GetSystemFirmwareTbl.return_value = 0
        self.assertIsNone(self.helper.get_ACPI_table('FACP'))
        self.log.log_error.assert_called_once_with('GetSystemFirmwareTable(FACP) returned error: winerr')


class TestWindowsHelperUnimplemented(WindowsHelperExtendedBase):

    def setUp(self):
        WindowsHelperExtendedBase.setUp(self)
        self.helper = self._new_helper()

    def test_msgbus_apis_raise(self):
        for name, args in (('msgbus_send_read_message', (1, 2)),
                           ('msgbus_send_write_message', (1, 2, 3)),
                           ('msgbus_send_message', (1, 2, 3))):
            with self.subTest(api=name):
                with self.assertRaises(UnimplementedAPIError) as ctx:
                    getattr(self.helper, name)(*args)
                self.assertIn(name, str(ctx.exception))


if __name__ == '__main__':
    unittest.main()
