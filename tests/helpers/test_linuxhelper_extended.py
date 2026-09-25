# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2023, Intel Corporation
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


# To execute: python[3] -m unittest tests.helpers.test_linuxhelper_extended

import array
import errno
import struct
import sys
import unittest
from unittest.mock import MagicMock, patch

import chipsec.helper.linux.linuxhelper as lh
from chipsec.library.exceptions import OsHelperError, UnimplementedAPIError

MOD = 'chipsec.helper.linux.linuxhelper'

PACK = 'Q' if sys.maxsize > 2 ** 32 else 'I'

TEST_GUID = '12345678-1234-1234-1234-123456789ABC'


def new_helper() -> 'lh.LinuxHelper':
    """Build a LinuxHelper that is initialized enough to pack/unpack ioctl buffers."""
    helper = lh.LinuxHelper()
    helper._pack = PACK
    helper._ioctl_base = helper.compute_ioctlbase()
    helper.dev_fh = MagicMock()
    return helper


def efivar_ioctl(responses):
    """Return an ioctl stub that writes driver responses back into the shared buffer.

    ``responses`` is a list of (new_size, status, attr, data) tuples, one per call.
    """
    state = {'call': 0}

    def _ioctl(_nr, buf, *_args):
        new_size, status, attr, data = responses[state['call']]
        state['call'] += 1
        buf[0:4] = array.array('B', struct.pack('I', new_size))
        buf[4:8] = array.array('B', struct.pack('I', status))
        buf[8:12] = array.array('B', struct.pack('I', attr))
        if data:
            buf[12:12 + len(data)] = array.array('B', data)
        return b''

    return _ioctl


class LinuxHelperModuleManagementTest(unittest.TestCase):

    def setUp(self):
        self.helper = lh.LinuxHelper()

    @patch(f'{MOD}.os.path.isdir', return_value=True)
    @patch(f'{MOD}.os.listdir', return_value=['x86_64'])
    @patch(f'{MOD}.defines.get_version', return_value='1.13.0')
    def test_get_dkms_module_location(self, _get_version, _listdir, _isdir):
        self.assertEqual(self.helper.get_dkms_module_location(),
                         f'/var/lib/dkms/chipsec/1.13.0/{self.helper.os_release}/x86_64/module/chipsec.ko')

    @patch(f'{MOD}.os.chmod')
    @patch(f'{MOD}.os.chown')
    @patch(f'{MOD}.os.path.exists', return_value=True)
    @patch(f'{MOD}.subprocess.check_output', return_value=b'')
    def test_load_chipsec_module_via_modprobe(self, check_output, _exists, chown, chmod):
        self.helper.load_chipsec_module()
        check_output.assert_called_once_with(['modprobe', 'chipsec'], stderr=lh.subprocess.STDOUT)
        chown.assert_called_once_with('/dev/chipsec', 0, 0)
        chmod.assert_called_once_with('/dev/chipsec', 0o600)
        self.assertEqual(self.helper.driverpath, '(modprobe chipsec)')

    @patch(f'{MOD}.os.chmod')
    @patch(f'{MOD}.os.chown')
    @patch(f'{MOD}.os.path.exists', return_value=True)
    @patch(f'{MOD}.subprocess.check_output')
    def test_load_chipsec_module_passes_symbol_addresses(self, check_output, _exists, _chown, _chmod):
        with patch.object(lh.LinuxHelper, 'SUPPORT_KERNEL26_GET_PAGE_IS_RAM', True), \
                patch.object(lh.LinuxHelper, 'SUPPORT_KERNEL26_GET_PHYS_MEM_ACCESS_PROT', True), \
                patch.object(lh.LinuxHelper, 'get_page_is_ram', return_value=b'ffff0001'), \
                patch.object(lh.LinuxHelper, 'get_phys_mem_access_prot', return_value=b'ffff0002'):
            self.helper.load_chipsec_module()
        check_output.assert_called_once_with(
            ['modprobe', 'chipsec', "a1=0xb'ffff0001'", "a2=0xb'ffff0002'"],
            stderr=lh.subprocess.STDOUT)

    @patch(f'{MOD}.os.chmod')
    @patch(f'{MOD}.os.chown')
    @patch(f'{MOD}.os.path.exists', return_value=True)
    @patch(f'{MOD}.subprocess.check_output')
    def test_load_chipsec_module_missing_symbols(self, check_output, _exists, _chown, _chmod):
        with patch.object(lh.LinuxHelper, 'SUPPORT_KERNEL26_GET_PAGE_IS_RAM', True), \
                patch.object(lh.LinuxHelper, 'SUPPORT_KERNEL26_GET_PHYS_MEM_ACCESS_PROT', True), \
                patch.object(lh.LinuxHelper, 'get_page_is_ram', return_value=None), \
                patch.object(lh.LinuxHelper, 'get_phys_mem_access_prot', return_value=None):
            self.helper.load_chipsec_module()
        check_output.assert_called_once_with(['modprobe', 'chipsec'], stderr=lh.subprocess.STDOUT)

    @patch(f'{MOD}.os.chmod')
    @patch(f'{MOD}.os.chown')
    @patch(f'{MOD}.os.path.exists', return_value=True)
    @patch(f'{MOD}.subprocess.check_output')
    def test_load_chipsec_module_falls_back_to_insmod(self, check_output, _exists, chown, chmod):
        check_output.side_effect = [OSError('no modprobe'), b'']
        self.helper.load_chipsec_module()
        self.assertEqual(check_output.call_count, 2)
        insmod_args = check_output.call_args_list[1][0][0]
        self.assertEqual(insmod_args[0], 'insmod')
        self.assertTrue(insmod_args[1].endswith('chipsec/helper/linux/chipsec.ko'))
        chown.assert_called_once_with('/dev/chipsec', 0, 0)
        chmod.assert_called_once_with('/dev/chipsec', 0o600)
        self.assertEqual(self.helper.driverpath, f'({insmod_args[1]})')

    @patch(f'{MOD}.os.chmod')
    @patch(f'{MOD}.os.chown')
    @patch(f'{MOD}.subprocess.check_output')
    def test_load_chipsec_module_uses_compressed_module(self, check_output, _chown, _chmod):
        check_output.side_effect = [OSError('no modprobe'), b'']

        def exists(path):
            return path.endswith('.xz') or path == '/dev/chipsec'

        with patch(f'{MOD}.os.path.exists', side_effect=exists):
            self.helper.load_chipsec_module()
        self.assertTrue(check_output.call_args_list[1][0][0][1].endswith('chipsec.ko.xz'))

    @patch(f'{MOD}.os.chmod')
    @patch(f'{MOD}.os.chown')
    @patch(f'{MOD}.subprocess.check_output')
    def test_load_chipsec_module_uses_dkms_location(self, check_output, _chown, _chmod):
        check_output.side_effect = [OSError('no modprobe'), b'']
        dkms_path = '/var/lib/dkms/chipsec/1.0/rel/x86_64/module/chipsec.ko'

        def exists(path):
            return path in (dkms_path, '/dev/chipsec')

        with patch(f'{MOD}.os.path.exists', side_effect=exists), \
                patch.object(lh.LinuxHelper, 'get_dkms_module_location', return_value=dkms_path):
            self.helper.load_chipsec_module()
        self.assertEqual(check_output.call_args_list[1][0][0][1], dkms_path)

    @patch(f'{MOD}.os.path.exists', return_value=False)
    @patch(f'{MOD}.subprocess.check_output', side_effect=OSError('boom'))
    def test_load_chipsec_module_not_found(self, _check_output, _exists):
        with patch.object(lh.LinuxHelper, 'get_dkms_module_location', side_effect=OSError('no dkms')):
            with self.assertRaises(Exception) as ctx:
                self.helper.load_chipsec_module()
        self.assertEqual(str(ctx.exception), 'Cannot find chipsec.ko module')

    @patch(f'{MOD}.os.path.exists', return_value=True)
    @patch(f'{MOD}.subprocess.check_output', side_effect=OSError('not permitted'))
    def test_load_chipsec_module_insmod_failure(self, _check_output, _exists):
        with self.assertRaises(Exception) as ctx:
            self.helper.load_chipsec_module()
        self.assertIn('Could not start Linux Helper', str(ctx.exception))

    @patch(f'{MOD}.logger')
    @patch(f'{MOD}.os.chmod')
    @patch(f'{MOD}.os.chown')
    @patch(f'{MOD}.subprocess.check_output')
    def test_load_chipsec_module_device_node_missing(self, check_output, _chown, _chmod, mock_logger):
        check_output.side_effect = [OSError('no modprobe'), b'']

        def exists(path):
            return path != '/dev/chipsec'

        with patch(f'{MOD}.os.path.exists', side_effect=exists):
            self.helper.load_chipsec_module()
        self.assertTrue(mock_logger.return_value.log_error.called)

    @patch(f'{MOD}.os.path.exists', return_value=False)
    @patch(f'{MOD}.subprocess.call')
    def test_unload_chipsec_module_when_loaded(self, subprocess_call, _exists):
        self.helper.driver_loaded = True
        self.helper.unload_chipsec_module()
        subprocess_call.assert_called_once_with(['rmmod', 'chipsec'])

    @patch(f'{MOD}.os.path.exists', return_value=True)
    @patch(f'{MOD}.subprocess.call')
    def test_unload_chipsec_module_when_device_present(self, subprocess_call, _exists):
        self.helper.driver_loaded = False
        self.helper.unload_chipsec_module()
        subprocess_call.assert_called_once_with(['rmmod', 'chipsec'])

    @patch(f'{MOD}.os.path.exists', return_value=False)
    @patch(f'{MOD}.subprocess.call')
    def test_unload_chipsec_module_noop(self, subprocess_call, _exists):
        self.helper.driver_loaded = False
        self.helper.unload_chipsec_module()
        subprocess_call.assert_not_called()

    @patch(f'{MOD}.open')
    def test_init_opens_device(self, mocked_open):
        self.helper.init()
        mocked_open.assert_called_once_with('/dev/chipsec', 'rb+', buffering=0)
        self.assertTrue(self.helper.driver_loaded)
        self.assertEqual(self.helper._pack, PACK)
        self.assertEqual(self.helper._ioctl_base, (3 << 30) | (ord('C') << 8) | (struct.calcsize(PACK) << 16))

    @patch(f'{MOD}.open', side_effect=IOError(errno.EACCES, 'Permission denied'))
    def test_init_io_error(self, _mocked_open):
        with self.assertRaises(OsHelperError) as ctx:
            self.helper.init()
        self.assertEqual(ctx.exception.errorcode, errno.EACCES)

    @patch(f'{MOD}.open', side_effect=ValueError('bad mode'))
    def test_init_generic_error(self, _mocked_open):
        with self.assertRaises(OsHelperError) as ctx:
            self.helper.init()
        self.assertEqual(ctx.exception.errorcode, errno.ENXIO)

    @patch(f'{MOD}.os.close')
    def test_close_releases_handles(self, os_close):
        self.helper.dev_fh = MagicMock()
        dev_fh = self.helper.dev_fh
        self.helper.dev_mem = 6
        self.helper.close()
        dev_fh.close.assert_called_once_with()
        os_close.assert_called_once_with(6)
        self.assertIsNone(self.helper.dev_fh)
        self.assertIsNone(self.helper.dev_mem)

    @patch(f'{MOD}.os.close')
    def test_close_without_handles(self, os_close):
        self.helper.dev_fh = None
        self.helper.dev_mem = None
        self.helper.close()
        os_close.assert_not_called()

    def test_compute_ioctlbase(self):
        self.helper._pack = PACK
        expected = (3 << 30) | (ord('C') << 8) | (struct.calcsize(PACK) << 16)
        self.assertEqual(self.helper.compute_ioctlbase(), expected)
        self.assertEqual(self.helper.compute_ioctlbase('D'),
                         (3 << 30) | (ord('D') << 8) | (struct.calcsize(PACK) << 16))

    @patch(f'{MOD}.os.path.exists', return_value=False)
    @patch(f'{MOD}.subprocess.call')
    def test_stop_closes_and_unloads(self, subprocess_call, _exists):
        self.helper.dev_fh = None
        self.helper.dev_mem = None
        self.helper.driver_loaded = False
        self.assertTrue(self.helper.stop())
        subprocess_call.assert_not_called()

    def test_get_helper_returns_instance(self):
        self.assertIsInstance(lh.get_helper(), lh.LinuxHelper)


class LinuxHelperIoctlTest(unittest.TestCase):

    def setUp(self):
        self.helper = new_helper()

    def test_ioctl_delegates_to_fcntl(self):
        with patch(f'{MOD}.fcntl') as mock_fcntl:
            mock_fcntl.ioctl.return_value = b'\x01'
            self.assertEqual(self.helper.ioctl(lh.IOCTL_RDIO, b'\x00'), b'\x01')
            mock_fcntl.ioctl.assert_called_once_with(self.helper.dev_fh,
                                                     self.helper._ioctl_base + lh.IOCTL_RDIO,
                                                     b'\x00')

    def test_mem_block_without_device(self):
        self.helper.dev_fh = None
        self.assertEqual(self.helper._LinuxHelper__mem_block(4), b'')

    def test_write_phys_mem_without_value(self):
        self.assertEqual(self.helper.write_phys_mem(0x1000, 4, None), 0)

    def test_write_phys_mem_without_device(self):
        self.helper.dev_fh = None
        self.assertEqual(self.helper.write_phys_mem(0x1000, 4, b'\x00'), 0)

    def test_va2pa_success(self):
        self.helper.ioctl = MagicMock(side_effect=[struct.pack(PACK, 0x1000),
                                                   struct.pack(f'4{PACK}', 39, 0, 0, 0)])
        self.assertEqual(self.helper.va2pa(0x7FFF0000), (0x1000, 0))

    def test_va2pa_above_max_physical_address(self):
        self.helper.ioctl = MagicMock(side_effect=[struct.pack(PACK, 1 << 40),
                                                   struct.pack(f'4{PACK}', 39, 0, 0, 0)])
        with patch(f'{MOD}.logger'):
            self.assertEqual(self.helper.va2pa(0x7FFF0000), (1 << 40, 1))

    def test_va2pa_ioctl_error(self):
        self.helper.ioctl = MagicMock(side_effect=IOError(errno.EIO, 'Input/output error'))
        with patch(f'{MOD}.logger'):
            self.assertEqual(self.helper.va2pa(0x7FFF0000), (None, errno.EIO))

    def test_read_pci_reg_error(self):
        self.helper.ioctl = MagicMock(side_effect=IOError(errno.EIO, 'Input/output error'))
        with patch(f'{MOD}.logger'):
            self.assertEqual(self.helper.read_pci_reg(0, 0, 0, 0, 4), 0)

    def test_write_pci_reg_error(self):
        self.helper.ioctl = MagicMock(side_effect=IOError(errno.EIO, 'Input/output error'))
        with patch(f'{MOD}.logger'):
            self.assertEqual(self.helper.write_pci_reg(0, 0, 0, 0, 0x1, 4), 0)

    def test_load_ucode_update_uses_invalid_array_typecode(self):
        self.helper.ioctl = MagicMock(return_value=b'')
        self.assertRaises(ValueError, self.helper.load_ucode_update, 0, b'\x55')

    def test_read_io_port_bad_response(self):
        self.helper.ioctl = MagicMock(return_value=b'\x00')
        with patch(f'{MOD}.logger'):
            self.assertEqual(self.helper.read_io_port(0xB8, 4), 0)

    def test_read_io_port_sizes(self):
        self.helper.ioctl = MagicMock(return_value=struct.pack(f'3{PACK}', 0, 0, 0x9A128086))
        self.assertEqual(self.helper.read_io_port(0xB8, 1), 0x86)
        self.assertEqual(self.helper.read_io_port(0xB8, 2), 0x8086)
        self.assertEqual(self.helper.read_io_port(0xB8, 4), 0x9A128086)

    def test_read_cr(self):
        self.helper.ioctl = MagicMock(return_value=struct.pack(f'3{PACK}', 0, 0, 0x80050033))
        with patch(f'{MOD}.os.sched_setaffinity'), patch(f'{MOD}.os.getpid', return_value=1):
            self.assertEqual(self.helper.read_cr(0, 0), 0x80050033)
        self.assertEqual(self.helper.ioctl.call_args[0][0], lh.IOCTL_RDCR)

    def test_write_cr(self):
        self.helper.ioctl = MagicMock(return_value=b'')
        with patch(f'{MOD}.os.sched_setaffinity'), patch(f'{MOD}.os.getpid', return_value=1):
            self.assertIsNone(self.helper.write_cr(0, 4, 0x20))
        self.assertEqual(self.helper.ioctl.call_args[0][0], lh.IOCTL_WRCR)
        self.assertEqual(self.helper.ioctl.call_args[0][1], struct.pack(f'3{PACK}', 0, 4, 0x20))

    def test_read_msr(self):
        self.helper.ioctl = MagicMock(return_value=struct.pack(f'4{PACK}', 0, 0, 0xDEAD, 0xBEEF))
        with patch(f'{MOD}.os.sched_setaffinity'), patch(f'{MOD}.os.getpid', return_value=1):
            self.assertEqual(self.helper.read_msr(0, 0x3A), (0xBEEF, 0xDEAD))

    def test_write_msr(self):
        self.helper.ioctl = MagicMock(return_value=b'')
        with patch(f'{MOD}.os.sched_setaffinity'), patch(f'{MOD}.os.getpid', return_value=1):
            self.assertIsNone(self.helper.write_msr(1, 0x3A, 0xAABB, 0xCCDD))
        self.assertEqual(self.helper.ioctl.call_args[0][1],
                         struct.pack(f'4{PACK}', 1, 0x3A, 0xCCDD, 0xAABB))

    def test_get_descriptor_table(self):
        self.helper.ioctl = MagicMock(return_value=struct.pack(f'5{PACK}', 0x67, 0x1, 0xFED00000, 0x2, 0xFEE00000))
        with patch(f'{MOD}.os.sched_setaffinity'), patch(f'{MOD}.os.getpid', return_value=1):
            limit, base, pa = self.helper.get_descriptor_table(0, 0)
        self.assertEqual(limit, 0x67)
        self.assertEqual(base, (1 << 32) + 0xFED00000)
        self.assertEqual(pa, (2 << 32) + 0xFEE00000)

    def test_msgbus_send_message_with_mdr(self):
        self.helper.ioctl = MagicMock(return_value=struct.pack(f'5{PACK}', 0, 0, 0, 0, 0x1234))
        self.assertEqual(self.helper.msgbus_send_message(0x1, 0x2, 0x3), 0x1234)
        self.assertEqual(self.helper.ioctl.call_args[0][1],
                         struct.pack(f'5{PACK}', lh.MSGBUS_MDR_IN_MASK | lh.MSGBUS_MDR_OUT_MASK, 0x1, 0x2, 0x3, 0))

    def test_hypercall(self):
        self.helper.ioctl = MagicMock(return_value=struct.pack(f'<11{PACK}', *([0x55] + [0] * 10)))
        self.assertEqual(self.helper.hypercall(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0), 0x55)

    def test_send_sw_smi(self):
        expected = tuple(range(7))
        self.helper.ioctl = MagicMock(return_value=struct.pack(f'7{PACK}', *expected))
        with patch(f'{MOD}.os.sched_setaffinity'), patch(f'{MOD}.os.getpid', return_value=1):
            self.assertEqual(self.helper.send_sw_smi(0, 0xDE, 1, 2, 3, 4, 5, 6), expected)

    def test_send_sw_smi_timed(self):
        expected = tuple(range(8))
        self.helper.ioctl = MagicMock(return_value=struct.pack(f'8{PACK}', *expected))
        with patch(f'{MOD}.os.sched_setaffinity'), patch(f'{MOD}.os.getpid', return_value=1):
            self.assertEqual(self.helper.send_sw_smi_timed(0, 0xDE, 1, 2, 3, 4, 5, 6), expected)

    def test_write_mmio_reg_packs_request(self):
        self.helper.ioctl = MagicMock(return_value=b'')
        self.helper.write_mmio_reg(0xFED00000, 4, 0x1234)
        self.assertEqual(self.helper.ioctl.call_args[0][0], lh.IOCTL_WRMMIO)
        self.assertEqual(self.helper.ioctl.call_args[0][1],
                         struct.pack(f'3{PACK}', 0xFED00000, 4, 0x1234))

    def test_enum_acpi_tables_unimplemented(self):
        self.assertRaises(UnimplementedAPIError, self.helper.enum_ACPI_tables)


class LinuxHelperAffinityAndInfoTest(unittest.TestCase):

    def setUp(self):
        self.helper = new_helper()

    @patch(f'{MOD}.os.sched_getaffinity', return_value={5})
    def test_get_affinity(self, _sched_getaffinity):
        self.assertEqual(self.helper.get_affinity(), 5)

    @patch(f'{MOD}.os.sched_getaffinity', side_effect=OSError)
    def test_get_affinity_failure(self, _sched_getaffinity):
        self.assertIsNone(self.helper.get_affinity())

    @patch(f'{MOD}.os.getpid', return_value=99)
    @patch(f'{MOD}.os.sched_setaffinity')
    def test_set_affinity(self, sched_setaffinity, _getpid):
        self.assertEqual(self.helper.set_affinity(2), 2)
        sched_setaffinity.assert_called_once_with(99, {2})

    @patch(f'{MOD}.os.sched_setaffinity', side_effect=OSError)
    def test_set_affinity_failure(self, _sched_setaffinity):
        self.assertIsNone(self.helper.set_affinity(2))

    @patch(f'{MOD}.get_tools_path', return_value='/opt/chipsec/tools')
    def test_get_tool_info_unknown_tool(self, _get_tools_path):
        name, path = self.helper.get_tool_info('unknown')
        self.assertIsNone(name)
        self.assertEqual(path, f'/opt/chipsec/tools/{self.helper.os_system.lower()}')

    @patch(f'{MOD}.get_tools_path', return_value='/opt/chipsec/tools')
    def test_get_tool_info_known_tool(self, _get_tools_path):
        with patch.dict(lh._tools, {'compression': 'TianoCompress'}, clear=False):
            name, _ = self.helper.get_tool_info('compression')
        self.assertEqual(name, 'TianoCompress')

    @patch('chipsec.library.file.read_file',
           return_value=b'ffffffff81000000 T start\nffffffff81234567 T page_is_ram\n')
    def test_get_page_is_ram(self, _read_file):
        self.assertEqual(self.helper.get_page_is_ram(), b'ffffffff81234567')

    @patch('chipsec.library.file.read_file', return_value=b'ffffffff81000000 T start\n')
    def test_get_page_is_ram_not_found(self, _read_file):
        self.assertIsNone(self.helper.get_page_is_ram())

    @patch('chipsec.library.file.read_file',
           return_value=b'ffffffff81000000 T start\nffffffff81999999 T phys_mem_access_prot\n')
    def test_get_phys_mem_access_prot(self, _read_file):
        self.assertEqual(self.helper.get_phys_mem_access_prot(), b'ffffffff81999999')

    @patch('chipsec.library.file.read_file', return_value=b'ffffffff81000000 T start\n')
    def test_get_phys_mem_access_prot_not_found(self, _read_file):
        self.assertIsNone(self.helper.get_phys_mem_access_prot())

    @patch(f'{MOD}.os.path.exists', side_effect=[False, True])
    def test_efi_supported_via_efivars(self, _exists):
        self.assertTrue(self.helper.EFI_supported())

    @patch(f'{MOD}.os.path.exists', side_effect=[False, False])
    def test_efi_not_supported(self, _exists):
        self.assertFalse(self.helper.EFI_supported())


class LinuxHelperEfiVariableTest(unittest.TestCase):

    def setUp(self):
        self.helper = new_helper()

    def test_kern_get_efi_variable_full(self):
        self.helper.ioctl = MagicMock(side_effect=efivar_ioctl([(4, 0, 0x7, b'\xde\xad\xbe\xef')]))
        off, buf, hdr, data, guid, attr = self.helper.kern_get_EFI_variable_full('TestVar', TEST_GUID)
        self.assertEqual((off, buf, hdr), (0, b'', 0))
        self.assertEqual(data, b'\xde\xad\xbe\xef')
        self.assertEqual(guid, TEST_GUID)
        self.assertEqual(attr, 0x7)

    def test_get_efi_variable_returns_data(self):
        self.helper.ioctl = MagicMock(side_effect=efivar_ioctl([(2, 0, 0x7, b'\x01\x02')]))
        self.assertEqual(self.helper.get_EFI_variable('TestVar', TEST_GUID), b'\x01\x02')

    def test_kern_get_efi_variable_full_retries_on_small_buffer(self):
        responses = [(8, 0x5, 0, b''), (8, 0, 0x7, b'\x01\x02\x03\x04\x05\x06\x07\x08')]
        self.helper.ioctl = MagicMock(side_effect=efivar_ioctl(responses))
        data = self.helper.kern_get_EFI_variable_full('TestVar', TEST_GUID)[3]
        self.assertEqual(self.helper.ioctl.call_count, 2)
        self.assertEqual(data, b'\x01\x02\x03\x04\x05\x06\x07\x08')

    def test_kern_get_efi_variable_full_retry_failure(self):
        first = efivar_ioctl([(8, 0x5, 0, b'')])
        calls = {'n': 0}

        def _ioctl(nr, buf, *args):
            calls['n'] += 1
            if calls['n'] == 1:
                return first(nr, buf, *args)
            raise IOError(errno.EIO, 'Input/output error')

        self.helper.ioctl = MagicMock(side_effect=_ioctl)
        with patch(f'{MOD}.logger'):
            result = self.helper.kern_get_EFI_variable_full('TestVar', TEST_GUID)
        self.assertEqual(result, (0, b'', 0, b'', TEST_GUID, 0))

    def test_kern_get_efi_variable_full_oversized_response(self):
        self.helper.ioctl = MagicMock(side_effect=efivar_ioctl([(0x1000, 0, 0x7, b'')]))
        with patch(f'{MOD}.logger'):
            result = self.helper.kern_get_EFI_variable_full('TestVar', TEST_GUID)
        self.assertEqual(result, (0, b'', 0, b'', TEST_GUID, 0))

    def test_kern_get_efi_variable_full_driver_error(self):
        self.helper.ioctl = MagicMock(side_effect=efivar_ioctl([(0, 14, 0, b'')]))
        with patch(f'{MOD}.logger'):
            result = self.helper.kern_get_EFI_variable_full('TestVar', TEST_GUID)
        self.assertEqual(result, (0, b'', 0, b'', '', 0))

    @patch(f'{MOD}.os.listdir', return_value=['Boot0001-12345678-1234-1234-1234-123456789ABC'])
    @patch(f'{MOD}.os.path.isdir', return_value=True)
    def test_kern_list_efi_variables(self, _isdir, _listdir):
        with patch.object(lh.LinuxHelper, 'kern_get_EFI_variable_full',
                          return_value=(0, b'', 0, b'\x01', TEST_GUID, 0x7)) as get_var:
            variables = self.helper.list_EFI_variables()
        self.assertEqual(list(variables.keys()), ['Boot0001'])
        self.assertEqual(variables['Boot0001'], [(0, b'', 0, b'\x01', TEST_GUID, 0x7)])
        get_var.assert_called_once_with('Boot0001', TEST_GUID)

    @patch(f'{MOD}.os.listdir', return_value=[])
    @patch(f'{MOD}.os.path.isdir', side_effect=[False, True])
    def test_kern_list_efi_variables_legacy_path(self, _isdir, listdir):
        self.assertEqual(self.helper.kern_list_EFI_variables(), {})
        listdir.assert_called_once_with('/sys/firmware/efi/vars')

    @patch(f'{MOD}.os.path.isdir', side_effect=[False, False])
    def test_kern_list_efi_variables_no_efivarfs(self, _isdir):
        self.assertIsNone(self.helper.kern_list_EFI_variables())

    @patch(f'{MOD}.os.path.isdir', side_effect=OSError('boom'))
    def test_kern_list_efi_variables_error(self, _isdir):
        with patch(f'{MOD}.logger'):
            self.assertIsNone(self.helper.kern_list_EFI_variables())

    @patch(f'{MOD}.os.system')
    def test_kern_set_efi_variable_success(self, os_system):
        self.helper.ioctl = MagicMock(side_effect=efivar_ioctl([(0, 0, 0, b'')]))
        self.assertEqual(self.helper.set_EFI_variable('TestVar', TEST_GUID, b'\x01\x02', 2), 0)
        os_system.assert_called_once_with(
            'umount /sys/firmware/efi/efivars; mount -t efivarfs efivarfs /sys/firmware/efi/efivars')

    @patch(f'{MOD}.os.system')
    def test_kern_set_efi_variable_accepts_str_value(self, _os_system):
        self.helper.ioctl = MagicMock(side_effect=efivar_ioctl([(0, 0, 0, b'')]))
        self.assertEqual(self.helper.kern_set_EFI_variable('TestVar', TEST_GUID, 'ab'), 0)
        sent = self.helper.ioctl.call_args[0][1]
        self.assertEqual(sent[-2:].tobytes(), b'ab')

    @patch(f'{MOD}.os.system')
    def test_kern_set_efi_variable_failure(self, os_system):
        self.helper.ioctl = MagicMock(side_effect=efivar_ioctl([(0, 26, 0, b'')]))
        with patch(f'{MOD}.logger'):
            self.assertEqual(self.helper.kern_set_EFI_variable('TestVar', TEST_GUID, b'\x01'), 26)
        os_system.assert_not_called()

    @patch(f'{MOD}.os.system')
    def test_delete_efi_variable(self, _os_system):
        self.helper.ioctl = MagicMock(side_effect=efivar_ioctl([(0, 0, 0, b'')]))
        self.assertEqual(self.helper.delete_EFI_variable('TestVar', TEST_GUID), 0)
        header_size = 60
        self.assertEqual(len(self.helper.ioctl.call_args[0][1]), header_size + len('TestVar'))


if __name__ == '__main__':
    unittest.main()
