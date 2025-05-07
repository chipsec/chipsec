# CHIPSEC: Platform Security Assessment Framework
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

import unittest
import tempfile
import os

import chipsec.library.uefi.varstore as varstore
from typing import Dict, List, Tuple

class TestVarStore(unittest.TestCase):
    """Test the ACPI Table Structures and Parsing."""

    def test_get_nvar_name_ascii(self):
        input_bytes = b'\x00\x00\x00\x00test\x00'
        name, name_size = varstore.get_nvar_name(input_bytes, 4, True)
        self.assertEqual(name, "test")
        self.assertEqual(name_size, 5)

    def test_get_nvar_name_utf(self):
        input_bytes = b'\x11\x00\x22\x00t\x00e\x00s\x00t\x00\x00\x00'
        name, name_size = varstore.get_nvar_name(input_bytes, 4, False)
        self.assertEqual(name, "test")
        self.assertEqual(name_size, 6)

    def test_run_placeholder_functions(self):
        varstore.parse_sha256(None)
        varstore.parse_rsa2048(None)
        varstore.parse_rsa2048_sha256(None)
        varstore.parse_sha1(None)
        varstore.parse_rsa2048_sha1(None)
        varstore.parse_x509(None)
        varstore.parse_sha224(None)
        varstore.parse_sha384(None)
        varstore.parse_sha512(None)
        varstore.parse_x509_sha256(None)
        varstore.parse_x509_sha384(None)
        varstore.parse_x509_sha512(None)
        varstore.parse_pkcs7(None)

    def test_parse_sb_db(self):
        input_bytes = b'\xa1Y\xc0\xa5\xe4\x94\xa7J\x87\xb5\xab\x15\\+\xf0r\x05\x05\x00\x00\x00\x00\x00\x00\xe9\x04\x00\x00QH\xdc&_\x19\xe1J\x9a\x19\xfb\xf8\x83\xbb\xb3^0\x82\x04\xd50\x82\x02\xbd\xa0\x03\x02\x01\x02\x02\x02\x10h0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x0b\x05\x000\x81\x801\x0b0\t\x06\x03U\x04\x06\x13\x02US1\x100\x0e\x06\x03U\x04\x08\x13\x07Arizona1\x110\x0f\x06\x03U\x04\x07\x13\x08Chandler1\x1a0\x18\x06\x03U\x04\n\x13\x11Intel Corporation1\r0\x0b\x06\x03U\x04\x0b\x13\x04EDSS1!0\x1f\x06\x03U\x04\x03\x13\x18azsdssprd04.ch.intel.com0\x1e\x17\r190607170720Z\x17\r290604170720Z0]1\x0b0\t\x06\x03U\x04\x06\x13\x02US1\x0b0\t\x06\x03U\x04\x08\x13\x02CA1\x140\x12\x06\x03U\x04\x07\x13\x0bSanta Clara1\x1a0\x18\x06\x03U\x04\n\x13\x11Intel Corporation1\x0f0\r\x06\x03U\x04\x03\x13\x06SBoot10\x82\x01"0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00\x03\x82\x01\x0f\x000\x82\x01\n\x02\x82\x01\x01\x00\xc1\x80a\xa8\xe7\x8a\n\x84\xab\x1f\x18\xf2c\x9d\xb4\xb4\xb2\xd0\x8e\xf9Kc\x81\xb0?\x81\xa9\xfdD\x1cNie\x93c\xa7y%\xc6W\x89\xd8W\xbcZ:}R~\xa9\xe8}\xb0y}\x19}\xe2M\xa7\xcd\x11q\xd1\x19M\xab\x0e\x86\xd0G\xe9\xc4h\xd2\xb7\xb4c\x9a{9\x0e8\xe0\x9a?\xa4N\x83:x\xdb\xc6\x0f\xbc\xa8?S\xcb\xb2\xd1X\xb27+\xfbm\xb6\xb8\xc0\xda!z(,mY\x98{\xabwB\t6y\x99\xd9w\x8e\x8b\xb3\xa9\xff\xfb\x0fk\xbd\xe0\x1d\x0e\xd0\xea\x040"\x97\xa6\x1fl\x01\x8d\x10\x88\xc7\xca\x9c% \xf3\xae&\x8f\x18\x82\x17\x05\xe9\x13\xeb,\x91+q\xadkc\x83t\x82\x99o~\x11\xbb\xfd\x8asn\x02.\xcai\xd5 \n\xcb\x9eI\t\xfct\xa7\xc3\x8d\xc8:\xe9\x85\xd5\xf1\xcb\xb9\x02P\xcf[\xe1=\x99e\xa3\xe0\xddi\x8b\xf8\x9a(P\xa3@L\x8c\xban\x8a\x84\x8f\x9d!P\xab\xcf\xf5\xaeV\x815\xe3\xfe\xff\x8f\xc8\x1b\xdfE\x02\x03\x01\x00\x01\xa3{0y0\t\x06\x03U\x1d\x13\x04\x020\x000,\x06\t`\x86H\x01\x86\xf8B\x01\r\x04\x1f\x16\x1dOpenSSL Generated Certificate0\x1d\x06\x03U\x1d\x0e\x04\x16\x04\x14\xa7\x87\x8c)g\xcdY]r\x8d\x03\x05\rb\xea\x89\xa0\x06\x1dO0\x1f\x06\x03U\x1d#\x04\x180\x16\x80\x14\xf1\xf2\xbf)\xcd\x0c*M\x1bh\xd1\xb6&\\\xafN\x17{XL0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x0b\x05\x00\x03\x82\x02\x01\x00\x15\xff\x12\x9dE\x07\xd1;\xe5\xa4N\xdf\xb0\x8f}^\x1b\xa6\xdd5\xb1\xbdSl\x11\xe1\x08H\xbe\xc7\x04\x9cO\x90Z\x98bj\xf7`\xc9i\xfdq\x8e\'\xd7V\xe0!\x94\xdf\xb7`nJ\xc03\xf0I\xcfU\xf7\xbf\x96\n\xdf\xc0\xa6\xf9X_B\r!t5\x85\xe8\x1f\x19"\xc1:j\xab\xe9\x12\x82G\x17e\xefg\x92j\xca\xf1\xb4\xe7HBl\x0b\xec\xd2\xbcyt\xafS#\xd0z\xf8\xbd\xd1\x8d\x964\x05<\xd6\xea5\xf2\xf5\xf7+\x05\x1f\xb7\xe6\xba\x1e\x07\x81\x19\xe2\xa8\xcb\x1a\xe2\x0f\xe8\x8fj\xce\x00Q\xca\xd0\xbej\xc8\r{\x8b\xf0\xaa\xb1\xd4\xca\xb5\x89^\xeb\xc9\xf3\xf1+\x8c\xcb\x80\xf7\xe1\xf55#!\xf9\xe9\x898\x83\x95Ka\xfb\xec\xaf\xd7?\xab\xda\xdbsz1xz^\x96,\xf4\xae\x150\xf4\xe4\xf2\x9e\xcdH\x9a\t\xe8d\xf7G\x84\xa8\xe3\xc2\x97\xbaO\xf3pF^\xb1\xf4-\xe2\x00\x02\xb9\xb7\xca\x7f\xfd\xd2\x8eY\xb8\x95\xaa\x7f\xd3\x1a\xb6\xf2L\xca\x9d\xbc*5\xfc\xe1\xe0\x07\xcf\x10U\x13j\x87\xd2=\x05\xc9\x0e\xbf\x18<D\x8a[\xbd\'\x1a~\x0fQ\xd4\xe3\n\nH\r~\xfd\x80k\xfe\xf3\xe9\xd5j<\xd0\xfc>\xd9\xad\xe6is\xca0\x06\x8c\xf6\xc8\xa9}\x1c9P\xc2\x1c\xe8U\xc1P\xacC@o\x9dw\x9c[\x18aT\xb9\\\xec\x81o\xcd3\x07CV\x89\xe4\x1f\xabvJ\x93\x91\xa2\xb3B\x0b>r\xb4\x12\xd7dv\'r!\x08G\x8c\xdb\xbb\xedpF\x1f\x84\xe0\xf7\xbccm3\x10&\xd8\xe8\x9b+`\xb4\xa0\x82\x8c~}\xab\xe4\xbd#Y-\xf5~\xeeV\xc4[r\xcb\t\xee\x8c\xde\xd8,-\t\xdc\xc0\x86\x8b\xd2\xee2\xe8\xd4\x89E\x81\x90\x8b\xca\xbd2\x82Z^Wh\xa0\x9b\x04M\xa7m_\x81\x96\xfcL\xb4\xf3\n\x92-\x92\xde\xb9\x07\xf3\x95\xa2\xef\t\x93)z;\xd4\xbf>z@%?p\xf2G\xe1Q\xbb\xf1+\x01\xc1`I.\xd2\xebIZ-\xe6\r\x81dJ<X\xd9b\x97s\x84\xe8\xb2\xee'
        
        with tempfile.TemporaryDirectory() as temp_dir:
            result = varstore.parse_sb_db(input_bytes, temp_dir)
    
        self.assertNotEqual(result, [])
        self.assertIsInstance(result[0], bytes)

    def test_parse_sb_db_invalid_input(self):
        input_bytes = b'test'
        
        with tempfile.TemporaryDirectory() as temp_dir:
            result = varstore.parse_sb_db(input_bytes, temp_dir)
    
        self.assertEqual(result, [])

    def test_parse_auth_var(self):
        pass

    def test_parse_esal_var(self):
        pass

    def test_parse_efivar_file_sb_db(self):
        input_bytes = b'\xa1Y\xc0\xa5\xe4\x94\xa7J\x87\xb5\xab\x15\\+\xf0r\x05\x05\x00\x00\x00\x00\x00\x00\xe9\x04\x00\x00QH\xdc&_\x19\xe1J\x9a\x19\xfb\xf8\x83\xbb\xb3^0\x82\x04\xd50\x82\x02\xbd\xa0\x03\x02\x01\x02'
        
        with tempfile.TemporaryDirectory() as temp_dir:
            start_file_count = len(os.listdir(temp_dir))
            filename = os.path.join(temp_dir, 'test_file')
            varstore.parse_efivar_file(filename, input_bytes)
            end_file_count = len(os.listdir(temp_dir))
        
        self.assertGreater(end_file_count, start_file_count)

    def test_getNVstore_EFI_invalid(self):
        input_bytes = b'\x00\x00\x00\x00test\x00'
        NVstore_EFI = varstore.getNVstore_EFI(input_bytes)

        self.assertEqual(NVstore_EFI, (-1, -1, None))

    def test_getNVstore_EFI_AUTH(self):
        input_bytes = b'\x00\x00\x00\x00test\x00'
        NVstore_EFI = varstore.getNVstore_EFI_AUTH(input_bytes)

        self.assertEqual(NVstore_EFI, (-1, -1, None))

    def test_getEFIvariables_UEFI_invalid(self):
        input_bytes = b'\x00\x00\x00\x00test\x00'
        EFIvariables_UEFI = varstore.getEFIvariables_UEFI(input_bytes)

        self.assertIsInstance(EFIvariables_UEFI, dict)

    def test_getEFIvariables_UEFI_AUTH_invalid(self):
        input_bytes = b'\x00\x00\x00\x00test\x00'
        EFIvariables_UEFI_AUTH = varstore.getEFIvariables_UEFI_AUTH(input_bytes)

        self.assertIsInstance(EFIvariables_UEFI_AUTH, dict)
        self.assertEqual(len(EFIvariables_UEFI_AUTH), 0)

    def test_getNVstore_NVAR_invalid(self):
        input_bytes = b'\x00\x00\x00\x00test\x00'
        NVstore_NVAR = varstore.getNVstore_NVAR(input_bytes)

        self.assertEqual(NVstore_NVAR, (-1, -1, None))

    def test_ord(self):
        test_char = 'a'
        test_int = 5
        ord_value = varstore._ord(test_char)
        
        self.assertEqual(ord_value, ord(test_char))
        self.assertEqual(varstore._ord(test_int), test_int)

    def test_getEFIvariables_NVAR_invalid(self):
        input_bytes = b'\x00\x00\x00\x00test\x00'
        EFIvariables_NVAR = varstore.getEFIvariables_NVAR(input_bytes)

        self.assertIsInstance(EFIvariables_NVAR, dict)
        self.assertEqual(len(EFIvariables_NVAR), 0)

    def test_getNVstore_NVAR_simple(self):
        input_bytes = b'\x00\x00\x00\x00NVAR\x00'
        NVstore_NVAR = varstore.getNVstore_NVAR_simple(input_bytes)

        self.assertEqual(NVstore_NVAR, (4, -1, None))

    def test_getEFIvariables_NVAR_simple(self):
        input_bytes = b'\x00\x00\x00\x00NVAR\x10\x00\x03\x04\x05\x06\x07TEST\x00\x00'
        EFIvariables_NVAR = varstore.getEFIvariables_NVAR_simple(input_bytes)

        self.assertIsInstance(EFIvariables_NVAR, dict)
        self.assertTrue('TEST' in EFIvariables_NVAR)
        self.assertEqual(len(EFIvariables_NVAR), 1)

    def test__getNVstore_VSS(self):
        input_bytes = b'\x00\x00\x00\x176\xcf\xddu2dA\x98\xb6\xfe\x85p\x7f\xfe}\xaa\x55\x01\x02\x03\x04\x05\x06\x08\x00\x00\x00\x01\x00\x00\x00\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1fT\x00E\x00S\x00T\x00\x00'
        NVstore_VSS = varstore._getNVstore_VSS(input_bytes, 'vss2')

        self.assertEqual(NVstore_VSS[0:2], (3, 33641898))