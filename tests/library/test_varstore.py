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

import chipsec.library.uefi.varstore as varstore

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
