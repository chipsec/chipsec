# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2026, Intel Corporation
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


import hashlib
import json
import struct
import unittest
from uuid import UUID

from chipsec.library.uefi.dbx import find_missing_entries, parse_dbx_entries
from chipsec.library.uefi.dbx import parse_microsoft_dbx_json


SHA256_GUID = 'C1C41626-504C-4092-ACA9-41F936934328'
X509_GUID = 'A5C059A1-94E4-4AA7-87B5-AB155C2BF072'


def signature_list(guid, signatures):
    signature_size = 16 + len(signatures[0])
    list_size = struct.calcsize('<16sIII') + signature_size * len(signatures)
    header = struct.pack(
        '<16sIII', UUID(guid).bytes_le, list_size, 0, signature_size
    )
    signature_data = b''.join(
        b'\x00' * 16 + signature for signature in signatures
    )
    return header + signature_data


class TestDbx(unittest.TestCase):

    def test_parse_microsoft_dbx_json(self):
        sha256 = bytes(range(32))
        certificate = b'example DER certificate'
        document = {
            'images': {
                'x64': [
                    {
                        'authenticodeHash': sha256.hex(),
                        'hashType': 'SHA256',
                    }
                ],
                'ia32': [],
            },
            'certificates': [
                {'thumbprint': hashlib.sha1(certificate).hexdigest()}
            ],
        }

        entries = parse_microsoft_dbx_json(json.dumps(document), 'x64')

        self.assertEqual(
            entries,
            {
                'sha256': {sha256},
                'x509_sha1': {hashlib.sha1(certificate).digest()},
            },
        )

    def test_parse_dbx_signature_lists_and_compare(self):
        sha256 = bytes(range(32))
        certificate = b'\x30\x03\x01\x01\xff'
        dbx_data = (
            signature_list(SHA256_GUID, [sha256])
            + signature_list(X509_GUID, [certificate])
        )
        reference = {'sha256': {sha256}, 'x509_cert': {certificate}}

        entries = parse_dbx_entries(dbx_data)

        self.assertEqual(entries, reference)
        reference_fingerprints = {
            'sha256': {sha256},
            'x509_sha1': {hashlib.sha1(certificate).digest()},
        }
        self.assertEqual(
            find_missing_entries(reference_fingerprints, entries), {}
        )

    def test_compare_reports_missing_entries_by_type(self):
        reference = {'sha256': {b'hash'}, 'x509_sha1': {b'fingerprint'}}
        dbx = {'sha256': {b'hash'}, 'x509_cert': set()}

        self.assertEqual(
            find_missing_entries(reference, dbx),
            {'x509_sha1': {b'fingerprint'}},
        )

    def test_rejects_invalid_microsoft_json(self):
        with self.assertRaisesRegex(
            ValueError, 'Invalid Microsoft DBX JSON'
        ):
            parse_microsoft_dbx_json('not JSON', 'x64')

    def test_rejects_missing_architecture(self):
        document = {'images': {'x64': []}, 'certificates': []}
        with self.assertRaisesRegex(ValueError, 'no image list for ia32'):
            parse_microsoft_dbx_json(json.dumps(document), 'ia32')

    def test_rejects_truncated_signature_list(self):
        with self.assertRaisesRegex(
            ValueError, 'Truncated EFI_SIGNATURE_LIST header'
        ):
            parse_dbx_entries(b'bad')


if __name__ == '__main__':
    unittest.main()
