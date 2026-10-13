# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2021, Intel Corporation
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


"""
Helpers for comparing a live UEFI ``dbx`` variable with Microsoft's Secure Boot
DBX reference JSON.

Before running the utility, download ``dbx_info_msft_latest.json`` from the
`Microsoft secureboot_objects repository <https://github.com/microsoft/secureboot_objects/blob/main/PreSignedObjects/DBX/dbx_info_msft_latest.json>`_.
CHIPSEC reads this local file and does not connect to the repository.

Usage::

    chipsec_util uefi dbx-check <architecture> <microsoft_dbx_json>

Example::

    chipsec_util uefi dbx-check x64 dbx_info_msft_latest.json

Supported architecture values are ``x64``, ``ia32``, ``aarch64``, and ``arm``.
The comparison checks image Authenticode SHA-256 hashes and certificate
thumbprints against live ``dbx`` entries. It does not inspect the active
bootloader or evaluate SVN records; a match only confirms the supplied JSON
snapshot.
"""

import hashlib
import json
import struct
from typing import Dict, Set

from chipsec.library.uefi.common import EFI_GUID_STR


SIGNATURE_LIST = '<16sIII'
SIGNATURE_LIST_SIZE = struct.calcsize(SIGNATURE_LIST)
EFI_GUID_SIZE = 16
EFI_CERT_SHA256_GUID = 'C1C41626-504C-4092-ACA9-41F936934328'
EFI_CERT_X509_GUID = 'A5C059A1-94E4-4AA7-87B5-AB155C2BF072'
DBX_ARCHITECTURES = ('x64', 'ia32', 'aarch64', 'arm')


def parse_microsoft_dbx_json(
    text: str, architecture: str
) -> Dict[str, Set[bytes]]:
    """Parse Microsoft's dbx_info JSON for one architecture."""
    if architecture not in DBX_ARCHITECTURES:
        raise ValueError(f'Unsupported architecture: {architecture}')
    try:
        data = json.loads(text)
    except json.JSONDecodeError as error:
        raise ValueError(f'Invalid Microsoft DBX JSON: {error}') from error

    images = data.get('images') if isinstance(data, dict) else None
    if (
        not isinstance(images, dict)
        or not isinstance(images.get(architecture), list)
    ):
        raise ValueError(
            f'Microsoft DBX JSON has no image list for {architecture}'
        )

    entries: Dict[str, Set[bytes]] = {'sha256': set(), 'x509_sha1': set()}
    for index, image in enumerate(images[architecture], 1):
        if not isinstance(image, dict) or image.get('hashType') != 'SHA256':
            raise ValueError(
                f'Invalid or unsupported image record {index} '
                f'for {architecture}'
            )
        try:
            image_hash = bytes.fromhex(image['authenticodeHash'])
        except ValueError as error:
            raise ValueError(
                f'Invalid SHA-256 hash in {architecture} image record {index}'
            ) from error
        except (KeyError, TypeError) as error:
            raise ValueError(
                f'Missing SHA-256 hash in {architecture} image record {index}'
            ) from error
        if len(image_hash) != 32:
            raise ValueError(
                f'SHA-256 hash in {architecture} image record {index} '
                'must be 32 bytes'
            )
        entries['sha256'].add(image_hash)

    certificates = data.get('certificates')
    if not isinstance(certificates, list):
        raise ValueError('Microsoft DBX JSON has no certificate list')
    for index, certificate in enumerate(certificates, 1):
        if not isinstance(certificate, dict):
            raise ValueError(f'Invalid certificate record {index}')
        try:
            thumbprint = bytes.fromhex(certificate['thumbprint'])
        except ValueError as error:
            raise ValueError(
                f'Invalid SHA-1 thumbprint in certificate record {index}'
            ) from error
        except (KeyError, TypeError) as error:
            raise ValueError(
                f'Missing SHA-1 thumbprint in certificate record {index}'
            ) from error
        if len(thumbprint) != 20:
            raise ValueError(
                f'SHA-1 thumbprint in certificate record {index} '
                'must be 20 bytes'
            )
        entries['x509_sha1'].add(thumbprint)

    if not any(entries.values()):
        raise ValueError('Microsoft DBX JSON contains no supported entries')
    return entries


def parse_dbx_entries(dbx: bytes) -> Dict[str, Set[bytes]]:
    """Extract SHA-256 and X.509 signatures from a UEFI signature database."""
    entries: Dict[str, Set[bytes]] = {'sha256': set(), 'x509_cert': set()}
    offset = 0
    while offset < len(dbx):
        remaining = len(dbx) - offset
        if remaining < SIGNATURE_LIST_SIZE:
            if not any(dbx[offset:]):
                break
            raise ValueError(
                f'Truncated EFI_SIGNATURE_LIST header at offset 0x{offset:X}'
            )
        if not any(dbx[offset:offset + SIGNATURE_LIST_SIZE]):
            break

        signature_header = struct.unpack_from(SIGNATURE_LIST, dbx, offset)
        type_bytes, list_size, header_size, signature_size = signature_header
        if list_size < SIGNATURE_LIST_SIZE or list_size > remaining:
            raise ValueError(
                f'Invalid EFI_SIGNATURE_LIST size at offset 0x{offset:X}'
            )
        if header_size > list_size - SIGNATURE_LIST_SIZE:
            raise ValueError(
                'Invalid EFI_SIGNATURE_LIST header size at '
                f'offset 0x{offset:X}'
            )
        if signature_size <= EFI_GUID_SIZE:
            raise ValueError(
                f'Invalid EFI_SIGNATURE_DATA size at offset 0x{offset:X}'
            )

        data_offset = offset + SIGNATURE_LIST_SIZE + header_size
        signature_end = offset + list_size
        signature_data_size = signature_end - data_offset
        if signature_data_size % signature_size:
            raise ValueError(
                f'Misaligned EFI_SIGNATURE_DATA at offset 0x{offset:X}'
            )

        signature_type = EFI_GUID_STR(type_bytes).upper()
        if signature_type in (EFI_CERT_SHA256_GUID, EFI_CERT_X509_GUID):
            kind = (
                'sha256'
                if signature_type == EFI_CERT_SHA256_GUID
                else 'x509_cert'
            )
            for entry_offset in range(
                data_offset, signature_end, signature_size
            ):
                signature = dbx[
                    entry_offset + EFI_GUID_SIZE:entry_offset + signature_size
                ]
                if kind == 'sha256' and len(signature) != 32:
                    raise ValueError(
                        'Invalid SHA-256 signature size at '
                        f'offset 0x{entry_offset:X}'
                    )
                entries[kind].add(signature)

        offset += list_size

    return entries


def find_missing_entries(
    reference: Dict[str, Set[bytes]], dbx: Dict[str, Set[bytes]]
) -> Dict[str, Set[bytes]]:
    """Return reference entries that are absent from dbx, grouped by type."""
    dbx_entries = dict(dbx)
    dbx_entries['x509_sha1'] = {
        hashlib.sha1(certificate).digest()
        for certificate in dbx.get('x509_cert', set())
    }
    missing = {}
    for kind, expected in reference.items():
        missing[kind] = expected - dbx_entries.get(kind, set())
    return {kind: values for kind, values in missing.items() if values}
