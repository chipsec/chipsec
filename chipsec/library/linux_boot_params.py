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

"""
Read the EFI System Table address from the x86 boot parameters ("zero page")
that the Linux kernel exposes in sysfs.
"""

import struct
from typing import Optional

from chipsec.library.logger import logger

BOOT_PARAMS_PATH = '/sys/kernel/boot_params/data'

# struct efi_info inside struct boot_params (Documentation/arch/x86/zero-page.rst):
#   efi_loader_signature, efi_systab, efi_memdesc_size, efi_memdesc_version,
#   efi_memmap, efi_memmap_size, efi_systab_hi, efi_memmap_hi
EFI_INFO_OFFSET = 0x1C0
EFI_INFO_FMT = '<4s7I'
EFI_INFO_SIZE = struct.calcsize(EFI_INFO_FMT)

# Only 64-bit firmware is supported; a 32-bit System Table does not match
# the layout CHIPSEC decodes.
EFI64_LOADER_SIGNATURE = b'EL64'


def get_efi_system_table_address(path: str = BOOT_PARAMS_PATH) -> Optional[int]:
    """Return the physical address of the EFI System Table, or None if unavailable."""
    try:
        with open(path, 'rb') as boot_params:
            boot_params.seek(EFI_INFO_OFFSET)
            efi_info = boot_params.read(EFI_INFO_SIZE)
    except OSError as err:
        logger().log_debug(f'[helper] Unable to read {path}: {err}')
        return None
    if len(efi_info) < EFI_INFO_SIZE:
        return None

    (signature, systab_lo, _, _, _, _, systab_hi, _) = struct.unpack(EFI_INFO_FMT, efi_info)
    if signature != EFI64_LOADER_SIGNATURE:
        logger().log_debug(f'[helper] boot_params EFI loader signature is {signature!r}; not a 64-bit EFI boot')
        return None
    return ((systab_hi << 32) | systab_lo) or None
