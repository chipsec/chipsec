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
Platform specific UEFI functionality (parsing platform specific EFI NVRAM, capsules, etc.)
"""

from uuid import UUID
from typing import List
from chipsec.library.uefi.varstore import VARIABLE_STORE_FV_GUID


#
# List of supported types of EFI NVRAM format (platform/vendor specific)
#


class FWType:
    EFI_FW_TYPE_UEFI = 'uefi'
    EFI_FW_TYPE_UEFI_AUTH = 'uefi_auth'
#    EFI_FW_TYPE_WIN       = 'win'      # Windows 8 GetFirmwareEnvironmentVariable format
    EFI_FW_TYPE_VSS = 'vss'       # NVRAM using format with '$VSS' signature
    EFI_FW_TYPE_VSS_AUTH = 'vss_auth'  # NVRAM using format with '$VSS' signature with extra fields
    # See "A Tour Beyond BIOS Implementing UEFI Authenticated
    # Variables in SMM with EDKII"
    EFI_FW_TYPE_VSS2 = 'vss2'
    EFI_FW_TYPE_VSS2_AUTH = 'vss2_auth'
    EFI_FW_TYPE_VSS_APPLE = 'vss_apple'
    EFI_FW_TYPE_NVAR = 'nvar'      # 'NVAR' NVRAM format
    EFI_FW_TYPE_EVSA = 'evsa'      # 'EVSA' NVRAM format


fw_types: List[str] = []
for i in [t for t in dir(FWType) if not callable(getattr(FWType, t))]:
    if not i.startswith('__'):
        fw_types.append(getattr(FWType, i))


NVRAM_ATTR_RT = 1
NVRAM_ATTR_DESC_ASCII = 2
NVRAM_ATTR_GUID = 4
NVRAM_ATTR_DATA = 8
NVRAM_ATTR_EXTHDR = 0x10
NVRAM_ATTR_AUTHWR = 0x40
NVRAM_ATTR_HER = 0x20
NVRAM_ATTR_VLD = 0x80

#
# Known GUIDs of NVRAM stored in EFI firmware volumes, FS files etc. of various firmware implementations
#
ADDITIONAL_NV_STORE_GUID = UUID('00504624-8A59-4EEB-BD0F-6B36E96128E0')
NVAR_NVRAM_FS_FILE = UUID("CEF5B9A3-476D-497F-9FDC-E98143E0422C")

LENOVO_FS1_GUID = UUID("16B45DA2-7D70-4AEA-A58D-760E9ECB841D")
LENOVO_FS2_GUID = UUID("E360BDBA-C3CE-46BE-8F37-B231E5CB9F35")

EFI_PLATFORM_FS_GUIDS = [LENOVO_FS1_GUID, LENOVO_FS2_GUID]
EFI_NVRAM_GUIDS = [VARIABLE_STORE_FV_GUID, ADDITIONAL_NV_STORE_GUID, NVAR_NVRAM_FS_FILE]
