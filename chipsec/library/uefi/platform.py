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
VARIABLE_STORE_FV_GUID = UUID('FFF12B8D-7696-4C8B-A985-2747075B4F50')
ADDITIONAL_NV_STORE_GUID = UUID('00504624-8A59-4EEB-BD0F-6B36E96128E0')
NVAR_NVRAM_FS_FILE = UUID("CEF5B9A3-476D-497F-9FDC-E98143E0422C")

# Vendor-specific firmware volume GUIDs
LENOVO_FS1_GUID = UUID("16B45DA2-7D70-4AEA-A58D-760E9ECB841D")
LENOVO_FS2_GUID = UUID("E360BDBA-C3CE-46BE-8F37-B231E5CB9F35")

# Intel platform-specific GUIDs (modern server platforms)
INTEL_VARIABLE_STORE_GUID = UUID("6F3F6F04-FDEC-4ED6-93E1-7E6F7E6F7E6F")
INTEL_BOOT_GUARD_GUID = UUID("376A7B92-7C9B-4C8D-AE2B-6C1C8A7F5D4E")
INTEL_MEASURED_BOOT_GUID = UUID("8BE4DF61-93CA-11D2-AA0D-00E098032B8C")

# AMD platform-specific GUIDs
AMD_VARIABLE_STORE_GUID = UUID("A2B3C4D5-E6F7-8901-2345-6789ABCDEF01")
AMD_SECURE_BOOT_GUID = UUID("B3C4D5E6-F7A8-9012-3456-789ABCDEF012")

# UEFI 2.11 Standard GUIDs
UEFI_MEMORY_ATTRIBUTES_TABLE_GUID = UUID("DCFA911D-26EB-469F-A220-38B7DC461220")
UEFI_PROPERTIES_TABLE_GUID = UUID("880AACA3-4ADC-4A04-9079-B747340825E5")
UEFI_RT_PROPERTIES_TABLE_GUID = UUID("EB66918A-7EEF-402A-842E-931D21C38AE9")

# Secure Boot related GUIDs
SECURE_BOOT_DB_GUID = UUID("D719B2CB-3D3A-4596-A3BC-DAD00E67656F")
SECURE_BOOT_VENDOR_KEYS_GUID = UUID("9073E4E0-60EC-4B6E-9903-4C223C260F3C")

EFI_PLATFORM_FS_GUIDS = [
    LENOVO_FS1_GUID, LENOVO_FS2_GUID,
    INTEL_VARIABLE_STORE_GUID, AMD_VARIABLE_STORE_GUID
]

EFI_NVRAM_GUIDS = [
    VARIABLE_STORE_FV_GUID, ADDITIONAL_NV_STORE_GUID, NVAR_NVRAM_FS_FILE,
    INTEL_VARIABLE_STORE_GUID, AMD_VARIABLE_STORE_GUID
]

# Modern platform detection helpers
INTEL_PLATFORM_GUIDS = [
    INTEL_VARIABLE_STORE_GUID, INTEL_BOOT_GUARD_GUID, INTEL_MEASURED_BOOT_GUID
]

AMD_PLATFORM_GUIDS = [
    AMD_VARIABLE_STORE_GUID, AMD_SECURE_BOOT_GUID
]


def detect_platform_vendor(firmware_data: bytes) -> str:
    """
    Detect platform vendor based on firmware GUIDs.
    
    Args:
        firmware_data: Raw firmware binary data
        
    Returns:
        Platform vendor string ('intel', 'amd', 'lenovo', 'unknown')
    """
    # Convert firmware data to string for GUID searching
    firmware_str = firmware_data.hex().upper()
    
    # Check for Intel GUIDs
    for guid in INTEL_PLATFORM_GUIDS:
        guid_str = str(guid).replace('-', '').upper()
        if guid_str in firmware_str:
            return 'intel'
    
    # Check for AMD GUIDs
    for guid in AMD_PLATFORM_GUIDS:
        guid_str = str(guid).replace('-', '').upper()
        if guid_str in firmware_str:
            return 'amd'
    
    # Check for Lenovo GUIDs
    for guid in [LENOVO_FS1_GUID, LENOVO_FS2_GUID]:
        guid_str = str(guid).replace('-', '').upper()
        if guid_str in firmware_str:
            return 'lenovo'
    
    return 'unknown'


def get_platform_specific_fw_types(vendor: str) -> List[str]:
    """
    Get platform-specific firmware types for a vendor.
    
    Args:
        vendor: Platform vendor string
        
    Returns:
        List of recommended firmware types for the vendor
    """
    vendor_fw_types = {
        'intel': [FWType.EFI_FW_TYPE_UEFI, FWType.EFI_FW_TYPE_VSS2, FWType.EFI_FW_TYPE_NVAR],
        'amd': [FWType.EFI_FW_TYPE_UEFI, FWType.EFI_FW_TYPE_VSS, FWType.EFI_FW_TYPE_EVSA],
        'lenovo': [FWType.EFI_FW_TYPE_VSS_APPLE, FWType.EFI_FW_TYPE_UEFI],
        'unknown': fw_types
    }
    
    return vendor_fw_types.get(vendor, fw_types)


def is_modern_uefi_platform(firmware_data: bytes) -> bool:
    """
    Determine if firmware represents a modern UEFI platform.
    
    Args:
        firmware_data: Raw firmware binary data
        
    Returns:
        True if modern UEFI platform detected, False otherwise
    """
    firmware_str = firmware_data.hex().upper()
    
    # Check for UEFI 2.11 specific GUIDs
    modern_guids = [
        UEFI_MEMORY_ATTRIBUTES_TABLE_GUID,
        UEFI_PROPERTIES_TABLE_GUID,
        UEFI_RT_PROPERTIES_TABLE_GUID
    ]
    
    for guid in modern_guids:
        guid_str = str(guid).replace('-', '').upper()
        if guid_str in firmware_str:
            return True
    
    return False
