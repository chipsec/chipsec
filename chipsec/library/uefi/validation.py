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

"""
UEFI-specific validation utilities that extend core file validation.
"""

import os
from typing import Optional, List

from chipsec.library.logger import logger
from chipsec.library.file import validate_file_exists, validate_file_size, validate_directory_path, validate_guid
from chipsec.library.uefi.config import UEFIConfig, UEFIValidationConfig, UEFIErrorConfig
from chipsec.library.uefi.platform import fw_types


class UEFIInputValidator:
    """UEFI-specific validation using core validation functions."""
    
    def __init__(self, error_mode: str = UEFIErrorConfig.DEFAULT_MODE):
        """Initialize validator with specified error handling mode."""
        self.error_mode = error_mode
        self.config = UEFIValidationConfig()
        self.uefi_config = UEFIConfig()
    
    def validate_uefi_file(self, filepath: str) -> bool:
        """
        Validate UEFI firmware file with UEFI-specific checks.
        
        Args:
            filepath: Path to UEFI firmware file
            
        Returns:
            True if file is valid, False otherwise
        """
        # Use core validation functions
        if not validate_file_exists(filepath, "UEFI firmware file"):
            return False
            
        return validate_file_size(filepath, self.uefi_config.MAX_FILE_SIZE)
    
    def validate_uefi_directory(self, dirpath: str, create_if_missing: bool = False) -> bool:
        """
        Validate UEFI output directory.
        
        Args:
            dirpath: Directory path to validate
            create_if_missing: Create directory if it doesn't exist
            
        Returns:
            True if directory is valid, False otherwise
        """
        return validate_directory_path(dirpath, create_if_missing)
    
    def validate_uefi_guid(self, guid_str: str) -> bool:
        """
        Validate UEFI GUID format.
        
        Args:
            guid_str: GUID string to validate
            
        Returns:
            True if GUID is valid, False otherwise
        """
        return validate_guid(guid_str)
    
    def validate_firmware_type(self, fwtype: Optional[str]) -> bool:
        """
        Validate firmware type against known types.
        
        Args:
            fwtype: Firmware type string to validate
            
        Returns:
            True if firmware type is valid, False otherwise
        """
        if fwtype is None:
            return True  # None is acceptable (auto-detect)
            
        if fwtype not in fw_types:
            logger().log_error(f"Unknown firmware type: {fwtype}. Valid types: {fw_types}")
            return False
            
        return True
    
    def validate_filetype_codes(self, ftypes: List[int]) -> List[int]:
        """
        Validate that filetype codes are within valid ranges.
        
        Args:
            ftypes: List of filetype codes to validate
            
        Returns:
            List of validated filetype codes
        """
        if not ftypes:
            return ftypes
            
        valid_codes = []
        for ftype in ftypes:
            if isinstance(ftype, int) and 0 <= ftype <= 255:
                valid_codes.append(ftype)
            else:
                logger().log_warning(f"Invalid filetype code: {ftype} (must be integer 0-255)")
                
        return valid_codes


def create_uefi_validator(error_mode: str = UEFIErrorConfig.DEFAULT_MODE) -> UEFIInputValidator:
    """
    Create a UEFI input validator with specified error handling mode.
    
    Args:
        error_mode: Error handling mode ('strict', 'permissive', 'silent')
        
    Returns:
        Configured UEFIInputValidator instance
    """
    return UEFIInputValidator(error_mode)
