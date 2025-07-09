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
Configuration constants and settings for UEFI operations.
"""


class UEFIConfig:
    """Configuration constants for UEFI operations."""
    
    # File extensions
    UEFI_LOG_EXT = '.UEFI.lst'
    NVRAM_LOG_EXT = '.nv.lst'
    NVRAM_EXT = '.nvram.lst'
    DIRECTORY_EXT = '.dir'
    JSON_EXT = '.UEFI.json'
    
    # Directory names
    FV_DIR_NAME = 'FV'
    VARIABLES_DIR_NAME = 'efi_variables.dir'
    VARIABLES_LOG_NAME = 'efi_variables.lst'
    
    # File naming patterns
    NVRAM_FILE_PATTERN = 'nvram_{fwtype}'
    
    # Supported hash algorithms
    HASH_ALGORITHMS = ['md5', 'sha1', 'sha256']
    
    # Default file size limits (100MB)
    MAX_FILE_SIZE = 100 * 1024 * 1024
    
    # Buffer sizes for processing
    DEFAULT_BUFFER_SIZE = 64 * 1024  # 64KB
    
    # Logging messages
    LOG_MESSAGES = {
        'parsing_volumes': "[spi_uefi] Decoding UEFI firmware volumes...",
        'parsing_nvram': "[spi_uefi] Decoding UEFI NVRAM...",
        'nvram_identification_failed': "Could not automatically identify EFI NVRAM type",
        'unrecognized_nvram_type': "Unrecognized NVRAM type {fwtype}",
        'nvram_parse_warning': "Couldn't identify NVRAM in FV {{{guid}}}",
        'nvram_extract_warning': "Couldn't extract NVRAM in {{{guid}}} using type '{nvram_type}'",
    }


class UEFIValidationConfig:
    """Validation configuration for UEFI operations."""
    
    # File validation settings
    VALIDATE_FILE_SIZE = True
    VALIDATE_FILE_EXTENSIONS = True
    VALIDATE_GUID_FORMAT = True
    
    # Allowed file extensions for different operations
    ALLOWED_ROM_EXTENSIONS = ['.rom', '.bin', '.fd', '.cap']
    ALLOWED_VAR_EXTENSIONS = ['.bin', '.var', '.dat']
    
    # GUID validation pattern
    GUID_PATTERN = r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'


class UEFIErrorConfig:
    """Error handling configuration for UEFI operations."""
    
    # Error handling modes
    STRICT_MODE = 'strict'  # Raise exceptions on any error
    PERMISSIVE_MODE = 'permissive'  # Log warnings but continue
    SILENT_MODE = 'silent'  # Ignore errors silently
    
    # Default error handling mode
    DEFAULT_MODE = PERMISSIVE_MODE
    
    # Error message templates
    ERROR_TEMPLATES = {
        'file_not_found': "Could not find {file_type} '{filepath}'",
        'invalid_guid': "Invalid GUID format: '{guid}'",
        'file_too_large': "File '{filepath}' exceeds maximum size limit ({max_size} bytes)",
        'invalid_file_extension': "Invalid file extension for {operation}: '{extension}'",
        'parse_error': "Failed to parse {component}: {error}",
        'validation_error': "Validation failed for {component}: {reason}",
    }
