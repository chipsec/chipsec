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


#
# -------------------------------------------------------------------------------
#
# CHIPSEC: Platform Hardware Security Assessment Framework
# (c) 2010-2012 Intel Corporation
#
# -------------------------------------------------------------------------------

"""
Reading from/writing to files with validation support

usage:
    >>> read_file(filename)
    >>> write_file(filename, buffer)
    >>> validate_file_exists(filename)
    >>> validate_file_size(filename, max_size)
"""

import os
import re
import uuid
from typing import Any, Optional, List
from chipsec.library.strings import get_datetime_str
from chipsec.library.logger import logger

TOOLS_DIR = 'chipsec_tools'


def read_file(filename: str, size: int = 0, validate: bool = True) -> bytes:
    """
    Read file with optional validation.
    
    Args:
        filename: Path to file to read
        size: Number of bytes to read (0 = read all)
        validate: Whether to validate file before reading
        
    Returns:
        File contents as bytes, or empty bytes if validation fails
    """
    if validate and not validate_file_exists(filename, "input file"):
        return b''
        
    try:
        with open(filename, 'rb') as f:
            if size:
                _file = f.read(size)
            else:
                _file = f.read()
            logger().log_debug(f"[file] Read {len(_file):d} bytes from '{filename:.256}'")
            return _file
    except OSError:
        logger().log_error(f"Unable to open file '{filename:.256}' for read access")
        return b''


def write_file(filename: str, buffer: Any, append: bool = False, validate: bool = True) -> bool:
    """
    Write file with optional validation.
    
    Args:
        filename: Path to file to write
        buffer: Data to write
        append: Whether to append to existing file
        validate: Whether to validate directory before writing
        
    Returns:
        True if write successful, False otherwise
    """
    if validate:
        # Validate directory exists or can be created
        dir_path = os.path.dirname(filename)
        if dir_path and not validate_directory_path(dir_path, create_if_missing=True):
            return False
    
    perm = 'a' if append else 'w'
    if isinstance(buffer, bytes) or isinstance(buffer, bytearray):
        perm += 'b'
    try:
        f = open(filename, perm)
    except OSError:
        logger().log_error(f"Unable to open file '{filename:.256}' for write access")
        return False
    f.write(buffer)
    f.close()

    logger().log_debug(f"[file] Wrote {len(buffer):d} bytes to '{filename:.256}'")
    return True


def write_unique_file(file_buffer: Any, file_name: str = '', file_extension: str = '') -> str:
    """Writes file with the name <file_name>_<year><month><day>-<hour><minute><second>.<file_extension>"""
    file_str = f'{file_name}_' if file_name else ''
    file_ext = f'.{file_extension}' if file_extension else ''
    file_name_str = f'{file_str}{get_datetime_str()}{file_ext}'
    return file_name_str if write_file(file_name_str, file_buffer) else ''


def get_main_dir() -> str:
    path = os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir, os.path.pardir))
    return path


def get_module_dir() -> str:
    path = os.path.join(get_main_dir(), "chipsec", "modules")
    return path


# ================================================
# File Validation Functions
# ================================================

def validate_file_exists(filepath: str, file_type: str = "file") -> bool:
    """
    Validate that a file exists and is accessible.
    
    Args:
        filepath: Path to the file to validate
        file_type: Description of the file type for error messages
        
    Returns:
        True if file exists and is accessible, False otherwise
        
    Raises:
        FileNotFoundValidationError: If file doesn't exist in strict mode
    """
    if not filepath:
        logger().log_error(f"Empty filepath provided for {file_type}")
        return False
        
    if not os.path.exists(filepath):
        logger().log_error(f"File not found: {file_type} '{filepath}'")
        return False
        
    if not os.path.isfile(filepath):
        logger().log_error(f"Path '{filepath}' exists but is not a file")
        return False
        
    return True


def validate_file_size(filepath: str, max_size: Optional[int] = None) -> bool:
    """
    Validate file size is within acceptable limits.
    
    Args:
        filepath: Path to the file to validate
        max_size: Maximum allowed file size in bytes (default: 500MB)
        
    Returns:
        True if file size is acceptable, False otherwise
    """
    if max_size is None:
        max_size = 500 * 1024 * 1024  # 500MB default
        
    try:
        file_size = os.path.getsize(filepath)
        if file_size > max_size:
            logger().log_error(
                f"File '{filepath}' size ({file_size} bytes) exceeds maximum allowed size ({max_size} bytes)"
            )
            return False
        return True
    except OSError as e:
        logger().log_error(f"Failed to get file size for '{filepath}': {e}")
        return False


def validate_directory_path(dirpath: str, create_if_missing: bool = False) -> bool:
    """
    Validate directory path and optionally create it.
    
    Args:
        dirpath: Directory path to validate
        create_if_missing: Create directory if it doesn't exist
        
    Returns:
        True if directory exists or was created successfully, False otherwise
    """
    if not dirpath:
        logger().log_error("Empty directory path provided")
        return False
        
    if os.path.exists(dirpath):
        if not os.path.isdir(dirpath):
            logger().log_error(f"Path '{dirpath}' exists but is not a directory")
            return False
        return True
    
    if create_if_missing:
        try:
            os.makedirs(dirpath, exist_ok=True)
            logger().log_debug(f"Created directory: {dirpath}")
            return True
        except OSError as e:
            logger().log_error(f"Failed to create directory '{dirpath}': {e}")
            return False
    else:
        logger().log_error(f"Directory '{dirpath}' does not exist")
        return False


def validate_file_extension(filepath: str, allowed_extensions: List[str],
                            case_sensitive: bool = False) -> bool:
    """
    Validate file extension against allowed list.
    
    Args:
        filepath: Path to the file to validate
        allowed_extensions: List of allowed file extensions (e.g., ['.bin', '.rom'])
        case_sensitive: Whether to perform case-sensitive comparison
        
    Returns:
        True if file extension is allowed, False otherwise
    """
    if not allowed_extensions:
        return True  # No restrictions
        
    file_ext = os.path.splitext(filepath)[1]
    if not case_sensitive:
        file_ext = file_ext.lower()
        allowed_extensions = [ext.lower() for ext in allowed_extensions]
        
    if file_ext not in allowed_extensions:
        logger().log_error(
            f"File '{filepath}' has invalid extension '{file_ext}'. "
            f"Allowed extensions: {allowed_extensions}"
        )
        return False
    return True


def validate_guid(guid_str: str) -> bool:
    """
    Validate GUID format.
    
    Args:
        guid_str: GUID string to validate
        
    Returns:
        True if GUID is valid, False otherwise
    """
    if not guid_str:
        logger().log_error("Empty GUID string provided")
        return False
        
    # Standard GUID pattern
    guid_pattern = r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    
    try:
        if re.match(guid_pattern, guid_str):
            # Try to parse as UUID to validate format
            uuid.UUID(guid_str)
            return True
        else:
            logger().log_error(f"Invalid GUID format: {guid_str}")
            return False
    except ValueError as e:
        logger().log_error(f"Invalid GUID format: {guid_str} - {e}")
        return False
