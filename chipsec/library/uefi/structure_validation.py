# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2025, Intel Corporation
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
UEFI structure validation and integrity checking functionality

This module provides enhanced validation capabilities for UEFI firmware
structures including CRC32 validation, size consistency checking, and
cross-reference validation.
"""

import struct
import zlib
from typing import Dict, List, Optional, Tuple, Any, Union
from uuid import UUID

from chipsec.library.logger import logger


class ValidationResult:
    """Result of structure validation operation."""
    
    def __init__(self):
        self.is_valid: bool = True
        self.crc_valid: bool = True
        self.size_consistent: bool = True
        self.alignment_valid: bool = True
        self.cross_refs_valid: bool = True
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.details: Dict[str, Any] = {}
        
    def add_error(self, error: str):
        """Add an error and mark validation as failed."""
        self.errors.append(error)
        self.is_valid = False
        
    def add_warning(self, warning: str):
        """Add a warning."""
        self.warnings.append(warning)
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary for JSON serialization."""
        return {
            'is_valid': self.is_valid,
            'crc_valid': self.crc_valid,
            'size_consistent': self.size_consistent,
            'alignment_valid': self.alignment_valid,
            'cross_refs_valid': self.cross_refs_valid,
            'errors': self.errors,
            'warnings': self.warnings,
            'details': self.details
        }


class UEFIStructureValidator:
    """
    UEFI structure validation and integrity checking.
    
    Provides comprehensive validation capabilities for UEFI firmware
    structures including CRC32 validation, size consistency checking,
    alignment verification, and cross-reference validation.
    """
    
    def __init__(self):
        self.validation_cache: Dict[str, ValidationResult] = {}
        
    def validate_firmware_volume_header(self, fv_data: bytes, offset: int = 0) -> ValidationResult:
        """
        Validate firmware volume header structure.
        
        Args:
            fv_data: Firmware volume data
            offset: Offset to start of FV header
            
        Returns:
            ValidationResult with validation details
        """
        result = ValidationResult()
        
        try:
            if len(fv_data) < offset + 56:  # Minimum FV header size
                result.add_error("Insufficient data for FV header")
                return result
                
            # Parse FV header
            header_data = fv_data[offset:offset + 56]
            
            # Zero vector (16 bytes)
            zero_vector = header_data[0:16]
            
            # File system GUID (16 bytes)
            fs_guid_data = header_data[16:32]
            fs_guid = UUID(bytes_le=fs_guid_data)
            
            # FV length (8 bytes)
            fv_length = struct.unpack('<Q', header_data[32:40])[0]
            
            # Signature (4 bytes) - should be "_FVH"
            signature = header_data[40:44]
            
            # Attributes (4 bytes)
            attributes = struct.unpack('<I', header_data[44:48])[0]
            
            # Header length (2 bytes)
            header_length = struct.unpack('<H', header_data[48:50])[0]
            
            # Checksum (2 bytes)
            checksum = struct.unpack('<H', header_data[50:52])[0]
            
            # Ext header offset (2 bytes)
            ext_header_offset = struct.unpack('<H', header_data[52:54])[0]
            
            # Reserved (1 byte)
            reserved = header_data[54]
            
            # Revision (1 byte)
            revision = header_data[55]
            
            # Store details
            result.details.update({
                'fs_guid': str(fs_guid),
                'fv_length': fv_length,
                'signature': signature.decode('ascii', errors='ignore'),
                'attributes': f'0x{attributes:08X}',
                'header_length': header_length,
                'checksum': f'0x{checksum:04X}',
                'ext_header_offset': ext_header_offset,
                'revision': revision
            })
            
            # Validate signature
            if signature != b'_FVH':
                result.add_error(f"Invalid FV signature: {signature}")
                
            # Validate header length
            if header_length < 56:
                result.add_error(f"Invalid header length: {header_length}")
            elif header_length > len(fv_data) - offset:
                result.add_error(f"Header length exceeds available data: {header_length}")
                
            # Validate FV length
            if fv_length > len(fv_data) - offset:
                result.add_error(f"FV length exceeds available data: {fv_length}")
                result.size_consistent = False
                
            # Validate alignment (FV should be aligned)
            if offset % 8 != 0:
                result.add_warning(f"FV not aligned to 8-byte boundary: offset=0x{offset:X}")
                result.alignment_valid = False
                
            # Validate checksum
            if self._validate_fv_checksum(header_data, checksum):
                result.details['checksum_valid'] = True
            else:
                result.add_error("FV header checksum validation failed")
                result.crc_valid = False
                
            # Validate extended header if present
            if ext_header_offset != 0:
                if ext_header_offset < header_length:
                    result.add_error(f"Extended header offset invalid: {ext_header_offset}")
                else:
                    ext_result = self._validate_extended_header(fv_data, offset + ext_header_offset)
                    if not ext_result.is_valid:
                        result.errors.extend(ext_result.errors)
                        result.warnings.extend(ext_result.warnings)
                        
        except Exception as e:
            result.add_error(f"FV header validation failed: {e}")
            
        return result

    def validate_file_header(self, file_data: bytes, offset: int = 0) -> ValidationResult:
        """
        Validate firmware file header structure.
        
        Args:
            file_data: File data
            offset: Offset to start of file header
            
        Returns:
            ValidationResult with validation details
        """
        result = ValidationResult()
        
        try:
            if len(file_data) < offset + 24:  # Minimum file header size
                result.add_error("Insufficient data for file header")
                return result
                
            # Parse file header
            header_data = file_data[offset:offset + 24]
            
            # Name GUID (16 bytes)
            name_guid_data = header_data[0:16]
            name_guid = UUID(bytes_le=name_guid_data)
            
            # Header checksum (1 byte)
            header_checksum = header_data[16]
            
            # Data checksum (1 byte)
            data_checksum = header_data[17]
            
            # File type (1 byte)
            file_type = header_data[18]
            
            # Attributes (1 byte)
            attributes = header_data[19]
            
            # Size (3 bytes)
            size_data = header_data[20:23] + b'\x00'  # Pad to 4 bytes
            file_size = struct.unpack('<I', size_data)[0]
            
            # State (1 byte)
            state = header_data[23]
            
            # Store details
            result.details.update({
                'name_guid': str(name_guid),
                'header_checksum': f'0x{header_checksum:02X}',
                'data_checksum': f'0x{data_checksum:02X}',
                'file_type': f'0x{file_type:02X}',
                'attributes': f'0x{attributes:02X}',
                'file_size': file_size,
                'state': f'0x{state:02X}'
            })
            
            # Validate file size
            if file_size > len(file_data) - offset:
                result.add_error(f"File size exceeds available data: {file_size}")
                result.size_consistent = False
                
            # Validate alignment (files should be aligned to 8-byte boundary)
            if offset % 8 != 0:
                result.add_warning(f"File not aligned to 8-byte boundary: offset=0x{offset:X}")
                result.alignment_valid = False
                
            # Validate file size alignment
            if file_size % 8 != 0:
                result.add_warning(f"File size not aligned to 8-byte boundary: {file_size}")
                result.alignment_valid = False
                
            # Validate checksums if requested
            if self._should_validate_checksums(attributes):
                if not self._validate_file_checksums(file_data[offset:offset + file_size], header_checksum, data_checksum):
                    result.add_error("File checksum validation failed")
                    result.crc_valid = False
                else:
                    result.details['checksums_valid'] = True
                    
        except Exception as e:
            result.add_error(f"File header validation failed: {e}")
            
        return result

    def validate_section_header(self, section_data: bytes, offset: int = 0) -> ValidationResult:
        """
        Validate section header structure.
        
        Args:
            section_data: Section data
            offset: Offset to start of section header
            
        Returns:
            ValidationResult with validation details
        """
        result = ValidationResult()
        
        try:
            if len(section_data) < offset + 4:  # Minimum section header size
                result.add_error("Insufficient data for section header")
                return result
                
            # Parse section header
            header_data = section_data[offset:offset + 4]
            
            # Size (3 bytes)
            size_data = header_data[0:3] + b'\x00'  # Pad to 4 bytes
            section_size = struct.unpack('<I', size_data)[0]
            
            # Type (1 byte)
            section_type = header_data[3]
            
            # Store details
            result.details.update({
                'section_size': section_size,
                'section_type': f'0x{section_type:02X}'
            })
            
            # Validate section size
            if section_size > len(section_data) - offset:
                result.add_error(f"Section size exceeds available data: {section_size}")
                result.size_consistent = False
                
            # Validate minimum section size
            if section_size < 4:
                result.add_error(f"Section size too small: {section_size}")
                result.size_consistent = False
                
            # Validate alignment (sections should be aligned to 4-byte boundary)
            if offset % 4 != 0:
                result.add_warning(f"Section not aligned to 4-byte boundary: offset=0x{offset:X}")
                result.alignment_valid = False
                
            # Check for extended size section
            if section_size == 0xFFFFFF:
                if len(section_data) < offset + 8:
                    result.add_error("Insufficient data for extended size section")
                    return result
                    
                # Parse extended size (4 bytes after normal header)
                ext_size_data = section_data[offset + 4:offset + 8]
                extended_size = struct.unpack('<I', ext_size_data)[0]
                result.details['extended_size'] = extended_size
                
                if extended_size > len(section_data) - offset:
                    result.add_error(f"Extended section size exceeds available data: {extended_size}")
                    result.size_consistent = False
                    
        except Exception as e:
            result.add_error(f"Section header validation failed: {e}")
            
        return result

    def validate_cross_references(self, modules: List[Any]) -> ValidationResult:
        """
        Validate cross-references between UEFI modules.
        
        Args:
            modules: List of UEFI modules to validate
            
        Returns:
            ValidationResult with cross-reference validation details
        """
        result = ValidationResult()
        
        try:
            guid_map: Dict[str, List[Any]] = {}
            dependency_map: Dict[str, List[str]] = {}
            
            # Build GUID map and dependency map
            for module in modules:
                if hasattr(module, 'Guid') and module.Guid:
                    guid_str = str(module.Guid)
                    if guid_str not in guid_map:
                        guid_map[guid_str] = []
                    guid_map[guid_str].append(module)
                    
                # Extract dependencies if available
                if hasattr(module, 'children') and module.children:
                    deps = self._extract_dependencies(module.children)
                    if deps:
                        dependency_map[guid_str] = deps
                        
            # Check for duplicate GUIDs
            duplicates = {guid: modules for guid, modules in guid_map.items() if len(modules) > 1}
            if duplicates:
                for guid, dup_modules in duplicates.items():
                    result.add_warning(f"Duplicate GUID found: {guid} ({len(dup_modules)} instances)")
                    
            # Validate dependencies
            unresolved_deps = []
            for module_guid, deps in dependency_map.items():
                for dep_guid in deps:
                    if dep_guid not in guid_map:
                        unresolved_deps.append((module_guid, dep_guid))
                        
            if unresolved_deps:
                result.cross_refs_valid = False
                for module_guid, dep_guid in unresolved_deps:
                    result.add_error(f"Unresolved dependency: {module_guid} -> {dep_guid}")
                    
            result.details.update({
                'total_modules': len(modules),
                'unique_guids': len(guid_map),
                'duplicate_guids': len(duplicates),
                'dependencies': len(dependency_map),
                'unresolved_dependencies': len(unresolved_deps)
            })
            
        except Exception as e:
            result.add_error(f"Cross-reference validation failed: {e}")
            
        return result

    def _validate_fv_checksum(self, header_data: bytes, expected_checksum: int) -> bool:
        """Validate firmware volume header checksum."""
        try:
            # Zero out the checksum field for calculation
            calc_data = bytearray(header_data)
            calc_data[50:52] = b'\x00\x00'
            
            # Calculate 16-bit checksum
            checksum = 0
            for i in range(0, len(calc_data), 2):
                if i + 1 < len(calc_data):
                    word = struct.unpack('<H', calc_data[i:i+2])[0]
                    checksum = (checksum + word) & 0xFFFF
                    
            # Two's complement
            checksum = (0x10000 - checksum) & 0xFFFF
            
            return checksum == expected_checksum
            
        except Exception:
            return False

    def _validate_file_checksums(self, file_data: bytes, header_checksum: int, data_checksum: int) -> bool:
        """Validate file header and data checksums."""
        try:
            # Validate header checksum (first 24 bytes with checksum fields zeroed)
            header_data = bytearray(file_data[:24])
            header_data[16:18] = b'\x00\x00'  # Zero checksum fields
            
            calc_header_checksum = (0x100 - sum(header_data)) & 0xFF
            
            # Validate data checksum (everything after header)
            if len(file_data) > 24:
                data_bytes = file_data[24:]
                calc_data_checksum = (0x100 - sum(data_bytes)) & 0xFF
            else:
                calc_data_checksum = 0
                
            return (calc_header_checksum == header_checksum and 
                   calc_data_checksum == data_checksum)
                   
        except Exception:
            return False

    def _should_validate_checksums(self, attributes: int) -> bool:
        """Check if checksums should be validated based on file attributes."""
        # Checksum validation enabled if bit 6 is NOT set
        return not (attributes & 0x40)

    def _validate_extended_header(self, fv_data: bytes, offset: int) -> ValidationResult:
        """Validate extended firmware volume header."""
        result = ValidationResult()
        
        try:
            if len(fv_data) < offset + 20:  # Minimum extended header size
                result.add_error("Insufficient data for extended header")
                return result
                
            # Parse extended header
            ext_header = fv_data[offset:offset + 20]
            
            # FV name GUID (16 bytes)
            fv_name_guid = UUID(bytes_le=ext_header[0:16])
            
            # Extended header size (4 bytes)
            ext_header_size = struct.unpack('<I', ext_header[16:20])[0]
            
            result.details.update({
                'fv_name_guid': str(fv_name_guid),
                'ext_header_size': ext_header_size
            })
            
            # Validate extended header size
            if ext_header_size < 20:
                result.add_error(f"Extended header size too small: {ext_header_size}")
            elif ext_header_size > len(fv_data) - offset:
                result.add_error(f"Extended header size exceeds available data: {ext_header_size}")
                
        except Exception as e:
            result.add_error(f"Extended header validation failed: {e}")
            
        return result

    def _extract_dependencies(self, children: List[Any]) -> List[str]:
        """Extract dependency GUIDs from module children."""
        dependencies = []
        
        try:
            for child in children:
                # Look for dependency sections
                if hasattr(child, 'Type') and child.Type in [0x13, 0x1B, 0x1E]:  # DEPEX sections
                    if hasattr(child, 'Image') and len(child.Image) >= 16:
                        # Parse dependency opcodes (simplified)
                        data = child.Image
                        offset = getattr(child, 'HeaderSize', 4)
                        
                        while offset + 16 <= len(data):
                            try:
                                guid = UUID(bytes_le=data[offset:offset + 16])
                                dependencies.append(str(guid))
                                offset += 16
                                
                                # Check for opcode after GUID
                                if offset < len(data):
                                    opcode = data[offset]
                                    if opcode in [0x02, 0x03, 0x04]:  # END, AND, OR
                                        break
                                    offset += 1
                            except Exception:
                                break
                                
        except Exception:
            pass
            
        return dependencies

    def validate_crc32(self, data: bytes, expected_crc: int) -> bool:
        """Validate CRC32 checksum."""
        try:
            calculated_crc = zlib.crc32(data) & 0xFFFFFFFF
            return calculated_crc == expected_crc
        except Exception:
            return False

    def calculate_crc32(self, data: bytes) -> int:
        """Calculate CRC32 checksum."""
        try:
            return zlib.crc32(data) & 0xFFFFFFFF
        except Exception:
            return 0
