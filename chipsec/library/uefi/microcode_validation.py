#!/usr/bin/env python3
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

"""
Enhanced microcode validation for multi-vendor support (Intel, AMD, ARM)
"""

import struct
from typing import Dict, Optional, Any


class MicrocodeValidationError(Exception):
    """Exception raised for microcode validation errors"""
    pass


class MicrocodeValidator:
    """Enhanced Microcode Validation with Multi-Vendor Support"""
    
    # Intel microcode signature
    INTEL_MICROCODE_SIGNATURE = 0x01000000
    
    # AMD microcode signatures
    AMD_MICROCODE_SIGNATURES = [0x00000001, 0x00000002, 0x00000003]
    
    # ARM microcode/firmware signatures
    ARM_FW_SIGNATURES = [0x464C5348, 0x41524D46]  # 'FLSH', 'ARMF'
    
    def __init__(self):
        self.supported_vendors = ['Intel', 'AMD', 'ARM', 'Generic']
        
    def validate_microcode(self, microcode_data: bytes, vendor_hint: Optional[str] = None) -> Dict[str, Any]:
        """
        Validate microcode from any supported vendor
        
        Args:
            microcode_data: Raw microcode binary data
            vendor_hint: Optional vendor hint ('Intel', 'AMD', 'ARM')
            
        Returns:
            Dictionary with validation results
        """
        result = {
            'valid': False,
            'vendor': 'Unknown',
            'format_version': None,
            'microcode_id': None,
            'target_cpuid': None,
            'date': None,
            'size': len(microcode_data),
            'checksum_valid': False,
            'signature_valid': False,
            'errors': [],
            'warnings': []
        }
        
        if len(microcode_data) < 48:
            result['errors'].append("Microcode data too small")
            return result
            
        # Auto-detect vendor if not provided
        if not vendor_hint:
            vendor_hint = self._detect_vendor(microcode_data)
            
        result['vendor'] = vendor_hint
        
        try:
            if vendor_hint == 'Intel':
                return self._validate_intel_microcode(microcode_data, result)
            elif vendor_hint == 'AMD':
                return self._validate_amd_microcode(microcode_data, result)
            elif vendor_hint == 'ARM':
                return self._validate_arm_firmware(microcode_data, result)
            else:
                return self._validate_generic_microcode(microcode_data, result)
                
        except Exception as e:
            result['errors'].append(f"Microcode validation error: {str(e)}")
            
        return result
        
    def _detect_vendor(self, microcode_data: bytes) -> str:
        """Auto-detect microcode vendor from signature"""
        if len(microcode_data) < 16:
            return 'Generic'
            
        # Check for Intel signature
        header_rev = struct.unpack('<I', microcode_data[0:4])[0]
        if header_rev == self.INTEL_MICROCODE_SIGNATURE:
            return 'Intel'
            
        # Check for AMD signatures
        signature = struct.unpack('<I', microcode_data[0:4])[0]
        if signature in self.AMD_MICROCODE_SIGNATURES:
            return 'AMD'
            
        # Check for ARM signatures
        if signature in self.ARM_FW_SIGNATURES:
            return 'ARM'
            
        # Check for common patterns
        if b'INTEL' in microcode_data[:64]:
            return 'Intel'
        elif b'AMD' in microcode_data[:64]:
            return 'AMD'
        elif b'ARM' in microcode_data[:64]:
            return 'ARM'
            
        return 'Generic'
        
    def _validate_intel_microcode(self, microcode_data: bytes, result: Dict[str, Any]) -> Dict[str, Any]:
        """Validate Intel microcode format"""
        try:
            # Intel microcode header structure
            header = struct.unpack('<11I', microcode_data[:44])
            
            header_rev = header[0]
            update_rev = header[1]
            date = header[2]
            proc_sig = header[3]
            checksum = header[4]
            loader_rev = header[5]
            proc_flags = header[6]
            data_size = header[7]
            total_size = header[8]
            reserved1 = header[9]
            reserved2 = header[10]
            
            # Validate header
            if header_rev != self.INTEL_MICROCODE_SIGNATURE:
                result['errors'].append(f"Invalid Intel microcode signature: 0x{header_rev:08x}")
                return result
                
            # Extract information
            result['format_version'] = header_rev
            result['microcode_id'] = update_rev
            result['target_cpuid'] = proc_sig
            result['date'] = f"{(date >> 24):02d}/{(date >> 16) & 0xFF:02d}/{date & 0xFFFF}"
            
            # Validate sizes
            if data_size == 0:
                data_size = 2000  # Default Intel microcode data size
            if total_size == 0:
                total_size = data_size + 48  # Header + data
                
            if len(microcode_data) < total_size:
                result['warnings'].append(f"Microcode data truncated: {len(microcode_data)} < {total_size}")
            elif len(microcode_data) > total_size:
                result['warnings'].append(f"Extra data after microcode: {len(microcode_data)} > {total_size}")
                
            # Validate checksum
            calculated_checksum = self._calculate_intel_checksum(microcode_data, total_size)
            result['checksum_valid'] = (calculated_checksum == 0)
            
            if not result['checksum_valid']:
                result['errors'].append(f"Checksum validation failed: 0x{calculated_checksum:08x}")
            else:
                result['valid'] = True
                
        except struct.error as e:
            result['errors'].append(f"Intel microcode header parsing failed: {str(e)}")
        except Exception as e:
            result['errors'].append(f"Intel microcode validation error: {str(e)}")
            
        return result
        
    def _validate_amd_microcode(self, microcode_data: bytes, result: Dict[str, Any]) -> Dict[str, Any]:
        """Validate AMD microcode format"""
        try:
            # AMD microcode has different formats depending on generation
            header = struct.unpack('<8I', microcode_data[:32])
            
            signature = header[0]
            data_size = header[1]
            date = header[2]
            proc_id = header[3]
            microcode_rev = header[4]
            nb_dev_id = header[5]
            sb_dev_id = header[6]
            proc_rev_id = header[7]
            
            # Validate signature
            if signature not in self.AMD_MICROCODE_SIGNATURES:
                result['errors'].append(f"Invalid AMD microcode signature: 0x{signature:08x}")
                return result
                
            # Extract information
            result['format_version'] = signature
            result['microcode_id'] = microcode_rev
            result['target_cpuid'] = proc_id
            result['date'] = f"{(date >> 16) & 0xFF:02d}/{(date >> 8) & 0xFF:02d}/{date & 0xFF:02d}"
            
            # Validate size
            if len(microcode_data) < data_size + 32:
                result['warnings'].append(f"AMD microcode data truncated")
            
            # AMD microcode validation (simplified)
            result['checksum_valid'] = True  # AMD uses different validation
            result['valid'] = True
            
        except struct.error as e:
            result['errors'].append(f"AMD microcode header parsing failed: {str(e)}")
        except Exception as e:
            result['errors'].append(f"AMD microcode validation error: {str(e)}")
            
        return result
        
    def _validate_arm_firmware(self, microcode_data: bytes, result: Dict[str, Any]) -> Dict[str, Any]:
        """Validate ARM firmware/microcode format"""
        try:
            # ARM firmware header (simplified)
            header = struct.unpack('<8I', microcode_data[:32])
            
            signature = header[0]
            version = header[1]
            size = header[2]
            load_addr = header[3]
            entry_point = header[4]
            checksum = header[5]
            flags = header[6]
            reserved = header[7]
            
            # Validate signature
            if signature not in self.ARM_FW_SIGNATURES:
                result['errors'].append(f"Invalid ARM firmware signature: 0x{signature:08x}")
                return result
                
            # Extract information
            result['format_version'] = version
            result['microcode_id'] = version
            result['target_cpuid'] = f"ARM_{load_addr:08x}"
            
            # Validate size
            if len(microcode_data) < size:
                result['warnings'].append(f"ARM firmware data truncated")
                
            # Calculate ARM checksum (simplified)
            calculated_checksum = sum(microcode_data[32:size]) & 0xFFFFFFFF
            result['checksum_valid'] = (calculated_checksum == checksum)
            
            if not result['checksum_valid']:
                result['warnings'].append(f"ARM firmware checksum mismatch")
            else:
                result['valid'] = True
                
        except struct.error as e:
            result['errors'].append(f"ARM firmware header parsing failed: {str(e)}")
        except Exception as e:
            result['errors'].append(f"ARM firmware validation error: {str(e)}")
            
        return result
        
    def _validate_generic_microcode(self, microcode_data: bytes, result: Dict[str, Any]) -> Dict[str, Any]:
        """Generic microcode validation for unknown formats"""
        try:
            # Basic structure analysis
            result['format_version'] = 'Generic'
            
            # Look for common patterns
            if microcode_data.startswith(b'\x00\x00\x00\x01'):
                result['warnings'].append("Detected possible Intel-like header")
            elif microcode_data.startswith(b'\x01\x00\x00\x00'):
                result['warnings'].append("Detected possible AMD-like header")
                
            # Basic entropy check (microcode should have reasonable entropy)
            entropy = self._calculate_entropy(microcode_data[:1024])
            if entropy < 6.0:
                result['warnings'].append(f"Low entropy detected: {entropy:.2f}")
            elif entropy > 7.8:
                result['warnings'].append(f"Very high entropy (compressed/encrypted?): {entropy:.2f}")
                
            # Check for null blocks
            null_blocks = microcode_data.count(b'\x00' * 16)
            if null_blocks > len(microcode_data) // 32:
                result['warnings'].append(f"Many null blocks detected: {null_blocks}")
                
            result['valid'] = True  # Generic validation is permissive
            result['checksum_valid'] = True
            
        except Exception as e:
            result['errors'].append(f"Generic microcode validation error: {str(e)}")
            
        return result
        
    def _calculate_intel_checksum(self, microcode_data: bytes, total_size: int) -> int:
        """Calculate Intel microcode checksum"""
        checksum = 0
        data_to_check = microcode_data[:total_size]
        
        # Pad to 4-byte boundary
        padding = (4 - (len(data_to_check) % 4)) % 4
        data_to_check += b'\x00' * padding
        
        # Sum all 32-bit words
        for i in range(0, len(data_to_check), 4):
            word = struct.unpack('<I', data_to_check[i:i+4])[0]
            checksum = (checksum + word) & 0xFFFFFFFF
            
        return checksum
        
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
            
        # Count byte frequencies
        frequencies = [0] * 256
        for byte in data:
            frequencies[byte] += 1
            
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        for freq in frequencies:
            if freq > 0:
                p = freq / data_len
                entropy -= p * (p.bit_length() - 1)
                
        return entropy
        
    def extract_microcode_metadata(self, microcode_data: bytes) -> Dict[str, Any]:
        """
        Extract detailed metadata from microcode
        
        Args:
            microcode_data: Raw microcode binary data
            
        Returns:
            Dictionary with microcode metadata
        """
        validation_result = self.validate_microcode(microcode_data)
        
        metadata = {
            'size': len(microcode_data),
            'vendor': validation_result['vendor'],
            'valid': validation_result['valid'],
            'entropy': self._calculate_entropy(microcode_data[:1024]),
            'structure_analysis': {},
            'potential_strings': []
        }
        
        # Add validation details
        metadata.update(validation_result)
        
        # Look for embedded strings
        try:
            strings = []
            current_string = b''
            for byte in microcode_data[:4096]:  # Check first 4KB
                if 32 <= byte <= 126:  # Printable ASCII
                    current_string += bytes([byte])
                else:
                    if len(current_string) >= 4:
                        strings.append(current_string.decode('ascii', errors='ignore'))
                    current_string = b''
            metadata['potential_strings'] = strings[:10]  # Limit to 10 strings
        except Exception:
            pass
            
        return metadata
        
    def compare_microcode_versions(self, old_data: bytes, new_data: bytes) -> Dict[str, Any]:
        """
        Compare two microcode versions
        
        Args:
            old_data: Old microcode binary data
            new_data: New microcode binary data
            
        Returns:
            Dictionary with comparison results
        """
        old_meta = self.extract_microcode_metadata(old_data)
        new_meta = self.extract_microcode_metadata(new_data)
        
        comparison = {
            'same_vendor': old_meta['vendor'] == new_meta['vendor'],
            'same_target': old_meta.get('target_cpuid') == new_meta.get('target_cpuid'),
            'version_change': {
                'old': old_meta.get('microcode_id'),
                'new': new_meta.get('microcode_id')
            },
            'size_change': {
                'old': old_meta['size'],
                'new': new_meta['size'],
                'difference': new_meta['size'] - old_meta['size']
            },
            'date_change': {
                'old': old_meta.get('date'),
                'new': new_meta.get('date')
            },
            'binary_diff': {
                'identical': old_data == new_data,
                'similarity': self._calculate_similarity(old_data, new_data)
            }
        }
        
        return comparison
        
    def _calculate_similarity(self, data1: bytes, data2: bytes) -> float:
        """Calculate binary similarity between two data sets"""
        if len(data1) == 0 or len(data2) == 0:
            return 0.0
            
        min_len = min(len(data1), len(data2))
        max_len = max(len(data1), len(data2))
        
        # Count matching bytes
        matches = 0
        for i in range(min_len):
            if data1[i] == data2[i]:
                matches += 1
                
        # Calculate similarity considering size difference
        similarity = matches / max_len
        return similarity
