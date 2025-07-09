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
Intel Boot Guard support for CHIPSEC UEFI framework
"""

import struct
from typing import Dict, Any, List

# Intel Boot Guard GUIDs and constants
INTEL_BOOT_GUARD_GUID = "BE30E0E0-0E7F-4E02-8BFE-8AC54D777F3C"
INTEL_BOOT_GUARD_FV_GUID = "77E8B0F3-CB1C-4B37-9F4B-C8A9CF56C49E"
INTEL_BOOT_GUARD_KEY_MANIFEST_GUID = "9AAE3F12-F9C8-4C6B-90C4-B10C4F5B2C9A"
INTEL_BOOT_GUARD_BOOT_POLICY_GUID = "C1C41626-504F-4A20-8F5D-4A0F80F3D0A5"

# Intel Boot Guard structure constants
IBB_HEADER_SIGNATURE = 0x54424249  # 'IBBT'
BOOT_POLICY_SIGNATURE = 0x5449424D  # 'MBIT'
KEY_MANIFEST_SIGNATURE = 0x4D4B4249  # 'IBKM'

# Boot Guard Profile Support
BOOT_GUARD_PROFILES = {
    0: "Legacy",
    1: "Server",
    2: "Performance",
    3: "High Assurance",
    4: "Platform Manufacturer"
}

# Hash algorithms
HASH_ALGORITHMS = {
    0x00: "None",
    0x01: "SHA-1",
    0x02: "SHA-256",
    0x03: "SHA-384",
    0x04: "SHA-512",
    0x10: "SM3"
}


class BootGuardValidationError(Exception):
    """Exception raised for Boot Guard validation errors"""
    pass


class IntelBootGuardValidator:
    """Intel Boot Guard Support and Validation"""
    
    def __init__(self):
        self.profiles = BOOT_GUARD_PROFILES
        self.hash_algorithms = HASH_ALGORITHMS
        
    def validate_boot_guard_structure(self, data: bytes, structure_type: str) -> Dict[str, Any]:
        """
        Validate Intel Boot Guard structures
        
        Args:
            data: Raw Boot Guard structure data
            structure_type: Type of structure ('key_manifest', 'boot_policy', 'ibb_header')
            
        Returns:
            Dictionary with validation results
        """
        result = {
            'valid': False,
            'structure_type': structure_type,
            'size': len(data),
            'version': None,
            'profile': None,
            'hash_algorithm': None,
            'signature_valid': False,
            'errors': [],
            'warnings': [],
            'details': {}
        }
        
        if len(data) < 16:
            result['errors'].append("Boot Guard structure too small")
            return result
            
        try:
            if structure_type == 'key_manifest':
                return self._validate_key_manifest(data, result)
            elif structure_type == 'boot_policy':
                return self._validate_boot_policy(data, result)
            elif structure_type == 'ibb_header':
                return self._validate_ibb_header(data, result)
            else:
                result['errors'].append(f"Unknown Boot Guard structure type: {structure_type}")
                
        except Exception as e:
            result['errors'].append(f"Boot Guard validation error: {str(e)}")
            
        return result
        
    def _validate_key_manifest(self, data: bytes, result: Dict[str, Any]) -> Dict[str, Any]:
        """Validate Boot Guard Key Manifest"""
        try:
            if len(data) < 32:
                result['errors'].append("Key manifest too small")
                return result
                
            # Parse key manifest header
            header = struct.unpack('<8I', data[:32])
            
            signature = header[0]
            if signature != KEY_MANIFEST_SIGNATURE:
                result['errors'].append(f"Invalid key manifest signature: 0x{signature:08x}")
                return result
                
            version = header[1]
            length = header[2]
            key_count = header[3]
            hash_alg = header[4]
            public_key_size = header[5]
            rsa_exp = header[6]
            # reserved = header[7]  # unused
            
            # Validate structure
            if length > len(data):
                result['warnings'].append(f"Key manifest length exceeds data size: {length} > {len(data)}")
            if key_count > 16:  # Reasonable limit
                result['warnings'].append(f"Unusual key count: {key_count}")
                
            # Extract information
            result['version'] = version
            result['hash_algorithm'] = self.hash_algorithms.get(hash_alg, f"Unknown (0x{hash_alg:02x})")
            result['details'] = {
                'length': length,
                'key_count': key_count,
                'public_key_size': public_key_size,
                'rsa_exponent': rsa_exp,
                'keys': []
            }
            
            # Parse public keys
            offset = 32
            for i in range(min(key_count, 8)):  # Limit to 8 keys for safety
                if offset + public_key_size <= len(data):
                    key_data = data[offset:offset + public_key_size]
                    key_info = self._analyze_public_key(key_data)
                    result['details']['keys'].append(key_info)
                    offset += public_key_size
                else:
                    result['warnings'].append(f"Key {i} extends beyond data")
                    break
                    
            result['valid'] = len(result['errors']) == 0
            
        except struct.error as e:
            result['errors'].append(f"Key manifest parsing error: {str(e)}")
            
        return result
        
    def _validate_boot_policy(self, data: bytes, result: Dict[str, Any]) -> Dict[str, Any]:
        """Validate Boot Guard Boot Policy"""
        try:
            if len(data) < 48:
                result['errors'].append("Boot policy too small")
                return result
                
            # Parse boot policy header
            header = struct.unpack('<12I', data[:48])
            
            signature = header[0]
            if signature != BOOT_POLICY_SIGNATURE:
                result['errors'].append(f"Invalid boot policy signature: 0x{signature:08x}")
                return result
                
            version = header[1]
            length = header[2]
            acm_svn = header[3]
            reserved1 = header[4]
            bp_flags = header[5]
            ibb_flags = header[6]
            ibb_hash_alg = header[7]
            ibb_segments = header[8]
            txt_flags = header[9]
            reserved2 = header[10]
            reserved3 = header[11]
            
            # Extract Boot Guard profile from flags
            profile_id = (bp_flags >> 4) & 0xF
            profile_name = self.profiles.get(profile_id, f"Unknown (0x{profile_id:x})")
            
            # Validate structure
            if length > len(data):
                result['warnings'].append(f"Boot policy length exceeds data size: {length} > {len(data)}")
            if ibb_segments > 16:  # Reasonable limit
                result['warnings'].append(f"Many IBB segments: {ibb_segments}")
                
            # Extract information
            result['version'] = version
            result['profile'] = profile_name
            result['hash_algorithm'] = self.hash_algorithms.get(ibb_hash_alg, f"Unknown (0x{ibb_hash_alg:02x})")
            result['details'] = {
                'length': length,
                'acm_svn': acm_svn,
                'boot_policy_flags': f"0x{bp_flags:08x}",
                'ibb_flags': f"0x{ibb_flags:08x}",
                'ibb_segments': ibb_segments,
                'txt_flags': f"0x{txt_flags:08x}",
                'features': self._decode_boot_policy_features(bp_flags, ibb_flags)
            }
            
            result['valid'] = len(result['errors']) == 0
            
        except struct.error as e:
            result['errors'].append(f"Boot policy parsing error: {str(e)}")
            
        return result
        
    def _validate_ibb_header(self, data: bytes, result: Dict[str, Any]) -> Dict[str, Any]:
        """Validate Boot Guard IBB (Initial Boot Block) Header"""
        try:
            if len(data) < 32:
                result['errors'].append("IBB header too small")
                return result
                
            # Parse IBB header
            header = struct.unpack('<8I', data[:32])
            
            signature = header[0]
            if signature != IBB_HEADER_SIGNATURE:
                result['errors'].append(f"Invalid IBB header signature: 0x{signature:08x}")
                return result
                
            version = header[1]
            flags = header[2]
            ibb_mchbar = header[3]
            vtd_bar = header[4]
            pmrl_base = header[5]
            pmrl_limit = header[6]
            reserved = header[7]
            
            # Extract information
            result['version'] = version
            result['details'] = {
                'flags': f"0x{flags:08x}",
                'ibb_mchbar': f"0x{ibb_mchbar:08x}",
                'vtd_bar': f"0x{vtd_bar:08x}",
                'pmrl_base': f"0x{pmrl_base:08x}",
                'pmrl_limit': f"0x{pmrl_limit:08x}",
                'features': self._decode_ibb_features(flags)
            }
            
            result['valid'] = len(result['errors']) == 0
            
        except struct.error as e:
            result['errors'].append(f"IBB header parsing error: {str(e)}")
            
        return result
        
    def _analyze_public_key(self, key_data: bytes) -> Dict[str, Any]:
        """Analyze a public key from Boot Guard manifest"""
        key_info = {
            'size': len(key_data),
            'type': 'Unknown',
            'modulus_size': 0,
            'hash': None
        }
        
        try:
            # Detect RSA key (common sizes: 256, 384, 512 bytes for RSA-2048, 3072, 4096)
            if len(key_data) in [256, 384, 512]:
                key_info['type'] = 'RSA'
                key_info['modulus_size'] = len(key_data) * 8
                
            # Calculate hash of key for identification
            import hashlib
            key_info['hash'] = hashlib.sha256(key_data).hexdigest()[:16]
            
        except Exception:
            pass
            
        return key_info
        
    def _decode_boot_policy_features(self, bp_flags: int, ibb_flags: int) -> List[str]:
        """Decode Boot Policy feature flags"""
        features = []
        
        # Boot Policy flags
        if bp_flags & 0x1:
            features.append("Measured Boot")
        if bp_flags & 0x2:
            features.append("Verified Boot")
        if bp_flags & 0x4:
            features.append("ACPI Table Protection")
        if bp_flags & 0x8:
            features.append("Key Manifest ID Verification")
            
        # IBB flags
        if ibb_flags & 0x1:
            features.append("IBB Measured")
        if ibb_flags & 0x2:
            features.append("IBB Verified")
        if ibb_flags & 0x4:
            features.append("Locality Indicator")
        if ibb_flags & 0x8:
            features.append("PCI Express Base Address")
            
        return features
        
    def _decode_ibb_features(self, flags: int) -> List[str]:
        """Decode IBB feature flags"""
        features = []
        
        if flags & 0x1:
            features.append("IBB Measured")
        if flags & 0x2:
            features.append("IBB Verified")  
        if flags & 0x4:
            features.append("No TXT")
        if flags & 0x8:
            features.append("Disable VT-d")
        if flags & 0x10:
            features.append("IBB Authority")
        if flags & 0x20:
            features.append("Authority Measured")
            
        return features
        
    def extract_boot_guard_info(self, firmware_data: bytes) -> Dict[str, Any]:
        """
        Extract Boot Guard information from firmware
        
        Args:
            firmware_data: Raw firmware binary data
            
        Returns:
            Dictionary with Boot Guard information
        """
        info = {
            'boot_guard_present': False,
            'structures_found': [],
            'key_manifests': [],
            'boot_policies': [],
            'ibb_headers': [],
            'profile': None,
            'security_features': []
        }
        
        try:
            # Search for Boot Guard GUIDs and signatures
            signatures = [
                (IBB_HEADER_SIGNATURE, 'ibb_header'),
                (BOOT_POLICY_SIGNATURE, 'boot_policy'),
                (KEY_MANIFEST_SIGNATURE, 'key_manifest')
            ]
            
            for signature, struct_type in signatures:
                sig_bytes = struct.pack('<I', signature)
                offset = 0
                while True:
                    pos = firmware_data.find(sig_bytes, offset)
                    if pos == -1:
                        break
                        
                    # Extract structure (assume max 4KB)
                    end_pos = min(pos + 4096, len(firmware_data))
                    struct_data = firmware_data[pos:end_pos]
                    
                    # Validate structure
                    validation = self.validate_boot_guard_structure(struct_data, struct_type)
                    if validation['valid']:
                        info['structures_found'].append({
                            'type': struct_type,
                            'offset': pos,
                            'validation': validation
                        })
                        
                        if struct_type == 'key_manifest':
                            info['key_manifests'].append(validation)
                        elif struct_type == 'boot_policy':
                            info['boot_policies'].append(validation)
                            if validation.get('profile'):
                                info['profile'] = validation['profile']
                        elif struct_type == 'ibb_header':
                            info['ibb_headers'].append(validation)
                            
                    offset = pos + 4
                    
            # Set Boot Guard presence
            info['boot_guard_present'] = len(info['structures_found']) > 0
            
            # Extract security features
            for bp in info['boot_policies']:
                if 'details' in bp and 'features' in bp['details']:
                    info['security_features'].extend(bp['details']['features'])
                    
            # Remove duplicates
            info['security_features'] = list(set(info['security_features']))
            
        except Exception as e:
            info['error'] = f"Boot Guard analysis error: {str(e)}"
            
        return info
        
    def check_boot_guard_configuration(self, firmware_data: bytes) -> Dict[str, Any]:
        """
        Check Boot Guard configuration and security status
        
        Args:
            firmware_data: Raw firmware binary data
            
        Returns:
            Dictionary with configuration analysis
        """
        bg_info = self.extract_boot_guard_info(firmware_data)
        
        config = {
            'enabled': bg_info['boot_guard_present'],
            'profile': bg_info.get('profile', 'Unknown'),
            'security_level': 'Unknown',
            'features_enabled': bg_info.get('security_features', []),
            'recommendations': [],
            'warnings': [],
            'key_manifests_count': len(bg_info.get('key_manifests', [])),
            'boot_policies_count': len(bg_info.get('boot_policies', [])),
            'issues': []
        }
        
        if not config['enabled']:
            config['security_level'] = 'None'
            config['recommendations'].append("Consider enabling Intel Boot Guard for enhanced security")
            return config
            
        # Analyze security level
        features = config['features_enabled']
        if 'Verified Boot' in features and 'Measured Boot' in features:
            config['security_level'] = 'High'
        elif 'Verified Boot' in features or 'Measured Boot' in features:
            config['security_level'] = 'Medium'
        else:
            config['security_level'] = 'Low'
            
        # Check for common issues
        if config['key_manifests_count'] == 0:
            config['issues'].append("No key manifests found")
        if config['boot_policies_count'] == 0:
            config['issues'].append("No boot policies found")
        if config['boot_policies_count'] > 1:
            config['warnings'].append("Multiple boot policies found")
            
        # Recommendations
        if 'Verified Boot' not in features:
            config['recommendations'].append("Enable Verified Boot for better security")
        if 'Measured Boot' not in features:
            config['recommendations'].append("Enable Measured Boot for attestation")
        if 'ACPI Table Protection' not in features:
            config['recommendations'].append("Consider enabling ACPI Table Protection")
            
        return config
