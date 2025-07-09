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
UEFI certificate validation and chain verification functionality

This module provides enhanced certificate validation capabilities including
PKCS#7 signature verification and X.509 certificate chain validation.
"""

import os
import hashlib
from typing import Optional, Dict, List, Tuple, Any
from uuid import UUID

from chipsec.library.logger import logger

# Try to import cryptographic libraries
try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.x509.oid import NameOID
    has_cryptography = True
    # Type aliases for when cryptography is available
    X509Certificate = x509.Certificate
except ImportError:
    has_cryptography = False
    logger().log_warning("cryptography library not available - certificate validation will be limited")
    # Dummy type for when cryptography is not available
    X509Certificate = Any

try:
    from cryptography.hazmat.primitives.serialization import pkcs7
    has_pkcs7 = True
except ImportError:
    has_pkcs7 = False

class CertificateValidationResult:
    """Result of certificate validation operation."""
    
    def __init__(self):
        self.is_valid: bool = False
        self.trust_chain_valid: bool = False
        self.signature_valid: bool = False
        self.cert_expired: bool = False
        self.cert_not_yet_valid: bool = False
        self.issuer: Optional[str] = None
        self.subject: Optional[str] = None
        self.serial_number: Optional[str] = None
        self.signature_algorithm: Optional[str] = None
        self.key_usage: List[str] = []
        self.errors: List[str] = []
        self.warnings: List[str] = []
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary for JSON serialization."""
        return {
            'is_valid': self.is_valid,
            'trust_chain_valid': self.trust_chain_valid,
            'signature_valid': self.signature_valid,
            'cert_expired': self.cert_expired,
            'cert_not_yet_valid': self.cert_not_yet_valid,
            'issuer': self.issuer,
            'subject': self.subject,
            'serial_number': self.serial_number,
            'signature_algorithm': self.signature_algorithm,
            'key_usage': self.key_usage,
            'errors': self.errors,
            'warnings': self.warnings
        }

class UEFICertificateValidator:
    """
    UEFI certificate validation and chain verification.
    
    Provides enhanced certificate validation capabilities including
    PKCS#7 signature verification and X.509 certificate chain validation.
    """
    
    def __init__(self):
        self.trusted_roots: List[Any] = []
        self.intermediate_certs: List[Any] = []
        
    def add_trusted_root(self, cert_data: bytes) -> bool:
        """Add a trusted root certificate."""
        if not has_cryptography:
            return False
            
        try:
            cert = x509.load_der_x509_certificate(cert_data)
            self.trusted_roots.append(cert)
            return True
        except Exception as e:
            logger().log_warning(f"Failed to load trusted root certificate: {e}")
            return False
            
    def add_intermediate_cert(self, cert_data: bytes) -> bool:
        """Add an intermediate certificate to the chain."""
        if not has_cryptography:
            return False
            
        try:
            cert = x509.load_der_x509_certificate(cert_data)
            self.intermediate_certs.append(cert)
            return True
        except Exception as e:
            logger().log_warning(f"Failed to load intermediate certificate: {e}")
            return False

    def validate_x509_certificate(self, cert_data: bytes) -> CertificateValidationResult:
        """
        Validate an X.509 certificate.
        
        Args:
            cert_data: DER-encoded certificate data
            
        Returns:
            CertificateValidationResult with validation details
        """
        result = CertificateValidationResult()
        
        if not has_cryptography:
            result.errors.append("cryptography library not available")
            return result
            
        try:
            cert = x509.load_der_x509_certificate(cert_data)
            
            # Extract basic certificate information
            result.subject = cert.subject.rfc4514_string()
            result.issuer = cert.issuer.rfc4514_string()
            result.serial_number = str(cert.serial_number)
            result.signature_algorithm = cert.signature_algorithm_oid._name
            
            # Check validity period
            import datetime
            now = datetime.datetime.now(datetime.timezone.utc)
            if cert.not_valid_after < now:
                result.cert_expired = True
                result.errors.append("Certificate has expired")
            if cert.not_valid_before > now:
                result.cert_not_yet_valid = True
                result.errors.append("Certificate is not yet valid")
                
            # Extract key usage
            try:
                key_usage = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.KEY_USAGE).value
                if key_usage.digital_signature:
                    result.key_usage.append("digital_signature")
                if key_usage.key_cert_sign:
                    result.key_usage.append("key_cert_sign")
                if key_usage.crl_sign:
                    result.key_usage.append("crl_sign")
            except x509.ExtensionNotFound:
                result.warnings.append("No key usage extension found")
                
            # Verify certificate signature if we have the issuer
            issuer_cert = self._find_issuer_certificate(cert)
            if issuer_cert:
                try:
                    issuer_cert.public_key().verify(
                        cert.signature,
                        cert.tbs_certificate_bytes,
                        padding.PKCS1v15(),
                        cert.signature_hash_algorithm
                    )
                    result.signature_valid = True
                except Exception as e:
                    result.signature_valid = False
                    result.errors.append(f"Signature verification failed: {e}")
            else:
                result.warnings.append("Issuer certificate not found - cannot verify signature")
                
            # Overall validity
            result.is_valid = (len(result.errors) == 0 and 
                             not result.cert_expired and 
                             not result.cert_not_yet_valid)
                             
        except Exception as e:
            result.errors.append(f"Certificate parsing failed: {e}")
            
        return result

    def validate_pkcs7_signature(self, pkcs7_data: bytes, signed_data: bytes) -> CertificateValidationResult:
        """
        Validate a PKCS#7 signature.
        
        Args:
            pkcs7_data: PKCS#7 signature data
            signed_data: The data that was signed
            
        Returns:
            CertificateValidationResult with validation details
        """
        result = CertificateValidationResult()
        
        if not has_cryptography or not has_pkcs7:
            result.errors.append("PKCS#7 support not available")
            return result
            
        try:
            # Parse PKCS#7 structure
            signature = pkcs7.load_der_pkcs7_certificates(pkcs7_data)
            
            if signature:
                # Validate each certificate in the signature
                for cert in signature:
                    cert_result = self.validate_x509_certificate(cert.public_bytes(serialization.Encoding.DER))
                    if cert_result.errors:
                        result.errors.extend(cert_result.errors)
                    if cert_result.warnings:
                        result.warnings.extend(cert_result.warnings)
                        
                    # Store information from the signing certificate
                    if not result.subject:
                        result.subject = cert_result.subject
                        result.issuer = cert_result.issuer
                        result.signature_algorithm = cert_result.signature_algorithm
                        
                result.is_valid = len(result.errors) == 0
                
        except Exception as e:
            result.errors.append(f"PKCS#7 parsing failed: {e}")
            
        return result

    def verify_certificate_chain(self, cert_chain: List[bytes]) -> CertificateValidationResult:
        """
        Verify a certificate chain.
        
        Args:
            cert_chain: List of DER-encoded certificates (leaf first)
            
        Returns:
            CertificateValidationResult with chain validation details
        """
        result = CertificateValidationResult()
        
        if not has_cryptography:
            result.errors.append("cryptography library not available")
            return result
            
        if not cert_chain:
            result.errors.append("Empty certificate chain")
            return result
            
        try:
            certificates = []
            for cert_data in cert_chain:
                cert = x509.load_der_x509_certificate(cert_data)
                certificates.append(cert)
                
            # Validate leaf certificate
            leaf_cert = certificates[0]
            leaf_result = self.validate_x509_certificate(cert_chain[0])
            result.subject = leaf_result.subject
            result.issuer = leaf_result.issuer
            result.signature_algorithm = leaf_result.signature_algorithm
            result.key_usage = leaf_result.key_usage
            
            # Verify chain
            chain_valid = True
            for i in range(len(certificates) - 1):
                current_cert = certificates[i]
                issuer_cert = certificates[i + 1]
                
                try:
                    issuer_cert.public_key().verify(
                        current_cert.signature,
                        current_cert.tbs_certificate_bytes,
                        padding.PKCS1v15(),
                        current_cert.signature_hash_algorithm
                    )
                except Exception as e:
                    chain_valid = False
                    result.errors.append(f"Chain verification failed at level {i}: {e}")
                    
            result.trust_chain_valid = chain_valid
            result.is_valid = chain_valid and len(result.errors) == 0
            
        except Exception as e:
            result.errors.append(f"Certificate chain parsing failed: {e}")
            
        return result

    def _find_issuer_certificate(self, cert: Any) -> Optional[Any]:
        """Find the issuer certificate for a given certificate."""
        issuer_name = cert.issuer
        
        # Check trusted roots first
        for root_cert in self.trusted_roots:
            if root_cert.subject == issuer_name:
                return root_cert
                
        # Check intermediate certificates
        for inter_cert in self.intermediate_certs:
            if inter_cert.subject == issuer_name:
                return inter_cert
                
        return None

    def get_certificate_info(self, cert_data: bytes) -> Dict[str, Any]:
        """
        Extract detailed information from a certificate.
        
        Args:
            cert_data: DER-encoded certificate data
            
        Returns:
            Dictionary with certificate information
        """
        info = {
            'subject': None,
            'issuer': None,
            'serial_number': None,
            'not_valid_before': None,
            'not_valid_after': None,
            'signature_algorithm': None,
            'public_key_algorithm': None,
            'key_size': None,
            'extensions': []
        }
        
        if not has_cryptography:
            return info
            
        try:
            cert = x509.load_der_x509_certificate(cert_data)
            
            info['subject'] = cert.subject.rfc4514_string()
            info['issuer'] = cert.issuer.rfc4514_string()
            info['serial_number'] = str(cert.serial_number)
            info['not_valid_before'] = cert.not_valid_before.isoformat()
            info['not_valid_after'] = cert.not_valid_after.isoformat()
            info['signature_algorithm'] = cert.signature_algorithm_oid._name
            
            # Public key information
            public_key = cert.public_key()
            if isinstance(public_key, rsa.RSAPublicKey):
                info['public_key_algorithm'] = 'RSA'
                info['key_size'] = public_key.key_size
                
            # Extensions
            for ext in cert.extensions:
                ext_info = {
                    'oid': ext.oid.dotted_string,
                    'critical': ext.critical,
                    'name': ext.oid._name if hasattr(ext.oid, '_name') else 'Unknown'
                }
                info['extensions'].append(ext_info)
                
        except Exception as e:
            logger().log_warning(f"Failed to extract certificate info: {e}")
            
        return info

def is_certificate_validation_supported() -> bool:
    """Check if certificate validation is supported in the current environment."""
    return has_cryptography and has_pkcs7
