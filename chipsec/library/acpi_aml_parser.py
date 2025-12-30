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
#


"""
Simple ACPI AML Binary Parser
Extracts OperationRegion definitions and _CRS resource descriptors from DSDT/SSDT binaries without external tools.
Supports both static OperationRegion declarations and dynamic _CRS method resource descriptors.
"""

from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple
import struct


@dataclass
class OperationRegion:
    """Represents a single OperationRegion definition."""
    name: str
    space_type: int
    space_type_name: str
    base: int
    length: int
    source: str = "OperationRegion"  # Track region source for debugging


class AMLParser:
    """Simple AML binary parser for OperationRegion enumeration."""
    
    # AML Opcodes
    OPCODE_OPERATION_REGION = 0x5B
    SUBOPCODE_OPERATION_REGION = 0x80
    OPCODE_NAME = 0x08
    OPCODE_STORE = 0x70
    OPCODE_METHOD = 0x14
    OPCODE_RETURN = 0xA4
    
    # Integer encoding opcodes
    ZERO_OP = 0x00
    ONE_OP = 0x01
    BYTE_PREFIX = 0x0A
    WORD_PREFIX = 0x0B
    DWORD_PREFIX = 0x0C
    QWORD_PREFIX = 0x0E
    
    # Space type names
    SPACE_TYPE_NAMES = {
        0x00: "SystemMemory",
        0x01: "SystemIO",
        0x02: "PCI_Config",
        0x03: "EmbeddedControl",
        0x04: "SMBus",
        0x05: "SystemCMOS",
        0x06: "PciBarTarget",
        0x07: "IPMI",
        0x08: "GeneralPurposeIO",
        0x09: "GenericSerialBus",
        0x0A: "PCC",
        0x0B: "PRM",
        0x0C: "FFH",
        0x0D: "GSBUS_OR_CCAGO",
    }
    
    def __init__(self):
        self.regions: List[OperationRegion] = []
        self.names: Dict[str, int] = {}  # Symbol table for Name() declarations
    
    def parse(self, dsdt_and_ssdts: List[bytes]) -> List[OperationRegion]:
        """
        Parse DSDT and optional SSDTs for OperationRegion definitions.
        
        Args:
            dsdt_and_ssdts: List of raw ACPI table binaries (header + content)
        
        Returns:
            List of OperationRegion objects
        """
        self.regions = []
        self.names = {}
        
        # First pass: collect all Name() declarations for symbol resolution
        for table_data in dsdt_and_ssdts:
            if len(table_data) < 36:
                continue
            aml_data = table_data[36:]
            self._scan_for_names(aml_data)
        
        # Second pass: scan for OperationRegion definitions
        for table_data in dsdt_and_ssdts:
            if len(table_data) < 36:
                continue
            aml_data = table_data[36:]
            self._scan_for_regions(aml_data)
        
        # Third pass: extract CRS Store field assignments (e.g., BAS1, LEN1, LIM1)
        for table_data in dsdt_and_ssdts:
            if len(table_data) < 36:
                continue
            aml_data = table_data[36:]
            crs_executor = CRSExecutor()
            crs_fields = crs_executor.extract_crs_fields(aml_data)
            
            # Create synthetic OperationRegions for each BAS field found
            for field_name, value in crs_fields.items():
                if field_name.startswith('BAS'):
                    # Extract the numeric suffix (e.g., "BAS1" -> 1)
                    base_name = field_name.rstrip('\x00')
                    suffix = base_name[3:]  # Get "1" from "BAS1"
                    
                    # Look for corresponding LEN and LIM fields
                    len_name = f'LEN{suffix}'
                    lim_name = f'LIM{suffix}'
                    
                    length = crs_fields.get(len_name, 0)
                    limit = crs_fields.get(lim_name, 0)
                    
                    if value > 0 and length > 0:
                        # Try to get the buffer name (PMCR, SPIR, P2BR) from mapping
                        buffer_name = crs_executor.field_to_buffer.get(base_name, '_CRS')
                        
                        # Create synthetic region from CRS fields
                        # Name format: PMCR:BAS1 or _CRS:BAS1 if buffer not found
                        region = OperationRegion(
                            name=f'{buffer_name}:{base_name}',
                            space_type=0,  # SystemMemory
                            space_type_name='SystemMemory',
                            base=value,
                            length=length,
                            source='CRS_Fields'
                        )
                        self.regions.append(region)
        
        # Sort by address for presentation
        self.regions = sorted([r for r in self.regions if r.base < 0x1000000000], 
                             key=lambda x: x.base)
        
        return self.regions
    
    def _scan_for_regions(self, aml_binary: bytes) -> None:
        """Scan binary for OperationRegion opcodes."""
        i = 0
        max_search = len(aml_binary)
        iter_count = 0
        max_iters = max_search * 2  # Safety: prevent infinite looping
        
        while i < max_search - 1 and iter_count < max_iters:
            iter_count += 1
            try:
                # Look for opcode sequence: 0x5B 0x80
                if (aml_binary[i] == self.OPCODE_OPERATION_REGION and 
                    i + 1 < len(aml_binary) and 
                    aml_binary[i + 1] == self.SUBOPCODE_OPERATION_REGION):
                    
                    # Found OperationRegion opcode, try to decode
                    region = self._decode_operation_region(aml_binary, i + 2)
                    if region:
                        self.regions.append(region)
                    # Always skip forward by at least 5 bytes
                    i += 5
                else:
                    i += 1
            except Exception:
                # On any error, skip forward
                i += 5
    
    def _scan_for_names(self, aml_binary: bytes) -> None:
        """Scan binary for Name() declarations to build symbol table."""
        i = 0
        max_search = len(aml_binary)
        iter_count = 0
        max_iters = max_search * 2
        
        while i < max_search - 1 and iter_count < max_iters:
            iter_count += 1
            try:
                # Look for Name opcode: 0x08
                if aml_binary[i] == self.OPCODE_NAME:
                    # Name(name, value) - try to extract
                    name, name_len = self._decode_name_string_simple(aml_binary, i + 1)
                    if name and name_len > 0 and name_len < 20:
                        pos = i + 1 + name_len
                        if pos < len(aml_binary):
                            value, val_len = self._decode_aml_integer(aml_binary, pos)
                            if value is not None and val_len > 0:
                                # Store in symbol table
                                self.names[name] = value
                    i += 5
                else:
                    i += 1
            except Exception:
                i += 5
    def _decode_operation_region(self, aml_binary: bytes, offset: int) -> Optional[OperationRegion]:
        """
        Decode a single OperationRegion definition.
        
        After opcode (0x5B 0x80):
            NameString (variable length, 1-4 bytes typically)
            SpaceType (1 byte)
            Address (AML Integer, 1-9 bytes)
            Length (AML Integer, 1-9 bytes)
        """
        if offset >= len(aml_binary) or offset + 5 > len(aml_binary):
            return None
        
        # Extract NameString (simple: just read up to 4 bytes as NameSeg)
        name, name_len = self._decode_name_string_simple(aml_binary, offset)
        if not name or name_len <= 0 or name_len > 20:
            return None
        
        pos = offset + name_len
        if pos >= len(aml_binary):
            return None
        
        # Extract SpaceType (1 byte)
        space_type = aml_binary[pos]
        pos += 1
        
        if pos >= len(aml_binary):
            return None
        
        # Extract Address (AML Integer)
        base, int_len = self._decode_aml_integer(aml_binary, pos)
        if base is None:
            # Try to resolve as variable reference
            var_name, var_len = self._decode_name_string_simple(aml_binary, pos)
            if var_name and var_name in self.names:
                base = self.names[var_name]
                int_len = var_len
            else:
                return None
        
        if int_len <= 0 or int_len > 10:
            return None
        
        pos += int_len
        if pos >= len(aml_binary):
            return None
        
        # Extract Length (AML Integer)
        length, int_len = self._decode_aml_integer(aml_binary, pos)
        if length is None:
            # Try to resolve as variable reference
            var_name, var_len = self._decode_name_string_simple(aml_binary, pos)
            if var_name and var_name in self.names:
                length = self.names[var_name]
                int_len = var_len
            else:
                return None
        
        if int_len <= 0 or int_len > 10:
            return None
        
        # Sanity checks
        if length == 0 or length > 0x10000000:  # Skip regions > 256MB
            return None
        if base == 0 or base == 0xFFFFFFFF:  # Skip invalid addresses
            return None
        
        space_type_name = self.SPACE_TYPE_NAMES.get(space_type, f"Unknown(0x{space_type:02X})")
        
        return OperationRegion(
            name=name,
            space_type=space_type,
            space_type_name=space_type_name,
            base=base,
            length=length
        )
    
    def _decode_name_string_simple(self, aml_binary: bytes, offset: int) -> Tuple[Optional[str], int]:
        """
        Simplified name string decoder - handles most common cases.
        Returns (name_string, bytes_consumed) or (None, 0) on error.
        """
        if offset >= len(aml_binary):
            return None, 0
        
        byte = aml_binary[offset]
        
        # RootPath prefix (0x5C)
        if byte == 0x5C:
            pos = offset + 1
            # Read NameSeg after root path
            if pos + 4 <= len(aml_binary):
                seg = self._read_name_seg(aml_binary, pos)
                if seg:
                    return '\\' + seg, 5
            return '\\', 1
        
        # ParentPath prefix (0x5E) - skip for now, just return None
        if byte == 0x5E:
            return None, 0
        
        # DualNamePath (0x2E)
        if byte == 0x2E:
            pos = offset + 1
            parts = []
            for _ in range(2):
                if pos + 4 <= len(aml_binary):
                    seg = self._read_name_seg(aml_binary, pos)
                    if seg:
                        parts.append(seg)
                        pos += 4
                    else:
                        break
            if len(parts) == 2:
                return '.'.join(parts), pos - offset
            return None, 0
        
        # MultiNamePath (0x2F)
        if byte == 0x2F:
            pos = offset + 1
            if pos >= len(aml_binary):
                return None, 0
            count = aml_binary[pos]
            pos += 1
            if count > 20 or count == 0:  # Sanity check
                return None, 0
            parts = []
            for _ in range(count):
                if pos + 4 <= len(aml_binary):
                    seg = self._read_name_seg(aml_binary, pos)
                    if seg:
                        parts.append(seg)
                        pos += 4
                    else:
                        break
            if len(parts) == count:
                return '.'.join(parts), pos - offset
            return None, 0
        
        # Simple NameSeg (4 characters: A-Z, 0-9, _)
        if self._is_name_char(byte):
            if offset + 4 <= len(aml_binary):
                seg = self._read_name_seg(aml_binary, offset)
                if seg:
                    return seg, 4
        
        return None, 0
    
    def _read_name_seg(self, aml_binary: bytes, offset: int) -> Optional[str]:
        """
        Read exactly 4 bytes as a NameSeg.
        Valid characters: A-Z, a-z, 0-9, _
        """
        if offset + 4 > len(aml_binary):
            return None
        
        seg = b''
        for i in range(4):
            byte = aml_binary[offset + i]
            if self._is_name_char(byte):
                seg += bytes([byte])
            elif byte == 0x5F:  # _ padding
                seg += bytes([byte])
            else:
                # Invalid character in NameSeg
                return None
        
        # Decode and strip trailing underscores
        name = seg.decode('ascii', errors='ignore').rstrip('_')
        return name if name else None
    
    def _is_name_char(self, byte: int) -> bool:
        """Check if byte is valid in a name (A-Z, a-z, 0-9, _)."""
        return ((ord('A') <= byte <= ord('Z')) or
                (ord('a') <= byte <= ord('z')) or
                (ord('0') <= byte <= ord('9')) or
                byte == ord('_'))
    
    def _decode_aml_integer(self, aml_binary: bytes, offset: int) -> Tuple[Optional[int], int]:
        """
        Decode AML Integer (variable-length encoding).
        Returns (value, bytes_consumed) or (None, 0) if variable reference detected.
        
        Formats:
            0x00 = zero (1 byte)
            0x01 = one (1 byte)
            0x0A = byte value follows (2 bytes total)
            0x0B = word value follows (3 bytes total)
            0x0C = dword value follows (5 bytes total)
            0x0E = qword value follows (9 bytes total)
            0x02-0x09 = literal single-byte values
        """
        if offset >= len(aml_binary):
            return None, 0
        
        opcode = aml_binary[offset]
        
        # Zero and one
        if opcode == self.ZERO_OP:
            return 0, 1
        elif opcode == self.ONE_OP:
            return 1, 1
        
        # Prefixed integers
        elif opcode == self.BYTE_PREFIX:
            if offset + 2 <= len(aml_binary):
                return aml_binary[offset + 1], 2
        elif opcode == self.WORD_PREFIX:
            if offset + 3 <= len(aml_binary):
                return struct.unpack('<H', aml_binary[offset + 1:offset + 3])[0], 3
        elif opcode == self.DWORD_PREFIX:
            if offset + 5 <= len(aml_binary):
                return struct.unpack('<I', aml_binary[offset + 1:offset + 5])[0], 5
        elif opcode == self.QWORD_PREFIX:
            if offset + 9 <= len(aml_binary):
                return struct.unpack('<Q', aml_binary[offset + 1:offset + 9])[0], 9
        
        # Direct single-byte values (0x02-0x09)
        elif 0x02 <= opcode <= 0x09:
            return opcode, 1
        
        # If it looks like a NameSeg or path, it's a variable reference
        # Return None to indicate this can't be decoded statically
        elif self._is_name_char(opcode) or opcode in (0x5C, 0x5E, 0x2E, 0x2F):
            return None, 0
        
        return None, 0


class ResourceDescriptorParser:
    """Parse resource descriptors in _CRS methods."""
    
    # Large resource descriptor opcodes (bit 7 = 1)
    DWORD_MEMORY = 0x87      # DWordMemory
    QWORD_MEMORY = 0x8A      # QWordMemory
    DWORD_IO = 0x81          # DWordIO
    QWORD_IO = 0x8B          # QWordIO
    DWORD_SPACE = 0x8C       # DWordSpace
    QWORD_SPACE = 0x8E       # QWordSpace
    
    def __init__(self):
        self.regions: List[Dict] = []
    
    def extract_from_crs_binary(self, aml_binary: bytes, field_values: Dict[str, int]) -> List[Dict]:
        """
        Scan _CRS method binary for resource descriptors and extract memory regions.
        field_values: dictionary of Store assignments (BAS1=0x..., LEN1=0x..., etc.)
        """
        regions = []
        i = 0
        
        while i < len(aml_binary) - 2:
            opcode = aml_binary[i]
            
            # Large resource items have bit 7 set (0x80-0xFF)
            if opcode >= 0x80:
                try:
                    # Large resource format: opcode, length_low, length_high, data...
                    if i + 2 >= len(aml_binary):
                        i += 1
                        continue
                    
                    length = aml_binary[i + 1] | (aml_binary[i + 2] << 8)
                    data_start = i + 3
                    data_end = data_start + length
                    
                    if data_end > len(aml_binary):
                        i += 1
                        continue
                    
                    # Parse based on opcode
                    if opcode in (self.DWORD_MEMORY, self.QWORD_MEMORY,
                                  self.DWORD_IO, self.QWORD_IO,
                                  self.DWORD_SPACE, self.QWORD_SPACE):
                        region = self._parse_address_space(opcode, aml_binary[data_start:data_end], field_values)
                        if region:
                            regions.append(region)
                    
                    i = data_end
                except Exception:
                    i += 1
            else:
                i += 1
        
        return regions
    
    def _parse_address_space(self, opcode: int, data: bytes, field_values: Dict[str, int]) -> Optional[Dict]:
        """Parse DWordMemory, QWordMemory, etc. resource descriptor."""
        if len(data) < 1:
            return None
        
        # Skip resource type specific parts, look for address/length
        # Format varies, but generally: flags, type_specific, then min/max/length
        
        try:
            if opcode in (self.DWORD_MEMORY, self.DWORD_IO, self.DWORD_SPACE):
                # DWord format
                if len(data) >= 20:
                    # Typical: flags(1), type(1), ... min(4), max(4), len(4)
                    # This is simplified - actual format varies by type
                    base = struct.unpack('<I', data[10:14])[0] if len(data) >= 14 else None
                    size = struct.unpack('<I', data[16:20])[0] if len(data) >= 20 else None
                    
                    if base and size and size > 0 and size < 0x10000000:
                        return {
                            'name': f'MEM_0x{base:08X}',
                            'base': base,
                            'size': size
                        }
            
            elif opcode in (self.QWORD_MEMORY, self.QWORD_IO, self.QWORD_SPACE):
                # QWord format
                if len(data) >= 36:
                    # Similar structure but 64-bit addresses
                    base = struct.unpack('<Q', data[14:22])[0] if len(data) >= 22 else None
                    size = struct.unpack('<Q', data[28:36])[0] if len(data) >= 36 else None
                    
                    if base and size and size > 0 and size < 0x10000000000:
                        return {
                            'name': f'MEM_0x{base:016X}',
                            'base': base,
                            'size': size
                        }
        except Exception:
            pass
        
        return None


class CRSExecutor:
    """Simple extractor for field assignments in _CRS methods."""
    
    OPCODE_STORE = 0x70
    OPCODE_METHOD = 0x14
    OPCODE_DEVICE = 0x82
    OPCODE_SCOPE = 0x10
    OPCODE_CREATE_DWORD_FIELD = 0x8A
    
    def __init__(self):
        self.field_values: Dict[str, int] = {}
        self.field_to_buffer: Dict[str, str] = {}  # Maps BAS1 -> PMCR, etc.
        self.context_method: str = "_CRS"  # Default to _CRS method name
    
    def extract_crs_fields(self, aml_binary: bytes) -> Dict[str, int]:
        """
        Scan for Store opcode patterns targeting BAS/LEN/LIM field assignments.
        Also maps field names to their source buffer names via CreateDWordField.
        """
        try:
            # First pass: build field-to-buffer mapping from CreateDWordField
            self._map_fields_to_buffers(aml_binary)
            
            # Second pass: scan for Store operations
            i = 0
            iterations = 0
            max_iter_limit = 1000000  # Hard stop after 1M iterations
            
            while i < len(aml_binary) - 5 and iterations < max_iter_limit:
                iterations += 1
                
                if aml_binary[i] == self.OPCODE_STORE:
                    try:
                        # Decode value following Store opcode
                        value, val_len = self._decode_simple_int(aml_binary, i + 1)
                        
                        if value is not None and 0 < val_len < 10:
                            # Check for valid name at target position
                            name_pos = i + 1 + val_len
                            if name_pos + 4 <= len(aml_binary):
                                # Extract 4-byte name
                                name_bytes = aml_binary[name_pos:name_pos+4]
                                
                                # Check if bytes are ASCII-like
                                try:
                                    name = name_bytes.decode('ascii')
                                    # Keep only BAS, LEN, LIM patterns
                                    if any(name.startswith(p) for p in ['BAS', 'LEN', 'LIM']):
                                        clean_name = name.rstrip('\x00')
                                        if clean_name and len(clean_name) >= 4:
                                            self.field_values[clean_name] = value
                                except:
                                    pass
                    except:
                        pass
                
                i += 1
        except:
            pass
        
        return self.field_values
    
    def _map_fields_to_buffers(self, aml_binary: bytes) -> None:
        """Build mapping of field names to buffer names via CreateDWordField opcodes."""
        try:
            i = 0
            while i < len(aml_binary) - 10:
                if aml_binary[i] == self.OPCODE_CREATE_DWORD_FIELD:
                    try:
                        # After CreateDWordField opcode comes:
                        # SourceBuffer (Name), ByteIndex (Integer), FieldName (Name)
                        
                        # Try to extract buffer name (usually 4 bytes)
                        pos = i + 1
                        if pos + 4 <= len(aml_binary):
                            # Extract potential buffer name (4 bytes)
                            buf_bytes = aml_binary[pos:pos+4]
                            try:
                                buf_name = buf_bytes.decode('ascii').rstrip('\x00')
                                if buf_name and len(buf_name) >= 3 and buf_name[0] not in '\x00\x01\x02':
                                    # Skip the buffer name and what follows (typically variable-length)
                                    # Try to find field name (BAS, LEN, LIM) in nearby bytes
                                    for j in range(pos, min(pos + 20, len(aml_binary) - 4)):
                                        field_bytes = aml_binary[j:j+4]
                                        try:
                                            field_name = field_bytes.decode('ascii').rstrip('\x00')
                                            if field_name and any(field_name.startswith(p) for p in ['BAS', 'LEN', 'LIM']):
                                                # Found a field name, map it to buffer
                                                self.field_to_buffer[field_name] = buf_name
                                                break
                                        except:
                                            pass
                            except:
                                pass
                    except:
                        pass
                i += 1
        except:
            pass
    
    def _find_crs_method_context(self, aml_binary: bytes) -> None:
        """Scan for _CRS method name for context."""
        try:
            # Look for pattern: Method opcode (0x14) followed by name string "_CRS"
            i = 0
            while i < len(aml_binary) - 10:
                if aml_binary[i] == self.OPCODE_METHOD:
                    # After Method opcode comes name (typically "_CRS" = 0x5F 0x43 0x52 0x53)
                    if i + 5 < len(aml_binary):
                        potential_name = aml_binary[i+1:i+5]
                        if b'_CRS' in potential_name or b'_CRS' == potential_name:
                            self.context_method = "_CRS"
                            return
                i += 1
        except:
            pass
    
    def _decode_simple_int(self, data: bytes, offset: int) -> Tuple[Optional[int], int]:
        """Decode integer at offset."""
        if offset >= len(data):
            return None, 0
        
        op = data[offset]
        if op == 0x00:
            return 0, 1
        elif op == 0x01:
            return 1, 1
        elif op == 0x0A and offset + 2 <= len(data):  # Byte
            return data[offset + 1], 2
        elif op == 0x0B and offset + 3 <= len(data):  # Word
            return struct.unpack('<H', data[offset + 1:offset + 3])[0], 3
        elif op == 0x0C and offset + 5 <= len(data):  # DWord
            return struct.unpack('<I', data[offset + 1:offset + 5])[0], 5
        elif op == 0x0E and offset + 9 <= len(data):  # QWord
            return struct.unpack('<Q', data[offset + 1:offset + 9])[0], 9
        elif 0x02 <= op <= 0x09:
            return op, 1
        
        return None, 0
    
    def _decode_simple_name(self, data: bytes, offset: int) -> Tuple[Optional[str], int]:
        """Decode a simple 4-byte name segment."""
        if offset + 4 > len(data):
            return None, 0
        
        seg = data[offset:offset+4]
        # Check if all bytes are valid name chars
        for b in seg:
            if not ((ord('A') <= b <= ord('Z')) or (ord('a') <= b <= ord('z')) or 
                    (ord('0') <= b <= ord('9')) or b == ord('_')):
                return None, 0
        
        name = seg.decode('ascii', errors='ignore').rstrip('_')
        return name if name else None, 4


class CRSResourceParser:
    """
    Extracts and decodes _CRS method resource descriptors from AML binary.
    Handles both static _CRS methods with direct Buffer returns and dynamic field assignments.
    """
    
    @staticmethod
    def parse_pkg_length(aml: bytes, pos: int) -> Tuple[int, int]:
        """
        Parse AML package length (variable-size encoding).
        
        Returns:
            (length, new_pos)
        """
        if pos >= len(aml):
            return 0, pos
        
        lead = aml[pos]
        pos += 1
        
        if lead < 0x40:
            return lead, pos
        
        byte_count = (lead >> 6) & 0x03
        length = lead & 0x0F
        
        for i in range(byte_count):
            if pos >= len(aml):
                return length, pos
            length |= (aml[pos] << (4 + 8 * i))
            pos += 1
        
        return length, pos
    
    @staticmethod
    def extract_crs_buffer(aml_bytes: bytes, target_name: bytes = b'_CRS') -> Optional[bytes]:
        """
        Walk AML binary to find _CRS method and extract its Buffer if simple Return(Buffer).
        
        Args:
            aml_bytes: Raw AML binary content
            target_name: Method name to search for (e.g., b'_CRS')
        
        Returns:
            Raw buffer bytes if found and parseable, None otherwise
        """
        pos = 0
        while pos < len(aml_bytes):
            try:
                opcode = aml_bytes[pos]
                
                if opcode == 0x14:  # MethodOp
                    pos += 1
                    pkg_len, pos = CRSResourceParser.parse_pkg_length(aml_bytes, pos)
                    end_pos = pos + pkg_len
                    
                    # NameString (4 bytes for simple name, or 0x00 0x00 for multi-segment)
                    if pos + 4 > len(aml_bytes):
                        pos = end_pos
                        continue
                    
                    name = aml_bytes[pos:pos+4]
                    pos += 4
                    
                    # Check if this is our target _CRS method
                    is_match = False
                    if target_name == b'_CRS' and name[:4] == b'_CRS':
                        is_match = True
                    elif name == target_name + b'\x00' * (4 - len(target_name)):
                        is_match = True
                    
                    if is_match:
                        # Skip flags byte
                        if pos >= len(aml_bytes):
                            pos = end_pos
                            continue
                        pos += 1
                        
                        # Look for ReturnOp (0xA4)
                        while pos < end_pos and pos < len(aml_bytes):
                            if aml_bytes[pos] == 0xA4:  # ReturnOp
                                pos += 1
                                
                                # Check for BufferOp (0x11)
                                if pos >= len(aml_bytes):
                                    break
                                if aml_bytes[pos] == 0x11:
                                    pos += 1
                                    buf_pkg_len, pos = CRSResourceParser.parse_pkg_length(aml_bytes, pos)
                                    
                                    # Parse BufferSize (assume simple ByteConst/WordConst)
                                    if pos >= len(aml_bytes):
                                        break
                                    
                                    if aml_bytes[pos] == 0x0A:  # ByteConst
                                        pos += 1
                                        if pos >= len(aml_bytes):
                                            break
                                        buf_size = aml_bytes[pos]
                                        pos += 1
                                    elif aml_bytes[pos] == 0x0B:  # WordConst
                                        pos += 1
                                        if pos + 2 > len(aml_bytes):
                                            break
                                        buf_size = struct.unpack('<H', aml_bytes[pos:pos+2])[0]
                                        pos += 2
                                    elif aml_bytes[pos] == 0x0C:  # DWordConst
                                        pos += 1
                                        if pos + 4 > len(aml_bytes):
                                            break
                                        buf_size = struct.unpack('<I', aml_bytes[pos:pos+4])[0]
                                        pos += 4
                                    else:
                                        break
                                    
                                    # Extract ByteList
                                    if pos + buf_size > len(aml_bytes):
                                        buf_size = len(aml_bytes) - pos
                                    
                                    buffer_data = aml_bytes[pos:pos + buf_size]
                                    return buffer_data
                                break
                            pos += 1
                    
                    pos = end_pos
                else:
                    pos += 1
            except Exception:
                pos += 1
        
        return None
    
    @staticmethod
    def decode_crs_buffer(buffer_bytes: bytes) -> List[Dict]:
        """
        Decode resource descriptors from _CRS Buffer bytes.
        
        Args:
            buffer_bytes: Raw resource descriptor buffer
        
        Returns:
            List of dicts: {type, description, address, size} for memory/IO resources
        """
        pos = 0
        resources = []
        
        while pos < len(buffer_bytes):
            if pos >= len(buffer_bytes):
                break
            
            tag = buffer_bytes[pos]
            
            # Check for End Tag (0x79)
            if tag == 0x79:
                if pos + 1 < len(buffer_bytes):
                    checksum = buffer_bytes[pos + 1]
                    # Optional: verify checksum
                break
            
            try:
                if tag & 0x80 == 0:  # Small descriptor
                    item_type = (tag >> 3) & 0x0F
                    length = tag & 0x07
                    data = buffer_bytes[pos + 1:pos + 1 + length]
                    pos += 1 + length
                else:  # Large descriptor
                    item_type = tag
                    if pos + 3 > len(buffer_bytes):
                        break
                    length = struct.unpack_from('<H', buffer_bytes, pos + 1)[0]
                    data = buffer_bytes[pos + 3:pos + 3 + length]
                    pos += 3 + length
                
                # Decode specific descriptor type
                res_dict = CRSResourceParser._decode_descriptor(item_type, data)
                if res_dict:
                    resources.append(res_dict)
            except Exception:
                pos += 1
        
        return resources
    
    @staticmethod
    def _decode_descriptor(item_type: int, data: bytes) -> Optional[Dict]:
        """Decode a single resource descriptor and extract address/size for memory resources."""
        
        try:
            # 0x84: 32-bit Memory Range (large)
            if item_type == 0x84:
                if len(data) >= 9:
                    flags = data[0]
                    min_addr = struct.unpack('<I', data[1:5])[0]
                    max_addr = struct.unpack('<I', data[5:9])[0]
                    alignment = struct.unpack('<I', data[9:13])[0] if len(data) >= 13 else 0
                    length = struct.unpack('<I', data[13:17])[0] if len(data) >= 17 else 0
                    
                    return {
                        'type': 'Memory32',
                        'address': min_addr,
                        'size': length if length > 0 else (max_addr - min_addr + 1),
                        'flags': flags,
                        'description': f'Memory32: base=0x{min_addr:08x}, size=0x{length:08x}'
                    }
            
            # 0x85: 32-bit Fixed Memory (large)
            elif item_type == 0x85:
                if len(data) >= 9:
                    flags = data[0]
                    base = struct.unpack('<I', data[1:5])[0]
                    length = struct.unpack('<I', data[5:9])[0]
                    
                    return {
                        'type': 'FixedMemory32',
                        'address': base,
                        'size': length,
                        'flags': flags,
                        'description': f'FixedMemory32: base=0x{base:08x}, size=0x{length:08x}'
                    }
            
            # 0x87: DWord Address Space (large) - Memory or I/O
            elif item_type == 0x87:
                if len(data) >= 23:
                    res_type = data[0]
                    gen_flags = data[1]
                    spec_flags = data[2]
                    min_addr = struct.unpack('<I', data[4:8])[0]
                    max_addr = struct.unpack('<I', data[8:12])[0]
                    gran = struct.unpack('<I', data[12:16])[0]
                    trans = struct.unpack('<I', data[16:20])[0]
                    length = struct.unpack('<I', data[20:24])[0]
                    
                    type_names = {0: 'Memory', 1: 'I/O', 2: 'BusNumber', 3: 'Reserved'}
                    type_str = type_names.get(res_type, 'Unknown')
                    
                    if res_type == 0:  # Memory
                        return {
                            'type': f'DWord{type_str}',
                            'address': min_addr,
                            'size': length if length > 0 else (max_addr - min_addr + 1),
                            'flags': gen_flags,
                            'description': f'DWord Memory: base=0x{min_addr:08x}, size=0x{length:08x}'
                        }
                    elif res_type == 1:  # I/O
                        return {
                            'type': f'DWord{type_str}',
                            'address': min_addr,
                            'size': length if length > 0 else (max_addr - min_addr + 1),
                            'flags': gen_flags,
                            'description': f'DWord I/O: base=0x{min_addr:04x}, size=0x{length:04x}'
                        }
            
            # 0x8A: QWord Address Space (large)
            elif item_type == 0x8A:
                if len(data) >= 47:
                    res_type = data[0]
                    gen_flags = data[1]
                    spec_flags = data[2]
                    min_addr = struct.unpack('<Q', data[4:12])[0]
                    max_addr = struct.unpack('<Q', data[12:20])[0]
                    gran = struct.unpack('<Q', data[20:28])[0]
                    trans = struct.unpack('<Q', data[28:36])[0]
                    length = struct.unpack('<Q', data[36:44])[0]
                    
                    type_names = {0: 'Memory', 1: 'I/O', 2: 'BusNumber', 3: 'Reserved'}
                    type_str = type_names.get(res_type, 'Unknown')
                    
                    if res_type == 0:  # Memory
                        return {
                            'type': f'QWord{type_str}',
                            'address': min_addr,
                            'size': length if length > 0 else (max_addr - min_addr + 1),
                            'flags': gen_flags,
                            'description': f'QWord Memory: base=0x{min_addr:016x}, size=0x{length:016x}'
                        }
            
            # 0x04: IRQ (small) - included for completeness
            elif item_type == 0x04:
                if len(data) >= 2:
                    flags = data[0]
                    irq_mask = struct.unpack('<H', data[1:3])[0] if len(data) >= 3 else data[1]
                    return {
                        'type': 'IRQ',
                        'description': f'IRQ: mask=0x{irq_mask:04x}'
                    }
            
            # 0x05: DMA (small)
            elif item_type == 0x05:
                if len(data) >= 2:
                    flags = data[0]
                    chan_mask = data[1]
                    return {
                        'type': 'DMA',
                        'description': f'DMA: channels=0x{chan_mask:02x}'
                    }
        
        except Exception:
            pass
        
        return None


def parse_operation_regions(tables: List[bytes]) -> List[Dict]:
    """
    Parse DSDT and SSDTs for all OperationRegion definitions.
    
    Args:
        tables: List of raw ACPI table binaries (header + AML content)
    
    Returns:
        List of dicts: {name, space_type, space_type_name, base, length}
    """
    parser = AMLParser()
    regions = parser.parse(tables)
    
    return [
        {
            'name': r.name,
            'space_type': r.space_type,
            'space_type_name': r.space_type_name,
            'base': r.base,
            'length': r.length,
            'source': r.source
        }
        for r in regions
    ]
