#!/usr/bin/env python3
"""
AMD PPR PDF to XML Register Definition Converter.

Parses AMD PPR PDF files and produces XML register definitions.
Uses a state machine approach for page-by-page processing.

Usage:
    python3 amd_ppr_pdf_to_xml.py <pdf1.pdf> [pdf2.pdf ...] [output.xml]
"""

import re
import html
import sys
import os
import pymupdf

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

# Devices that use indirect access type
INDIRECT_DEVICES = {'SMUTHM', 'MPM', 'NBIO', 'PCIE', 'GMI', 'DF', 'IOMMUL1INT', 'IOMMUL2A', 'IOMMUL2B'}

# Register type constants
REG_TYPE_MSR = 'msr'
REG_TYPE_IO = 'io'
REG_TYPE_MEMORY = 'memory'
REG_TYPE_PCICFG = 'pcicfg'
REG_TYPE_APIC = 'apic'
REG_TYPE_CPUID = 'cpuid'
REG_TYPE_MMIOBAR = 'mmiobar'
REG_TYPE_INDIRECT = 'indirect'

# ─────────────────────────────────────────────────────────────────────────────
# Pre-compiled Regex Patterns
# ─────────────────────────────────────────────────────────────────────────────

# Section pattern - matches "9 FCH", "9.2 FCH", "9.2.1 Some Title"
_SEC_RE = re.compile(r'^(\d+(?:\.\d+)*)\s+([\w\(].{1,110})$')

# Register header pattern
# Groups: 1=identifier, 2=name, 3/4=namespace
BOUNDARY_RE = re.compile(r"""(?x)^\s*(
    [A-Z][A-Z0-9]+(?:\[[^\]]+\])?[x_][\w\[\]\.]+
)(?:\s*\[([A-Za-z](?:[^\[\]]|\[[^\]]*\])+)\]\s*(?:\(([^)]+)\))?|\s*\(([^)]+)\))""")


# Field patterns
_BITS_HEADER_RE = re.compile(r'^Bits\s+Description', re.I)
# Fixed: allow optional whitespace before colon/period to handle PDF text extraction spacing
_FIELD_RE = re.compile(r'^(\d+(?::\d+)?)\s+([\w][\w\d]*(?:\[[^\]]*\])*)\s*(?:[:.]\s*(.*))?$')
_FIELD_NAME_RE = re.compile(r'^([A-Z][A-Za-z0-9]*(?:\[[^\]]*\])*)\s*[:.]\s+(.*)$')
_RESERVED_RE = re.compile(r'^(\d+(?::\d+)?)\s+Reserved\.?$')
_BIT_NUMBER_RE = re.compile(r'^(\d+(?::\d+)?)$')
_NS_LINE_RE = re.compile(r'^\s*\(([A-Za-z][^)\n]{2,100})\)')
# ValidValues marker pattern - allow optional space before colon
_VALIDVALUES_RE = re.compile(r'^ValidValues\s*:$')

# ValidValues patterns (simplified - we'll use layout-based parsing instead)
_TWO_COL_HEADER_RE = re.compile(r'^(?:Value|Bit)\s+Descriptions?$', re.I)
_THREE_COL_HEADER_RE = re.compile(r'^\[?Bit\]?\s+Name\s+Descriptions?$', re.I)
_BIT_DESC_HEADER_RE = re.compile(r'^Bit\s+Description$', re.I)

# 4-column field table header: "Field Name Bits Default Description"
# Used in some registers like RMTPLLCNTL0
_FOUR_COL_FIELD_HEADER_RE = re.compile(r'^Field\s+Name\s+Bits\s+Default\s+Description$', re.I)

# Table header pattern - matches "Table N:" where N is a number
_TABLE_HEADER_RE = re.compile(r'^Table\s+\d+\s*:', re.I)

# Table register description pattern - matches "REGISTER_NAME - RW/RO - N bits"
# Used in non-standard register definitions like RMT_PLLCNTL_0_REG
_TABLE_REG_DESC_RE = re.compile(r'^([A-Z][A-Za-z0-9_]+)\s*-\s*(RW|RO|RW1C|RW1S)\s*-\s*(\d+)\s*bits?$', re.I)

# Prose register reference pattern - matches "DEVICExoff[bits] is useful" or similar
# Used to extract device/offset from prose text before table-based register definitions
_PROSE_REG_REF_RE = re.compile(r'^([A-Z][A-Z0-9]{2,15})x([0-9A-Fa-f]+)\[(\d+:\d+)\]\s+is\s+', re.I)

# ACPI MMIO Space Allocation table entry pattern
# Matches "00FFh-0000h", "01FFh-0100h", etc. (HIGHh-LOWh format)
_ACPI_MMIO_RANGE_RE = re.compile(r'^([0-9A-Fa-f]+)h-([0-9A-Fa-f]+)h$')

# Offset list pattern in metadata - matches "DEVICExBASE[off1,off2,...];"
# e.g., GPIOx000[F8,F4,F0,EC,E8,...,00]; or AOACx0000[7E,7C,7A,...,40];
# Used to determine actual instance offsets and stride
_OFFSET_LIST_RE = re.compile(
    r'([A-Z][A-Z0-9]{2,15})x([0-9A-Fa-f]+)\[([0-9A-Fa-f,\s]+)\]\s*;'
)

# Address assignment pattern in metadata - matches "DEVICE=ADDRESSh"
# e.g., GPIO=FED8_1500h or AOAC=FED8_1E00h
_ADDR_ASSIGN_RE = re.compile(r'^[A-Z][A-Z0-9]{2,15}=[0-9A-Fa-f_]+h$')

# Metadata line patterns - lines that are metadata but don't start with '_'
# MSR address alone: MSRC001_029B
# Other register identifiers that appear as standalone metadata lines
_METADATA_LINE_RE = re.compile(
    r'^('
    r'MSR[C0-9A-Fa-f]{4}_[0-9A-Fa-f]{4}'  # MSR address: MSRC001_029B
    r'|IOAPIC[xX][0-9A-Fa-f]+'             # IOAPIC offset: IOAPICx0010
    r'|APIC[xX][0-9A-Fa-f]+'               # APIC offset: APICx080
    r'|[A-Z][A-Z0-9]{2,15}x[0-9A-Fa-f]+'   # Generic device offset pattern
    r')$'
)

# AccessType pattern in field descriptions - used to determine lock relationships
# Pattern: AccessType: NAMESPACE::RegisterName[FieldName] ? Read-only : Read-write
# or: AccessType: (NAMESPACE::Reg[Field] && NAMESPACE::Reg[Field]) ? Read-write : Read-only
_ACCESS_TYPE_RE = re.compile(
    r'AccessType:\s*'
    r'(\([^)]+\)|[A-Za-z_][A-Za-z0-9_:.\s\[\]]*)'  # Condition (with or without parens) - group 1
    r'\s*\?\s*(\w+-\w+)\s*:\s*(\w+-\w+)'  # ? value1 : value2 - groups 2, 3
)

# Locking field pattern - matches optional '!' followed by NAMESPACE::RegisterName[FieldName]
# Group 1: optional '!' or '~' (or None if not present)
# Group 2: namespace (e.g., "Core::X86::Msr" or "FCH::ITF::SPI")
# Group 3: register name (e.g., "HWCR" or "AltSPICS")
# Group 4: field name (e.g., "McStatusWrEn" or "SpiProtectLock")
_LOCK_FIELD_RE = re.compile(
    r'(!|\~)?([A-Za-z][A-Za-z0-9:]*)::([A-Za-z][A-Za-z0-9_]*)\s*\[([A-Za-z][A-Za-z0-9_]*)\]'
)

# XML formatting
_WHITESPACE_RE = re.compile(r'\s+')
_HYPHEN_WRAP_RE = re.compile(r'(\w)-\s+([a-z])')

# Field name extraction pattern - matches field name followed by optional metadata
# Field names are typically: NAME followed by ". Reset:", ". Read-only", or just "."
# Examples:
#   "CUR_TEMP. Reset: 000h. Provides the current control temperature" -> name="CUR_TEMP", desc="Reset: 000h. Provides..."
#   "SVI0_PLANE0_VDDCOR. Read-only. Reset: 000h. Read only. VDD by Telemetry" -> name="SVI0_PLANE0_VDDCOR", desc="Read-only. Reset..."
_FIELD_NAME_DESC_RE = re.compile(r'^([A-Z][A-Za-z0-9_]*(?:\[[^\]]*\])?)(?:\.\s*)?(.*)$')


# ─────────────────────────────────────────────────────────────────────────────
# Utility Functions
# ─────────────────────────────────────────────────────────────────────────────

def extract_field_name_and_desc(text: str) -> tuple:
    """Extract field name and description from field description text.

    Some PDFs have field descriptions in format: "NAME. Reset: XXX. Description text"
    This function separates the field name from the rest.

    Args:
        text: Field description text like "CUR_TEMP. Reset: 000h. Provides the current control temperature"

    Returns:
        tuple: (field_name, description) where description may be empty

    Examples:
        "CUR_TEMP. Reset: 000h. Provides the current control temperature"
            -> ("CUR_TEMP", "Reset: 000h. Provides the current control temperature")
        "SVI0_PLANE0_VDDCOR. Read-only. Reset: 000h. Read only."
            -> ("SVI0_PLANE0_VDDCOR", "Read-only. Reset: 000h. Read only.")
        "SomeFieldName"
            -> ("SomeFieldName", "")
    """
    if not text:
        return ('', '')

    # Try to match the pattern: NAME followed by optional ". desc"
    match = _FIELD_NAME_DESC_RE.match(text)
    if match:
        name = match.group(1)
        desc = match.group(2).strip()
        return (name, desc)

    # Fallback: if pattern doesn't match, look for first period
    period_idx = text.find('.')
    if period_idx > 0:
        name = text[:period_idx]
        desc = text[period_idx + 1:].strip()
        return (name, desc)

    # No period found - entire text is the name
    return (text, '')

def escape_xml(s: str) -> str:
    """Escape XML special characters."""
    return html.escape(str(s), quote=False).replace('"', '&quot;')


def parse_bits(bits_str: str) -> tuple:
    """Parse bit range string like '31:0' or '5' into (bit_start, size)."""
    if ':' in bits_str:
        hi, lo = map(int, bits_str.split(':'))
        return lo, hi - lo + 1
    return int(bits_str), 1


def calc_register_size(fields: list) -> int:
    """Calculate register size in bytes based on highest bit position."""
    if not fields:
        return 4
    max_bit = max(f['bit'] + f['size'] - 1 for f in fields)
    if max_bit <= 7:
        return 1
    elif max_bit <= 15:
        return 2
    elif max_bit <= 31:
        return 4
    return 8


def msr_to_addr(hi4: str, lo4: str) -> str:
    """Convert MSR high and low parts to full hex address."""
    return f'0x{int(hi4 + lo4, 16):08X}'


def get_instance_stride(lo_int: int, hi_int: int) -> int:
    """Return stride (1 or 2) for multi-instance range based on parity."""
    return 2 if (lo_int % 2 == hi_int % 2) else 1


def format_hex_offset(offset_str: str) -> str:
    """Format offset as hex string, preserving width from PDF input.

    Args:
        offset_str: Hex string (without 0x prefix)

    Examples:
        format_hex_offset('13') -> '0x13'
        format_hex_offset('000') -> '0x000'
        format_hex_offset('00000088') -> '0x00000088'
        format_hex_offset('02050') -> '0x02050'
    """
    val = int(offset_str, 16)
    width = len(offset_str)
    hex_str = format(val, f'0{width}X')
    return f'0x{hex_str}'


def get_xml_name(reg: dict) -> str:
    """Derive XML name from namespace or title."""
    if reg.get('xml_name_override'):
        return reg['xml_name_override']
    ns = reg.get('ns', '')
    name = ns.split('::')[-1].strip()
    return name if name else reg.get('name')


def get_device_from_namespace(ns: str) -> str:
    """Extract device name from namespace, handling FCH:: prefix and other patterns.

    Examples:
        FCH::ITF::LPC::RomProtect -> LPC
        FCH::PM::Pm1Stat -> ACPI (PM registers are ACPI registers)
        FCH::IOAPIC::IOSel -> IOAPIC
        FCH::TMR::HPET::HpetId -> HPET
        FCH::TMR::WDT::WatchdogCtl -> WDT
        FCH::SMI::EventStat -> SMI
        FCH::EMMC::EMMC_DEV_VEN_ID -> EMMCCFG
        IOMMUL1::L1_SB_LOCATION -> IOMMUL1INT
        IOMMUL2::L2_L2A_CK_GATE_CONTROL -> IOMMUL2A
        IOMMUL2::IOMMU_VENDOR_ID -> IOMMU
        SMU::THM::THM_TCON_CUR_TMP -> SMUTHM
    """
    if not ns:
        return ''

    # Handle FCH:: prefix patterns
    if ns.startswith('FCH::'):
        parts = ns.split('::')
        # FCH::ITF::<device>::... -> device
        if len(parts) >= 3 and parts[1] == 'ITF':
            return parts[2]  # e.g., LPC, SPI, ESPI
        # FCH::TMR::<device>::... -> device (HPET, WDT)
        if len(parts) >= 3 and parts[1] == 'TMR':
            return parts[2]  # e.g., HPET, WDT
        # FCH::PM::... -> device depends on register name
        # - Names starting with 'Acpi' (AcpiPm*, AcpiGpe*, AcpiSmi*) -> PM device
        # - Specific names (PmCtl, EventStat, etc.) -> ACPI device
        # - Other PM registers -> PM device
        if len(parts) >= 2 and parts[1] == 'PM':
            reg_name = parts[-1] if len(parts) >= 3 else ''
            # ACPI device registers (IO port registers)
            acpi_device_regs = {'PmCtl', 'TmrValue_ETmrValu', 'EventStat', 'EventEnable', 'SmiCmdPort', 'SmiCmdStat', 'Pm1Stat', 'Pm1En'}
            if reg_name in acpi_device_regs:
                return 'ACPI'
            # Acpi* prefixed registers are PM device (memory-mapped PM registers)
            # Other PM registers default to PM device
            return 'PM'
        # FCH::<device>::... -> device
        if len(parts) >= 2:
            return parts[1]  # e.g., SMI, IOAPIC, EMMC

    # Handle IOMMU patterns
    if ns.startswith('IOMMUL1::'):
        return 'IOMMUL1INT'
    if ns.startswith('IOMMUL2::'):
        # Check if it's MMIO BAR register
        if 'MMIO' in ns or 'IOMMU_' in ns.split('::')[-1]:
            return 'IOMMU'
        # For L2_ prefixed registers, determine which L2 controller
        name = ns.split('::')[-1] if '::' in ns else ns
        if name.startswith('L2_L2A_'):
            return 'IOMMUL2A'
        if name.startswith('L2_L2B_'):
            return 'IOMMUL2B'
        return 'IOMMU'  # Default for IOMMUL2 vendor/capability registers

    # Handle SMU patterns
    if ns.startswith('SMU::'):
        # SMU::THM::... -> SMUTHM
        parts = ns.split('::')
        if len(parts) >= 2:
            return 'SMU' + parts[1]  # e.g., SMUTHM

    # Default: use first segment, stripping L<digit> suffix
    first_seg = ns.split('::')[0] if '::' in ns else ns
    return re.sub(r'L\d+$', '', first_seg)


def format_description(text: str) -> str:
    """Normalize description text."""
    if not text or not text.strip():
        return ''
    text = _HYPHEN_WRAP_RE.sub(r'\1-\2', text)
    text = _WHITESPACE_RE.sub(' ', text).strip()
    if text and text[0].islower():
        text = text[0].upper() + text[1:]
    # Don't add period if text ends with :, ., !, or ?
    if text and text[-1] not in '.!?:':
        text += '.'
    return text


def extract_locking_fields(field_desc: str, current_reg_name: str = '', current_reg_ns: str = '') -> list:
    """Extract locking field information from AccessType in field description.

    Returns list of tuples: (register_name, field_name, lock_value) for fields that lock this register.
    Returns ALL locking fields found - the caller is responsible for selecting the dominant lock.

    lock_value is determined by the AccessType pattern:
    - If TRUE result is "Read-only" -> lock_value=1 (locked when condition is true)
    - If TRUE result is "Read-write" -> lock_value=0 (locked when condition is false)
    - If '!' operator precedes the field reference, the lock_value is inverted

    Note: We do NOT filter out locks from the same register because a lock field within
    a register can legitimately lock other fields in the same register. For example,
    AltSPICS[SpiProtectLock] locks AltSPICS[SpiProtectEn0] and AltSPICS[SpiProtectEn1].

    AccessType patterns:
    - AccessType: NAMESPACE::Reg[Field] ? Read-only : Read-write
      -> Reg[Field]=1 locks (Read-only when true), lock_value=1
    - AccessType: (Reg[Field] && Reg[Field2]) ? Read-write : Read-only
      -> Reg[Field]=0 AND Reg[Field2]=0 unlocks, lock_value=0
    - AccessType: (!Reg[Field]) ? Read-write : Read-only
      -> Reg[Field]=1 locks (because !1=0, false branch is Read-only), lock_value=1
    """
    locking_fields = []

    # Find AccessType in description
    at_match = _ACCESS_TYPE_RE.search(field_desc)
    if not at_match:
        return locking_fields

    # Groups: 1=condition, 2=value_when_true, 3=value_when_false
    condition_text = at_match.group(1)
    value_when_true = at_match.group(2)
    # value_when_false = at_match.group(3)

    # Determine lock value based on the AccessType pattern:
    # - If TRUE result is "Read-only" -> locked when condition is TRUE -> lock_value=1
    # - If TRUE result is "Read-write" -> locked when condition is FALSE -> lock_value=0
    if 'read-only' in value_when_true.lower():
        lock_value = 1  # Locked when condition is true
    else:
        lock_value = 0  # Locked when condition is false

    # Find all register[field] patterns in the condition only
    # New regex: (!)?ns::reg[field] - group 1 is optional '!'
    lock_matches = _LOCK_FIELD_RE.findall(condition_text)

    for not_op, ns, reg_name, field_name in lock_matches:
        # A lock field within the same register CAN lock other fields in that register.
        # We don't filter based on register name matching because this is a valid pattern.
        # The lock field itself (e.g., SpiProtectLock) won't have an AccessType referencing itself,
        # so we don't need to worry about true self-references.

        # If '!' operator is present, invert the lock_value
        final_lock_value = 1 - lock_value if not_op else lock_value

        locking_fields.append((reg_name, field_name, final_lock_value))

    # Return all locking fields - caller will determine which one locks the most fields
    return locking_fields


def process_lock_relationships(registers: list) -> dict:
    """Process all registers to build lock relationships.

    Returns a dict mapping:
    - locked_regs: register_name -> set containing single (locking_reg_name, locking_field_name, lock_value)
                  The lock is determined by which lock locks the most fields.
                  If multiple locks lock the same number of fields, the last one is used.
    - locking_info: (locking_reg_name, locking_field_name) -> {'locked_regs': [...], 'lock_value': value}
    """
    locked_regs = {}  # reg_name -> set of (locking_reg, locking_field, lock_value) - will contain only one entry
    locking_info = {}  # (locking_reg, locking_field) -> {'locked_regs': [...], 'lock_value': value}

    # Build a mapping of register names to registers
    reg_by_name = {}
    for reg in registers:
        name = reg.get('name', '')
        if name:
            reg_by_name[name] = reg

    # Process each register's fields for AccessType
    for reg in registers:
        reg_name = reg.get('name', '')
        if not reg_name:
            continue

        # Count how many fields each lock locks
        # Key: (locking_reg, locking_field), Value: {'count': int, 'lock_value': int}
        lock_field_counts = {}
        # Preserve order of locks encountered (for tie-breaking - use last one)
        lock_order = []

        for field in reg.get('fields', []):
            field_desc = field.get('desc', '')
            locking_fields = extract_locking_fields(field_desc, reg_name, reg.get('ns', ''))

            for lock_reg, lock_field, lock_value in locking_fields:
                lock_key = (lock_reg, lock_field)
                if lock_key not in lock_field_counts:
                    lock_field_counts[lock_key] = {'count': 0, 'lock_value': lock_value}
                    lock_order.append(lock_key)
                lock_field_counts[lock_key]['count'] += 1

        if lock_field_counts:
            # Find the lock that locks the most fields
            # If tie, use the last one encountered (last in lock_order)
            max_count = 0
            best_lock = None

            for lock_key in lock_order:  # Iterate in order, so ties go to last
                count = lock_field_counts[lock_key]['count']
                if count >= max_count:  # >= ensures last one wins on tie
                    max_count = count
                    best_lock = lock_key

            if best_lock:
                lock_value = lock_field_counts[best_lock]['lock_value']
                locked_regs[reg_name] = {(best_lock[0], best_lock[1], lock_value)}

            # Also update locking_info for all locks (for locks section generation)
            for lock_key in lock_field_counts:
                lock_value = lock_field_counts[lock_key]['lock_value']
                if lock_key not in locking_info:
                    locking_info[lock_key] = {'locked_regs': [], 'lock_value': lock_value}
                if reg_name not in locking_info[lock_key]['locked_regs']:
                    locking_info[lock_key]['locked_regs'].append(reg_name)

    return locked_regs, locking_info


# ─────────────────────────────────────────────────────────────────────────────
# Register Header Parsing
# ─────────────────────────────────────────────────────────────────────────────

def parse_register_header(match) -> dict:
    """Build register dict from generic BOUNDARY regex match.

    The regex captures:
    - Group 1: identifier (register address pattern)
    - Group 2: name (when [name] present), None otherwise
    - Group 3: namespace (when both [name] and (namespace) present)
    - Group 4: namespace (when only (namespace) present)

    This function parses the identifier to determine register type and extract details.
    """
    identifier = match.group(1)
    # Group 2 is name when [name] is present
    name = match.group(2).strip() if match.group(2) else ''
    # Group 3 is namespace when both [name] and (namespace) present
    # Group 4 is namespace when only (namespace) present
    ns = match.group(3) or match.group(4) or ''
    ns = ns.strip() if ns else ''

    # Reject if name looks like a bit range (e.g., "7:0", "31:25")
    # This happens when MISC2x30[7:0] is incorrectly parsed as identifier + [name]
    if name and re.match(r'^\d+:\d+$', name):
        return None

    # Helper to extract name from namespace
    def name_from_ns(ns_val, fallback):
        return ns_val.split('::')[-1] if '::' in ns_val and ns_val else fallback

    # Determine register type based on identifier prefix and parse accordingly

    # MSR patterns: MSRxxxx_xxxx or MSRxxxx_x[lo...hi] or MSRxxxx_xxxx...MSRxxxx_xxxx
    if identifier.startswith('MSR'):
        return _parse_msr_identifier(identifier, name, ns, name_from_ns)

    # PCI config patterns: DxxFxxoff or DxxFxxoff[lo...hi]
    if re.match(r'^D[0-9A-Fa-f]{2}F[0-9A-Fa-f]x', identifier):
        return _parse_pci_identifier(identifier, name, ns, name_from_ns)

    # APIC patterns: APICxoff or APICx[pre][lo...hi]suf
    if identifier.startswith('APIC'):
        return _parse_apic_identifier(identifier, name, ns, name_from_ns)

    # IOAPIC patterns: IOAPICxnnnn_indirectaddressoffset
    if identifier.startswith('IOAPIC'):
        return _parse_ioapic_identifier(identifier, name, ns, name_from_ns)

    # IO patterns: IOxport or IOxport_xidx
    # IMPORTANT: Must match only IOx<hex> patterns, not device patterns like IOMMUL2Ax... or IOMMUBARx...
    # IO port identifiers start with exactly "IOx" (not "IO<letters>x")
    if identifier.startswith('IOx'):
        return _parse_io_identifier(identifier, name, ns, name_from_ns)

    # CPUID patterns: CPUID_Fnxxxxxxxx_Exxx or CPUID_Fnxxxxxxxx_Exxx_xxx
    if identifier.startswith('CPUID'):
        return _parse_cpuid_identifier(identifier, name, ns, name_from_ns)

    # PM patterns: PMxoff or PMxoff[lo...hi] (must start with PMx, not PMC)
    if identifier.startswith('PMx'):
        return _parse_pm_identifier(identifier, name, ns, name_from_ns)

    # HPET patterns: HPETxoff or HPETxoff[lo...hi]
    if identifier.startswith('HPET'):
        return _parse_hpet_identifier(identifier, name, ns, name_from_ns)

    # SDHC patterns: SDHCxoff
    if identifier.startswith('SDHC'):
        return _parse_sdhc_identifier(identifier, name, ns, name_from_ns)

    # MMIO BAR patterns: DEVICEBARxoff
    if 'BAR' in identifier and 'x' in identifier:
        return _parse_bar_identifier(identifier, name, ns, name_from_ns)

    # Generic device patterns: DEVICExoff or DEVICExoff[lo...hi] or DEVICE[lo...hi]xoff
    return _parse_device_identifier(identifier, name, ns, name_from_ns)


def _parse_msr_identifier(identifier: str, name: str, ns: str, name_from_ns) -> dict:
    """Parse MSR identifier patterns using a single unified regex."""

    # Unified regex explanation:
    # 1. ^MSR                        : Starts with MSR
    # 2. ([0-9A-Fa-f]{4})            : Group 1 - High 4 hex digits
    # 3. _                           : Underscore separator
    # 4. ([0-9A-Fa-f]{1,4})          : Group 2 - Low part (1-4 digits).
    #                                  Covers single full address (4) or range prefix (1-3).
    # 5. (?: ... )?                  : Optional non-capturing group for range suffix
    #    A) \s*\.\.\.\s*MSR...       : Matches explicit range " ... MSR..."
    #       (Non-capturing end address since original code only used start)
    #    B) \[...\]...               : Matches suffix range notation
    #       ([0-9A-Fa-f]+)           : Group 3 - Range start
    #       \.\.\.                   : Ellipsis
    #       ([0-9A-Fa-f]+)           : Group 4 - Range end
    #       \]                       : Closing bracket
    #       ([0-9A-Fa-f]*)           : Group 5 - Optional suffix after bracket

    msr_unified_re = re.compile(
        r'^MSR'
        r'([0-9A-Fa-f]{4})_'                # Group 1: High 4 digits
        r'([0-9A-Fa-f]{1,4})'               # Group 2: Low part (flexible size)
        r'(?:'                              # Optional Range Part Start
        r'\s*\.\.\.\s*MSR([C0-9A-Fa-f]{4}_[0-9A-Fa-f]{1,4})' # Case: Explicit Range
        r'|\[([0-9A-Fa-f]+)\.\.\.([0-9A-Fa-f]+)\]([0-9A-Fa-f]*)'   # Case: Suffix Range [lo...hi]suffix
        r')?$'                              # Optional Range Part End
    )

    match = msr_unified_re.match(identifier)
    if not match:
        return None

    hi4 = match.group(1)
    lo_part = match.group(2)

    # Common properties
    base_result = {
        'type': REG_TYPE_MSR,
        'name': name,
        'title': name,
        'ns': ns
    }

    if match.group(6) is not None:
        # Case: MSRxxxx_x[lo...hi]suffix
        lo_int = int(match.group(4), 16)
        hi_int = int(match.group(5), 16)
        lo_suffix = match.group(6)

        stride = get_instance_stride(lo_int, hi_int)
        dw = max(len(match.group(4)), len(match.group(5)))

        # Calculate all addresses in range
        addrs = [lo_part + format(v, f'0{dw}X') + lo_suffix for v in range(lo_int, hi_int + 1, stride)]

        base_result.update({
            'multi': True,
            'multi_label': 'MSR',
            'msr': msr_to_addr(hi4.zfill(4), addrs[0].zfill(4)),
            'todo_ids': [f'MSR{hi4.upper()}_{a.upper().zfill(4)}' for a in addrs[1:]]
        })
    elif match.group(3) is not None:
        # Case: MSRxxxx_x...MSRxxxx_x
        msr_end = match.group(3)
        base_result.update({
            'multi': True,
            'multi_label': 'MSR',
            'msr': msr_to_addr(hi4.zfill(4), lo_part.zfill(4)),
            'todo_ids': [f'MSR{msr_end}']
        })
    else:
        # Case: Single MSR
        base_result['msr'] = msr_to_addr(hi4.zfill(4), lo_part.zfill(4))

    return base_result


def _parse_pci_identifier(identifier: str, name: str, ns: str, name_from_ns) -> dict:
    """Parse PCI config identifier patterns: DxxFxxoff."""
    # Pattern: DxxFxxoff[lo...hi] (with range)
    range_match = re.match(r'^D([0-9A-Fa-f]{2})F([0-9A-Fa-f])x([0-9A-Fa-f]+)\[([0-9A-Fa-f]+)\.\.\.([0-9A-Fa-f]+)\]$', identifier)
    if range_match:
        dev = range_match.group(1)
        func = range_match.group(2)
        off_prefix = range_match.group(3)
        lo_int = int(range_match.group(4), 16)
        hi_int = int(range_match.group(5), 16)
        stride = get_instance_stride(lo_int, hi_int)
        first_offset_val = int(off_prefix + format(lo_int, 'X'), 16)
        return {
            'type': REG_TYPE_PCICFG,
            'name': name_from_ns(ns, name) if name else name_from_ns(ns, ns),
            'title': name,
            'ns': ns,
            'device': get_device_from_namespace(ns),
            'offset': f'0x{first_offset_val:03X}',
            'multi': True,
            'multi_label': 'PCICFG',
            'todo_ids': [f'D{dev}F{func}x{off_prefix}{format(v, "X")}'
                        for v in range(lo_int + stride, hi_int + 1, stride)]
        }

    # Pattern: DxxFxxoff (single)
    single_match = re.match(r'^D([0-9A-Fa-f]{2})F([0-9A-Fa-f])x([0-9A-Fa-f]+)$', identifier)
    if single_match:
        offset = single_match.group(3)
        return {
            'type': REG_TYPE_PCICFG,
            'name': name_from_ns(ns, name) if name else name_from_ns(ns, ns),
            'title': name,
            'ns': ns,
            'device': get_device_from_namespace(ns),
            'offset': format_hex_offset(offset)
        }

    return None


def _parse_apic_identifier(identifier: str, name: str, ns: str, name_from_ns) -> dict:
    """Parse APIC identifier patterns."""
    # Pattern: APICxpre[lo...hi]suf (with range)
    range_match = re.match(r'^APICx([0-9A-Fa-f]{1,2})\[([0-9A-Fa-f])\.\.\.([0-9A-Fa-f])\]([0-9A-Fa-f]*)$', identifier, re.IGNORECASE)
    if range_match:
        pre = range_match.group(1)
        lo_int = int(range_match.group(2), 16)
        hi_int = int(range_match.group(3), 16)
        suf = range_match.group(4)
        stride = get_instance_stride(lo_int, hi_int)
        dw = max(len(range_match.group(2)), len(range_match.group(3)))
        addrs = [pre + format(v, f'0{dw}X') + suf for v in range(lo_int, hi_int + 1, stride)]
        return {
            'type': REG_TYPE_APIC,
            'name': name,
            'title': name,  # Preserve name from [Name] bracket
            'ns': ns,
            'multi': True,
            'multi_label': 'APIC',
            'offset': f'0x{int(addrs[0], 16):03X}',
            'todo_ids': [f'APICx{a.upper().zfill(3)}' for a in addrs[1:]]
        }

    # Pattern: APICxoff (single)
    single_match = re.match(r'^APICx([0-9A-Fa-f]+)$', identifier, re.IGNORECASE)
    if single_match:
        return {
            'type': REG_TYPE_APIC,
            'name': name,
            'title': name,  # Preserve name from [Name] bracket
            'ns': ns,
            'offset': f'0x{int(single_match.group(1), 16):03X}'
        }

    return None


def _parse_ioapic_identifier(identifier: str, name: str, ns: str, name_from_ns) -> dict:
    """Parse IOAPIC identifier patterns.

    IOAPIC registers can be:
    1. Direct access: IOAPICxNNNN (e.g., IOAPICx0000 for IOSel)
       - offset = NNNN
    2. Indirect access: IOAPICxNNNN_indirectaddressoffsetXX (e.g., IOAPICx0010_indirectaddressoffset02)
       - offset = NNNN (the IO Window register)
       - IOSel = XX (value to write to IOSel register to access this indirect register)
    """
    # Pattern: IOAPICxnnnn_indirectaddressoffset[lo...hi]
    range_match = re.match(r'^IOAPICx([0-9A-Fa-f]+)_indirectaddressoffset\[([0-9A-Fa-f]+)\.\.\.([0-9A-Fa-f]+)\]$', identifier, re.IGNORECASE)
    if range_match:
        base_off = range_match.group(1)
        lo_str = range_match.group(2)
        lo_int = int(lo_str, 16)
        hi_int = int(range_match.group(3), 16)
        stride = get_instance_stride(lo_int, hi_int)
        return {
            'type': REG_TYPE_MEMORY,
            'name': name_from_ns(ns, name) if name else name_from_ns(ns, ns),
            'title': name,
            'ns': ns,
            'device': 'IOAPIC',
            'multi': True,
            'multi_label': 'IOAPIC_IND',
            'offset': format_hex_offset(base_off),
            'iosel': '0x' + lo_str.upper(),
            'iosel_base': lo_int,
            'todo_ids': [f'IOAPIC_IND{format(v, "X")}' for v in range(lo_int + stride, hi_int + 1, stride)]
        }

    # Pattern: IOAPICxnnnn_indirectaddressoffsetXX (single indirect access)
    # e.g., IOAPICx0010_indirectaddressoffset02 -> offset=0x0010, IOSel=0x02
    single_match = re.match(r'^IOAPICx([0-9A-Fa-f]+)_indirectaddressoffset([0-9A-Fa-f]+)$', identifier, re.IGNORECASE)
    if single_match:
        base_off = single_match.group(1)
        indirect_off = single_match.group(2)
        return {
            'type': REG_TYPE_MEMORY,
            'name': name_from_ns(ns, name) if name else name_from_ns(ns, ns),
            'title': name,
            'ns': ns,
            'device': 'IOAPIC',
            'offset': format_hex_offset(base_off),
            'iosel': '0x' + indirect_off.upper()
        }

    # Pattern: IOAPICxnnnn (direct register access, e.g., IOAPICx0000 for IOSel)
    # These are memory-mapped registers at the IOAPIC base address (FEC0_0000h)
    direct_match = re.match(r'^IOAPICx([0-9A-Fa-f]+)$', identifier, re.IGNORECASE)
    if direct_match:
        return {
            'type': REG_TYPE_MEMORY,
            'name': name_from_ns(ns, name) if name else name_from_ns(ns, ns),
            'title': name,
            'ns': ns,
            'device': 'IOAPIC',
            'offset': format_hex_offset(direct_match.group(1))
        }

    return None


def _parse_io_identifier(identifier: str, name: str, ns: str, name_from_ns) -> dict:
    """Parse IO port identifier patterns."""
    # Pattern: IOxport_xidx (indexed IO)
    indexed_match = re.match(r'^IOx([0-9A-Fa-f]+)_x([0-9A-Fa-f]+)$', identifier, re.IGNORECASE)
    if indexed_match:
        return {
            'type': REG_TYPE_IO,
            'name': name,
            'title': name,  # Preserve name from [Name] bracket
            'ns': ns,
            'port': format_hex_offset(indexed_match.group(1)),
            'index': '0x' + indexed_match.group(2)
        }

    # Pattern: IOxport (single)
    single_match = re.match(r'^IOx([0-9A-Fa-f]+)$', identifier, re.IGNORECASE)
    if single_match:
        return {
            'type': REG_TYPE_IO,
            'name': name_from_ns(ns, name) if name else name_from_ns(ns, ns),
            'title': name,
            'ns': ns,
            'port': format_hex_offset(single_match.group(1))
        }

    return None


def _parse_cpuid_identifier(identifier: str, name: str, ns: str, name_from_ns) -> dict:
    """Parse CPUID identifier patterns."""
    # Pattern: CPUID_Fnxxxxxxxx_Exxx_xxx or CPUID_Fnxxxxxxxx_Exxx
    match = re.match(r'^CPUID_Fn([0-9A-Fa-f]{8})_E([A-Z]+(?:[A-Z0-9]*)?)(?:_x([0-9A-Fa-f]+))?$', identifier)
    if match:
        eax = match.group(1)
        output = match.group(2)
        ecx = match.group(3)
        return {
            'type': REG_TYPE_CPUID,
            'name': name,
            'title': name,  # Preserve name from [Name] bracket
            'ns': ns,
            'eax': f'0x{eax.upper()}',
            'output': 'E' + output,
            'ecx': f'0x{ecx.upper()}' if ecx else None
        }

    return None


def _parse_pm_identifier(identifier: str, name: str, ns: str, name_from_ns) -> dict:
    """Parse PM/ACPI identifier patterns."""
    # Pattern: PMxoff or PMxoff[lo...hi]
    match = re.match(r'^PMx([0-9A-Fa-f]+)$', identifier, re.IGNORECASE)
    if match:
        offset = match.group(1)
        parsed_name = name_from_ns(ns, name) if name else name_from_ns(ns, ns)
        # Determine device based on register name
        if ns.startswith('FCH::PM::'):
            acpi_device_regs = {'PmCtl', 'TmrValue_ETmrValu', 'EventStat', 'EventEnable',
                               'SmiCmdPort', 'SmiCmdStat', 'Pm1Stat', 'Pm1En'}
            device = 'ACPI' if parsed_name in acpi_device_regs else 'PM'
        else:
            device = get_device_from_namespace(ns)
        return {
            'type': REG_TYPE_MEMORY,
            'name': parsed_name,
            'title': name,
            'ns': ns,
            'device': device,
            'offset': format_hex_offset(offset)
        }

    return None


def _parse_hpet_identifier(identifier: str, name: str, ns: str, name_from_ns) -> dict:
    """Parse HPET identifier patterns."""
    # Pattern: HPETxoff[lo...hi]
    range_match = re.match(r'^HPETx([0-9A-Fa-f]+)\[([0-9A-Fa-f]+)\.\.\.([0-9A-Fa-f]+)\]([0-9A-Fa-f]*)$', identifier, re.IGNORECASE)
    if range_match:
        pre = range_match.group(1)
        lo_int = int(range_match.group(2), 16)
        hi_int = int(range_match.group(3), 16)
        suf = range_match.group(4)
        stride = get_instance_stride(lo_int, hi_int)
        dw = max(len(range_match.group(2)), len(range_match.group(3)))
        addrs = [pre + format(v, f'0{dw}X') + suf for v in range(lo_int, hi_int + 1, stride)]
        return {
            'type': REG_TYPE_MEMORY,
            'name': name_from_ns(ns, name) if name else name_from_ns(ns, ns),
            'title': name,
            'ns': ns,
            'device': 'HPET',
            'multi': True,
            'multi_label': 'HPET',
            'offset': format_hex_offset(addrs[0]),
            'todo_ids': [f'HPETx{a.upper()}' for a in addrs[1:]]
        }

    # Pattern: HPETxoff (single)
    single_match = re.match(r'^HPETx([0-9A-Fa-f]+)$', identifier, re.IGNORECASE)
    if single_match:
        return {
            'type': REG_TYPE_MEMORY,
            'name': name_from_ns(ns, name) if name else name_from_ns(ns, ns),
            'title': name,
            'ns': ns,
            'device': 'HPET',
            'offset': format_hex_offset(single_match.group(1))
        }

    return None


def _parse_sdhc_identifier(identifier: str, name: str, ns: str, name_from_ns) -> dict:
    """Parse SDHC identifier patterns."""
    # Pattern: SDHCxoff
    match = re.match(r'^SDHCx([0-9A-Fa-f]+)$', identifier, re.IGNORECASE)
    if match:
        return {
            'type': REG_TYPE_MMIOBAR,
            'name': name_from_ns(ns, ns),
            'title': ns,
            'ns': ns,
            'bar': 'SDHC',
            'offset': format_hex_offset(match.group(1))
        }

    return None


def _parse_bar_identifier(identifier: str, name: str, ns: str, name_from_ns) -> dict:
    """Parse MMIO BAR identifier patterns."""
    # Pattern: DEVICEBARxoff
    match = re.match(r'^([A-Z][A-Z0-9]+)BARx([0-9A-Fa-f]+)$', identifier)
    if match:
        bar_name = match.group(1)
        offset = match.group(2)
        return {
            'type': REG_TYPE_MMIOBAR,
            'name': name_from_ns(ns, ns),
            'title': ns,
            'ns': ns,
            'bar': bar_name + 'BAR',
            'offset': format_hex_offset(offset)
        }

    return None


def _parse_device_identifier(identifier: str, name: str, ns: str, name_from_ns) -> dict:
    """Parse generic device identifier patterns."""
    # Pattern: DEVICE[lo...hi]xoff (range before offset)
    range_before_match = re.match(r'^([A-Z][A-Z0-9]{2,15})\[([0-9A-Fa-f]+)\.\.\.([0-9A-Fa-f]+)\]x([0-9A-Fa-f]+)$', identifier)
    if range_before_match:
        dev = range_before_match.group(1)
        lo_int = int(range_before_match.group(2), 16)
        hi_int = int(range_before_match.group(3), 16)
        offset = range_before_match.group(4)
        stride = get_instance_stride(lo_int, hi_int)
        reg_type = get_register_type_from_device(dev, ns)
        return {
            'type': reg_type,
            'name': name_from_ns(ns, ns),
            'title': ns,
            'ns': ns,
            'multi': True,
            'multi_label': dev,
            'device': dev + format(lo_int, 'X'),
            'offset': format_hex_offset(offset),
            'todo_ids': [f'{dev}{format(v, "X")}' for v in range(lo_int + stride, hi_int + 1, stride)]
        }

    # Pattern: DEVICExbase[lo...hi] (range after offset)
    range_after_match = re.match(r'^([A-Z][A-Z0-9]{2,15})x([0-9A-Fa-f]+)\[([0-9A-Fa-f]+)\.\.\.([0-9A-Fa-f]+)\]$', identifier)
    if range_after_match:
        dev = range_after_match.group(1)
        base = range_after_match.group(2)
        lo_str = range_after_match.group(3)
        hi_str = range_after_match.group(4)
        lo_int = int(lo_str, 16)
        hi_int = int(hi_str, 16)
        stride = get_instance_stride(lo_int, hi_int)
        reg_type = get_register_type_from_device(dev, ns)
        base_val = int(base, 16)
        lo_width = len(lo_str)
        first_offset = (base_val << (lo_width * 4)) + lo_int
        width = max(len(base) + lo_width, 4)
        return {
            'type': reg_type,
            'name': name_from_ns(ns, name) if name else name_from_ns(ns, ns),
            'title': name,
            'ns': ns,
            'multi': True,
            'multi_label': dev,
            'device': dev,
            'offset': format_hex_offset(format(first_offset, f'0{width}X')),
            'todo_ids': [f'{dev}x{format(first_offset + v * stride, f"0{width}X")}'
                        for v in range(1, (hi_int - lo_int) // stride + 1)]
        }

    # Pattern: DEVICEx[lo...hi] (range with no base offset - e.g., SBRMIx[04...4A])
    range_no_base_match = re.match(r'^([A-Z][A-Z0-9]{2,15})x\[([0-9A-Fa-f]+)\.\.\.([0-9A-Fa-f]+)\]$', identifier)
    if range_no_base_match:
        dev = range_no_base_match.group(1)
        lo_str = range_no_base_match.group(2)
        hi_str = range_no_base_match.group(3)
        lo_int = int(lo_str, 16)
        hi_int = int(hi_str, 16)
        stride = get_instance_stride(lo_int, hi_int)
        reg_type = get_register_type_from_device(dev, ns)
        width = max(len(lo_str), 2)
        return {
            'type': reg_type,
            'name': name_from_ns(ns, name) if name else name_from_ns(ns, ns),
            'title': name,
            'ns': ns,
            'multi': True,
            'multi_label': dev,
            'device': dev,
            'offset': format_hex_offset(format(lo_int, f'0{width}X')),
            'todo_ids': [f'{dev}x{format(v, f"0{width}X")}'
                        for v in range(lo_int + stride, hi_int + 1, stride)]
        }

    # Pattern: DEVICExoff[hi:lo] (bits range - special case for RMTPLLCNTL0)
    bits_match = re.match(r'^([A-Z][A-Z0-9]{2,15})x([0-9A-Fa-f]+)\[(\d+:\d+)\]$', identifier)
    if bits_match:
        dev = bits_match.group(1)
        offset = bits_match.group(2)
        bits_range = bits_match.group(3)
        reg_type = get_register_type_from_device(dev, '')
        return {
            'type': reg_type,
            'name': None,
            'title': None,
            'ns': '',
            'device': dev,
            'offset': format_hex_offset(offset),
            'pending_name': True,
            'bits_range': bits_range
        }

    # Pattern: DEVICExoff (single)
    single_match = re.match(r'^([A-Z][A-Z0-9]{2,15})x([0-9A-Fa-f]+)$', identifier)
    if single_match:
        dev = single_match.group(1)
        offset = single_match.group(2)
        reg_type = get_register_type_from_device(dev, ns)
        return {
            'type': reg_type,
            'name': name_from_ns(ns, name) if name else name_from_ns(ns, ns),
            'title': name,
            'ns': ns,
            'device': dev,
            'offset': format_hex_offset(offset)
        }

    return None



def get_register_type_from_device(dev: str, ns: str = '') -> str:
    """Determine register type based on device name and namespace.

    Priority:
    1. If device is in INDIRECT_DEVICES -> 'indirect'
    2. If device starts with SMU or is SMUTHM -> 'indirect'
    3. If device starts with IOMMUL (IOMMUL1INT, IOMMUL2A, IOMMUL2B) -> 'indirect'
    4. If device is IOMMU (PCI config space) -> 'pcicfg'
    5. Check namespace for additional hints
    6. Default -> 'memory'
    """
    # Direct device name checks
    if dev in INDIRECT_DEVICES:
        return 'indirect'
    if dev.startswith('SMU'):
        return 'indirect'
    if dev.startswith('IOMMUL'):
        return 'indirect'
    if dev == 'IOMMU':
        return 'pcicfg'

    # Check namespace for additional hints
    if ns:
        # IOMMUL1:: prefix -> indirect via IOMMUL1INT
        if ns.startswith('IOMMUL1::'):
            return 'indirect'
        # IOMMUL2:: prefix with L2_L2A_ or L2_L2B_ -> indirect
        if ns.startswith('IOMMUL2::'):
            name = ns.split('::')[-1] if '::' in ns else ''
            if name.startswith('L2_L2A_') or name.startswith('L2_L2B_'):
                return 'indirect'
        # SMU:: prefix -> indirect via SMUTHM etc.
        if ns.startswith('SMU::'):
            return 'indirect'
        # Check if first segment is in INDIRECT_DEVICES
        ns_dev = ns.split('::')[0]
        if ns_dev in INDIRECT_DEVICES or ns_dev.startswith('SMU') or ns_dev.startswith('IOMMUL'):
            return 'indirect'

    # Default to memory
    return 'memory'


def smart_join_spans(spans: list) -> str:
    """Join spans intelligently, avoiding spaces before punctuation.

    Punctuation characters that should not have a space before them:
    : . , ; ! ? ) ]

    Punctuation characters that should not have a space after them:
    [ (
    """
    if not spans:
        return ''

    result = []
    prev_span_text = ''

    for span_text, x0, y0, x1, y1 in spans:
        stripped = span_text.strip()
        if not stripped:
            continue

        # Check if this span starts with punctuation that shouldn't have a preceding space
        starts_with_punct = stripped[0] in ':.,;!?)\'"`]-'

        # Check if previous span ends with punctuation that indicates no space needed after
        # Include '[' and '(' to avoid space after opening brackets
        prev_ends_with_punct = prev_span_text and prev_span_text[-1] in ':.,;!?(\'"`[-'

        if result and not starts_with_punct and not prev_ends_with_punct:
            result.append(' ')

        result.append(stripped)
        prev_span_text = stripped

    return ''.join(result)


def extract_page_lines_with_positions(page) -> list:
    """Extract lines from page with full position info for each text span.

    Returns list of (text, x_pos, y_pos, spans) tuples sorted by y then x.
    Each span is (text, x0, y0, x1, y1) for individual text elements.
    """
    blocks = page.get_text("dict", flags=pymupdf.TEXT_PRESERVE_WHITESPACE)["blocks"]
    if not blocks:
        return []

    # Collect all spans with their positions
    all_spans = []
    for block in blocks:
        if "lines" not in block:
            continue
        for line in block["lines"]:
            for span in line["spans"]:
                text = span["text"]
                if text.strip():
                    x0, y0, x1, y1 = span["bbox"]
                    all_spans.append((text, x0, y0, x1, y1))

    # Group spans by y-position (with tolerance)
    y_tolerance = 3.0
    y_groups = {}
    for span in all_spans:
        text, x0, y0, x1, y1 = span
        # Find existing group or create new one
        found = False
        for y_key in y_groups:
            if abs(y_key - y0) <= y_tolerance:
                y_groups[y_key].append(span)
                found = True
                break
        if not found:
            y_groups[y0] = [span]

    # Sort by y, then by x within each y group
    result = []
    for y in sorted(y_groups.keys()):
        spans = sorted(y_groups[y], key=lambda s: s[1])  # Sort by x0
        # Create combined line text using smart joining
        combined_text = smart_join_spans(spans)
        min_x = min(s[1] for s in spans)
        result.append((combined_text, min_x, y, spans))

    return result


# ─────────────────────────────────────────────────────────────────────────────
# State Machine for Page Processing
# ─────────────────────────────────────────────────────────────────────────────

class PDFProcessor:
    """State machine for processing PDF pages and extracting registers.

    Supports processing multiple PDF files, accumulating all registers and metadata.
    Usage:
        processor = PDFProcessor()
        processor.process_pdfs(['vol1.pdf', 'vol2.pdf'])
        regs = processor.registers
        pci_devices = processor.pci_devices
        # ... etc
    """

    MAX_VV_ENTRIES = 100
    HEADER_FOOTER_GAP_THRESHOLD = 15

    def __init__(self):
        # Initialize all state
        self._init_accumulated_state()
        self._reset_pdf_state()
        self._reset_page_state()

    def _init_accumulated_state(self):
        """Initialize state that accumulates across all PDFs."""
        # PCI devices extracted from PCI Device ID Assignments table
        self.pci_devices = []
        self.pci_table_pages = []

        # Memory ranges extracted from "Memory Map - Main Memory"
        self.memory_ranges = {}  # device_name -> {'address': str, 'max_offset': int}
        self.memory_map_pages = []

        # IMA (Indirect Memory Access) entries from "Memory Map - SMN"
        self.ima_entries = {}  # device_name -> {'base': str}
        self.ima_pages = []

        # IO BARs extracted from "IO mapped base address" text patterns
        self.io_bars = []  # list of {'name': str, 'register': str, 'base_field': str, 'page': int}

        # Address space mappings from "Address Space Mapping" table
        self.address_mappings = []  # list of {'name': str, 'access': str, 'address': str, 'size': str, 'is_reserved': bool}
        self.address_mapping_pages = []

        # ACPI MMIO Space Allocation ranges
        self.acpi_mmio_ranges = []  # list of {'name': str, 'offset': int, 'size': int, 'is_reserved': bool}
        self.acpi_mmio_table_pages = []

        # Reference string extracted from first PDF (e.g., "55570-B1 Rev 3.14")
        self.reference = "FIXME"

        # All registers from all PDFs
        self.registers = []

        # Current volume number (1-indexed)
        self.current_volume = 0

    def _reset_pdf_state(self):
        """Reset state that should be cleared between PDFs."""
        # Track if we've found the start of PCI device table
        self.pci_table_started = False

        # State for multi-page address mapping table parsing
        self.addr_map_current_func = None
        self.addr_map_current_addr_parts = []
        self.addr_map_table_started = False

        # Section titles for current PDF
        self.section_titles = {}

        # Register state machine
        self.state = 'IDLE'
        self.current_reg = None
        self.current_fields = []
        self.current_desc_lines = []
        self.current_desc_line_info = []
        self.current_field = None
        self.current_section = None
        self.start_page = None
        self.last_content_page = None  # Track last page where content was added
        self.in_register_metadata = False

        # Multi-line offset list accumulation
        self.offset_list_buffer = []
        self.offset_list_device = None
        self.offset_list_base = None

        # ValidValues state - reset between PDFs
        self.vv_col1_x = None
        self.vv_col2_x = None
        self.vv_col3_x = None
        self.vv_entries = []
        self.vv_current_value = []
        self.vv_current_name = []
        self.vv_current_desc = []
        self.vv_in_table = False
        self.vv_lines = []
        self.vv_is_bit_desc = False

        # Field table column positions - reset between PDFs
        self.field_bits_x = None
        self.field_desc_x = None

        # 4-column field table format - reset between PDFs
        self.field_4col_format = False
        self.field_4col_name_x = None
        self.field_4col_bits_x = None
        self.field_4col_default_x = None
        self.field_4col_desc_x = None
        self.field_4col_current = None

        # Prose register reference tracking - for non-standard register formats
        # like "MISC2x30[7:0] is useful..." followed by table-based definition
        self.pending_prose_device = None
        self.pending_prose_offset = None
        self.pending_prose_bits = None
        self.pending_prose_text = None  # Full prose text for description
        self.pending_table_title = None  # Table title (e.g., "RMT PLLCNTL0 REG")
        self.desc_complete = False  # Flag to indicate description is already complete

    def _reset_page_state(self):
        """Reset state that should be cleared between pages."""
        self.current_page = None
        # Note: header_y and footer_y are detected per-page but stored in local variables
        # in _process_single_pdf(), so they don't need to be reset here
        self.bullet_levels = []

        # Note: ValidValues state (vv_entries, vv_in_table, etc.) is NOT reset here
        # because ValidValues tables can span multiple pages. The state is cleared
        # when ValidValues are finalized or when a new PDF is processed.

        # Note: Field table column positions (field_bits_x, field_desc_x) are NOT reset here
        # because field tables can span multiple pages. They are reset when:
        # - A new PDF is processed (_reset_pdf_state)
        # - A new register starts (_transition_to_fields)
        # - A 4-column field table is detected (overrides 2-column settings)

    def process_pdfs(self, pdf_paths: list):
        """Process multiple PDF files, accumulating all registers and metadata.

        Args:
            pdf_paths: List of paths to PDF files to process
        """
        for pdf_num, pdf_path in enumerate(pdf_paths, 1):
            print(f"Processing {pdf_path}...", file=sys.stderr)
            self.current_volume = pdf_num
            self._reset_pdf_state()
            self._process_single_pdf(pdf_path)

    def _process_single_pdf(self, pdf_path: str):
        """Process a single PDF file."""
        doc = pymupdf.open(pdf_path)
        try:
            total_pages = len(doc)

            # Calculate global left margin from first page (before header/footer filtering)
            first_page = doc[0]
            first_page_lines = extract_page_lines_with_positions(first_page)
            self.page_left_margin = min((x for _, x, _, _ in first_page_lines), default=0)

            # Extract reference info from first PDF only
            if self.current_volume == 1:
                self._extract_reference(first_page)

            for page_num in range(1, total_pages + 1):
                self._reset_page_state()
                self.current_page = page_num
                page = doc[page_num - 1]
                page_text = page.get_text()
                lines = extract_page_lines_with_positions(page)

                # Detect header/footer y-positions FIRST
                header_y, footer_y = self._detect_header_footer(page)

                # Filter out header/footer lines immediately based on y-position
                if header_y is not None or footer_y is not None:
                    filtered = []
                    for text, x_pos, y_pos, spans in lines:
                        if header_y is not None and y_pos <= header_y:
                            continue
                        if footer_y is not None and y_pos >= footer_y:
                            continue
                        filtered.append((text, x_pos, y_pos, spans))
                    lines = filtered

                # Extract PCI devices from PCI Device ID Assignments table
                self._extract_pci_devices(lines, page_text, page_num)

                # Extract memory ranges from "Memory Map - Main Memory" section
                self._extract_memory_ranges(lines, page_text, page_num)

                # Extract IMA entries from "Memory Map - SMN" section
                self._extract_ima_entries(lines, page_text, page_num)

                # Extract IO BARs from "IO mapped base address" patterns
                self._extract_io_bars(page_text, page_num)

                # Extract address space mappings from "Address Space Mapping" table
                self._extract_address_mappings(lines, page_text, page_num)

                # Extract ACPI MMIO Space Allocation ranges
                self._extract_acpi_mmio_ranges(lines, page_text, page_num)

                # Process each line
                for line_info in lines:
                    self._process_line(line_info)

                if page_num == total_pages:
                    self._finalize_register()

        finally:
            doc.close()

        # Calculate actual memory range sizes after all registers are parsed
        self._calculate_memory_range_sizes()

    def _extract_reference(self, first_page):
        """Extract reference info from first page of first PDF."""
        first_page_text = first_page.get_text()
        lines = first_page_text.strip().split('\n')

        # First line typically contains: "55898 Rev 0.50 - May 27, 2021"
        doc_info = lines[0].strip() if lines else ""

        # Look for title line
        title = ""
        family = ""
        model = ""
        for line in lines[1:10]:
            line = line.strip()
            match = re.match(r'PPR(?: Vol \d+)? for AMD Family (\d+h) (Models? \d+h(?:,\d+h)?)', line)
            if match:
                family = match.group(1)
                model = match.group(2)
                break

        # Look for revision info
        revision = ""
        for line in lines:
            rev_match = re.search(r'Revision\s+([A-Z]\d)', line)
            if rev_match:
                revision = f"Revision {rev_match.group(1)}"
                break

        # Build title from family, model, revision
        if family and model:
            title = f"PPR for AMD Family {family} {model}"

        # Build reference string
        if title and revision:
            self.reference = f"{title}, {revision}. {doc_info}"
        elif doc_info:
            self.reference = doc_info

    def _finalize_register(self):
        """Finalize the current register and add volume tag."""
        if self.current_reg:
            self.current_reg['volume'] = self.current_volume
            self._do_finalize_register()

    def _do_finalize_register(self):
        """Internal method to finalize register - calls the implementation."""
        self._finalize_register_impl()

    def _detect_header_footer(self, page) -> tuple:
        """Detect header and footer y-positions for a specific page."""
        blocks = page.get_text("dict", flags=pymupdf.TEXT_PRESERVE_WHITESPACE)["blocks"]

        if not blocks:
            return None, None

        y_positions = []
        for block in blocks:
            if "lines" not in block:
                continue
            for line in block["lines"]:
                text = "".join(span["text"] for span in line["spans"])
                if text.strip():
                    y0 = line["bbox"][1]
                    y_positions.append(y0)

        if len(y_positions) < 3:
            return None, None

        y_positions = sorted(set(y_positions))
        gaps = [(y_positions[i+1] - y_positions[i], i) for i in range(len(y_positions)-1)]

        if not gaps:
            return None, None

        max_gap = max(g[0] for g in gaps)

        if max_gap < self.HEADER_FOOTER_GAP_THRESHOLD:
            return None, None

        header_y = None
        footer_y = None

        page_height = page.rect.height
        header_zone = page_height * 0.15
        footer_zone = page_height * 0.85

        for gap, idx in gaps[:min(3, len(gaps))]:
            if gap > self.HEADER_FOOTER_GAP_THRESHOLD and y_positions[idx] < header_zone:
                header_y = y_positions[idx]
                break

        for gap, idx in reversed(gaps[-min(3, len(gaps)):]):
            if gap > self.HEADER_FOOTER_GAP_THRESHOLD and y_positions[idx + 1] > footer_zone:
                footer_y = y_positions[idx + 1]
                break

        return header_y, footer_y

    def _convert_bullets(self, text: str, line_info_list: list) -> str:
        """Convert bullet lists to hierarchical numbered lists with proper context detection."""
        if '•' not in text or not self.bullet_levels:
            return text

        QUANTIZE_STEP = 5.0
        text_to_x = {}
        for line_text, x_pos, y_pos, spans in line_info_list:
            stripped = line_text.strip()
            quantized_x = round(x_pos / QUANTIZE_STEP) * QUANTIZE_STEP
            text_to_x[stripped] = quantized_x

        quantized_levels = [round(lvl / QUANTIZE_STEP) * QUANTIZE_STEP for lvl in self.bullet_levels]

        left_margin = min(text_to_x.values()) if text_to_x else 0

        lines = text.split('\n')
        result = []
        level_counters = {}
        current_content = []

        for line in lines:
            stripped = line.strip()
            if not stripped:
                if current_content:
                    result.append(' '.join(current_content))
                    current_content = []
                continue

            line_x = text_to_x.get(stripped, quantized_levels[0] if quantized_levels else 0)

            if stripped.startswith('•'):
                if current_content:
                    result.append(' '.join(current_content))
                    current_content = []

                bullet_text = stripped[1:].strip()

                indent_level = 0
                for i, level_x in enumerate(quantized_levels):
                    if line_x >= level_x - 10:
                        indent_level = i

                for lvl in list(level_counters.keys()):
                    if lvl > indent_level:
                        del level_counters[lvl]

                if indent_level in level_counters:
                    level_counters[indent_level] += 1
                else:
                    level_counters[indent_level] = 1

                num_parts = []
                for lvl in range(indent_level + 1):
                    if lvl in level_counters:
                        num_parts.append(str(level_counters[lvl]))
                    else:
                        level_counters[lvl] = 1
                        num_parts.append('1')

                num = '.'.join(num_parts)
                current_content = [f"{num}) {bullet_text}"]
            else:
                if line_x <= left_margin + 5 and current_content:
                    if ':' in stripped and not stripped.startswith('See ') and not stripped.startswith('E.g.'):
                        result.append(' '.join(current_content))
                        current_content = []
                        level_counters = {}
                        result.append(stripped)
                        continue

                if current_content:
                    current_content.append(stripped)
                else:
                    result.append(stripped)

        if current_content:
            result.append(' '.join(current_content))

        return _WHITESPACE_RE.sub(' ', ' '.join(result)).strip()

    def _extract_pci_devices(self, lines: list, page_text: str, page_num: int):
        """Extract PCI device entries from PCI Device ID Assignments table.

        Detects the table by looking for "Table N: PCI Device ID Assignments" header
        together with the characteristic table row pattern (VIDh DIDh Bus Dev Fun Component).
        Once started, continues extracting from subsequent pages that have the pattern.

        Args:
            lines: List of (text, x_pos, y_pos, spans) tuples, already filtered for header/footer
            page_text: Full text of the page (for pattern matching)
            page_num: Page number (1-indexed)
        """
        # Check if this page contains the PCI Device ID Assignments table header
        has_table_header = bool(re.search(r'Table\s+\d+:\s*PCI\s+Device\s+ID\s+Assignments', page_text, re.IGNORECASE))

        # Check if this page has characteristic PCI table row pattern
        # Pattern: VIDh DIDh (e.g., "1022h 15D0h")
        has_pci_pattern = bool(re.search(r'[0-9A-Fa-f]{4}h\s+[0-9A-Fa-f]{4}h', page_text))

        # Determine if we should process this page:
        # - Start: page has BOTH table header AND pci pattern (actual table, not TOC)
        # - Continue: table already started and page has pci pattern
        should_process = False

        if has_table_header and has_pci_pattern:
            # This is the actual table start (not TOC which has header but no data)
            should_process = True
            self.pci_table_started = True
        elif self.pci_table_started and has_pci_pattern:
            # Continuation of multi-page table
            should_process = True

        if not should_process:
            return

        # Track page for comment
        if page_num not in self.pci_table_pages:
            self.pci_table_pages.append(page_num)

        # Build rows from lines: group spans by y-position
        # Each line is (text, x_pos, y_pos, spans) where spans is list of (text, x0, y0, x1, y1)
        rows = {}  # y-position -> list of (x-position, text)
        for line_text, x_pos, y_pos, spans in lines:
            y = round(y_pos, 0)
            for span in spans:
                span_text, x0, y0, x1, y1 = span
                span_text = span_text.strip()
                if span_text:
                    if y not in rows:
                        rows[y] = []
                    rows[y].append((x0, span_text))

        # Sort rows by y-position
        for y in sorted(rows.keys()):
            cells = sorted(rows[y], key=lambda c: c[0])  # Sort by x position
            texts = [c[1] for c in cells]

            # Check if this looks like a table row: VIDh DIDh Bus Dev Fun Component
            if len(texts) >= 6:
                # Check if first two columns are hex values ending with 'h'
                if (texts[0].endswith('h') and len(texts[0]) == 5 and
                    texts[1].endswith('h') and len(texts[1]) == 5):
                    try:
                        vid = texts[0][:-1].upper()  # Remove 'h' suffix
                        did = texts[1][:-1].upper()
                        bus_str = texts[2]
                        dev = int(texts[3])
                        fun = int(texts[4])
                        component = ' '.join(texts[5:])  # May have spaces in component name

                        # Validate hex values
                        int(vid, 16)
                        int(did, 16)

                        # Check for duplicates
                        device_key = (vid, did, bus_str, dev, fun)
                        if not any((d['vid'], d['did'], d['bus'], d['dev'], d['fun']) == device_key
                                   for d in self.pci_devices):
                            self.pci_devices.append({
                                'vid': vid,
                                'did': did,
                                'bus': bus_str,
                                'dev': dev,
                                'fun': fun,
                                'component': component
                            })
                    except (ValueError, IndexError):
                        pass

    def _extract_memory_ranges(self, lines: list, page_text: str, page_num: int):
        """Extract memory range entries from 'Memory Map - Main Memory' section.

        Args:
            lines: List of (text, x_pos, y_pos, spans) tuples, already filtered for header/footer
            page_text: Full text of the page (for pattern matching)
            page_num: Page number (1-indexed)
        """
        # Look for "Memory Map - Main Memory" header
        if 'Memory Map - Main Memory' not in page_text:
            return

        # Skip Table of Contents pages - check for actual table content
        # The real Memory Map page has entries like "FEC00000:" or physical addresses
        if not re.search(r'[A-Fa-f0-9]{6,}:.*x[0-9A-Fa-f]+', page_text):
            return

        # Track page for comment
        if page_num not in self.memory_map_pages:
            self.memory_map_pages.append(page_num)

        # Build spans from lines (already filtered for header/footer)
        spans = []
        for line_text, x_pos, y_pos, line_spans in lines:
            for span in line_spans:
                span_text, x0, y0, x1, y1 = span
                span_text = span_text.strip()
                if span_text:
                    spans.append((span_text, y0, x0))

        # Sort by y then x
        spans.sort(key=lambda s: (s[1], s[2]))

        # Pattern to match lines like: FEC00000: IOAPICx0000...x0010
        # Format: <hex_address>: <device>x<range_start>...<range_end> or <device>x<offset>
        # Namespace follows on same y-position at higher x

        # Group spans by y-position (with tolerance)
        y_tolerance = 3.0
        y_groups = {}
        for text, y, x in spans:
            # Find existing group or create new one
            found_group = None
            for group_y in y_groups:
                if abs(y - group_y) < y_tolerance:
                    found_group = group_y
                    break
            if found_group is None:
                found_group = y
            if found_group not in y_groups:
                y_groups[found_group] = []
            y_groups[found_group].append((x, text))

        # Process each row
        for y in sorted(y_groups.keys()):
            cells = sorted(y_groups[y], key=lambda c: c[0])  # Sort by x position

            # Look for pattern: hex_address: device_info
            # First column should have format like "FEC00000:" or "FEC00000: IOAPICx..."
            if not cells:
                continue

            first_text = cells[0][1]

            # Check if this looks like a memory map entry
            # Pattern: HEX_ADDR: DEVICE_INFO or HEX_ADDRh: DEVICE_INFO
            match = re.match(r'^([0-9A-Fa-f_]+)(h)?:\s*(.*)$', first_text)
            if not match:
                continue

            addr_str = match.group(1).replace('_', '')
            device_info = match.group(3)

            # Get namespace from second column if present
            namespace = ''
            if len(cells) >= 2:
                namespace = cells[1][1]

            # If device_info is empty, this might be a continuation line
            # where device name is in a separate span
            if not device_info and len(cells) >= 2:
                device_info = cells[1][1]
                namespace = cells[2][1] if len(cells) >= 3 else ''

            # Parse device name and offset range from device_info
            # Pattern: DEVICE_NAMExOFFSET or DEVICE_NAMExSTART...END
            device_match = re.match(r'^([A-Za-z][A-Za-z0-9_]*)x([0-9A-Fa-f]+)(?:\.\.\.x?([0-9A-Fa-f]+))?', device_info)
            if not device_match:
                continue

            device_name = device_match.group(1)
            offset_start = int(device_match.group(2), 16)
            offset_end = int(device_match.group(3), 16) if device_match.group(3) else offset_start

            # Use device name from mnemonic (e.g., HCE from HCEx040...x050)
            # not from namespace (e.g., FCH::USBLEGACY)
            base_name = device_name

            # Calculate max offset for this device
            max_offset = offset_end

            # Store or update memory range
            # We'll calculate the actual size after parsing all registers
            if base_name not in self.memory_ranges:
                self.memory_ranges[base_name] = {
                    'address': addr_str.upper(),
                    'max_offset': max_offset,
                    'namespace': namespace
                }
            else:
                # Update max offset if this one is larger
                existing = self.memory_ranges[base_name]
                if max_offset > existing['max_offset']:
                    existing['max_offset'] = max_offset

    def _calculate_memory_range_sizes(self):
        """Calculate actual memory range sizes based on register sizes.

        Called after all registers are parsed. The memory map shows the last
        register offset (inclusive), so the actual size is:
        max_offset + size_of_last_register
        """
        for device_name, range_info in self.memory_ranges.items():
            max_offset = range_info['max_offset']

            # Find the register at max_offset for this device
            last_reg_size = 4  # Default to 4 bytes if not found

            for reg in self.registers:
                reg_device = reg.get('device', '')
                reg_offset_str = reg.get('offset', '')

                # Match device name
                if reg_device != device_name:
                    continue

                # Parse offset and compare
                if reg_offset_str.startswith('0x'):
                    try:
                        reg_offset = int(reg_offset_str, 16)
                        if reg_offset == max_offset:
                            # Found the last register, get its size
                            fields = reg.get('fields', [])
                            if fields:
                                last_reg_size = calc_register_size(fields)
                            break
                    except ValueError:
                        pass

            # Update the max_offset to include register size
            range_info['size'] = max_offset + last_reg_size

    def _extract_ima_entries(self, lines: list, page_text: str, page_num: int):
        """Extract IMA (Indirect Memory Access) entries from 'Memory Map - SMN' section.

        The SMN (System Management Network) map shows devices accessed indirectly
        through SMN index/data registers.

        Args:
            lines: List of (text, x_pos, y_pos, spans) tuples, already filtered for header/footer
            page_text: Full text of the page (for pattern matching)
            page_num: Page number (1-indexed)
        """
        # Look for "Memory Map - SMN" header
        if 'Memory Map - SMN' not in page_text:
            return

        # Skip Table of Contents pages - check for actual table content
        # The real SMN map has entries like "13F01000: IOMMUL2Bx..."
        if not re.search(r'[A-Fa-f0-9]{6,}:\s*[A-Za-z]+x[0-9A-Fa-f]+', page_text):
            return

        # Track page for comment
        if page_num not in self.ima_pages:
            self.ima_pages.append(page_num)

        # Build spans from lines (already filtered for header/footer)
        spans = []
        for line_text, x_pos, y_pos, line_spans in lines:
            for span in line_spans:
                span_text, x0, y0, x1, y1 = span
                span_text = span_text.strip()
                if span_text:
                    spans.append((span_text, y0, x0))

        # Sort by y then x
        spans.sort(key=lambda s: (s[1], s[2]))

        # Group spans by y-position (with tolerance)
        y_tolerance = 3.0
        y_groups = {}
        for text, y, x in spans:
            found_group = None
            for group_y in y_groups:
                if abs(y - group_y) < y_tolerance:
                    found_group = group_y
                    break
            if found_group is None:
                found_group = y
            if found_group not in y_groups:
                y_groups[found_group] = []
            y_groups[found_group].append((x, text))

        # Process each row
        for y in sorted(y_groups.keys()):
            cells = sorted(y_groups[y], key=lambda c: c[0])

            if not cells:
                continue

            first_text = cells[0][1]

            # Check if this looks like an SMN map entry
            # Pattern: HEX_ADDR: DEVICE_INFO (e.g., "13F01000: IOMMUL2Bx0000012C...x00000250")
            match = re.match(r'^([0-9A-Fa-f_]+)(h)?:\s*([A-Za-z][A-Za-z0-9]*)x([0-9A-Fa-f]+)', first_text)
            if not match:
                continue

            addr_str = match.group(1).replace('_', '')
            device_name = match.group(3)

            # Store the IMA entry
            if device_name not in self.ima_entries:
                self.ima_entries[device_name] = {
                    'base': addr_str.upper()
                }

    def _extract_io_bars(self, page_text: str, page_num: int):
        """Extract IO BAR entries from 'IO mapped base address' text patterns.

        Pattern: "The IO mapped base address of this register block is defined by NAMESPACE::RegisterName."
        This indicates an IO BAR that should be included in the <io> section.

        Args:
            page_text: Full text of the page (for pattern matching)
            page_num: Page number (1-indexed)
        """
        # Pattern to match IO mapped base address definitions
        # Example: "The IO mapped base address of this register block is defined by FCH::PM::AcpiPm1EvtBlk."
        # Register names can contain digits (e.g., AcpiPm1EvtBlk, AcpiGpe0Blk)
        pattern = r'The IO mapped base address of this register block is defined by ([A-Za-z:]+)::([A-Za-z0-9]+)\.'

        matches = re.findall(pattern, page_text)

        for namespace, register_name in matches:
            # Check if we already have this BAR
            if not any(bar['register'] == register_name for bar in self.io_bars):
                self.io_bars.append({
                    'name': register_name,
                    'register': register_name,
                    'base_field': register_name,
                    'page': page_num
                })

    def _extract_address_mappings(self, lines: list, page_text: str, page_num: int):
        """Extract address space mapping entries from "Table N: Address Space Mapping".

        Parses address ranges and function names from the address mapping table.
        Format: "Function name" | "Address Mapping in HOST Space" | "NOTES"

        Address formats:
        - Single range: "00_FEDC_0XXXh" (XXX means any value 0-F)
        - Range: "00_FEDC_3FFFh - 00_FEDC_1000h" (HIGH - LOW format in PDF!)
        - Bit range: "00_FED8_[1:0]XXXh" (bits [1:0] can vary)

        Args:
            lines: List of (text, x_pos, y_pos, spans) tuples, already filtered for header/footer
            page_text: Full text of the page (for pattern matching)
            page_num: Page number (1-indexed)
        """
        # Check if this page contains the Address Space Mapping table or is a continuation
        # Page 348 has "Address Space Mapping" header, page 349 is continuation without header
        # IMPORTANT: TOC pages also have "Address Space Mapping" text, so we need to be very specific
        has_table_header = 'Address Space Mapping' in page_text
        has_func_header = 'Function name' in page_text

        # Very specific patterns for the actual address mapping table (Table 77)
        # These patterns match the EXACT format from the table, not just any hex values
        has_table_content = bool(
            # FCH MMIO addresses with XXX wildcard: 00_FEDC_0XXXh
            re.search(r'00_FED[CD]_[0-9A-Fa-f]XXXh', page_text) or
            # ROM_1 exact address range
            re.search(r'00_000F_FFFFh\s*-\s*00_0000_0000h', page_text) or
            # ROM_2 exact address range
            re.search(r'00_FFFF_FFFFh\s*-\s*00_FF00_0000h', page_text) or
            # ROM_3 exact address range
            re.search(r'FD_03FF_FFFFh\s*-\s*FD_0000_0000h', page_text) or
            # ACPI with bit range
            re.search(r'00_FED8_\[\d+:\d+\]XXXh', page_text)
        )

        # Only process if we have the ACTUAL table (not TOC):
        # - Page with "Function name" header is definitely the table start
        # - Page without header but with table content is a continuation
        if not has_func_header and not has_table_content:
            return

        # Track page for comment
        if page_num not in self.address_mapping_pages:
            self.address_mapping_pages.append(page_num)

        # Build spans from lines (already filtered for header/footer), with deduplication
        spans_set = set()
        spans = []
        for line_text, x_pos, y_pos, line_spans in lines:
            for span in line_spans:
                span_text, x0, y0, x1, y1 = span
                span_text = span_text.strip()
                if span_text:
                    # Deduplicate based on text and approximate position
                    key = (span_text, round(y0), round(x0))
                    if key not in spans_set:
                        spans_set.add(key)
                        spans.append((span_text, y0, x0))

        # Sort by y then x
        spans.sort(key=lambda s: (s[1], s[2]))

        # Group spans by y-position (with tolerance)
        y_tolerance = 5.0
        y_groups = {}
        for text, y, x in spans:
            found_group = None
            for group_y in y_groups:
                if abs(y - group_y) < y_tolerance:
                    found_group = group_y
                    break
            if found_group is None:
                found_group = y
            if found_group not in y_groups:
                y_groups[found_group] = []
            y_groups[found_group].append((x, text))

        # Find the y-position of "Function name" header to know where table starts
        table_start_y = None
        for y in sorted(y_groups.keys()):
            cells = y_groups[y]
            for x, text in cells:
                if text == 'Function name':
                    table_start_y = y
                    self.addr_map_table_started = True
                    break
            if table_start_y:
                break

        # Build rows: function name in column 1, address in column 2
        # The table has function names at x ~39 and addresses at x ~150
        # Use instance variables to persist state across pages
        current_func = self.addr_map_current_func
        current_addr_parts = self.addr_map_current_addr_parts

        # Process rows and collect function/addr pairs
        rows = []

        for y in sorted(y_groups.keys()):
            # Skip rows before the table header (only if table has started on this page)
            if table_start_y and y <= table_start_y:
                continue

            # Skip if table hasn't started yet (not the right page)
            if not self.addr_map_table_started and not has_func_header:
                continue

            cells = sorted(y_groups[y], key=lambda c: c[0])

            if not cells:
                continue

            first_text = cells[0][1]
            first_x = cells[0][0]

            # Check if we've hit a new section (ends the table)
            # Section headers like "9.2", "9.2.1", etc. indicate the table has ended
            if re.match(r'^\d+\.\d+(\.\d+)?\s*$', first_text):
                # Save current entry and stop processing
                if current_func and current_addr_parts:
                    rows.append((current_func, ' '.join(current_addr_parts)))
                # Clear state - table is done
                current_func = None
                current_addr_parts = []
                self.addr_map_current_func = None
                self.addr_map_current_addr_parts = []
                self.addr_map_table_started = False
                break  # Stop processing rows - table has ended

            # Skip header rows (shouldn't happen after table_start_y check, but be safe)
            if first_text in ('Function name', 'Address Mapping', 'NOTES', 'Table', 'Mapping', 'Space'):
                continue

            # Check if this is a function name (left column, x < 100) or address continuation
            is_func_col = first_x < 100 and not re.match(r'^[0-9A-Fa-f_]+(-|h)', first_text)

            # Check if this row has an address (in the address column, x >= 100)
            has_addr = any(x >= 100 and (re.search(r'[0-9A-Fa-f_\[\]:X]+h', text) or text == '-')
                          for x, text in cells)

            if is_func_col:
                if has_addr:
                    # This is a function name row WITH an address - start a new entry
                    # First, save any previous entry
                    if current_func and current_addr_parts:
                        rows.append((current_func, ' '.join(current_addr_parts)))

                    current_func = first_text
                    current_addr_parts = []

                    # Collect address from same row
                    for x, text in cells:
                        if x >= 100 and (re.search(r'[0-9A-Fa-f_\[\]:X]+h', text) or text == '-'):
                            current_addr_parts.append(text)
                elif current_func:
                    # This is a function name row WITHOUT an address - continuation of previous name
                    # Append to current function name
                    current_func = current_func + ' ' + first_text
            elif has_addr and current_func:
                # This is address continuation (for multi-line address ranges)
                for x, text in cells:
                    if x >= 100 and (re.search(r'[0-9A-Fa-f_\[\]:X]+h', text) or text == '-'):
                        current_addr_parts.append(text)

        # Save state back to instance variables for next page
        self.addr_map_current_func = current_func
        self.addr_map_current_addr_parts = current_addr_parts

        # Don't forget last entry (only if we have a complete entry - has address ending with 'h')
        if current_func and current_addr_parts:
            addr_str = ' '.join(current_addr_parts)
            # Only add if address looks complete (ends with hex digit + h, or has XXXh)
            if re.search(r'[0-9A-Fa-f]h\s*$', addr_str) or 'XXXh' in addr_str:
                rows.append((current_func, addr_str))
                # Clear after adding - don't double-count on next page
                self.addr_map_current_func = None
                self.addr_map_current_addr_parts = []

        # Now parse each row
        for func_name, full_addr in rows:
            # Skip if no address (check for any hex-like pattern including XXX and bit ranges)
            if not full_addr or not re.search(r'[0-9A-Fa-f_]+', full_addr):
                continue

            # Skip reserved entries for now (we'll output them as comments)
            is_reserved = func_name.lower() == 'reserved'

            try:
                base_val = 0  # Initialize
                end_address = None  # For reserved comments

                # Pattern for bit range: "00_FED8_[1:0]XXXh" (MUST check before single XXX)
                bit_range_match = re.match(
                    r'([0-9A-Fa-f_]+)\[(\d+):(\d+)\]XXXh',
                    full_addr
                )

                # Pattern for range: HIGH - LOW (Note: PDF shows high first!)
                # Also handle multi-line format: "HIGHh - LOWh"
                range_match = re.match(
                    r'([0-9A-Fa-f_]+)h\s*-\s*([0-9A-Fa-f_]+)h',
                    full_addr
                )

                # Pattern for single with XXX wildcard: "00_FEDC_0XXXh"
                single_match = re.match(
                    r'([0-9A-Fa-f_]+)XXXh',
                    full_addr
                )

                if bit_range_match:
                    # Bit range: 00_FED8_[1:0]XXXh
                    # The format is: PREFIX[hi:lo]XXXh
                    # [hi:lo] means the digit can range from lo to hi (inclusive)
                    # For [1:0]: digit can be 0 or 1, giving 2 values
                    # XXX means last 12 bits can vary from 000 to FFF
                    base_str = bit_range_match.group(1).replace('_', '')
                    hi_digit = int(bit_range_match.group(2))
                    lo_digit = int(bit_range_match.group(3))

                    # The prefix represents hex digits before the digit range position
                    # For "00_FED8_[1:0]XXXh": prefix = 00FED8 (6 hex digits)
                    # The full address is: PREFIX << 16 (to make room for the digit and XXX)
                    base_val = int(base_str, 16) << 16

                    # Size = (number of digit values) * 0x1000 - 1
                    # For [1:0]: hi=1, lo=0, so count = 1 - 0 + 1 = 2
                    # Size = 2 * 0x1000 - 1 = 0x1FFF
                    num_digit_values = hi_digit - lo_digit + 1
                    size = num_digit_values * 0x1000 - 1

                    address = f'0x{base_val:010X}'
                    size_hex = f'0x{size:04X}'

                elif range_match:
                    # Range format: HIGH - LOW (Note: PDF shows high first!)
                    high_str = range_match.group(1).replace('_', '')
                    low_str = range_match.group(2).replace('_', '')

                    high_val = int(high_str, 16)
                    low_val = int(low_str, 16)

                    # Calculate base address (lower value) and size
                    base_addr = min(high_val, low_val)
                    end_addr = max(high_val, low_val)
                    base_val = base_addr
                    # Size = end - start (not +1, as per expected format)
                    size = end_addr - base_addr

                    address = f'0x{base_addr:010X}'
                    size_hex = f'0x{size:04X}' if size <= 0xFFFF else f'0x{size:X}'
                    end_address = f'0x{end_addr:010X}'  # For reserved comments

                elif single_match:
                    # Single with XXX wildcard: 00_FEDC_0XXXh means 0x00FEDC0000 - 0x00FEDC0FFF
                    # XXX represents 12 bits (3 hex digits) that can vary from 000 to FFF
                    # The base is the part before XXX, shifted left by 12 bits
                    base_str = single_match.group(1).replace('_', '')
                    base_val = int(base_str, 16) << 12  # Multiply by 0x1000

                    # Size = end - base = 0xFFF - 0x000 = 0xFFF
                    address = f'0x{base_val:010X}'
                    size_hex = '0x0FFF'

                else:
                    # Try simple single address
                    simple_match = re.search(r'([0-9A-Fa-f_]+)h', full_addr)
                    if simple_match:
                        base_str = simple_match.group(1).replace('_', '')
                        base_val = int(base_str, 16)
                        address = f'0x{base_val:010X}'
                        size_hex = '0x0FFF'  # Default size for single entry
                    else:
                        continue

                # Clean up function name
                # Remove "LPC/SPI " prefix for ROM entries
                clean_name = func_name
                if clean_name.startswith('LPC/SPI '):
                    clean_name = clean_name[8:]  # Remove "LPC/SPI " prefix

                # Handle "I2C_N Master" -> "I2C_N"
                if clean_name.endswith(' Master'):
                    clean_name = clean_name[:-7]  # Remove " Master" suffix

                # Handle "I2C_4 Slave for USB Power Delivery" -> "PowerDelivery"
                if 'Power Delivery' in clean_name:
                    clean_name = 'PowerDelivery'

                # Handle "UART_N" naming consistency
                if clean_name.startswith('UART') and len(clean_name) == 5 and clean_name[4].isdigit():
                    # UART0 -> UART_0, UART1 -> UART_1
                    clean_name = 'UART_' + clean_name[4]

                # Handle "EMMC Control" -> "EMMC_Control"
                clean_name = clean_name.replace(' ', '_')
                clean_name = clean_name.replace('/', '_')

                # Determine access type based on address and name
                # DRAM: ROM entries or addresses well below MMIO region
                # MMIO: addresses in FEDxxxxx range (memory-mapped I/O)
                if 'ROM' in clean_name:
                    access = 'dram'
                elif base_val >= 0xFEC00000:
                    access = 'mmio'
                else:
                    access = 'dram'

                # Check for duplicates before storing
                # For non-reserved entries, deduplicate by name
                # For reserved entries, deduplicate by (name, address) pair
                if is_reserved:
                    key = (clean_name, address)
                    is_dup = any((m['name'], m['address']) == key and m['is_reserved']
                                 for m in self.address_mappings)
                else:
                    is_dup = any(m['name'] == clean_name and not m['is_reserved']
                                 for m in self.address_mappings)

                if not is_dup:
                    self.address_mappings.append({
                        'name': clean_name,
                        'access': access,
                        'address': address,
                        'size': size_hex,
                        'is_reserved': is_reserved,
                        'end_address': end_address  # For reserved comments
                    })

            except (ValueError, AttributeError):
                continue

    def _extract_acpi_mmio_ranges(self, lines: list, page_text: str, page_num: int):
        """Extract ACPI MMIO Space Allocation entries from "Table 80: ACPI MMIO Space Allocation".

        Parses the ACPI MMIO space allocation table which shows offsets within the ACPI MMIO region.
        Format: "HIGHh-LOWh" | "Name/Description"

        The ACPI base address is taken from previously collected address_mappings.

        Args:
            lines: List of (text, x_pos, y_pos, spans) tuples, already filtered for header/footer
            page_text: Full text of the page (for pattern matching)
            page_num: Page number (1-indexed)
        """
        # Check if this page contains the ACPI MMIO Space Allocation table
        # Use generic pattern to work with different PDFs (table number may vary)
        if 'ACPI MMIO Space Allocation' not in page_text:
            return

        # Track page for comment
        if page_num not in self.acpi_mmio_table_pages:
            self.acpi_mmio_table_pages.append(page_num)

        # The table lines have format: "XXFFh-XX00h Name/Description"
        # where both columns are already joined into a single line
        # Pattern: starts with hex range like "00FFh-0000h" (at least 3 hex digits required
        # to distinguish from ValidValues patterns like "3h-1h Reserved.")
        range_name_re = re.compile(r'^([0-9A-Fa-f]{3,})h-([0-9A-Fa-f]{3,})h\s+(.+)$')

        for text, x_pos, y_pos, spans in lines:
            stripped = text.strip()
            m = range_name_re.match(stripped)
            if not m:
                continue

            try:
                high = int(m.group(1), 16)
                low = int(m.group(2), 16)
                name = m.group(3).strip()

                # Validate: low should be less than high, and both should be reasonable offsets
                # ACPI MMIO region is typically up to 0x2000 bytes
                if low >= high or low > 0x2000 or high > 0x2000:
                    continue

                # Size = high - low (the range covers low to high inclusive)
                size = high - low

                # Convert descriptive name to device name first
                clean_name = self._acpi_mmio_name_to_device(name)

                # Determine if this is reserved
                # Special case: "Reserved. AOAC Registers" is actually AOAC, not reserved
                if name.strip().startswith('Reserved. AOAC'):
                    is_reserved = False
                else:
                    is_reserved = name.lower().startswith('reserved')

                self.acpi_mmio_ranges.append({
                    'name': clean_name,
                    'offset': low,
                    'size': size,
                    'is_reserved': is_reserved
                })

            except ValueError:
                continue

    def _acpi_mmio_name_to_device(self, name: str) -> str:
        """Convert ACPI MMIO table descriptive name to device name.

        Maps the descriptive names from Table 80 to proper device names
        that match the naming convention used elsewhere in the XML.

        Examples:
            "SMBus PCI configuration registers" -> "SMBus_PCI"
            "BIOS RAM" -> "BIOS_RAM"
            "GPIO Bank 0" -> "GPIO0"
            "Wake Device (AC DC timer)" -> "ACDC"
        """
        # Strip trailing period and whitespace
        name = name.strip()
        if name.endswith('.'):
            name = name[:-1]

        # Direct mappings for known patterns
        name_map = {
            'SMBus PCI configuration registers': 'SMBus_PCI',
            'SMBus registers': 'SMBus',
            'SMI': 'SMI',
            'PMIO': 'PMIO',
            'PMIO2': 'PMIO2',
            'BIOS RAM': 'BIOS_RAM',
            'CMOS RAM': 'CMOS_RAM',
            'CMOS': 'CMOS',
            'ACPI': 'ACPI',
            'ASF registers': 'ASF',
            'Watchdog registers': 'WDT',
            'HPET': 'HPET',
            'IOMux': 'IOMUX',
            'Miscellaneous registers': 'MISC',
            'Shadow System Counter': 'SHADOW_COUNTER',
            'DP-VGA': 'DP_VGA',
            'GPIO Bank 0': 'GPIO0',
            'GPIO Bank 1': 'GPIO1',
            'GPIO Bank 2': 'GPIO2',
            'Wake Device (AC DC timer)': 'ACDC',
            'Reserved. AOAC Registers': 'AOAC',
        }

        if name in name_map:
            return name_map[name]

        # Handle "GPIO Bank N" pattern generically
        gpio_match = re.match(r'GPIO Bank (\d+)', name)
        if gpio_match:
            return f'GPIO{gpio_match.group(1)}'

        # Default: convert spaces to underscores, remove special chars
        clean = re.sub(r'[^A-Za-z0-9_]', '_', name)
        clean = re.sub(r'_+', '_', clean).strip('_')
        return clean if clean else name

    def _process_line(self, line_info: tuple):
        """Process a single line based on current state.

        This method implements the state machine for PDF parsing. All state transitions
        are detected here, then dispatched to state-specific handlers.

        States:
        - IDLE: Not processing any register
        - IN_REGISTER: Processing register description/metadata
        - IN_FIELDS: Processing field definitions
        - IN_VALID_VALUES: Processing valid values table
        """
        text, x_pos, y_pos, spans = line_info
        stripped = text.strip()
        if not stripped:
            return

        # ═══════════════════════════════════════════════════════════════════
        # GLOBAL PATTERNS - These are checked regardless of current state
        # ═══════════════════════════════════════════════════════════════════

        # Section header (e.g., "9 FCH", "9.2.1 Some Title")
        # Must be exactly at left margin (within 1 point) to distinguish from:
        # - Field definitions like "31 ConfigEn" that accidentally match the pattern
        # - Table content like "0 R_AGPIO144..." in IOMUX function table
        # - Table of Contents entries that are indented
        # Section headers in the main content are always exactly at the left margin.
        sec_m = _SEC_RE.match(stripped)
        if sec_m and x_pos <= self.page_left_margin + 1:
            sec_num = sec_m.group(1)
            sec_title = sec_m.group(2).strip()
            self.current_section = (sec_num, sec_title)
            self.section_titles[sec_num] = sec_title
            self._handle_state_exit(finalize_register=True)
            return

        # Check for prose register reference pattern (e.g., "MISC2x30[7:0] is useful...")
        # This is used for non-standard register definitions where the device/offset
        # is mentioned in prose before a table-based register definition
        prose_m = _PROSE_REG_REF_RE.match(stripped)
        if prose_m:
            self.pending_prose_device = prose_m.group(1)
            self.pending_prose_offset = prose_m.group(2)
            self.pending_prose_bits = prose_m.group(3)
            self.pending_prose_text = stripped  # Capture full prose text
            # Don't return - continue processing, might be more context

        # Check for table header pattern to capture table title
        table_header_m = _TABLE_HEADER_RE.match(stripped)
        if table_header_m and self.pending_prose_device:
            # Extract table title (everything after "Table N:")
            self.pending_table_title = stripped.split(':', 1)[1].strip() if ':' in stripped else ''
            # Don't return - wait for the register description line

        # Check for table register description pattern (e.g., "RMT_PLLCNTL_0_REG - RW - 32 bits")
        # This follows a "Table N:" header and contains the register name
        table_reg_m = _TABLE_REG_DESC_RE.match(stripped)
        if table_reg_m and self.pending_prose_device:
            # We have a prose reference and now a table register description
            # Start a new register using the prose device/offset
            reg_name = table_reg_m.group(1)
            reg_size_bits = int(table_reg_m.group(3))
            reg_size_bytes = reg_size_bits // 8

            self._handle_state_exit(finalize_register=True)

            # Build description from table title and prose text
            desc_parts = []
            if self.pending_table_title:
                desc_parts.append(self.pending_table_title)
            if self.pending_prose_text:
                desc_parts.append(self.pending_prose_text)
            desc = '. '.join(desc_parts) if desc_parts else reg_name

            # Create register dict from prose reference
            self.current_reg = {
                'type': 'memory',
                'name': reg_name,
                'title': reg_name,
                'ns': '',
                'device': self.pending_prose_device,
                'offset': format_hex_offset(self.pending_prose_offset),
                'size': reg_size_bytes,
                'volume': self.current_volume,
            }
            # Add section info
            if self.current_section:
                self.current_reg['sec_num'] = self.current_section[0]
                self.current_reg['sec_title'] = self.current_section[1]
                sec_num = self.current_section[0]
                if sec_num.count('.') >= 1:
                    parent = sec_num.rsplit('.', 1)[0]
                    self.current_reg['sec_parent_title'] = self.section_titles.get(parent)
            # Set description directly and mark as complete
            self.current_desc_lines = [desc]
            self.current_desc_line_info = []
            self.current_fields = []
            self.desc_complete = True  # Description is already complete
            self.state = 'IN_REGISTER'
            self.start_page = self.current_page

            # Clear prose reference
            self.pending_prose_device = None
            self.pending_prose_offset = None
            self.pending_prose_bits = None
            self.pending_prose_text = None
            self.pending_table_title = None
            return

        # Register header (e.g., "MSRC001_0010 [Some Register] (Namespace)")
        # Must be at or near left margin to avoid matching identifiers in field descriptions
        reg_m = BOUNDARY_RE.match(stripped)
        if reg_m and x_pos <= self.page_left_margin + 5:
            self._handle_state_exit(finalize_register=True)
            self._start_register(reg_m, stripped)
            return

        # Appendix/summary section headers that end register parsing
        appendix_headers = ('List of Namespaces', 'List of Definitions', 'Memory Map')
        if stripped.startswith(appendix_headers):
            self._handle_state_exit(finalize_register=True)
            return

        # ═══════════════════════════════════════════════════════════════════
        # STATE-SPECIFIC PATTERNS - Checked based on current state
        # ═══════════════════════════════════════════════════════════════════

        if self.state == 'IDLE':
            # Nothing to process in IDLE state
            return

        elif self.state == 'IN_REGISTER':
            # Check for "Bits Description" header - transition to IN_FIELDS
            if _BITS_HEADER_RE.match(stripped):
                self._transition_to_fields(line_info)
                return
            # Check for "Field Name Bits Default Description" header - transition to IN_FIELDS (4-column format)
            if _FOUR_COL_FIELD_HEADER_RE.match(stripped):
                self._transition_to_fields_4col(line_info)
                return
            # Check for field definition without header - some registers (like SMUSVI0_TEL_PLANE0)
            # don't have "Bits Description" header but have field definitions directly
            if self._looks_like_field_definition(line_info):
                self._transition_to_fields_from_data(line_info)
                self._process_field_content(stripped, x_pos, line_info)
                return
            # Otherwise, let the state handler process the line
            self._process_register_content(stripped, x_pos, line_info)

        elif self.state == 'IN_FIELDS':
            # Check for ValidValues marker - transition to IN_VALID_VALUES
            if _VALIDVALUES_RE.match(stripped):
                self._transition_to_valid_values()
                return

            # Check for table header - finalize current field but stay in IN_FIELDS
            if _TABLE_HEADER_RE.match(stripped):
                self._finalize_current_field()
                return

            # Otherwise, let the state handler process the line
            self._process_field_content(stripped, x_pos, line_info)

        elif self.state == 'IN_VALID_VALUES':
            # Check for field definition pattern - transition back to IN_FIELDS
            field_match = _FIELD_RE.match(stripped)
            if field_match:
                bits_str = field_match.group(1)
                name = field_match.group(2)
                # This is a field if it has bit range or starts with letter
                if ':' in bits_str or (name and name[0].isalpha() and not name.startswith('[')):
                    self._finalize_valid_values_entry()
                    self._finalize_valid_values()
                    self.state = 'IN_FIELDS'
                    self._process_field_content(stripped, x_pos, line_info)
                    return

            # Check for reserved field pattern - transition back to IN_FIELDS
            if _RESERVED_RE.match(stripped):
                self._finalize_valid_values_entry()
                self._finalize_valid_values()
                self.state = 'IN_FIELDS'
                self._process_field_content(stripped, x_pos, line_info)
                return

            # Otherwise, let the state handler process the line
            self._process_valid_values_content(line_info)

    def _handle_state_exit(self, finalize_register: bool = False):
        """Handle exiting current state, with optional register finalization."""
        if self.state == 'IN_VALID_VALUES':
            self._finalize_valid_values_entry()
            self._finalize_valid_values()
        elif self.state == 'IN_FIELDS':
            self._finalize_current_field()

        if finalize_register:
            self._finalize_register()

    def _transition_to_fields(self, line_info: tuple):
        """Transition from IN_REGISTER to IN_FIELDS state."""
        self.state = 'IN_FIELDS'
        self.in_register_metadata = False
        # Clear any pending offset list buffer
        self.offset_list_buffer = []
        self.offset_list_device = None
        self.offset_list_base = None

        # Reset 4-column format flag
        self.field_4col_format = False

        # Detect column positions from "Bits Description" header spans
        _, _, _, spans = line_info
        if spans and len(spans) >= 2:
            sorted_spans = sorted(spans, key=lambda s: s[1])
            self.field_bits_x = sorted_spans[0][1]  # Bits column x
            self.field_desc_x = sorted_spans[1][1]  # Description column x
        else:
            # Fallback to default values
            self.field_bits_x = 42.0
            self.field_desc_x = 70.0

    def _transition_to_fields_4col(self, line_info: tuple):
        """Transition from IN_REGISTER to IN_FIELDS state with 4-column format.

        The 4-column format is: Field Name | Bits | Default | Description
        Used in registers like RMTPLLCNTL0.
        """
        self.state = 'IN_FIELDS'
        self.in_register_metadata = False
        # Clear any pending offset list buffer
        self.offset_list_buffer = []
        self.offset_list_device = None
        self.offset_list_base = None

        # Set 4-column format flag
        self.field_4col_format = True
        self.field_4col_current = None

        # Detect column positions from header spans
        # Header: "Field Name Bits Default Description"
        # The spans may be: ["Field Name", "Bits", "Default Description"] or similar
        _, _, _, spans = line_info
        if spans:
            sorted_spans = sorted(spans, key=lambda s: s[1])
            # Column positions based on span x positions
            self.field_4col_name_x = sorted_spans[0][1]  # "Field Name" column
            if len(sorted_spans) >= 3:
                self.field_4col_bits_x = sorted_spans[1][1]  # "Bits" column
                # "Default Description" might be in one span, estimate positions
                self.field_4col_default_x = sorted_spans[2][1]  # "Default" column
                # Description column is typically further right
                # We'll detect it from data rows
                self.field_4col_desc_x = None
            else:
                # Fallback to typical values based on observed PDF
                self.field_4col_bits_x = 164.0
                self.field_4col_default_x = 196.0
                self.field_4col_desc_x = 237.0
        else:
            # Fallback to typical values based on observed PDF
            self.field_4col_name_x = 39.0
            self.field_4col_bits_x = 164.0
            self.field_4col_default_x = 196.0
            self.field_4col_desc_x = 237.0

    def _looks_like_field_definition(self, line_info: tuple) -> bool:
        """Check if a line looks like a field definition without a header.

        Some registers (like SMUSVI0_TEL_PLANE0) don't have a "Bits Description" header
        but have field definitions directly. This method detects such cases by checking:
        1. First span is at bits column position (~39-50)
        2. First span matches a bit range pattern (e.g., "31:25", "7:0", "31")
        3. There's a second span at description column position (~97+)
        """
        text, x_pos, y_pos, spans = line_info

        if not spans or len(spans) < 2:
            return False

        # Sort spans by x position
        sorted_spans = sorted(spans, key=lambda s: s[1])
        first_span_text = sorted_spans[0][0].strip()
        first_span_x = sorted_spans[0][1]
        second_span_x = sorted_spans[1][1]

        # Check if first span is at bits column position (typically 39-50)
        # and matches a bit range pattern
        if first_span_x > 55:  # Not at bits column
            return False

        # Check if it's a bit range pattern (e.g., "31:25", "7:0", "31")
        if not _BIT_NUMBER_RE.match(first_span_text):
            return False

        # Check if second span is at description column position (typically 97+)
        # This indicates a 2-column field table format
        if second_span_x < 80:  # Not at description column
            return False

        # Check if we're past the metadata section (after lines starting with '_')
        # This prevents false positives on metadata lines
        if self.in_register_metadata:
            return True  # We're past metadata, this looks like a field

        # If we haven't seen metadata yet, check if this line is likely a field
        # by verifying the second span has text that looks like a field name or "Reserved."
        second_span_text = sorted_spans[1][0].strip()
        if second_span_text == 'Reserved.' or re.match(r'^[A-Z][A-Za-z0-9_]*\.?', second_span_text):
            return True

        return False

    def _transition_to_fields_from_data(self, line_info: tuple):
        """Transition from IN_REGISTER to IN_FIELDS state when field data is detected directly.

        This is used for registers that don't have a "Bits Description" header but have
        field definitions directly. The column positions are detected from the first data row.
        """
        self.state = 'IN_FIELDS'
        self.in_register_metadata = False
        # Clear any pending offset list buffer
        self.offset_list_buffer = []
        self.offset_list_device = None
        self.offset_list_base = None

        # Reset 4-column format flag
        self.field_4col_format = False

        # Detect column positions from the field data row
        _, _, _, spans = line_info
        if spans and len(spans) >= 2:
            sorted_spans = sorted(spans, key=lambda s: s[1])
            self.field_bits_x = sorted_spans[0][1]  # Bits column x
            self.field_desc_x = sorted_spans[1][1]  # Description column x
        else:
            # Fallback to default values
            self.field_bits_x = 42.0
            self.field_desc_x = 97.0

    def _transition_to_valid_values(self):
        """Transition from IN_FIELDS to IN_VALID_VALUES state."""
        self._finalize_current_field()
        self.state = 'IN_VALID_VALUES'
        self.vv_col1_x = None
        self.vv_col2_x = None
        self.vv_col3_x = None
        self.vv_entries = []
        self.vv_current_value = []
        self.vv_current_name = []
        self.vv_current_desc = []
        self.vv_in_table = False
        self.vv_lines = []
        self.vv_is_bit_desc = False

    def _start_register(self, match, line: str):
        """Start a new register."""
        self.current_reg = parse_register_header(match)
        if not self.current_reg:
            self.state = 'IDLE'
            return

        self.state = 'IN_REGISTER'
        self.current_fields = []
        self.current_desc_lines = []
        self.current_desc_line_info = []
        self.current_field = None
        self.start_page = self.current_page
        self.last_content_page = self.current_page  # Initialize to start page
        # Reset metadata state for new register
        self.in_register_metadata = False
        # Reset multi-line offset list state
        self.offset_list_buffer = []
        self.offset_list_device = None
        self.offset_list_base = None
        # Reset 4-column field format state
        self.field_4col_format = False
        self.field_4col_current = None
        # Reset description complete flag
        self.desc_complete = False

        # Handle indb_bits format - extract remaining text from the line as description
        if self.current_reg.get('pending_name'):
            matched_text = match.group(0)  # The matched portion
            # For indb_bits format, include the full line text (matched portion + remaining)
            # This gives us "MISC2x30[7:0] is useful to determine..."
            remaining = line[len(matched_text):].strip()
            if remaining:
                # Prepend the matched portion (device+offset) to the remaining text
                full_desc = matched_text + ' ' + remaining
                self.current_desc_lines.append(full_desc)
            elif matched_text:
                self.current_desc_lines.append(matched_text)

        if self.current_section:
            self.current_reg['sec_num'] = self.current_section[0]
            self.current_reg['sec_title'] = self.current_section[1]
            sec_num = self.current_section[0]
            if sec_num.count('.') >= 1:
                parent = sec_num.rsplit('.', 1)[0]
                self.current_reg['sec_parent_title'] = self.section_titles.get(parent)

    def _process_register_content(self, text: str, x_pos: float, line_info: tuple):
        """Process content while in IN_REGISTER state.

        Handles register description and metadata lines. Does NOT handle state transitions.
        """
        # Handle pending_name flag - extract register name from lines like "NAME - RW - N bits"
        if self.current_reg.get('pending_name'):
            # Check for register name pattern: "NAME - RW - N bits" or "NAME - RO - N bits"
            name_match = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)\s*-\s*(RW|RO|RW/RO)\s*-\s*\d+\s*bits?\s*$', text.strip(), re.I)
            if name_match:
                self.current_reg['name'] = name_match.group(1)
                self.current_reg['title'] = name_match.group(1)
                self.current_reg['pending_name'] = False
                return
            # Check for "Table N:" pattern - capture the table caption as description prefix
            table_match = _TABLE_HEADER_RE.match(text.strip())
            if table_match:
                # Extract the table caption (text after "Table N:")
                caption = text.strip()[table_match.end():].strip()
                if caption:
                    self.current_reg['table_caption'] = caption
                return
            # Skip other lines while waiting for name
            return

        # If we're in metadata mode, skip lines but still check for offset lists
        if self.in_register_metadata:
            # Still handle multi-line offset lists
            if self.offset_list_buffer:
                self.offset_list_buffer.append(text.strip())
                if '];' in text:
                    full_text = ' '.join(self.offset_list_buffer)
                    self._parse_offset_list(full_text)
                    self.offset_list_buffer = []
                    self.offset_list_device = None
                    self.offset_list_base = None
                return

            # Check for start of offset list pattern
            incomplete_m = re.match(
                r'([A-Z][A-Z0-9]{2,15})x([0-9A-Fa-f]+)\[([0-9A-Fa-f,\s]+)$',
                text.strip()
            )
            if incomplete_m and not text.strip().endswith('];'):
                self.offset_list_buffer = [text.strip()]
                return

            # Check for complete offset list on one line
            off_m = _OFFSET_LIST_RE.search(text)
            if off_m:
                self._parse_offset_list_from_match(off_m)
            return

        # Check for namespace line
        ns_m = _NS_LINE_RE.match(text)
        if ns_m and not self.current_reg.get('ns'):
            self.current_reg['ns'] = ns_m.group(1).strip()
            return

        # Check if this line starts with '_' - indicates start of metadata section
        # Enter metadata mode and skip this line
        if text.strip().startswith('_') or '_lthree' in text or '_alias' in text:
            self.in_register_metadata = True
            return

        # Check if this line matches metadata patterns (register identifiers alone)
        # e.g., "MSRC001_029B" or "IOAPICx0010" on a line by itself
        if _METADATA_LINE_RE.match(text.strip()):
            self.in_register_metadata = True
            return

        # Add to description
        self.current_desc_lines.append(text)
        self.current_desc_line_info.append(line_info)

    def _parse_offset_list_from_match(self, off_m):
        """Parse offset list from a regex match and update todo_ids."""
        dev = off_m.group(1)
        base = off_m.group(2)
        offsets_str = off_m.group(3)
        self._update_todo_ids_from_offsets(dev, base, offsets_str)

    def _parse_offset_list(self, full_text: str):
        """Parse a complete offset list from accumulated text."""
        # Extract the offset list pattern from the full text
        off_m = _OFFSET_LIST_RE.search(full_text)
        if off_m:
            self._parse_offset_list_from_match(off_m)

    def _update_todo_ids_from_offsets(self, dev: str, base: str, offsets_str: str):
        """Update todo_ids based on parsed offset list."""
        # Parse comma-separated offsets
        offsets = [o.strip().upper() for o in offsets_str.split(',') if o.strip()]
        if len(offsets) >= 2 and self.current_reg.get('multi'):
            # The header gives us the first offset (lo), and metadata lists all offsets
            first_offset = int(self.current_reg.get('offset', '0'), 16)

            # Collect all offsets greater than first_offset
            offset_values = []
            for off_str in offsets:
                off_val = int(off_str, 16)
                if off_val > first_offset:
                    offset_values.append(off_val)

            # Sort in ascending order
            offset_values.sort()

            # Generate todo_ids from sorted offsets
            todo_offsets = []
            for off_val in offset_values:
                # Format offset with consistent width
                width = max(2, len(base) + 2)
                todo_offsets.append(f'{dev}x{base}{format(off_val, f"0{width}X")}')

            if todo_offsets:
                self.current_reg['todo_ids'] = todo_offsets

    def _process_field_content(self, text: str, x_pos: float, line_info: tuple):
        """Process content while in IN_FIELDS state using x-position based table parsing.

        The field table can have 2 formats:
        1. 2 columns: Bits | Description
           - Bits column: bit number/range (e.g., "31", "7:0", "31:8 Reserved.")
           - Description column: field name followed by description text
           For example: "7:0 Priority . Read-write. Reset: 00h. ..."

        2. 4 columns: Field Name | Bits | Default | Description
           - Used in some registers like RMTPLLCNTL0
           - Field Name can span multiple lines
           - Bits: bit number/range
           - Default: default value (ignored in output)
           - Description: description text (can span multiple lines)

        Does NOT handle state transitions.
        """
        # Check if we're in 4-column format
        if self.field_4col_format:
            self._process_field_content_4col(text, x_pos, line_info)
            return

        # Use x-position based parsing for field table (2-column format)
        _, _, _, spans = line_info

        # Get column positions
        bits_x = self.field_bits_x or 42.0
        desc_x = self.field_desc_x or 70.0

        # Tolerance for column matching
        bits_tolerance = 10.0
        desc_tolerance = 10.0

        if not spans:
            return

        # Sort spans by x position
        sorted_spans = sorted(spans, key=lambda s: s[1])
        first_span_text = sorted_spans[0][0].strip()
        first_span_x = sorted_spans[0][1]

        # Check if first span is at the bits column
        if first_span_x > bits_x + bits_tolerance:
            # First span is not at bits column - this is description continuation
            if self.current_field is not None:
                bit, size, name, desc_lines, desc_line_info = self.current_field
                desc_lines.append(text.strip())
                desc_line_info.append(line_info)
                self.current_field = (bit, size, name, desc_lines, desc_line_info)
                self.last_content_page = self.current_page
            return

        # First span is at bits column - check if it's a bit number or reserved pattern
        # Handle "31:8 Reserved." case (all in one span)
        res_m = _RESERVED_RE.match(first_span_text)
        if res_m:
            self._finalize_current_field()
            bit_start, size = parse_bits(res_m.group(1))
            self.current_fields.append({
                'bit': bit_start, 'size': size, 'name': 'Reserved',
                'desc': '', 'reserved': True
            })
            self.last_content_page = self.current_page
            return

        # Check for bit number pattern (e.g., "31", "7:0", "31:8")
        bit_m = _BIT_NUMBER_RE.match(first_span_text)
        if not bit_m:
            # Doesn't match bit pattern - treat as description continuation
            if self.current_field is not None:
                bit, size, name, desc_lines, desc_line_info = self.current_field
                desc_lines.append(text.strip())
                desc_line_info.append(line_info)
                self.current_field = (bit, size, name, desc_lines, desc_line_info)
                self.last_content_page = self.current_page
            return

        # This is a new field - extract bit number and look for name/description
        bits_text = first_span_text
        remaining_spans = sorted_spans[1:]

        # Extract field name and description from remaining spans
        name_text = ''
        desc_parts = []

        if remaining_spans:
            # First span in description column is the field name (or "Reserved.")
            name_span_text = remaining_spans[0][0].strip()
            name_span_x = remaining_spans[0][1]

            # Check if this span is at the description column position
            if abs(name_span_x - desc_x) <= desc_tolerance:
                # Check if this is a "Reserved." field
                if name_span_text == 'Reserved.':
                    self._finalize_current_field()
                    bit_start, size = parse_bits(bits_text)
                    self.current_fields.append({
                        'bit': bit_start, 'size': size, 'name': 'Reserved',
                        'desc': '', 'reserved': True
                    })
                    self.last_content_page = self.current_page
                    return

                # Extract field name and initial description from the span text
                # The span may contain: "FIELD_NAME. Reset: XXX. Description text"
                # We need to separate the field name from the metadata/description
                name_text, initial_desc = extract_field_name_and_desc(name_span_text)
                if initial_desc:
                    desc_parts.append(initial_desc)

                # Process remaining spans to build description
                # Pattern: ": subtitle . description" or ". description"
                # The subtitle should be included in the description
                subtitle_parts = []
                found_desc_start = False

                for span_text, span_x, span_y, span_x1, span_y1 in remaining_spans[1:]:
                    stripped = span_text.strip()
                    if not found_desc_start:
                        # Check if this span starts with ". " (actual description start)
                        if stripped.startswith('. '):
                            found_desc_start = True
                            # Add subtitle parts if any, with period separator
                            if subtitle_parts:
                                desc_parts.append(' '.join(subtitle_parts) + '.')
                            desc_parts.append(stripped[2:])  # Add text after ". "
                        elif stripped == ':':
                            # Skip just the colon separator
                            pass
                        elif stripped.startswith(': '):
                            # Colon with text after - this is subtitle start
                            subtitle_parts.append(stripped[2:])
                        else:
                            # This is subtitle text (between ": " and ". ")
                            subtitle_parts.append(stripped)
                    else:
                        # After finding description start, add all remaining spans
                        desc_parts.append(stripped)
            else:
                # Not at description column - might be continuation of previous field
                # Or the entire line is description
                if self.current_field is not None:
                    bit, size, name, desc_lines, desc_line_info = self.current_field
                    desc_lines.append(text.strip())
                    desc_line_info.append(line_info)
                    self.current_field = (bit, size, name, desc_lines, desc_line_info)
                    self.last_content_page = self.current_page
                return

        desc_text = ' '.join(desc_parts).strip()

        # Create new field
        self._finalize_current_field()
        bit_start, size = parse_bits(bits_text)

        if name_text:
            self.current_field = (bit_start, size, name_text, [desc_text] if desc_text else [], [line_info] if desc_text else [])
            # Update last_content_page when field is created with initial content
            if desc_text:
                self.last_content_page = self.current_page
        else:
            # No name found - treat as description continuation
            if self.current_field is not None:
                bit, size, name, desc_lines, desc_line_info = self.current_field
                desc_lines.append(text.strip())
                desc_line_info.append(line_info)
                self.current_field = (bit, size, name, desc_lines, desc_line_info)
                self.last_content_page = self.current_page

    def _process_field_content_4col(self, text: str, x_pos: float, line_info: tuple):
        """Process content while in IN_FIELDS state with 4-column format.

        The 4-column format is: Field Name | Bits | Default | Description
        - Column 1 (x≈39): Field Name - can span multiple lines
        - Column 2 (x≈164): Bits - bit number/range (e.g., "7:6")
        - Column 3 (x≈196): Default - default value (ignored in output)
        - Column 4 (x≈237): Description - can span multiple lines

        The field name and description can wrap to subsequent lines, so we need
        to detect when a new field starts (by detecting a bits pattern in the
        bits column).

        Does NOT handle state transitions.
        """
        _, _, _, spans = line_info

        if not spans:
            return

        # Get column positions (with defaults based on observed PDF)
        name_x = self.field_4col_name_x or 39.0
        bits_x = self.field_4col_bits_x or 164.0
        default_x = self.field_4col_default_x or 196.0
        desc_x = self.field_4col_desc_x or 237.0

        # Tolerance for column matching
        tolerance = 10.0

        # Sort spans by x position
        sorted_spans = sorted(spans, key=lambda s: s[1])

        # Parse spans into columns
        name_parts = []
        bits_parts = []
        default_parts = []
        desc_parts = []

        for span_text, span_x0, span_y0, span_x1, span_y1 in sorted_spans:
            stripped = span_text.strip()
            if span_x0 >= desc_x - tolerance:
                # Description column
                desc_parts.append(stripped)
                # Detect description column position from first description span
                if self.field_4col_desc_x is None:
                    self.field_4col_desc_x = span_x0
                    desc_x = span_x0
            elif span_x0 >= default_x - tolerance:
                # Default column
                default_parts.append(stripped)
            elif span_x0 >= bits_x - tolerance:
                # Bits column
                bits_parts.append(stripped)
            elif span_x0 >= name_x - tolerance:
                # Field Name column
                name_parts.append(stripped)

        name_text = ''.join(name_parts).strip()
        bits_text = ''.join(bits_parts).strip()
        default_text = ''.join(default_parts).strip()
        desc_text = ' '.join(desc_parts).strip()

        # Check if this line has a bits pattern (indicates new field)
        has_bits = bool(_BIT_NUMBER_RE.match(bits_text))

        if has_bits and name_text:
            # This is a new field - finalize the previous one
            self._finalize_current_field()

            # Start a new field
            # field_4col_current = (name_parts, bits_parts, default_parts, desc_lines, desc_line_info)
            self.field_4col_current = (
                [name_text],
                [bits_text],
                [default_text] if default_text else [],
                [desc_text] if desc_text else [],
                [line_info] if desc_text else []
            )
            self.last_content_page = self.current_page
        elif self.field_4col_current is not None:
            # This is a continuation line - append to current field
            name_parts_cur, bits_parts_cur, default_parts_cur, desc_lines_cur, desc_line_info_cur = self.field_4col_current

            # Append to the appropriate columns
            if name_text:
                name_parts_cur.append(name_text)
            if bits_text:
                bits_parts_cur.append(bits_text)
            if default_text:
                default_parts_cur.append(default_text)
            if desc_text:
                desc_lines_cur.append(desc_text)
                desc_line_info_cur.append(line_info)

            self.field_4col_current = (name_parts_cur, bits_parts_cur, default_parts_cur, desc_lines_cur, desc_line_info_cur)
            self.last_content_page = self.current_page
        elif name_text and not has_bits:
            # No current field and no bits - could be continuation before any field started
            # or a malformed line - ignore for now
            pass

    def _process_valid_values_content(self, line_info: tuple):
        """Process content while in IN_VALID_VALUES state using layout coordinates.

        This method parses the ValidValues table based on column x-positions:
        - Value column: typically x < 100
        - Description column: typically x >= 100

        When a line has text only in the value column (no text in description column),
        it means the value is continuing from the previous line.

        Does NOT handle state transitions.
        """
        text, x_pos, y_pos, spans = line_info
        stripped = text.strip()

        # Check for table headers
        if stripped in ('Value', 'Description', 'Name', 'Bit'):
            return

        # Detect three-column header: "Bit Name Description"
        if _THREE_COL_HEADER_RE.match(stripped):
            self.vv_in_table = True
            # Detect column positions from header spans
            # Note: "Name Description" may be in a single span, so we may only have 2 spans
            if spans and len(spans) >= 2:
                sorted_spans = sorted(spans, key=lambda s: s[1])
                self.vv_col1_x = sorted_spans[0][1]  # Bit column x
                if len(sorted_spans) >= 3:
                    # Three separate spans: Bit, Name, Description
                    self.vv_col2_x = sorted_spans[1][1]  # Name column x
                    self.vv_col3_x = sorted_spans[2][1]  # Description column x
                else:
                    # Two spans: Bit, "Name Description" combined
                    # Mark as 3-column format but detect col2/col3 from first data row
                    # Use a placeholder to indicate we need column detection
                    self.vv_col3_x = 0  # Placeholder: will be detected from data row
            return

        # Check _BIT_DESC_HEADER_RE before _TWO_COL_HEADER_RE since it's more specific
        # "Bit Description" matches both patterns, but we want vv_is_bit_desc set
        if _BIT_DESC_HEADER_RE.match(stripped):
            self.vv_in_table = True
            self.vv_is_bit_desc = True  # Mark as Bit Description format
            # Detect column positions from header spans: "Bit Description"
            if spans and len(spans) >= 2:
                sorted_spans = sorted(spans, key=lambda s: s[1])
                self.vv_col1_x = sorted_spans[0][1]  # Bit column x
                self.vv_col2_x = sorted_spans[1][1]  # Description column x
                self.vv_col3_x = None  # 2-column format
            return

        if _TWO_COL_HEADER_RE.match(stripped):
            self.vv_in_table = True
            # Detect column positions from header spans: "Value Description"
            if spans and len(spans) >= 2:
                sorted_spans = sorted(spans, key=lambda s: s[1])
                self.vv_col1_x = sorted_spans[0][1]  # Value column x
                self.vv_col2_x = sorted_spans[1][1]  # Description column x
                self.vv_col3_x = None  # 2-column format
            return

        # Parse the table row based on column positions
        if self.vv_in_table and spans and self.vv_col1_x is not None:
            if self.vv_col3_x is not None:
                # Three-column format: Bit, Name, Description
                # Check if we need to detect col2_x and col3_x from this data row
                if self.vv_col3_x == 0 and len(spans) >= 3:
                    # Detect column positions from first data row
                    sorted_spans = sorted(spans, key=lambda s: s[1])
                    self.vv_col2_x = sorted_spans[1][1]  # Name column x
                    self.vv_col3_x = sorted_spans[2][1]  # Description column x

                bit_parts = []
                name_parts = []
                desc_parts = []

                # Use col2_x and col3_x if available, otherwise use heuristics
                col2_threshold = self.vv_col2_x if self.vv_col2_x else self.vv_col1_x + 30
                col3_threshold = self.vv_col3_x if self.vv_col3_x and self.vv_col3_x != 0 else col2_threshold + 40

                for span_text, span_x0, span_y0, span_x1, span_y1 in spans:
                    if span_x0 >= col3_threshold - 5:
                        desc_parts.append(span_text.strip())
                    elif span_x0 >= col2_threshold - 5:
                        name_parts.append(span_text.strip())
                    else:
                        bit_parts.append(span_text.strip())

                bit_text = ''.join(bit_parts).strip()
                name_text = ''.join(name_parts).strip()
                desc_text = ''.join(desc_parts).strip()

                # If we have at least bit, it's a valid entry
                if bit_text:
                    # Finalize any pending entry first
                    self._finalize_valid_values_entry()

                    # Start new entry
                    self.vv_current_value = [bit_text]
                    self.vv_current_name = [name_text] if name_text else []
                    self.vv_current_desc = [desc_text] if desc_text else []
                    self.last_content_page = self.current_page

            else:
                # Two-column format: Value, Description
                value_parts = []
                desc_parts = []

                # Use detected column positions
                for span_text, span_x0, span_y0, span_x1, span_y1 in spans:
                    if span_x0 < self.vv_col2_x - 5:  # 5 pixel tolerance
                        value_parts.append(span_text.strip())
                    else:
                        desc_parts.append(span_text.strip())

                value_text = ''.join(value_parts).strip()
                desc_text = ''.join(desc_parts).strip()

                # If we have both value and description, it's a complete entry
                if value_text and desc_text:
                    # Finalize any pending entry first
                    self._finalize_valid_values_entry()

                    # Start new entry (but don't finalize yet - value may continue on next lines)
                    self.vv_current_value = [value_text]
                    self.vv_current_desc = [desc_text]
                    self.last_content_page = self.current_page

                elif value_text and not desc_text:
                    # Only value column has text - continuation of value
                    if self.vv_current_value:
                        # Append to current value
                        self.vv_current_value.append(value_text)
                        self.last_content_page = self.current_page
                    else:
                        # Orphan value (no prior entry to append to), start new
                        self.vv_current_value = [value_text]
                        self.last_content_page = self.current_page

                elif desc_text and not value_text:
                    # Only description column has text - continuation of description
                    if self.vv_current_value:
                        self.vv_current_desc.append(desc_text)
                        self.last_content_page = self.current_page
                    # else: orphan description, ignore
        else:
            # Fallback: treat as continuation if we have pending entry
            if self.vv_current_value or self.vv_current_desc:
                # This is a text line without clear column structure
                # Could be continuation of description
                self.vv_current_desc.append(stripped)
                self.last_content_page = self.current_page

    def _finalize_valid_values_entry(self):
        """Finalize the current ValidValues entry and add to entries list."""
        if self.vv_current_value or self.vv_current_desc or self.vv_current_name:
            value = ''.join(self.vv_current_value).strip()
            name = ''.join(self.vv_current_name).strip() if self.vv_current_name else ''
            desc = ' '.join(self.vv_current_desc).strip() if self.vv_current_desc else ''

            if value:
                if self.vv_col3_x is not None:
                    # Three-column format: Bit [x] (name) - description.
                    # or [x] - description. if no name
                    desc = desc.rstrip('.')
                    if name and name.lower() != 'reserved':
                        self.vv_entries.append(f'{value} ({name}) - {desc}.')
                    else:
                        self.vv_entries.append(f'{value} - {desc}.')
                else:
                    # Two-column format
                    if desc:
                        desc = desc.rstrip('.')
                        self.vv_entries.append(f'{value} - {desc}.')
                    else:
                        self.vv_entries.append(f'{value} - (no description).')

            self.vv_current_value = []
            self.vv_current_name = []
            self.vv_current_desc = []

    def _finalize_current_field(self):
        """Finalize the current field being built.

        Handles both 2-column and 4-column field formats.
        """
        # Handle 4-column format
        if self.field_4col_format and self.field_4col_current is not None:
            name_parts, bits_parts, default_parts, desc_lines, desc_line_info = self.field_4col_current

            name = ''.join(name_parts).strip()
            bits_text = ''.join(bits_parts).strip()
            # default is ignored in output

            if bits_text and name:
                bit_start, size = parse_bits(bits_text)

                desc_text = '\n'.join(desc_lines)

                # Detect bullet levels specific to this field's description
                if '•' in desc_text and desc_line_info:
                    field_bullet_levels = self._detect_bullet_levels_from_lines(desc_line_info)
                    if field_bullet_levels:
                        self.bullet_levels = field_bullet_levels
                        desc_text = self._convert_bullets(desc_text, desc_line_info)

                desc_text = _WHITESPACE_RE.sub(' ', desc_text).strip()
                desc = format_description(desc_text)
                self.current_fields.append({
                    'bit': bit_start, 'size': size, 'name': name,
                    'desc': desc, 'reserved': False
                })
                # Note: last_content_page is updated when content is parsed, not when finalized

            self.field_4col_current = None
            return

        # Handle 2-column format
        if self.current_field is not None:
            bit, size, name, desc_lines, desc_line_info = self.current_field
            desc_text = '\n'.join(desc_lines)

            # Detect bullet levels specific to this field's description
            if '•' in desc_text and desc_line_info:
                field_bullet_levels = self._detect_bullet_levels_from_lines(desc_line_info)
                if field_bullet_levels:
                    self.bullet_levels = field_bullet_levels
                    desc_text = self._convert_bullets(desc_text, desc_line_info)

            desc_text = _WHITESPACE_RE.sub(' ', desc_text).strip()
            desc = format_description(desc_text)
            self.current_fields.append({
                'bit': bit, 'size': size, 'name': name,
                'desc': desc, 'reserved': False
            })
            # Note: last_content_page is updated when content is parsed, not when finalized
            self.current_field = None

    def _detect_bullet_levels_from_lines(self, line_info_list: list):
        """Detect bullet indentation levels from a list of (text, x_pos, y_pos, spans) tuples."""
        bullet_x_positions = []
        for text, x_pos, y_pos, spans in line_info_list:
            if text.strip().startswith('•'):
                bullet_x_positions.append(x_pos)

        if not bullet_x_positions:
            return []

        QUANTIZE_STEP = 5.0
        quantized = [round(x / QUANTIZE_STEP) * QUANTIZE_STEP for x in bullet_x_positions]

        quantized.sort()
        clusters = []
        current_cluster = [quantized[0]]

        for x in quantized[1:]:
            if x - current_cluster[-1] < 20:
                current_cluster.append(x)
            else:
                clusters.append(sum(current_cluster) / len(current_cluster))
                current_cluster = [x]
        clusters.append(sum(current_cluster) / len(current_cluster))

        return sorted(set(clusters))

    def _finalize_valid_values(self):
        """Finalize ValidValues and add to current field."""
        # Finalize any pending entry
        self._finalize_valid_values_entry()

        if self.vv_entries and self.current_fields:
            last_field = self.current_fields[-1]
            if not last_field.get('reserved'):
                # For three-column format or Bit Description format, add "Bit" prefix
                if self.vv_col3_x is not None or self.vv_is_bit_desc:
                    vv_str = 'ValidValues: Bit ' + ' '.join(self.vv_entries)
                else:
                    vv_str = 'ValidValues: ' + ' '.join(self.vv_entries)

                base_desc = last_field.get('desc', '')
                combined = (base_desc + ' ' + vv_str).strip() if base_desc else vv_str
                last_field['desc'] = combined

        # Reset all ValidValues state after finalizing
        self.vv_col1_x = None
        self.vv_col2_x = None
        self.vv_col3_x = None
        self.vv_entries = []
        self.vv_current_value = []
        self.vv_current_name = []
        self.vv_current_desc = []
        self.vv_in_table = False
        self.vv_lines = []
        self.vv_is_bit_desc = False

    def _finalize_register_impl(self):
        """Finalize and emit the current register."""
        if self.current_reg is None:
            return

        self._finalize_current_field()

        # 'title' is set only when there's a [Name] in brackets
        # 'name' may be extracted from namespace if no brackets
        reg_title = self.current_reg.get('title', '')
        reg_name = self.current_reg.get('name', '')
        reg_ns = self.current_reg.get('ns', '')

        # For indb_bits format, use table_caption as title prefix in description
        table_caption = self.current_reg.get('table_caption')

        # Determine the name for description prefix
        # Priority: [Name] bracket > full namespace
        if reg_title:
            # Name was explicitly provided in [Name] brackets
            desc_prefix = reg_title
        elif reg_ns:
            # Use full namespace when no [Name] bracket
            desc_prefix = reg_ns
        else:
            desc_prefix = ''

        if self.current_desc_lines:
            desc_text = '\n'.join(self.current_desc_lines)

            # Detect bullet levels specific to this register's description
            if '•' in desc_text and self.current_desc_line_info:
                reg_bullet_levels = self._detect_bullet_levels_from_lines(self.current_desc_line_info)
                if reg_bullet_levels:
                    self.bullet_levels = reg_bullet_levels
                    desc_text = self._convert_bullets(desc_text, self.current_desc_line_info)

            desc_text = _WHITESPACE_RE.sub(' ', desc_text).strip()
            # If description is already complete (e.g., from prose-based register), use as-is
            if not self.desc_complete:
                # For indb_bits format, use table_caption as prefix
                if table_caption:
                    desc_text = table_caption + '. ' + desc_text
                # Use description prefix (from [Name], name, or namespace)
                elif desc_prefix:
                    desc_text = desc_prefix + '. ' + desc_text
        else:
            # No description lines - use table_caption or description prefix
            if table_caption:
                desc_text = table_caption
            elif desc_prefix:
                desc_text = desc_prefix
            else:
                desc_text = ''

        self.current_reg['desc'] = format_description(desc_text)
        self.current_reg['fields'] = self.current_fields
        self.current_reg['size'] = calc_register_size(self.current_fields)

        # Use last_content_page for accurate page range
        # (current_page may include pages with only unprocessed ValidValues tables)
        end_page = self.last_content_page or self.current_page
        if self.start_page == end_page:
            self.current_reg['page_str'] = str(self.start_page)
        else:
            self.current_reg['page_str'] = f'{self.start_page}-{end_page}'

        self.registers.append(self.current_reg)

        self.current_reg = None
        self.current_fields = []
        self.current_desc_lines = []
        self.current_desc_line_info = []
        self.current_field = None
        self.state = 'IDLE'
        self.desc_complete = False
        self.last_content_page = None


# ─────────────────────────────────────────────────────────────────────────────
# XML Generation
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# Data Preparation Functions
# ─────────────────────────────────────────────────────────────────────────────

def prepare_register_xml_data(reg: dict, prev_reg: dict = None, emitted_sections: set = None,
                               emitted_pages: set = None, locked_regs: dict = None) -> dict:
    """Prepare register data for XML writing.

    This function extracts and formats all data needed to write a register's XML,
    without actually generating any XML. The returned dict contains:
    - comments: list of comment lines to write before the register
    - tag: the register tag name (always 'register')
    - attrs: dict of attribute name -> value
    - fields: list of field data dicts (each with 'attrs' and 'is_reserved')
    - todo_comments: list of TODO comment lines for multi-instance registers

    Args:
        reg: Register dict from PDF processing
        prev_reg: Previous register dict (for section/page deduplication)
        emitted_sections: Set of already-emitted section numbers
        emitted_pages: Set of already-emitted page strings
        locked_regs: Dict mapping register name to locking field info

    Returns:
        dict with prepared data ready for write_register_xml()
    """
    if emitted_sections is None:
        emitted_sections = set()
    if emitted_pages is None:
        emitted_pages = set()
    if locked_regs is None:
        locked_regs = {}

    result = {
        'comments': [],
        'tag': 'register',
        'attrs': {},
        'fields': [],
        'todo_comments': [],
        'is_self_closing': True
    }

    # Prepare page comment
    # Use (volume, page_str) tuple for uniqueness to handle same page numbers in different volumes
    page_str = reg.get('page_str')
    volume = reg.get('volume', 1)
    page_key = (volume, page_str) if page_str else None
    sec_num = reg.get('sec_num')
    prev_sec = prev_reg.get('sec_num') if prev_reg else None

    # Emit page comment if:
    # 1. Page hasn't been emitted before, OR
    # 2. Section changed (emit page comment for first register in new section), OR
    # 3. Register spans multiple pages (page range) - always emit page range comments
    section_changed = sec_num and prev_sec and sec_num != prev_sec
    has_page_range = page_str and '-' in page_str
    if page_key and (page_key not in emitted_pages or section_changed or has_page_range):
        if volume >= 2:
            if '-' in page_str:
                result['comments'].append(f'volume {volume}, pages {page_str}')
            else:
                result['comments'].append(f'volume {volume}, page {page_str}')
        else:
            if '-' in page_str:
                result['comments'].append(f'pages {page_str}')
            else:
                result['comments'].append(f'page {page_str}')
        emitted_pages.add(page_key)

    # Prepare section comments
    sec_title = reg.get('sec_title')
    if sec_num and sec_title:
        # For subsections (with at least one dot), emit parent section first if not already emitted
        if sec_num.count('.') >= 1:
            parent_sec = sec_num.rsplit('.', 1)[0]
            parent_title = reg.get('sec_parent_title')
            if parent_sec and parent_title and parent_sec not in emitted_sections:
                result['comments'].append(f'{parent_sec} {parent_title}')
                emitted_sections.add(parent_sec)

        if sec_num != prev_sec and sec_num not in emitted_sections:
            result['comments'].append(f'{sec_num} {sec_title}')
            emitted_sections.add(sec_num)

    # Prepare rename comment
    if reg.get('rename_original_name'):
        original_name = reg['rename_original_name']
        new_name = reg['xml_name_override']
        conflicting_ns = reg.get('rename_conflicting_ns', '')
        current_ns = reg.get('ns', '')

        if current_ns and conflicting_ns:
            result['comments'].append(
                f'Actual name {current_ns} but renamed to {new_name} because {conflicting_ns} already uses the name {original_name}'
            )
        elif current_ns:
            result['comments'].append(
                f'Actual name {current_ns} but renamed to {new_name} due to name collision with {original_name}'
            )
        else:
            result['comments'].append(
                f'Renamed to {new_name} due to name collision with {original_name}'
            )

    # Prepare attributes
    xml_name = get_xml_name(reg)
    reg_type = reg.get('type', '')

    result['attrs']['name'] = xml_name

    if reg_type == 'msr':
        result['attrs']['type'] = 'msr'
        result['attrs']['msr'] = reg['msr']
    elif reg_type == 'apic':
        result['attrs']['type'] = 'mmio'
        result['attrs']['bar'] = 'APIC'
        result['attrs']['offset'] = reg['offset']
    elif reg_type == 'io':
        result['attrs']['type'] = 'io'
        result['attrs']['port'] = reg['port']
        if reg.get('index'):
            result['attrs']['AltRTCAddrPort'] = reg['index']
    elif reg_type == 'cpuid':
        result['attrs']['type'] = 'cpuid'
        result['attrs']['eax'] = reg['eax']
        if reg.get('ecx'):
            result['attrs']['ecx'] = reg['ecx']
        result['attrs']['output'] = reg['output']
    elif reg_type == 'mmiobar':
        result['attrs']['type'] = 'mmio'
        if reg.get('bar'):
            result['attrs']['bar'] = reg['bar']
        result['attrs']['offset'] = reg['offset']
    elif reg_type == 'indirect':
        result['attrs']['type'] = 'indirect'
        if reg.get('device'):
            result['attrs']['device'] = reg['device']
        result['attrs']['offset'] = reg['offset']
    elif reg_type == 'pcicfg':
        result['attrs']['type'] = 'pcicfg'
        if reg.get('device'):
            result['attrs']['device'] = reg['device']
        result['attrs']['offset'] = reg['offset']
    elif reg_type == 'memory':
        result['attrs']['type'] = 'memory'
        if reg.get('device'):
            result['attrs']['device'] = reg['device']
        result['attrs']['offset'] = reg['offset']
        if reg.get('iosel'):
            result['attrs']['IOSel'] = reg['iosel']
    else:
        result['attrs']['type'] = reg_type
        if reg.get('device'):
            result['attrs']['device'] = reg['device']
        if reg.get('offset'):
            result['attrs']['offset'] = reg['offset']

    result['attrs']['size'] = reg['size']

    # Add lockedby attribute
    reg_name = reg.get('name', '')
    if reg_name in locked_regs:
        for locking_reg, locking_field, lock_value in locked_regs[reg_name]:
            result['attrs']['lockedby'] = locking_field
            break

    if reg.get('desc'):
        result['attrs']['desc'] = reg['desc']

    # Prepare fields
    fields = reg.get('fields', [])
    for f in fields:
        if f.get('reserved', False):
            bit_start = f['bit']
            bit_size = f['size']
            if bit_size == 1:
                result['fields'].append({
                    'is_reserved': True,
                    'text': f'Bit {bit_start} reserved.'
                })
            else:
                bit_end = bit_start + bit_size - 1
                result['fields'].append({
                    'is_reserved': True,
                    'text': f'Bits {bit_end}:{bit_start} reserved.'
                })
        else:
            field_attrs = {
                'name': f['name'],
                'bit': f['bit'],
                'size': f['size']
            }
            if f.get('desc'):
                field_attrs['desc'] = f['desc']
            result['fields'].append({
                'is_reserved': False,
                'attrs': field_attrs
            })

    # If there are fields, register is not self-closing
    if fields:
        result['is_self_closing'] = False

    # Prepare TODO comments for multi-instance registers
    if reg.get('multi'):
        multi_label = reg.get('multi_label', '')
        for todo_id in reg.get('todo_ids', []):
            result['todo_comments'].append(f'TODO Multiple {multi_label} `{xml_name}` instances, skipping {todo_id}')

    return result


def prepare_locks_data(locking_info: dict) -> list:
    """Prepare locks data for XML writing.

    Args:
        locking_info: Dict mapping (locking_reg, locking_field) -> {'locked_regs': [...], 'lock_value': value}

    Returns:
        List of dicts, each with 'name', 'register', 'field', 'value', 'desc' keys
    """
    locks = []

    if not locking_info:
        return locks

    # Count occurrences of each lock field name to determine uniqueness
    field_name_counts = {}
    for (locking_reg, locking_field) in locking_info.keys():
        if locking_field not in field_name_counts:
            field_name_counts[locking_field] = 0
        field_name_counts[locking_field] += 1

    # Sort by (locking_reg, locking_field) for consistent output
    for (locking_reg, locking_field), lock_data in sorted(locking_info.items()):
        locked_reg_names = lock_data['locked_regs']
        lock_value = lock_data['lock_value']

        # Generate unique lock name
        if field_name_counts[locking_field] == 1:
            lock_name = locking_field
        else:
            lock_name = f"{locking_reg}_{locking_field}"

        # Generate description
        if len(locked_reg_names) == 1:
            desc = f"Lock {locked_reg_names[0]}"
        else:
            desc = f"Lock {', '.join(sorted(locked_reg_names))}"

        locks.append({
            'name': lock_name,
            'register': locking_reg,
            'field': locking_field,
            'value': lock_value,
            'desc': desc
        })

    return locks


def prepare_memory_entries(address_mappings: list, acpi_mmio_ranges: list, memory_ranges: dict) -> list:
    """Prepare memory entries for XML writing.

    Args:
        address_mappings: List of address mapping dicts
        acpi_mmio_ranges: List of ACPI MMIO range dicts
        memory_ranges: Dict of memory range name -> range data

    Returns:
        List of memory entry dicts sorted and categorized by source.
        Each entry has 'end_address' calculated from 'address + size'.
    """
    all_entries = []

    # Collect address mappings
    if address_mappings:
        for m in address_mappings:
            addr_val = int(m['address'], 16)
            size_val = int(m['size'], 16)
            # Use provided end_address or calculate from address + size
            end_addr = int(m['end_address'], 16) if m.get('end_address') else (addr_val + size_val)
            all_entries.append({
                'name': m['name'],
                'access': m['access'],
                'address': addr_val,
                'size': size_val,
                'is_reserved': m['is_reserved'],
                'source': 'address_mapping',
                'end_address': end_addr
            })

    # Collect ACPI MMIO ranges
    if acpi_mmio_ranges:
        # Find ACPI base address from address_mappings
        acpi_base = 0
        if address_mappings:
            for m in address_mappings:
                if m['name'].upper() == 'ACPI':
                    acpi_base = int(m['address'], 16)
                    break

        for r in acpi_mmio_ranges:
            full_addr = acpi_base + r['offset']
            size_val = r['size']
            all_entries.append({
                'name': r['name'],
                'access': 'mmio',
                'address': full_addr,
                'size': size_val,
                'is_reserved': r['is_reserved'],
                'source': 'acpi_mmio',
                'end_address': full_addr + size_val
            })

    # Collect memory ranges from Memory Map
    if memory_ranges:
        valid_ranges = {name: r for name, r in memory_ranges.items()
                        if r['address'] and r['address'] != '00000000' and int(r['address'], 16) > 0}

        for name, r in valid_ranges.items():
            addr_val = int(r['address'], 16)
            size_val = r.get('size', r['max_offset'])
            all_entries.append({
                'name': name,
                'access': 'mmio',
                'address': addr_val,
                'size': size_val,
                'is_reserved': False,
                'source': 'memory_map',
                'end_address': addr_val + size_val
            })

    return all_entries


# ─────────────────────────────────────────────────────────────────────────────
# XML Writing Functions
# ─────────────────────────────────────────────────────────────────────────────

def write_xml_line(f, line: str, indent: int = 0):
    """Write a single line to the XML file with optional indentation."""
    f.write('  ' * indent + line + '\n')


def write_section_header(f, title: str, indent: int = 1):
    """Write a section header comment block."""
    prefix = '  ' * indent
    f.write(f'{prefix}<!-- #################################### -->\n')
    f.write(f'{prefix}<!--                                      -->\n')
    f.write(f'{prefix}<!-- {title:<36} -->\n')
    f.write(f'{prefix}<!--                                      -->\n')
    f.write(f'{prefix}<!-- #################################### -->\n')


def write_comment(f, text: str, indent: int = 2):
    """Write an XML comment."""
    f.write('  ' * indent + f'<!-- {text} -->\n')


def write_page_comment(f, page_str: str, indent: int = 2):
    """Write a page comment."""
    f.write('  ' * indent + f'<!-- page {page_str} -->\n')


def write_pages_comment(f, start_page: int, end_page: int, indent: int = 2):
    """Write a pages range comment."""
    f.write('  ' * indent + f'<!-- pages {start_page}-{end_page} -->\n')


def write_register_xml(f, data: dict, indent: int = 2):
    """Write a register element to XML file.

    Args:
        f: Output file handle
        data: Prepared register data from prepare_register_xml_data()
        indent: Indentation level
    """
    prefix = '  ' * indent

    # Write comments
    for comment in data.get('comments', []):
        f.write(f'{prefix}<!-- {comment} -->\n')

    # Write register tag
    attrs = data.get('attrs', {})
    attr_str = ' '.join(f'{k}="{escape_xml(v)}"' for k, v in attrs.items())

    if data.get('is_self_closing', True):
        f.write(f'{prefix}<register {attr_str} />\n')
    else:
        f.write(f'{prefix}<register {attr_str}>\n')

        # Write fields
        field_prefix = prefix + '  '
        for field in data.get('fields', []):
            if field.get('is_reserved'):
                f.write(f'{field_prefix}<!-- {field["text"]} -->\n')
            else:
                field_attrs = field.get('attrs', {})
                field_attr_str = ' '.join(f'{k}="{escape_xml(v)}"' for k, v in field_attrs.items())
                f.write(f'{field_prefix}<field {field_attr_str} />\n')

        f.write(f'{prefix}</register>\n')

    # Write TODO comments
    for todo in data.get('todo_comments', []):
        f.write(f'{prefix}<!-- {todo} -->\n')


def write_pci_device(f, device: dict, max_widths: dict, indent: int = 2):
    """Write a PCI device element with column alignment."""
    prefix = '  ' * indent

    name_pad = ' ' * (max_widths['name'] - len(device['name']))
    bus_pad = ' ' * (max_widths['bus'] - len(device['bus']))
    dev_pad = ' ' * (max_widths['dev'] - len(device['dev']))
    fun_pad = ' ' * (max_widths['fun'] - len(device['fun']))
    vid_pad = ' ' * (max_widths['vid'] - len(device['vid']))

    f.write(f'{prefix}<device name="{device["name"]}"{name_pad} bus="{device["bus"]}"{bus_pad} '
            f'dev="{device["dev"]}"{dev_pad} fun="{device["fun"]}"{fun_pad} '
            f'vid="{device["vid"]}"{vid_pad} did="{device["did"]}" />\n')


def write_memory_range(f, entry: dict, max_widths: dict, indent: int = 2):
    """Write a memory range element with column alignment."""
    prefix = '  ' * indent

    addr_str = f'0x{entry["address"]:010X}'
    size_str = f'0x{entry["size"]:X}'

    name_pad = ' ' * (max_widths['name'] - len(entry['name']))
    access_pad = ' ' * (max_widths['access'] - len(entry['access']))

    f.write(f'{prefix}<range name="{entry["name"]}"{name_pad} access="{entry["access"]}"{access_pad} '
            f'address="{addr_str}" size="{size_str}" />\n')


def write_memory_reserved(f, entry: dict, indent: int = 2):
    """Write a reserved memory range comment.

    Format: <!-- start_address - end_address - reserved. -->
    Requires entry to have 'end_address' populated (done in prepare_memory_entries).
    """
    prefix = '  ' * indent

    addr_str = f'0x{entry["address"]:010X}'
    end_str = f'0x{entry["end_address"]:010X}'
    f.write(f'{prefix}<!-- {addr_str} - {end_str} - reserved. -->\n')


def write_ima_indirect(f, name: str, base: str, max_widths: dict, indent: int = 2):
    """Write an IMA indirect element with column alignment."""
    prefix = '  ' * indent

    name_pad = ' ' * (max_widths['name'] - len(name))
    base_pad = ' ' * (max_widths['base'] - len(base))

    f.write(f'{prefix}<indirect name="{name}"{name_pad} index="SmnIndex" data="SmnData" base="0x{base}"{base_pad} />\n')


def write_io_bar(f, bar: dict, max_widths: dict, indent: int = 2):
    """Write an IO BAR element with column alignment."""
    prefix = '  ' * indent

    name_pad = ' ' * (max_widths['name'] - len(bar['name']))
    reg_pad = ' ' * (max_widths['register'] - len(bar['register']))
    field_pad = ' ' * (max_widths['field'] - len(bar['base_field']))

    f.write(f'{prefix}<bar name="{bar["name"]}"{name_pad} register="{bar["register"]}"{reg_pad} '
            f'base_field="{bar["base_field"]}"{field_pad} desc="" />\n')


def write_lock(f, lock: dict, indent: int = 2):
    """Write a lock element."""
    prefix = '  ' * indent
    f.write(f'{prefix}<lock name="{escape_xml(lock["name"])}" register="{escape_xml(lock["register"])}" '
            f'field="{escape_xml(lock["field"])}" value="{lock["value"]}" desc="{escape_xml(lock["desc"])}" />\n')


# ─────────────────────────────────────────────────────────────────────────────
# Legacy Emit Functions (now use preparation + writing functions)
# ─────────────────────────────────────────────────────────────────────────────

def emit_register_xml(reg: dict, prev_reg: dict = None, emitted_sections: set = None,
                       emitted_pages: set = None, locked_regs: dict = None) -> list:
    """Generate XML lines for a register.

    This function now uses prepare_register_xml_data() for processing
    and converts the result to lines for backward compatibility.
    """
    data = prepare_register_xml_data(reg, prev_reg, emitted_sections, emitted_pages, locked_regs)
    lines = []

    # Convert comments to lines
    for comment in data.get('comments', []):
        lines.append(f'    <!-- {comment} -->')

    # Build register tag
    attrs = data.get('attrs', {})
    attr_str = ' '.join(f'{k}="{escape_xml(v)}"' for k, v in attrs.items())

    if data.get('is_self_closing', True):
        lines.append(f'    <register {attr_str} />')
    else:
        lines.append(f'    <register {attr_str}>')

        # Add fields
        for field in data.get('fields', []):
            if field.get('is_reserved'):
                lines.append(f'      <!-- {field["text"]} -->')
            else:
                field_attrs = field.get('attrs', {})
                field_attr_str = ' '.join(f'{k}="{escape_xml(v)}"' for k, v in field_attrs.items())
                lines.append(f'      <field {field_attr_str} />')

        lines.append('    </register>')

    # Add TODO comments
    for todo in data.get('todo_comments', []):
        lines.append(f'    <!-- {todo} -->')

    return lines


def resolve_name_collisions(regs: list):
    """Resolve XML name collisions by renaming.

    When a register name collides with an existing one, the register is renamed
    and rename information is stored for comment generation:
    - 'xml_name_override': the new name
    - 'rename_original_name': the original name that was attempted
    - 'rename_conflicting_ns': the namespace of the register that already uses the name
    """
    # seen maps name -> (index, namespace) of the first register using this name
    seen = {}
    for i, r in enumerate(regs):
        n = get_xml_name(r)
        prev_info = seen.get(n)
        if prev_info is not None and prev_info[0] < i:
            # Name collision detected - need to rename
            t = r.get('type', '')
            ns = r.get('ns', '')
            device = r.get('device', '')

            # Determine prefix for renaming:
            # 1. If namespace starts with FCH::PM::, use 'PM' prefix
            # 2. If device is available, use device as prefix (for SBTSI::Status -> SBTSIStatus)
            # 3. If register type is msr, use 'Msr' prefix
            # 4. If register type is apic/mmio, use 'Apic' prefix
            # 5. Fall back to type-based suffix
            if ns.startswith('FCH::PM::'):
                prefix = 'PM'
            elif device:
                # Use device as prefix for collision resolution
                prefix = device
            elif t == 'msr':
                prefix = 'Msr'
            elif t == 'apic':
                prefix = 'Apic'
            else:
                prefix = ''

            new_name = prefix + n if prefix else f'{n}_{t.capitalize()}'

            # Store rename information for comment generation
            r['xml_name_override'] = new_name
            r['rename_original_name'] = n
            r['rename_conflicting_ns'] = prev_info[1]  # namespace of conflicting register

            if new_name not in seen:
                seen[new_name] = (i, r.get('ns', ''))
        else:
            seen[n] = (i, r.get('ns', ''))


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def parse_args(args: list):
    """Parse command line arguments."""
    pdfs = []
    output = './registers.xml'
    force = False

    i = 0
    while i < len(args):
        arg = args[i]
        if arg == '-f' or arg == '--force':
            force = True
        elif arg == '-o' or arg == '--output':
            i += 1
            if i < len(args):
                output = args[i]
        elif arg.endswith('.pdf'):
            pdfs.append(arg)
        elif arg.endswith('.xml'):
            output = arg
        i += 1

    return pdfs, output, force


def generate_device_name(component: str, bus: str, dev: int, fun: int, did: str) -> str:
    """Generate a short device name from component description.

    Creates consistent, short names for devices based on their component description.
    """
    component_lower = component.lower()

    # Map common component patterns to short names
    name_mappings = [
        (r'root complex', 'ROOT'),
        (r'^iommu$', 'IOMMU'),
        (r'dummy host bridge', 'HOSTDUMMY'),
        (r'internal pcie.*gpp bridge.*bus a', 'GPP0TOBUSA'),
        (r'internal pcie.*gpp bridge.*bus b', 'GPP0TOBUSB'),
        (r'gpp bridge (\d+)', lambda m: f'GPP{m.group(1)}'),
        (r'data fabric.*function (\d+)', lambda m: f'DF{m.group(1)}'),
        (r'data fabric.*device (\d+)h.*function (\d+)', lambda m: f'DF{m.group(2)}'),
        (r'internal gpu.*model (\d+h)', lambda m: f'GPU'),
        (r'internal gpu.*model', 'GPU'),
        (r'display hd audio', 'DISPLAYHDAUDIO'),
        (r'audio processor.*hd audio', 'HDAUDIO'),
        (r'audio processor', 'AUDIO'),
        (r'usb', 'USB'),
        (r'sata ahci mode.*ms driver', 'SATAMS'),
        (r'sata ahci mode.*amd driver', 'SATAAMD'),
        (r'sata controller.*raid.*second vendor', 'SATARAID1'),
        (r'sata controller.*raid.*ahci mode for', 'SATARAID1'),
        (r'sata controller.*raid', 'SATARAID0'),
        (r'sata ahci', 'SATA'),
        (r'sd controller', 'SD'),
        (r'smbus', 'SMBUS'),
        (r'lpc bridge', 'LPC'),
        (r'gbe controller port (\d+)', lambda m: f'GBE{m.group(1)}'),
        (r'10 gbe controller port (\d+)', lambda m: f'GBE{m.group(1)}'),
        (r'primary pcie.*dummy', 'FUNCTIONDUMMY'),
    ]

    for pattern, name in name_mappings:
        match = re.search(pattern, component_lower)
        if match:
            if callable(name):
                return name(match)
            return name

    # Fallback: use DID as name base
    return f'DEV_{did}'


def process_pci_devices(pci_devices: list) -> list:
    """Process PCI devices and return formatted list ready for XML output.

    This function:
    - Generates device names
    - Handles name collisions with counter (only for multiple instances)
    - Consolidates GPU DIDs (collects all GPU DIDs from the PDF)
    - Formats bus/device/function values

    Returns list of dicts with keys: name, bus, dev, fun, vid, did, bus_type
    """
    if not pci_devices:
        return []

    # Count occurrences of each base name
    name_counts = {}
    for dev in pci_devices:
        base_name = generate_device_name(dev['component'], dev['bus'], dev['dev'], dev['fun'], dev['did'])
        if base_name not in name_counts:
            name_counts[base_name] = 0
        name_counts[base_name] += 1

    # Collect all GPU DIDs for consolidation
    gpu_dids = set()
    for dev in pci_devices:
        base_name = generate_device_name(dev['component'], dev['bus'], dev['dev'], dev['fun'], dev['did'])
        if base_name == 'GPU' and dev['vid'] == '1002':
            gpu_dids.add(dev['did'])

    # Process devices
    processed_devices = []
    name_counters = {}  # base_name -> current counter
    emitted_gpu = False

    for dev in pci_devices:
        vid = dev['vid']
        did = dev['did']
        bus_raw = dev['bus']
        device_num = dev['dev']
        fun = dev['fun']
        component = dev['component']

        # Determine bus value
        if bus_raw == '0':
            bus = '0x00'
            bus_type = 'fixed'
        elif 'Bus A' in bus_raw:
            bus = '0x05'  # Assume A = 5
            bus_type = 'bus_a'
        elif 'Bus B' in bus_raw:
            bus = '0x01'  # Assume B = 1
            bus_type = 'bus_b'
        else:
            bus = '0x00'
            bus_type = 'fixed'

        # Generate device name
        base_name = generate_device_name(component, bus_raw, device_num, fun, did)

        # Handle GPU consolidation - emit once with all DIDs
        if base_name == 'GPU' and vid == '1002':
            if emitted_gpu:
                continue
            name = base_name
            # Collect all GPU DIDs sorted
            did_str = ','.join(f'0x{d}' for d in sorted(gpu_dids))
            emitted_gpu = True
            processed_devices.append({
                'name': name,
                'bus': bus,
                'dev': f'0x{device_num:02X}',
                'fun': str(fun),
                'vid': f'0x{vid}',
                'did': did_str,
                'bus_type': bus_type
            })
            continue

        # Handle naming: single instance = no suffix, multiple instances = counter suffix
        if name_counts[base_name] > 1:
            # Multiple instances: use counter (NAME0, NAME1, NAME2, ...)
            if base_name not in name_counters:
                name_counters[base_name] = 0
            name = f'{base_name}{name_counters[base_name]}'
            name_counters[base_name] += 1
        else:
            # Single instance: no suffix
            name = base_name

        did_str = f'0x{did}'

        processed_devices.append({
            'name': name,
            'bus': bus,
            'dev': f'0x{device_num:02X}',
            'fun': str(fun),
            'vid': f'0x{vid}',
            'did': did_str,
            'bus_type': bus_type
        })

    return processed_devices


def prepare_header_data(platform: str, reference: str, pci_devices: list = None, pci_table_pages: list = None,
                         memory_ranges: dict = None, memory_map_pages: list = None,
                         address_mappings: list = None, address_mapping_pages: list = None,
                         acpi_mmio_ranges: list = None, acpi_mmio_table_pages: list = None,
                         ima_entries: dict = None, ima_pages: list = None,
                         io_bars: list = None) -> dict:
    """Prepare all data needed for XML header.

    This function processes all input data and returns a structured dict
    ready for writing. No XML generation happens here.

    Returns:
        dict with sections: 'info', 'pci', 'mmio', 'memory', 'ima', 'io', 'registers_header'
    """
    data = {
        'platform': platform,
        'reference': reference,
        'pci': {'devices': [], 'pages': pci_table_pages or []},
        'memory': {'entries': [], 'pages': {}},
        'ima': {'entries': [], 'pages': ima_pages or []},
        'io': {'bars': [], 'pages': []}
    }

    # Process PCI devices - calculate max widths
    if pci_devices:
        max_widths = {
            'name': max(len(d['name']) for d in pci_devices),
            'bus': max(len(d['bus']) for d in pci_devices),
            'dev': max(len(d['dev']) for d in pci_devices),
            'fun': max(len(d['fun']) for d in pci_devices),
            'vid': max(len(d['vid']) for d in pci_devices)
        }
        data['pci']['devices'] = pci_devices
        data['pci']['max_widths'] = max_widths

    # Process memory entries using the helper function
    memory_entries = prepare_memory_entries(address_mappings or [], acpi_mmio_ranges or [], memory_ranges or {})
    data['memory']['entries'] = memory_entries
    data['memory']['pages'] = {
        'address_mapping': address_mapping_pages or [],
        'acpi_mmio': acpi_mmio_table_pages or [],
        'memory_map': memory_map_pages or []
    }

    # Process IMA entries
    if ima_entries:
        max_name = max(len(name) for name in ima_entries.keys())
        max_base = max(len(e['base']) for e in ima_entries.values())
        data['ima']['entries'] = ima_entries
        data['ima']['max_widths'] = {'name': max_name, 'base': max_base}

    # Process IO bars
    if io_bars:
        pages = sorted(set(bar['page'] for bar in io_bars))
        max_name = max(len(bar['name']) for bar in io_bars)
        max_reg = max(len(bar['register']) for bar in io_bars)
        max_field = max(len(bar['base_field']) for bar in io_bars)
        data['io']['bars'] = io_bars
        data['io']['pages'] = pages
        data['io']['max_widths'] = {'name': max_name, 'register': max_reg, 'field': max_field}

    return data


def write_xml(f, header_data: dict, register_data_list: list, locks_data: list):
    """Write complete XML file.

    This is the single entry point for all XML writing. It writes:
    - XML declaration and configuration opening tag
    - Info section
    - PCI section with devices
    - MMIO section
    - Memory section with ranges
    - IMA section with indirect accesses
    - IO section with BARs
    - Registers section with all registers and fields
    - Controls section
    - Locks section
    - Configuration closing tag

    All data processing is done before calling this function.
    This function only handles the actual writing.

    Args:
        f: Output file handle
        header_data: Prepared header data from prepare_header_data()
        register_data_list: List of prepared register data from prepare_register_xml_data()
        locks_data: List of lock dicts from prepare_locks_data()
    """
    platform = header_data['platform']
    reference = header_data['reference']

    # ═══════════════════════════════════════════════════════════════════
    # XML declaration and opening tag
    # ═══════════════════════════════════════════════════════════════════
    f.write('<?xml version="1.0"?>\n')
    f.write(f'<configuration platform="{platform}">\n')
    f.write('<!--\n')
    f.write(f'XML configuration for {platform} based platforms\n')
    f.write('\n')
    f.write(f'Reference: {reference}.\n')
    f.write('\n')
    f.write('-->\n')
    f.write('\n')

    # ═══════════════════════════════════════════════════════════════════
    # Information section
    # ═══════════════════════════════════════════════════════════════════
    write_section_header(f, 'Information')
    f.write('  <info family="core">\n')
    f.write('    <sku did="FIXME" name="FIXME" code="FIXME" longname="FIXME Root Complex" />\n')
    f.write('  </info>\n')
    f.write('\n')

    # ═══════════════════════════════════════════════════════════════════
    # PCI section
    # ═══════════════════════════════════════════════════════════════════
    write_section_header(f, 'Integrated devices')
    f.write('  <pci>\n')

    pci_data = header_data.get('pci', {})
    if pci_data.get('pages'):
        pages = pci_data['pages']
        if len(pages) == 1:
            write_comment(f, f'page {pages[0]}')
        else:
            write_comment(f, f'pages {pages[0]}-{pages[-1]}')

    if pci_data.get('devices'):
        f.write('    <!-- PCI Device ID Assignments -->\n')
        f.write('    <!-- Bus A and B are programmable. Here, we assume A = 5 and B = 1. -->\n')

        max_widths = pci_data.get('max_widths', {})
        prev_bus_type = None
        for d in pci_data['devices']:
            if prev_bus_type is not None and d.get('bus_type') != prev_bus_type:
                f.write('\n')
            prev_bus_type = d.get('bus_type')
            write_pci_device(f, d, max_widths)

    f.write('  </pci>\n')
    f.write('\n')

    # ═══════════════════════════════════════════════════════════════════
    # MMIO section (empty)
    # ═══════════════════════════════════════════════════════════════════
    write_section_header(f, 'Memory Mapped I/O spaces (MMIO BARs)')
    f.write('  <mmio>\n')
    f.write('  </mmio>\n')
    f.write('\n')

    # ═══════════════════════════════════════════════════════════════════
    # Memory section
    # ═══════════════════════════════════════════════════════════════════
    write_section_header(f, 'Memory ranges')
    f.write('  <memory>\n')

    memory_data = header_data.get('memory', {})
    memory_entries = memory_data.get('entries', [])
    memory_pages = memory_data.get('pages', {})

    if memory_entries:
        # Calculate max widths for non-reserved entries
        non_reserved = [e for e in memory_entries if not e['is_reserved']]
        if non_reserved:
            max_widths = {
                'name': max(len(e['name']) for e in non_reserved),
                'access': max(len(e['access']) for e in non_reserved)
            }
        else:
            max_widths = {'name': 0, 'access': 0}

        # Group by source
        address_map_entries = [e for e in memory_entries if e['source'] == 'address_mapping']
        acpi_mmio_entries = [e for e in memory_entries if e['source'] == 'acpi_mmio']
        memory_map_entries = [e for e in memory_entries if e['source'] == 'memory_map']

        # Output Address Space Mapping
        if address_map_entries:
            pages = memory_pages.get('address_mapping', [])
            if pages:
                if len(pages) == 1:
                    write_comment(f, f'page {pages[0]}')
                else:
                    write_comment(f, f'pages {pages[0]}-{pages[-1]}')
            f.write('    <!-- Address Space Mapping -->\n')

            for e in address_map_entries:
                if e['is_reserved']:
                    write_memory_reserved(f, e)
                else:
                    write_memory_range(f, e, max_widths)

        # Output ACPI MMIO Space Allocation
        if acpi_mmio_entries:
            pages = memory_pages.get('acpi_mmio', [])
            if pages:
                if len(pages) == 1:
                    write_comment(f, f'page {pages[0]}')
                else:
                    write_comment(f, f'pages {pages[0]}-{pages[-1]}')
            f.write('    <!-- ACPI MMIO Space Allocation -->\n')

            for e in acpi_mmio_entries:
                if e['is_reserved']:
                    write_memory_reserved(f, e)
                else:
                    write_memory_range(f, e, max_widths)

        # Output Memory Map - Main Memory
        if memory_map_entries:
            pages = memory_pages.get('memory_map', [])
            if pages:
                if len(pages) == 1:
                    write_comment(f, f'page {pages[0]}')
                else:
                    write_comment(f, f'pages {pages[0]}-{pages[-1]}')
            f.write('    <!-- Memory Map - Main Memory -->\n')

            # Sort by preferred order
            device_order = ['IOAPIC', 'SPI', 'ESPI', 'HPET', 'HCE', 'SMI', 'PM', 'PM2', 'GPIO',
                            'RTCHOST', 'WDT', 'IOMUX', 'MISC', 'ACDC', 'AOAC', 'EMMCHC', 'EMMCCFG']

            def sort_key(e):
                try:
                    return (0, device_order.index(e['name']))
                except ValueError:
                    return (1, e['name'])

            for e in sorted(memory_map_entries, key=sort_key):
                write_memory_range(f, e, max_widths)

    f.write('  </memory>\n')
    f.write('\n')

    # ═══════════════════════════════════════════════════════════════════
    # IMA section
    # ═══════════════════════════════════════════════════════════════════
    write_section_header(f, 'Indirect memory accesses')
    f.write('  <ima>\n')

    ima_data = header_data.get('ima', {})
    if ima_data.get('pages'):
        pages = ima_data['pages']
        if len(pages) == 1:
            write_comment(f, f'page {pages[0]}')
        else:
            write_comment(f, f'pages {pages[0]}-{pages[-1]}')

    if ima_data.get('entries'):
        f.write('    <!-- Memory Map - SMN -->\n')

        ima_entries = ima_data['entries']
        max_widths = ima_data.get('max_widths', {'name': 0, 'base': 0})

        # Preferred order
        device_order = ['SMUTHM', 'IOMMUMMIO', 'IOMMUCFG', 'IOMMUL2B', 'IOMMUL1INT0', 'IOMMUL1INT1', 'IOMMUL2A']

        # Output in preferred order
        for name in device_order:
            if name in ima_entries:
                write_ima_indirect(f, name, ima_entries[name]['base'], max_widths)

        # Output remaining
        for name, e in sorted(ima_entries.items()):
            if name not in device_order:
                write_ima_indirect(f, name, e['base'], max_widths)

    f.write('  </ima>\n')
    f.write('\n')

    # ═══════════════════════════════════════════════════════════════════
    # IO section
    # ═══════════════════════════════════════════════════════════════════
    write_section_header(f, 'I/O spaces (I/O BARs)')
    f.write('  <io>\n')

    io_data = header_data.get('io', {})
    if io_data.get('bars'):
        pages = io_data.get('pages', [])
        if pages:
            if len(pages) == 1:
                write_comment(f, f'page {pages[0]}')
            else:
                write_comment(f, f'pages {pages[0]}-{pages[-1]}')

        max_widths = io_data.get('max_widths', {'name': 0, 'register': 0, 'field': 0})
        for bar in io_data['bars']:
            write_io_bar(f, bar, max_widths)

    f.write('  </io>\n')
    f.write('\n')

    # ═══════════════════════════════════════════════════════════════════
    # Registers section
    # ═══════════════════════════════════════════════════════════════════
    write_section_header(f, 'Configuration registers')
    f.write('  <registers>\n')

    for reg_data in register_data_list:
        write_register_xml(f, reg_data)

    f.write('  </registers>\n')
    f.write('\n')

    # ═══════════════════════════════════════════════════════════════════
    # Controls section
    # ═══════════════════════════════════════════════════════════════════
    write_section_header(f, 'Controls')
    f.write('  <controls>\n')
    f.write('  </controls>\n')
    f.write('\n')

    # ═══════════════════════════════════════════════════════════════════
    # Locks section
    # ═══════════════════════════════════════════════════════════════════
    write_section_header(f, 'Locks')
    f.write('  <locks>\n')

    if locks_data:
        for lock in locks_data:
            write_lock(f, lock)

    f.write('  </locks>\n')
    f.write('\n')

    # ═══════════════════════════════════════════════════════════════════
    # Closing tag
    # ═══════════════════════════════════════════════════════════════════
    f.write('</configuration>\n')


def main():
    """Main entry point.

    This function orchestrates the PDF-to-XML conversion:
    1. Parse command line arguments
    2. Process PDFs to extract registers and metadata
    3. Resolve name collisions and lock relationships
    4. Prepare all data for XML output
    5. Write XML file
    """
    pdfs, output, force = parse_args(sys.argv[1:])

    if not pdfs:
        print("Usage: python3 amd_ppr_pdf_to_xml.py <pdf1.pdf> [pdf2.pdf ...] [output.xml]")
        sys.exit(1)

    if os.path.exists(output) and not force:
        print(f"Error: Output file '{output}' already exists. Use -f to overwrite.")
        sys.exit(1)

    # ═══════════════════════════════════════════════════════════════════
    # Step 1: Process PDFs - extract registers and metadata
    # ═══════════════════════════════════════════════════════════════════
    processor = PDFProcessor()
    processor.process_pdfs(pdfs)

    # ═══════════════════════════════════════════════════════════════════
    # Step 2: Resolve name collisions and lock relationships
    # ═══════════════════════════════════════════════════════════════════

    resolve_name_collisions(processor.registers)
    locked_regs, locking_info = process_lock_relationships(processor.registers)

    # Process PCI devices (generate names, consolidate GPUs, etc.)
    processed_pci_devices = process_pci_devices(processor.pci_devices)

    # ═══════════════════════════════════════════════════════════════════
    # Step 3: Prepare all data for XML output
    # ═══════════════════════════════════════════════════════════════════

    platform = "FIXME"  # PDF doesn't contain reliable platform info

    # Prepare header data
    header_data = prepare_header_data(
        platform, processor.reference, processed_pci_devices, processor.pci_table_pages,
        processor.memory_ranges, processor.memory_map_pages,
        processor.address_mappings, processor.address_mapping_pages,
        processor.acpi_mmio_ranges, processor.acpi_mmio_table_pages,
        processor.ima_entries, processor.ima_pages, processor.io_bars
    )

    # Prepare register data for each register
    register_data_list = []
    prev_reg = None
    emitted_sections = set()
    emitted_pages = set()
    for reg in processor.registers:
        reg_data = prepare_register_xml_data(reg, prev_reg, emitted_sections, emitted_pages, locked_regs)
        register_data_list.append(reg_data)
        prev_reg = reg

    # Prepare locks data
    locks_data = prepare_locks_data(locking_info)

    # ═══════════════════════════════════════════════════════════════════
    # Step 4: Write XML file
    # ═══════════════════════════════════════════════════════════════════

    print(f"Writing {len(processor.registers)} registers to {output}...", file=sys.stderr)

    with open(output, 'w', encoding='utf-8') as f:
        write_xml(f, header_data, register_data_list, locks_data)

    print(f"Wrote {len(processor.registers)} registers to {output}", file=sys.stderr)


if __name__ == '__main__':
    main()
