#!/usr/bin/env python3

# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2026, Intel Corporation

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; Version 2.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

# Contact information:
# chipsec@intel.com
"""
XML Configuration Register Extractor

This script parses CHIPSEC XML configuration files and extracts all registers
into a single flat file. It follows 'config' attributes to include referenced
files and identifies duplicate registers with their differences.

- Built with AI assistance.

Usage:
    python extract_registers.py [<xml_file_or_glob> ...] [-o output_file_or_dir] [--cfg-dir CFG_DIR]

Notes:
    - If one or more XML files or glob patterns are provided, the script processes
      those inputs directly and -o specifies the output file.
    - If no XML inputs are provided, the script auto-discovers platform XML files
      under --cfg-dir and -o specifies the output directory.

Examples:
    python extract_registers.py "chipsec/cfg/8086/adl.xml" -o registers.txt
    python extract_registers.py --cfg-dir chipsec/cfg -o out/
"""

import xml.etree.ElementTree as ET
import argparse
import glob
import os
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


class RegisterInfo:
    """Store information about a register."""

    def __init__(self, name: str, element: ET.Element, source_file: str, parent_path: str = "", top_level_file: str = ""):
        self.name = name
        self.element = element
        self.source_file = source_file
        self.parent_path = parent_path
        self.top_level_file = top_level_file

    def get_attributes_str(self) -> str:
        """Get all attributes as a formatted string."""
        attrs = dict(self.element.attrib)
        return ", ".join([f'{k}="{v}"' for k, v in sorted(attrs.items())])

    def get_fields(self) -> List[Tuple[str, Dict[str, str]]]:
        """Get all field elements with their attributes."""
        fields = []
        for field in self.element.findall('field'):
            field_name = field.get('name', 'unnamed')
            field_attrs = dict(field.attrib)
            fields.append((field_name, field_attrs))
        return fields

    def to_xml_string(self) -> str:
        """Convert register element to formatted XML string."""
        return ET.tostring(self.element, encoding='unicode', method='xml')

    def get_signature(self) -> str:
        """Get a signature for comparison (excludes desc and some non-critical attributes)."""
        attrs = dict(self.element.attrib)
        # Remove description for comparison
        sig_attrs = {k: v for k, v in attrs.items() if k not in ['desc']}

        # Add field information
        field_sigs = []
        for field_name, field_attrs in self.get_fields():
            field_sig_attrs = {k: v for k, v in field_attrs.items() if k not in ['desc']}
            field_sigs.append(f"{field_name}:{sorted(field_sig_attrs.items())}")

        return f"{sorted(sig_attrs.items())}|{'|'.join(sorted(field_sigs))}"


class ControlInfo:
    """Store information about a control."""

    def __init__(self, name: str, element: ET.Element, source_file: str, parent_path: str = "", top_level_file: str = ""):
        self.name = name
        self.element = element
        self.source_file = source_file
        self.parent_path = parent_path
        self.top_level_file = top_level_file

    def get_attributes_str(self) -> str:
        """Get all attributes as a formatted string."""
        attrs = dict(self.element.attrib)
        return ", ".join([f'{k}="{v}"' for k, v in sorted(attrs.items())])

    def to_xml_string(self) -> str:
        """Convert control element to formatted XML string."""
        return ET.tostring(self.element, encoding='unicode', method='xml')


class CrossReference:
    """Store a cross-reference from an element to a register/field."""

    def __init__(self, tag: str, element_name: str, source_file: str,
                 register_attr: str, register_name: str,
                 field_attr: str, field_name: str):
        self.tag = tag                      # e.g., 'bar', 'subcomponent', 'control', 'lock'
        self.element_name = element_name    # name attribute of the referencing element
        self.source_file = source_file
        self.register_attr = register_attr  # attribute name holding the register ref (e.g., 'register')
        self.register_name = register_name  # value of the register attribute
        self.field_attr = field_attr        # attribute name holding the field ref (e.g., 'base_field')
        self.field_name = field_name        # value of the field attribute


class XMLConfigParser:
    """Parse CHIPSEC XML configuration files and extract registers."""

    def __init__(self, base_paths: List[str]):
        self.base_paths = [Path(p).resolve() for p in base_paths]
        self.registers: Dict[str, List[RegisterInfo]] = defaultdict(list)
        self.controls: Dict[str, List[ControlInfo]] = defaultdict(list)
        self.cross_references: List[CrossReference] = []
        self.parse_errors: List[str] = []
        self._cached_validation_errors: List[str] = None
        self.processed_files: Set[str] = set()
        self.file_tree: Dict[str, List[str]] = defaultdict(list)
        self.file_to_top_level: Dict[str, str] = {}  # Maps any file to its top-level source

    def find_config_file(self, config_path: str, current_file: str) -> Optional[str]:
        """Find the actual path of a config file."""
        current_dir = Path(current_file).parent

        # Convert dot notation to path (e.g., HOSTCTL.hostctl1.xml -> HOSTCTL/hostctl1.xml)
        # Split on first dot to get directory and filename
        if '.' in config_path:
            parts = config_path.split('.', 1)
            if len(parts) == 2:
                config_path_converted = f"{parts[0]}/{parts[1]}"
            else:
                config_path_converted = config_path
        else:
            config_path_converted = config_path

        # Try relative to current file with dot notation converted
        potential_path = current_dir / config_path_converted
        if potential_path.exists():
            return str(potential_path.resolve())

        # Try as-is relative to current file
        potential_path = current_dir / config_path
        if potential_path.exists():
            return str(potential_path.resolve())

        # Find the vendor directory (e.g., 8086, 1022) from current file
        # Walk up from current_dir looking for a parent whose parent is named 'cfg'
        vendor_dir = self._find_vendor_dir(current_dir)

        if vendor_dir:
            # Try with dot notation converted
            potential_path = vendor_dir / config_path_converted
            if potential_path.exists():
                return str(potential_path.resolve())

            # Try as-is
            potential_path = vendor_dir / config_path
            if potential_path.exists():
                return str(potential_path.resolve())

        # Try each base path
        for base_path in self.base_paths:
            cfg_dir = base_path.parent if base_path.is_file() else base_path
            vendor_dir = self._find_vendor_dir(cfg_dir)

            if vendor_dir:
                # Try with dot notation converted
                potential_path = vendor_dir / config_path_converted
                if potential_path.exists():
                    return str(potential_path.resolve())

                # Try as-is
                potential_path = vendor_dir / config_path
                if potential_path.exists():
                    return str(potential_path.resolve())

        return None

    @staticmethod
    def _find_vendor_dir(start_dir: Path) -> Optional[Path]:
        """Walk up from start_dir to find the vendor directory (child of cfg/).
        The vendor directory name must be a 4-digit hex value (e.g., 8086, 1022)."""
        search_dir = start_dir.resolve()
        while search_dir.parent != search_dir:
            if search_dir.parent.name == 'cfg' and re.fullmatch(r'[0-9a-fA-F]{4}', search_dir.name):
                return search_dir
            search_dir = search_dir.parent
        return None

    def parse_file(self, file_path: str, parent_path: str = "", top_level_file: str = None) -> None:
        """Parse an XML file and extract registers."""
        file_path = str(Path(file_path).resolve())

        # Track the top-level file that caused this file to be processed
        if top_level_file is None:
            top_level_file = file_path  # This is a top-level file

        if file_path not in self.file_to_top_level:
            self.file_to_top_level[file_path] = top_level_file

        if file_path in self.processed_files:
            return

        self.processed_files.add(file_path)

        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
        except ET.ParseError as e:
            msg = f"ERROR: Failed to parse {file_path}: {e}"
            print(msg, file=sys.stderr)
            self.parse_errors.append(msg)
            return
        except FileNotFoundError:
            msg = f"ERROR: File not found: {file_path}"
            print(msg, file=sys.stderr)
            self.parse_errors.append(msg)
            return

        # Extract registers from this file
        for register in root.findall('.//register'):
            name = register.get('name')
            if name:
                reg_info = RegisterInfo(name, register, file_path, parent_path, top_level_file)
                self.registers[name].append(reg_info)

        # Extract controls from this file
        for control in root.findall('.//control'):
            name = control.get('name')
            if name:
                ctrl_info = ControlInfo(name, control, file_path, parent_path, top_level_file)
                self.controls[name].append(ctrl_info)

        # Collect cross-references for validation
        self._collect_cross_references(root, file_path)

        # Follow config references
        self._follow_config_references(root, file_path, parent_path, top_level_file)

    def _collect_cross_references(self, root: ET.Element, source_file: str) -> None:
        """Collect cross-references between elements and registers/fields."""
        # Define which tags/attributes reference register fields
        # Format: (xpath, register_attr, [(field_attr, field_register_attr)])
        # field_register_attr: which attribute holds the register for this field (usually same as register_attr)
        ref_specs = [
            ('.//bar',          'register', [('base_field', None), ('enable_field', None)]),
            ('.//subcomponent',  'register', [('base_field', None), ('enable_field', None), ('valid', None), ('valid_field', None)]),
            ('.//subcomponent',  'limit_register', [('limit_field', None)]),
            ('.//control',      'register', [('field', None)]),
            ('.//lock',         'register', [('field', None)]),
        ]

        for xpath, reg_attr, field_specs in ref_specs:
            for elem in root.findall(xpath):
                reg_name = elem.get(reg_attr)
                if not reg_name:
                    continue

                elem_name = elem.get('name', elem.tag)

                # Check register-only references (register exists?)
                self.cross_references.append(CrossReference(
                    tag=elem.tag, element_name=elem_name, source_file=source_file,
                    register_attr=reg_attr, register_name=reg_name,
                    field_attr='', field_name=''
                ))

                # Check field references
                for field_attr, field_reg_attr in field_specs:
                    field_name = elem.get(field_attr)
                    if field_name:
                        target_reg = elem.get(field_reg_attr) if field_reg_attr else reg_name
                        self.cross_references.append(CrossReference(
                            tag=elem.tag, element_name=elem_name, source_file=source_file,
                            register_attr=reg_attr, register_name=target_reg,
                            field_attr=field_attr, field_name=field_name
                        ))

    def _follow_config_references(self, element: ET.Element, current_file: str, parent_path: str, top_level_file: str) -> None:
        """Recursively follow config attributes in XML elements."""
        config_attr = element.get('config')

        if config_attr:
            # Support comma-separated config paths
            config_paths = [path.strip() for path in config_attr.split(',')]

            for config_path in config_paths:
                config_file = self.find_config_file(config_path, current_file)
                if config_file:
                    # Build parent path for context
                    element_name = element.get('name', element.tag)
                    new_parent_path = f"{parent_path}/{element_name}" if parent_path else element_name

                    self.file_tree[current_file].append(config_file)
                    self.parse_file(config_file, new_parent_path, top_level_file)
                else:
                    msg = f"ERROR: Config file not found: {config_path} (referenced from {current_file})"
                    print(msg, file=sys.stderr)
                    self.parse_errors.append(msg)

        # Recursively process children
        for child in element:
            self._follow_config_references(child, current_file, parent_path, top_level_file)

    def get_register_deltas(self, reg_name: str) -> List[str]:
        """Compare multiple definitions of a register and return differences."""
        reg_infos = self.registers[reg_name]
        if len(reg_infos) <= 1:
            return []

        deltas = []
        base_reg = reg_infos[0]

        for i, reg in enumerate(reg_infos[1:], 1):
            delta_lines = []
            delta_lines.append(f"Difference #{i}:")
            delta_lines.append(f"  File 1: {base_reg.source_file}")
            delta_lines.append(f"  File 2: {reg.source_file}")

            # Compare attributes
            base_attrs = dict(base_reg.element.attrib)
            curr_attrs = dict(reg.element.attrib)

            all_attr_keys = set(base_attrs.keys()) | set(curr_attrs.keys())
            attr_diffs = []

            for key in sorted(all_attr_keys):
                base_val = base_attrs.get(key, '<not defined>')
                curr_val = curr_attrs.get(key, '<not defined>')
                if base_val != curr_val:
                    attr_diffs.append(f"    {key}: '{base_val}' vs '{curr_val}'")

            if attr_diffs:
                delta_lines.append("  Attribute differences:")
                delta_lines.extend(attr_diffs)

            # Compare fields
            base_fields = {name: attrs for name, attrs in base_reg.get_fields()}
            curr_fields = {name: attrs for name, attrs in reg.get_fields()}

            all_field_names = set(base_fields.keys()) | set(curr_fields.keys())
            field_diffs = []

            for field_name in sorted(all_field_names):
                if field_name not in base_fields:
                    field_diffs.append(f"    + Field '{field_name}' added in file 2")
                    field_diffs.append(f"      {curr_fields[field_name]}")
                elif field_name not in curr_fields:
                    field_diffs.append(f"    - Field '{field_name}' removed in file 2")
                elif base_fields[field_name] != curr_fields[field_name]:
                    field_diffs.append(f"    ~ Field '{field_name}' modified:")
                    base_f = base_fields[field_name]
                    curr_f = curr_fields[field_name]
                    all_f_keys = set(base_f.keys()) | set(curr_f.keys())
                    for k in sorted(all_f_keys):
                        bv = base_f.get(k, '<not defined>')
                        cv = curr_f.get(k, '<not defined>')
                        if bv != cv:
                            field_diffs.append(f"      {k}: '{bv}' vs '{cv}'")

            if field_diffs:
                delta_lines.append("  Field differences:")
                delta_lines.extend(field_diffs)

            if len(delta_lines) > 3:  # Only add if there are actual differences
                deltas.append('\n'.join(delta_lines))

        return deltas

    def _resolve_register_name(self, reg_name: str) -> str:
        """Resolve dotted register names (e.g., 'PWRMBASE.VGPIO_BAR' -> 'VGPIO_BAR')."""
        if '.' in reg_name:
            return reg_name.rsplit('.', 1)[-1]
        return reg_name

    def validate_cross_references(self) -> List[str]:
        """Validate all cross-references and return a list of error messages."""
        errors = []
        seen = set()

        # Precompute register -> set(field_names) map
        reg_field_map: Dict[str, Set[str]] = {}
        for reg_name, reg_infos in self.registers.items():
            fields = set()
            for reg_info in reg_infos:
                for fname, _ in reg_info.get_fields():
                    fields.add(fname)
            reg_field_map[reg_name] = fields

        for xref in self.cross_references:
            resolved_name = self._resolve_register_name(xref.register_name)

            # Check if referenced register exists
            if resolved_name not in self.registers:
                key = (xref.tag, xref.element_name, xref.source_file, xref.register_attr, xref.register_name)
                if key not in seen:
                    seen.add(key)
                    errors.append(
                        f"ERROR: <{xref.tag} name=\"{xref.element_name}\"> in {xref.source_file}\n"
                        f"  {xref.register_attr}=\"{xref.register_name}\" references undefined register \"{resolved_name}\""
                    )
                continue

            # If this is a field reference, check that the field exists
            if xref.field_name:
                field_names = reg_field_map[resolved_name]

                if xref.field_name not in field_names:
                    key = (xref.tag, xref.element_name, xref.source_file, resolved_name, xref.field_attr, xref.field_name)
                    if key not in seen:
                        seen.add(key)
                        suggestion = ""
                        # Try to find a close match
                        for fname in sorted(field_names):
                            if xref.field_name.lower() in fname.lower() or fname.lower() in xref.field_name.lower():
                                suggestion = f" (did you mean \"{fname}\"?)"
                                break
                        errors.append(
                            f"ERROR: <{xref.tag} name=\"{xref.element_name}\"> in {xref.source_file}\n"
                            f"  {xref.field_attr}=\"{xref.field_name}\" not found in register \"{resolved_name}\"{suggestion}\n"
                            f"  Available fields: {', '.join(sorted(field_names)) if field_names else '(no fields defined)'}"
                        )

        return errors

    def generate_output(self, output_file: str = None) -> None:
        """Generate the flat register list output."""
        output = sys.stdout if output_file is None else open(output_file, 'w', encoding='utf-8')

        try:
            # Header
            output.write("=" * 80 + "\n")
            output.write("CHIPSEC XML Configuration - Flat Register List\n")
            output.write("=" * 80 + "\n\n")

            output.write(f"Total unique registers: {len(self.registers)}\n")
            output.write(f"Total unique controls: {len(self.controls)}\n")
            output.write(f"Total files processed: {len(self.processed_files)}\n")

            # Use cached validation results if available, otherwise compute
            validation_errors = self._cached_validation_errors if self._cached_validation_errors is not None else self.validate_cross_references()
            output.write(f"Cross-reference errors: {len(validation_errors)}\n")
            output.write(f"Parse/config errors: {len(self.parse_errors)}\n\n")

            # Output validation errors first if any
            if validation_errors:
                output.write("!" * 80 + "\n")
                output.write("CROSS-REFERENCE VALIDATION ERRORS\n")
                output.write("!" * 80 + "\n\n")
                for i, error in enumerate(validation_errors, 1):
                    output.write(f"{i}. {error}\n\n")
                output.write("=" * 80 + "\n\n")

            # List processed files
            output.write("Processed files:\n")
            for i, file_path in enumerate(sorted(self.processed_files), 1):
                output.write(f"  {i}. {file_path}\n")
            output.write("\n")

            # File dependency tree
            output.write("File dependency tree:\n")
            self._write_file_tree(output)
            output.write("\n")

            output.write("=" * 80 + "\n")
            output.write("REGISTERS\n")
            output.write("=" * 80 + "\n\n")

            # Group registers by type, then by context, then by offset
            registers_by_type = defaultdict(lambda: defaultdict(list))
            for reg_name in self.registers.keys():
                reg_infos = self.registers[reg_name]
                reg_type = reg_infos[0].element.get('type', 'unknown')
                reg_context = reg_infos[0].parent_path if reg_infos[0].parent_path else '(root)'
                registers_by_type[reg_type][reg_context].append(reg_name)

            # Output registers by type
            for reg_type in sorted(registers_by_type.keys()):
                output.write(f"\n{'=' * 80}\n")
                output.write(f"Type: {reg_type.upper()}\n")
                output.write(f"{'=' * 80}\n\n")

                # Sort contexts
                for context in sorted(registers_by_type[reg_type].keys()):
                    output.write(f"\n{'-' * 80}\n")
                    output.write(f"Context: {context}\n")
                    output.write(f"{'-' * 80}\n\n")

                    # Sort registers within context by offset
                    reg_names = registers_by_type[reg_type][context]

                    # Create tuples of (offset_value, reg_name) for sorting
                    reg_with_offsets = []
                    for reg_name in reg_names:
                        reg_info = self.registers[reg_name][0]
                        offset_str = reg_info.element.get('offset', reg_info.element.get('msr', '0'))
                        # Convert hex string to int for proper sorting
                        try:
                            if offset_str.startswith('0x'):
                                offset_val = int(offset_str, 16)
                            else:
                                offset_val = int(offset_str)
                        except (ValueError, AttributeError):
                            offset_val = 0
                        reg_with_offsets.append((offset_val, offset_str, reg_name))

                    # Sort by offset value
                    reg_with_offsets.sort(key=lambda x: x[0])

                    for _, _, reg_name in reg_with_offsets:
                        self._write_register(output, reg_name)

            # Output controls section
            if self.controls:
                output.write(f"\n\n{'=' * 80}\n")
                output.write("CONTROLS\n")
                output.write(f"{'=' * 80}\n\n")

                # Group controls by context
                controls_by_context = defaultdict(list)
                for ctrl_name in self.controls.keys():
                    ctrl_infos = self.controls[ctrl_name]
                    ctrl_context = ctrl_infos[0].parent_path if ctrl_infos[0].parent_path else '(root)'
                    controls_by_context[ctrl_context].append(ctrl_name)

                # Output controls by context
                for context in sorted(controls_by_context.keys()):
                    output.write(f"\n{'-' * 80}\n")
                    output.write(f"Context: {context}\n")
                    output.write(f"{'-' * 80}\n\n")

                    # Sort controls alphabetically within context
                    for ctrl_name in sorted(controls_by_context[context]):
                        self._write_control(output, ctrl_name)

        finally:
            if output_file is not None:
                output.close()

    def _write_file_tree(self, output, file_path: str = None, indent: int = 0, visited: Set[str] = None) -> None:
        """Write file dependency tree recursively."""
        if visited is None:
            visited = set()
            # Start from root files (those not referenced by others)
            referenced = set()
            for refs in self.file_tree.values():
                referenced.update(refs)
            root_files = self.processed_files - referenced
            for root in sorted(root_files):
                self._write_file_tree(output, root, 0, visited)
            return

        if file_path in visited:
            output.write("  " * indent + f"└─ {file_path} [already shown]\n")
            return

        visited.add(file_path)
        output.write("  " * indent + f"└─ {file_path}\n")

        if file_path in self.file_tree:
            for child in sorted(self.file_tree[file_path]):
                self._write_file_tree(output, child, indent + 1, visited)

    def _write_register(self, output, reg_name: str) -> None:
        """Write a register definition with all its information."""
        reg_infos = self.registers[reg_name]

        # Header for register
        output.write("-" * 80 + "\n")
        output.write(f"Register: {reg_name}\n")
        output.write("-" * 80 + "\n")

        # If multiple definitions, note it
        if len(reg_infos) > 1:
            output.write(f"!!! DEFINED IN {len(reg_infos)} FILES !!!\n\n")

        # Write first (primary) definition
        primary = reg_infos[0]
        output.write(f"Source: {primary.source_file}\n")
        # Show which top-level file included this source
        if primary.top_level_file and primary.top_level_file != primary.source_file:
            output.write(f"Included by: {primary.top_level_file}\n")
        if primary.parent_path:
            output.write(f"Context: {primary.parent_path}\n")
        output.write(f"Type: {primary.element.get('type', 'unknown')}\n")

        # Write all attributes
        attrs = dict(primary.element.attrib)
        if 'name' in attrs:
            del attrs['name']  # Already shown
        if 'type' in attrs:
            del attrs['type']  # Already shown

        for key, value in sorted(attrs.items()):
            output.write(f"{key}: {value}\n")

        # Write fields
        fields = primary.get_fields()
        if fields:
            output.write("\nFields:\n")
            for field_name, field_attrs in fields:
                output.write(f"  - {field_name}\n")
                for key, value in sorted(field_attrs.items()):
                    if key != 'name':
                        output.write(f"      {key}: {value}\n")

        # Write XML representation
        output.write("\nXML:\n")
        xml_lines = primary.to_xml_string().split('\n')
        for line in xml_lines:
            if line.strip():
                output.write(f"  {line}\n")

        # If there are duplicates, show deltas
        if len(reg_infos) > 1:
            # Show additional sources with their top-level files
            output.write("\nAlso defined in:\n")
            for i, reg_info in enumerate(reg_infos[1:], 2):
                output.write(f"  {i}. {reg_info.source_file}\n")
                if reg_info.top_level_file and reg_info.top_level_file != reg_info.source_file:
                    output.write(f"     Included by: {reg_info.top_level_file}\n")

            deltas = self.get_register_deltas(reg_name)
            if deltas:
                output.write("\n" + "!" * 80 + "\n")
                output.write("DUPLICATE DEFINITIONS - DELTAS:\n")
                output.write("!" * 80 + "\n")
                for delta in deltas:
                    output.write(delta + "\n\n")
            else:
                output.write("\n(Additional definitions are identical)\n")

        output.write("\n")

    def _write_control(self, output, ctrl_name: str) -> None:
        """Write a control definition with all its information."""
        ctrl_infos = self.controls[ctrl_name]

        # Header for control
        output.write("-" * 80 + "\n")
        output.write(f"Control: {ctrl_name}\n")
        output.write("-" * 80 + "\n")

        # If multiple definitions, note it
        if len(ctrl_infos) > 1:
            output.write(f"!!! DEFINED IN {len(ctrl_infos)} FILES !!!\n\n")

        # Write first (primary) definition
        primary = ctrl_infos[0]
        output.write(f"Source: {primary.source_file}\n")
        # Show which top-level file included this source
        if primary.top_level_file and primary.top_level_file != primary.source_file:
            output.write(f"Included by: {primary.top_level_file}\n")
        if primary.parent_path:
            output.write(f"Context: {primary.parent_path}\n")

        # Write all attributes
        attrs = dict(primary.element.attrib)
        if 'name' in attrs:
            del attrs['name']  # Already shown

        for key, value in sorted(attrs.items()):
            output.write(f"{key}: {value}\n")

        # Write XML representation
        output.write("\nXML:\n")
        xml_lines = primary.to_xml_string().split('\n')
        for line in xml_lines:
            if line.strip():
                output.write(f"  {line}\n")

        # If there are duplicates, show them
        if len(ctrl_infos) > 1:
            output.write("\nAlso defined in:\n")
            for i, ctrl_info in enumerate(ctrl_infos[1:], 2):
                output.write(f"  {i}. {ctrl_info.source_file}\n")
                if ctrl_info.top_level_file and ctrl_info.top_level_file != ctrl_info.source_file:
                    output.write(f"     Included by: {ctrl_info.top_level_file}\n")

            # Show deltas
            deltas = self._get_control_deltas(ctrl_name)
            if deltas:
                output.write("\n" + "!" * 80 + "\n")
                output.write("DUPLICATE DEFINITIONS - DELTAS:\n")
                output.write("!" * 80 + "\n")
                for delta in deltas:
                    output.write(delta + "\n\n")
            else:
                output.write("\n(Additional definitions are identical)\n")

        output.write("\n")

    def _get_control_deltas(self, ctrl_name: str) -> List[str]:
        """Compare multiple definitions of a control and return differences."""
        ctrl_infos = self.controls[ctrl_name]
        if len(ctrl_infos) <= 1:
            return []

        deltas = []
        base_ctrl = ctrl_infos[0]

        for i, ctrl in enumerate(ctrl_infos[1:], 1):
            delta_lines = []
            delta_lines.append(f"Difference #{i}:")
            delta_lines.append(f"  File 1: {base_ctrl.source_file}")
            delta_lines.append(f"  File 2: {ctrl.source_file}")

            # Compare attributes
            base_attrs = dict(base_ctrl.element.attrib)
            curr_attrs = dict(ctrl.element.attrib)

            all_attr_keys = set(base_attrs.keys()) | set(curr_attrs.keys())
            attr_diffs = []

            for key in sorted(all_attr_keys):
                base_val = base_attrs.get(key, '<not defined>')
                curr_val = curr_attrs.get(key, '<not defined>')
                if base_val != curr_val:
                    attr_diffs.append(f"    {key}: '{base_val}' vs '{curr_val}'")

            if attr_diffs:
                delta_lines.append("  Attribute differences:")
                delta_lines.extend(attr_diffs)

            if len(delta_lines) > 3:  # Only add if there are actual differences
                deltas.append('\n'.join(delta_lines))

        return deltas


def discover_platforms(cfg_dir: str) -> Dict[str, List[str]]:
    """Scan cfg_dir for XML files with <configuration platform="..."> and group by platform."""
    platforms = defaultdict(list)
    pattern = re.compile(r'<configuration\s+platform="([^"]+)"')

    for xml_path in sorted(glob.glob(os.path.join(cfg_dir, '**', '*.xml'), recursive=True)):
        if os.path.basename(xml_path) == 'template.xml':
            continue
        try:
            with open(xml_path, 'r', encoding='utf-8', errors='ignore') as f:
                # Only need to check first few KB for the configuration tag
                head = f.read(4096)
            match = pattern.search(head)
            if match:
                platform = match.group(1)
                platforms[platform].append(xml_path)
        except OSError:
            continue

    return dict(platforms)


def process_files(xml_files: List[str], output_file: str = None) -> Tuple[int, int]:
    """Process a list of XML files and generate output. Returns (xref_errors, parse_errors)."""
    base_paths = [os.path.dirname(os.path.abspath(f)) for f in xml_files]

    xml_parser = XMLConfigParser(base_paths)

    print(f"Processing {len(xml_files)} file(s)...", file=sys.stderr)
    for xml_file in xml_files:
        print(f"  - {xml_file}", file=sys.stderr)
        xml_parser.parse_file(xml_file)

    print(f"\nFound {len(xml_parser.registers)} unique registers and {len(xml_parser.controls)} unique controls across {len(xml_parser.processed_files)} files",
          file=sys.stderr)

    if xml_parser.parse_errors:
        print(f"\n!!! {len(xml_parser.parse_errors)} PARSE ERROR(S) !!!", file=sys.stderr)

    validation_errors = xml_parser.validate_cross_references()
    xml_parser._cached_validation_errors = validation_errors
    if validation_errors:
        print(f"\n!!! {len(validation_errors)} CROSS-REFERENCE ERROR(S) FOUND !!!", file=sys.stderr)
        for error in validation_errors:
            print(f"  {error}", file=sys.stderr)

    if output_file:
        print(f"\nWriting output to {output_file}...", file=sys.stderr)

    xml_parser.generate_output(output_file)

    if output_file:
        print("Done!", file=sys.stderr)

    return len(validation_errors), len(xml_parser.parse_errors)


def main():
    parser = argparse.ArgumentParser(
        description='Extract all registers from CHIPSEC XML configuration files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single file
  python extract_registers.py chipsec/cfg/8086/adl.xml

  # Multiple files
  python extract_registers.py chipsec/cfg/8086/adl.xml chipsec/cfg/8086/adl_addition.xml

  # Glob pattern
  python extract_registers.py "chipsec/cfg/8086/adl*.xml"

  # With output file
  python extract_registers.py chipsec/cfg/8086/adl.xml -o adl_registers.txt

  # Auto-discover all platforms (no args, searches chipsec/cfg/)
  python extract_registers.py
""")

    parser.add_argument('xml_files', nargs='*', help='XML configuration files or glob patterns to process. '
                        'If omitted, auto-discovers platforms from chipsec/cfg/')
    parser.add_argument('-o', '--output', help='Output file (default: stdout). In auto-discover mode, '
                        'used as output directory for <platform>_registers.txt files')
    parser.add_argument('--cfg-dir', default='chipsec/cfg',
                        help='Config directory to scan for auto-discovery (default: chipsec/cfg)')

    args = parser.parse_args()

    if args.xml_files:
        # Explicit file mode: expand globs and process
        expanded_files = []
        for pattern in args.xml_files:
            matches = sorted(glob.glob(pattern))
            if matches:
                expanded_files.extend(matches)
            else:
                print(f"Error: No files matched: {pattern}", file=sys.stderr)
                return 1

        for xml_file in expanded_files:
            if not os.path.exists(xml_file):
                print(f"Error: File not found: {xml_file}", file=sys.stderr)
                return 1

        xref_errors, parse_errors = process_files(expanded_files, args.output)
        return 1 if (xref_errors + parse_errors) > 0 else 0

    # Auto-discover mode
    cfg_dir = args.cfg_dir
    if not os.path.isdir(cfg_dir):
        print(f"Error: Config directory not found: {cfg_dir}", file=sys.stderr)
        return 1

    platforms = discover_platforms(cfg_dir)
    if not platforms:
        print(f"Error: No platform configurations found in {cfg_dir}", file=sys.stderr)
        return 1

    print(f"Auto-discovered {len(platforms)} platform(s): {', '.join(sorted(platforms.keys()))}\n", file=sys.stderr)

    # Use -o as output directory in auto-discover mode
    output_dir = args.output if args.output else '.'
    if output_dir != '.' and not os.path.isdir(output_dir):
        if os.path.exists(output_dir):
            print(f"Error: Output path exists and is not a directory: {output_dir}", file=sys.stderr)
            return 1
        os.makedirs(output_dir, exist_ok=True)

    total_xref_errors = 0
    total_parse_errors = 0
    for platform in sorted(platforms.keys()):
        files = platforms[platform]
        output_file = os.path.join(output_dir, f"{platform.lower()}_registers.txt")

        print(f"{'=' * 80}", file=sys.stderr)
        print(f"Platform: {platform} ({len(files)} file(s)) -> {output_file}", file=sys.stderr)
        print(f"{'=' * 80}", file=sys.stderr)

        xref_errors, parse_errors = process_files(files, output_file)
        total_xref_errors += xref_errors
        total_parse_errors += parse_errors
        print("", file=sys.stderr)

    print(f"{'=' * 80}", file=sys.stderr)
    print(f"Summary: Processed {len(platforms)} platform(s), "
          f"{total_xref_errors} cross-reference error(s), "
          f"{total_parse_errors} parse/config error(s)", file=sys.stderr)

    return 1 if (total_xref_errors + total_parse_errors) > 0 else 0


if __name__ == '__main__':
    sys.exit(main())
