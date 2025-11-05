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

import xml.etree.ElementTree as ET
from typing import Dict, List, Tuple
import os.path as op
import sys
from os import listdir

sys.path.append(op.abspath(op.join(__file__, "..", "..")))
from chipsec.library.file import get_main_dir
from chipsec.library.defines import is_hex

CFG_PATH = op.join(get_main_dir(), 'chipsec', 'cfg') # Where to look for config files

"""
Usage: python xml_validator.py [config_file1] [config_file2] ...
Run with no arguments to vlidatate all XML config files in the default cfg directory.
"""

class ConfigAttributeValidator:
    """Validates XML configuration attributes against expected data types"""

    def __init__(self):
        # Define expected attribute types based on _config_convert_data function
        self.integer_attrs = {'dev', 'fun', 'vid', 'did', 'rid', 'offset', 
                              'bit', 'size', 'port', 'msr', 'value', 'address',
                              'fixed_address', 'base_align', 'align_bits', 'mask',
                              'reg_align', 'limit_align', 'regh_align', 'width', 'reg'}

        self.boolean_attrs = {'req_pch'}
        self.int_list_attrs = {'bus'}
        self.str_list_attrs = {'config'}
        self.range_list_attrs = {'detection_value'}
        self.validation_errors = []
        self.passed_file_count = 0
        self.file_count = 0
        

    def validate_integer_value(self, value: str) -> bool:
        """Validate if a string can be converted to integer (base 10 or 16)"""
        try:
            int(value, 0)
            return True
        except ValueError:
            return False

    def validate_boolean_value(self, value: str) -> bool:
        """Validate if a string represents a boolean value"""
        return value.lower() in ('true', 'false')

    def validate_integer_list(self, value: str) -> bool:
        """Validate comma-separated integer values"""
        try:
            for item in value.split(','):
                int(item.strip(), 0)
            return True
        except ValueError:
            return False

    def validate_range_format(self, value: str) -> bool:
        """Validate range format (wildcards, ranges, single values)"""
        try:
            for item in value.split(','):
                item = item.strip()
                if item.upper().endswith('*'):
                    int(item.replace('*', '0'), 0)
                elif '-' in item:
                    parts = item.split('-', 1)
                    if len(parts) != 2:
                        return False
                    int(parts[0], 0)
                    int(parts[1], 0)
                else:
                    int(item, 0)
            return True
        except ValueError:
            return False

    def validate_attribute(self, attr_name: str, attr_value: str, element_tag: str, did_is_range: bool = False) -> bool:
        """Validate a single attribute based on its expected type"""
        # Handle special case where 'did' can be range format
        if did_is_range and attr_name == 'did':
            if not self.validate_range_format(attr_value):
                self.validation_errors.append(
                    f"Element '{element_tag}': Attribute '{attr_name}' has invalid range format: '{attr_value}'"
                )
                return False
        elif attr_name in self.integer_attrs:
            if not self.validate_integer_value(attr_value):
                self.validation_errors.append(
                    f"Element '{element_tag}': Attribute '{attr_name}' must be integer: '{attr_value}'"
                )
                return False
        elif attr_name in self.boolean_attrs:
            if not self.validate_boolean_value(attr_value):
                self.validation_errors.append(
                    f"Element '{element_tag}': Attribute '{attr_name}' must be boolean (true/false): '{attr_value}'"
                )
                return False
        elif attr_name in self.int_list_attrs:
            if not self.validate_integer_list(attr_value):
                self.validation_errors.append(
                    f"Element '{element_tag}': Attribute '{attr_name}' must be comma-separated integers: '{attr_value}'"
                )
                return False
        elif attr_name in self.range_list_attrs:
            if not self.validate_range_format(attr_value):
                self.validation_errors.append(
                    f"Element '{element_tag}': Attribute '{attr_name}' has invalid range format: '{attr_value}'"
                )
                return False

        return True

    def validate_xml_element(self, element: ET.Element, did_is_range: bool = False) -> bool:
        """Validate all attributes of an XML element"""
        element_valid = True

        for attr_name, attr_value in element.attrib.items():
            if not self.validate_attribute(attr_name, attr_value, element.tag, did_is_range):
                element_valid = False

        return element_valid

    def validate_xml_file(self, file_path: str) -> Tuple[bool, List[str]]:
        """Validate an entire XML configuration file"""
        self.validation_errors = []

        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
        except ET.ParseError as e:
            self.validation_errors.append(f"XML parsing error in '{file_path}': {e}")
            return False, self.validation_errors
        except FileNotFoundError:
            self.validation_errors.append(f"File not found: '{file_path}'")
            return False, self.validation_errors

        file_valid = True

        # Validate different element types with appropriate settings
        for element in root.iter():
            if element.tag in ('device', 'sku'):
                # These elements can have 'did' as range
                if not self.validate_xml_element(element, did_is_range=True):
                    file_valid = False
            else:
                if not self.validate_xml_element(element):
                    file_valid = False

        return file_valid, self.validation_errors

    def print_validation_report(self, file_path: str):
        """Print a validation report for a configuration file"""
        is_valid, errors = self.validate_xml_file(file_path)
        self.file_count += 1
        message = "\t"
        if is_valid:
            message += f"✓ Configuration file is valid for: {file_path}"
            self.passed_file_count += 1
        else:
            message += f"✗ Found {len(errors)} validation errors in {file_path}:"
            for error in errors:
                message += f"\n\t- {error}"
        print(message)

    def print_summary(self):
        """Print a summary of validation results"""
        print(f"\nValidation Summary: {self.passed_file_count}/{self.file_count} files passed validation.")


def validate_configuration_files(file_paths: List[str]) -> Dict[str, bool]:
    """Validate multiple configuration files and return results"""
    validator = ConfigAttributeValidator()
    results = {}
    print("Validation Report:\n")
    for file_path in file_paths:
        is_valid, _ = validator.validate_xml_file(file_path)
        results[file_path] = is_valid
        validator.print_validation_report(file_path)
    validator.print_summary()
    return results


def find_xml_files(paths: List[str]) -> List[str]:
    files = []
    dirs = []
    for path in paths:
        for cfg_file in listdir(path):
            filepath = op.join(path, cfg_file)
            if op.isdir(filepath):
                dirs.append(filepath)
            if filepath.endswith('.xml'):
                files.append(filepath)
    if dirs:
        files.extend(find_xml_files(dirs))
    return files


def find_base_config_dirs() -> List[str]:
    vid_list = [f for f in listdir(CFG_PATH) if op.isdir(op.join(CFG_PATH, f)) and is_hex(f)]
    base_dirs = [op.join(CFG_PATH, vid) for vid in vid_list]
    return base_dirs


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        results = validate_configuration_files(find_xml_files(find_base_config_dirs()))
    else:
        results = validate_configuration_files(sys.argv[1:])
    
    if all(results.values()):
        sys.exit(0)
    else:
        sys.exit(1)
