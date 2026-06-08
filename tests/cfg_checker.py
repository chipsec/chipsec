#!/usr/bin/env python3
# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2022-2023, Intel Corporation
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

from os import listdir, walk
import os.path as op
import sys
import xml.etree.ElementTree as ET
from collections import namedtuple

sys.path.append(op.abspath(op.join(__file__, "..", "..")))
from chipsec.library.file import get_main_dir
from chipsec.library.defines import is_hex


class ConfigChecker():

    VALID_SUBCOMPONENT_TYPES = ['mmiobar', 'iobar']

    def __init__(self) -> None:
        self.BYTES_TO_BITS = 8
        self.inconsistency_found = False  # Global flag to track inconsistencies
        self.FieldInterval = namedtuple('FieldInterval', ['start', 'end'])
        self.cfg_path = op.join(get_main_dir(), 'chipsec', 'cfg')
        self.log_messages = []
        self._logged_messages = set()

    def _add_error(self, message):
        self.inconsistency_found = True
        if message not in self._logged_messages:
            self.log_messages.append(message)
            self._logged_messages.add(message)

    def _get_vid_from_path(self, cfg_file):
        try:
            rel_path = op.relpath(cfg_file, self.cfg_path)
        except ValueError:
            return None
        vid = rel_path.split(op.sep)[0]
        if is_hex(vid):
            return vid
        return None

    def _process_config_path(self, fxml):
        return fxml.replace('.', op.sep, fxml.count('.') - 1)

    def _is_vendor_scoped_include(self, fxml):
        if op.isabs(fxml):
            return False
        if '/' in fxml or '\\' in fxml:
            return False
        return fxml.count('.') >= 2

    def _resolve_config_include_path(self, cfg_file, vid, fxml):
        include_path = self._process_config_path(fxml)
        if op.isabs(include_path):
            return include_path
        if vid is not None and self._is_vendor_scoped_include(fxml):
            return op.join(self.cfg_path, vid, include_path)
        return op.join(op.dirname(cfg_file), include_path)

    def _iter_config_tokens(self, et_node):
        config = et_node.attrib.get('config', '')
        for fxml in config.split(','):
            fxml = fxml.strip()
            if fxml:
                yield fxml

    def _get_register_fields(self, root):
        register_fields = {}
        for reg in root.findall('./registers/register'):
            if 'name' not in reg.attrib:
                continue
            reg_name = reg.attrib['name']
            reg_field_names = set()
            for field in reg.findall('./field'):
                if 'name' in field.attrib:
                    reg_field_names.add(field.attrib['name'])
            register_fields[reg_name] = reg_field_names
            if reg.attrib.get('type') in ['mmio', 'iobar'] and 'bar' in reg.attrib:
                register_fields[f'{reg.attrib["bar"]}.{reg_name}'] = reg_field_names
        return register_fields

    def _get_referenced_register_fields(self, et_node, cfg_file, vid):
        register_fields = self._get_register_fields(et_node)
        for fxml in self._iter_config_tokens(et_node):
            include_path = self._resolve_config_include_path(cfg_file, vid, fxml)
            if not op.exists(include_path):
                continue
            try:
                include_root = ET.parse(include_path).getroot()
            except ET.ParseError as e:
                self._add_error(f'{cfg_file}: failed to parse referenced config file {include_path}. Error message: {e}')
                continue
            register_fields.update(self._get_register_fields(include_root))
        return register_fields

    def _check_config_file_references(self, root, cfg_file, vid):
        for et_node in root.iter():
            for fxml in self._iter_config_tokens(et_node):
                include_path = self._resolve_config_include_path(cfg_file, vid, fxml)
                if not op.exists(include_path):
                    self._add_error(f'{cfg_file}: referenced config file does not exist: {fxml} ({include_path})')

    def _check_bar_register_reference(self, bar, register_fields, cfg_file, bar_context):
        if 'register' not in bar.attrib:
            self._add_error(f'{cfg_file}: {bar_context} does not have a "register=" attribute.')
            return
        if 'base_field' not in bar.attrib:
            self._add_error(f'{cfg_file}: {bar_context} does not have a "base_field=" attribute.')
            return

        register = bar.attrib['register']
        base_field = bar.attrib['base_field']
        if register not in register_fields:
            self._add_error(f'{cfg_file}: {bar_context} references undefined BAR register {register}.')
            return
        if base_field not in register_fields[register]:
            self._add_error(f'{cfg_file}: {bar_context} references undefined BAR base field {register}.{base_field}.')

    def check_bar_definitions(self, root, cfg_file):
        vid = self._get_vid_from_path(cfg_file)
        self._check_config_file_references(root, cfg_file, vid)
        root_register_fields = self._get_register_fields(root)

        for dev in root.findall('./pci/device'):
            register_fields = root_register_fields.copy()
            register_fields.update(self._get_referenced_register_fields(dev, cfg_file, vid))
            for dev_subcomponent in dev.findall('./subcomponent'):
                register_fields.update(self._get_referenced_register_fields(dev_subcomponent, cfg_file, vid))
            dev_name = dev.attrib.get('name', '<unknown>')

            for subcomponent in dev.findall('./subcomponent'):
                sub_type = subcomponent.attrib.get('type')
                sub_name = subcomponent.attrib.get('name', '<unknown>')
                sub_context = f'subcomponent {dev_name}.{sub_name}'
                if sub_type not in self.VALID_SUBCOMPONENT_TYPES:
                    self._add_error(f'{cfg_file}: {sub_context} has invalid type {sub_type}. Expected one of: {", ".join(self.VALID_SUBCOMPONENT_TYPES)}.')
                self._check_bar_register_reference(subcomponent, register_fields, cfg_file, sub_context)


    def _fields_overlap(self, field_intervals):
        field_intervals.sort(key=lambda f: f.start)
        for i in range(len(field_intervals) - 1):
            if field_intervals[i].end >= field_intervals[i + 1].start:
                return True
        return False

    def _get_register_size(self, reg, cfg_file):
        if 'type' in reg.attrib and reg.attrib['type'] == 'msr':
            # MSR registers are assumed 8 bytes
            register_size = 8 * self.BYTES_TO_BITS
        elif 'size' in reg.attrib:
            register_size = int(reg.attrib['size']) * self.BYTES_TO_BITS
        else:
            # Register does not contain a well-defined size
            self.log_messages.append(f'{cfg_file}: found a non-MSR register without an explictly defined size. ({reg.attrib["name"]})')
            self.inconsistency_found = True
            return None
        return register_size

    def _parse_register_fields(self, reg, register_size, cfg_file):
        register_end_index = 0
        field_intervals = []
        # Loop over all fields found in this register
        for field in reg.findall('./field'):
            try:
                # Running calculation of register's end index based on the fields we've seen so far
                current_register_end_index = int(field.attrib['bit']) + int(field.attrib['size'])
            except ValueError:
                # All fields must have a starting bit and a size
                self.log_messages.append(f'{cfg_file}: found a field without an integer value for bit or size. ({reg.attrib["name"]}, {field.attrib["name"]})')
                self.inconsistency_found = True
                continue
            # Collect intervals from fields' start bits and sizes
            field_intervals.append(self.FieldInterval(start=int(field.attrib['bit']), end=current_register_end_index - 1))
            # Update running calculation of register's end index
            if current_register_end_index > register_end_index:
                register_end_index = current_register_end_index
                if register_end_index > register_size:
                    # Updated register end index exceeds the register size that we calculated earlier
                    self.log_messages.append(f'{cfg_file}: found a field that is too large to fit in the register. ({reg.attrib["name"]}, {field.attrib["name"]})')
                    self.inconsistency_found = True

        # Calculate if there is any overlap in the field intervals
        if self._fields_overlap(field_intervals):
            self.log_messages.append(f'{cfg_file}: found overlapping fields in a register. ({reg.attrib["name"]})')
            self.inconsistency_found = True

    def check_platform_codes(self, root, cfg_file):
        if ('platform' in root.attrib):
            platform = root.attrib['platform']
            for sku in root.findall("./info/sku"):
                if 'code' in sku.attrib:
                    if sku.attrib['code'] != platform:
                        self.inconsistency_found = True
                        self.log_messages.append(f'ERROR: SKU platform code with DID {sku.attrib["did"]} in {cfg_file} is not equivalent to XML platform code ({platform})')
                else:
                    self.inconsistency_found = True
                    self.log_messages.append(f'ERROR: SKU with DID {sku.attrib["did"]} in {cfg_file} does not have a "code=" attribute.')

    def check_registers(self, root, cfg_file):
        REGISTER_INCONSISTENT = '{}: Register {} with offset {} should be of type \'{}\', not \'{}\''
        for reg in root.findall('./registers/register'):
            try:
                # Skip this register if it does not contain any fields
                if reg.find('./field') is None:
                    continue

                # Determine size in bits of current register
                register_size = self._get_register_size(reg, cfg_file)
                if register_size is None:
                    continue

                # Run through all fields in the register and flag issues along the way
                self._parse_register_fields(reg, register_size, cfg_file)
            except RuntimeError as e:
                self.log_messages.append(f'{cfg_file}: encountered unexpected exception at register {reg.attrib["name"]}. Error message: {e}')
                self.inconsistency_found = True

            if ('type' in reg.attrib) and ('offset' in reg.attrib) and (reg.attrib['type'] == 'pcicfg' or reg.attrib['type'] == 'mmcfg'):
                offset = int(reg.attrib['offset'], 16)
                if 0x0 <= offset <= 0xFF:
                    # Register must be either type pcicfg or mmcfg
                    if reg.attrib['type'] != 'pcicfg' and reg.attrib['type'] != 'mmcfg':
                        self.log_messages.append(REGISTER_INCONSISTENT.format(cfg_file, reg.attrib['name'], reg.attrib['offset'], 'pcicfg', reg.attrib['type']))
                        self.inconsistency_found = True
                elif 0xFF < offset <= 0xFFF:
                    # Register must be type mmcfg
                    if reg.attrib['type'] != 'mmcfg':
                        self.log_messages.append(REGISTER_INCONSISTENT.format(cfg_file, reg.attrib['name'], reg.attrib['offset'], 'mmcfg', reg.attrib['type']))
                        self.inconsistency_found = True

    def run_checks(self):
        # Iterate over all XML files in chipsec/cfg, including subdirectories
        vid_list = [f for f in listdir(self.cfg_path) if op.isdir(op.join(self.cfg_path, f)) and is_hex(f)]
        for vid in vid_list:
            vid_path = op.join(self.cfg_path, vid)
            for dirpath, _, filenames in walk(vid_path):
                for cfg_file in filenames:
                    if not cfg_file.endswith('.xml'):
                        continue
                    filepath = op.join(dirpath, cfg_file)
                    print(".", end="")
                    tree = ET.parse(filepath)
                    root = tree.getroot()
                    self.check_registers(root, filepath)
                    self.check_platform_codes(root, filepath)
                    self.check_bar_definitions(root, filepath)

        print("")
        for message in self.log_messages:
            print(message)

        # Exit code 0 or 1
        return int(self.inconsistency_found)


if __name__ == '__main__':
    try:
        sys.exit(ConfigChecker().run_checks())
    except Exception as e:
        print(f'Error: {e}')
        sys.exit(1)
