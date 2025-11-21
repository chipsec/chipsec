# !/usr/bin/python
# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2021, Intel Corporation
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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA  02110-1301, USA.

# Contact information:
# chipsec@intel.com

"""
>>> chipsec_util config show [config] <name>

Examples:

>>> chipsec_util config show ALL
>>> chipsec_util config show [CONFIG_PCI|MEMORY_RANGES|MM_MSGBUS|MSGBUS|IO|MSR]
>>> chipsec_util config show SCOPE
"""

from argparse import ArgumentParser

from chipsec.command import BaseCommand, toLoad


class CONFIGCommand(BaseCommand):
    """Command to display configuration information."""
    
    # Initialize command
    def __init__(self, argv, cs):
        """Initialize the command with base class and set options."""
        super(CONFIGCommand, self).__init__(argv, cs)
        self.skip_list = ["LOCKS", "CONTROLS", "ALL"]
        try:
            # Get parent keys from scope manager
            self.all_options = (
                self.cs.Cfg.scope_manager.parent_keys +
                self.skip_list + ["SCOPE"]
            )
        except (AttributeError, TypeError):
            # Fallback if scope_manager is not available
            self.all_options = [
                "CONFIG_PCI_RAW", "CONFIG_PCI", "MEMORY_RANGES", "MM_MSGBUS",
                "MSGBUS", "IO", "MSR", "MMIO_BARS", "IO_BARS", "LOCKS",
                "CONTROLS", "ALL", "SCOPE"
            ]
        self.child_details = False  # Default to not showing child details

    # Command setup and infrastructure methods
    def requirements(self):
        """Specify resource requirements for this command."""
        return toLoad.All

    def parse_arguments(self):
        """Parse command line arguments."""
        parser = ArgumentParser(usage='chipsec_util config')
        subparsers = parser.add_subparsers()

        # Show command
        parser_show = subparsers.add_parser('show')
        parser_show.add_argument(
            'config',
            choices=self.all_options,
            default="ALL"
        )
        parser_show.add_argument(
            '-c', '--child-details',
            action='store_true',
            help='Include child details'
        )
        parser_show.set_defaults(func=self.show, config="ALL")

        parser.parse_args(self.argv, namespace=self)
        return True

    # Main display methods
    def show(self):
        """Show configuration information based on selected option."""
        if self.config == "SCOPE":
            self.scope_details()
            return
            
        if self.config == "ALL":
            # Exclude SCOPE from all_options when processing ALL
            config = [x for x in self.all_options if x != "SCOPE"]
            # Also show scope information when 'ALL' is selected
            self.scope_details()
        else:
            config = [self.config]
            
        for mconfig in config:
            if mconfig in self.skip_list:
                continue
                
            try:
                cfg = getattr(self.cs.Cfg, mconfig)
            except AttributeError:
                self.logger.log(f"\n{mconfig} - Not available")
                continue
                
            self.logger.log(f"\n{mconfig}")
            for vid in cfg.keys():
                self.logger.log(f"{vid}:")
                for name in cfg[vid].keys():
                    if mconfig in ["CONFIG_PCI_RAW"]:
                        cfg_data = cfg[vid][name]
                        self.logger.log(
                            f'\t{name} - {self.pci_details(cfg_data)}'
                        )
                    elif mconfig in ["CONFIG_PCI"]:
                        cfg_data = cfg[vid][name]
                        self.logger.log(
                            f'\t{name} - {self.pci_details(cfg_data)}'
                        )
                    elif mconfig == "MEMORY_RANGES":
                        self.logger.log(
                            f'\t{name} - {self.memory_details(cfg[vid][name])}'
                        )
                    elif mconfig in ["MM_MSGBUS", "MSGBUS", "IO"]:
                        port_details = self.get_port_details(cfg[vid][name])
                        self.logger.log(f'\t{name} - {port_details}')
                    elif mconfig in ["MMIO_BARS", "IO_BARS"]:
                        for cfg_data in cfg[vid][name]:
                            details = self.mmio_details(
                                cfg[vid][name][cfg_data]
                            )
                            self.logger.log(f'\t{cfg_data} - {details}')
                    elif mconfig == "MSR":
                        self.logger.log(
                            f'\t{name} - {self.msr_details(cfg[vid][name])}'
                        )
                        
                    if (self.child_details and
                            mconfig not in ["CONFIG_PCI_RAW"]):
                        if mconfig not in ["MMIO_BARS", "IO_BARS"]:
                            self.get_child_details(vid, name)
                        else:
                            for cfg_data in cfg[vid][name]:
                                self.get_child_details(
                                    vid, cfg[vid][name][cfg_data].name
                                )

        if set(config).intersection({"LOCKS", "ALL"}):
            self.lock_details()
        if set(config).intersection({"CONTROLS", "ALL"}):
            self.control_details()
        return

    # Detail formatting methods for different types of registers/configurations
    def msr_details(self, regi):
        """Format MSR register details."""
        ret = f'config: {regi.config}'
        return ret

    def memory_details(self, regi):
        """Format memory range details."""
        try:
            # Try to access as dictionary first
            if isinstance(regi, dict):
                # Basic attributes always displayed
                ret = (f"access: {regi.get('access', 'N/A')}, "
                       f"address: {regi.get('address', 'N/A')}, "
                       f"size: {regi.get('size', 'N/A')}")
                
                # Add configuration if available
                if 'config' in regi:
                    ret += f", config: {regi['config']}"
                
                # BEGIN: Extended MMIO Functionality
                # Display extended MMIO attributes if available
                if 'base_ref' in regi:
                    ret += f", base_ref: {regi['base_ref']}"
                    if 'base_value' in regi:
                        ret += f" (0x{regi['base_value']:x})"
                        
                if 'ip_ref' in regi:
                    ret += f", ip_ref: {regi['ip_ref']}"
                    if 'ip_value' in regi:
                        ret += f" (0x{regi['ip_value']:x})"
                        
                if 'scope' in regi:
                    ret += f", scope: {regi['scope']}"
                # END: Extended MMIO Functionality
                
            else:
                # Fall back to attribute access if it's an object
                ret = (f"access: {getattr(regi, 'access', 'N/A')}, "
                       f"address: {getattr(regi, 'address', 'N/A')}, "
                       f"size: {getattr(regi, 'size', 'N/A')}")
                
                # Add configuration if available
                if hasattr(regi, 'config'):
                    ret += f", config: {regi.config}"
                
                # BEGIN: Extended MMIO Functionality
                # Display extended MMIO attributes if available
                if hasattr(regi, 'base_ref') and regi.base_ref:
                    ret += f", base_ref: {regi.base_ref}"
                    if hasattr(regi, 'base_value') and regi.base_value:
                        ret += f" (0x{regi.base_value:x})"
                        
                if hasattr(regi, 'ip_ref') and regi.ip_ref:
                    ret += f", ip_ref: {regi.ip_ref}"
                    if hasattr(regi, 'ip_value') and regi.ip_value:
                        ret += f" (0x{regi.ip_value:x})"
                        
                if hasattr(regi, 'scope') and regi.scope:
                    ret += f", scope: {regi.scope}"
                # END: Extended MMIO Functionality
                
        except (KeyError, AttributeError):
            # In case of any error, just return the string representation
            ret = str(regi)
        return ret

    def get_port_details(self, regi):
        """Format port details."""
        ret = ''
        if regi:
            ret = f'port: {regi.port}, config: {regi.config}'
        return ret

    def ima_details(self, regi):
        """Format IMA register details."""
        base_value = regi['base'] if 'base' in regi.keys() else None
        ret = f"index: {regi['index']}, data: {regi['data']}, " \
              f"base: {base_value}"
        return ret

    def register_details(self, regi):
        """Format register details based on type."""
        ret = ""
        if regi['type'] == 'pcicfg' or regi['type'] == 'mmcfg':
            ret = f"device: {regi['device']}, offset: {regi['offset']}, " \
                  f"size: {regi['size']}"
        elif regi['type'] == 'mmio':
            ret = f"bar: {regi['bar']}, offset: {regi['offset']}, " \
                  f"size: {regi['size']}"
        elif regi['type'] == 'mm_msgbus':
            ret = f"offset: {regi['offset']}, size: {regi['size']}"
        elif regi['type'] == 'io':
            ret = f"size: {regi['size']}"
        elif regi['type'] == 'iobar':
            ret = f"bar: {regi['bar']}, offset: {regi['offset']}, " \
                  f"size: {regi['size']}"
        elif regi['type'] == 'msr':
            if 'size' in regi:
                ret = f"msr: {regi['msr']}, size: {regi['size']}"
            else:
                ret = f"msr: {regi['msr']}"
        elif regi['type'] == 'R Byte':
            if 'size' in regi:
                ret = f"offset: {regi['offset']}, size: {regi['size']}"
            else:
                ret = f"offset: {regi['offset']}"
        elif regi['type'] == 'memory':
            ret = f"access: {regi['access']}, offset: {regi['offset']}, " \
                  f"size: {regi['size']}"
            
        # Add field information if available
        try:
            if isinstance(regi, (list, tuple)) and len(regi) > 0:
                reg_obj = regi[0]
                if hasattr(reg_obj, 'fields') and reg_obj.fields:
                    for key in reg_obj.fields:
                        bit = reg_obj.fields[key]['bit']
                        size = reg_obj.fields[key]['size']
                        end_bit = bit + size - 1
                        ret += f'\n\t\t\t{key} - bit {bit}:{end_bit}'
        except (IndexError, AttributeError, TypeError):
            # Silently ignore errors when accessing fields
            pass
                
        return ret

    def pci_details(self, regi):
        """Format PCI configuration details."""
        return str(regi)

    def mmio_details(self, regi):
        """Format MMIO details."""
        return str(regi)

    def io_details(self, regi):
        """Format IO details."""
        if 'register' in regi:
            fixed_addr = (
                regi['fixed_address'] if 'fixed_address' in regi else None
            )
            ret = (f"register: {regi['register']}, "
                   f"base_field: {regi['base_field']}, "
                   f"size: {regi['size']}, "
                   f"fixed_addr: {fixed_addr}")
        else:
            size = regi['size'] if 'size' in regi else None
            fixed_addr = (
                regi['fixed_address'] if 'fixed_address' in regi else None
            )
            ret = (f"bus: {regi['bus']}, "
                   f"dev: {regi['dev']}, "
                   f"func: {regi['fun']}, "
                   f"reg: {regi['reg']}, "
                   f"mask: {regi['mask']}, "
                   f"size: {size}, "
                   f"fixed_addr: {fixed_addr}")
        return ret

    # Data display methods for child details, controls, and locks
    def get_child_details(self, vid, dev):
        """Get and display child configuration details."""
        self.logger.log(f'get_child details {dev}')
        config = self.cs.Cfg.child_keys
        for mconfig in config:
            if mconfig in ["CONTROLS", "LOCKS", "LOCKEDBY"]:
                continue
                
            cfg = getattr(self.cs.Cfg, mconfig)
            self.logger.log(f"\t{mconfig}:")
            
            if mconfig == "IMA_REGISTERS":
                if vid in cfg and dev in cfg[vid]:
                    for name in cfg[vid][dev].keys():
                        details = self.ima_details(cfg[vid][dev][name])
                        self.logger.log(f'\t\t{name} - {details}')
            elif mconfig == "REGISTERS":
                try:
                    if vid in cfg and dev in cfg[vid]:
                        for name in cfg[vid][dev].keys():
                            details = self.register_details(
                                cfg[vid][dev][name]
                            )
                            self.logger.log(f'\t\t{name} - {details}')
                except KeyError:
                    pass
        self.logger.log("")
        
    def control_details(self):
        """Display control details."""
        self.logger.log("\nCONTROLS")
        try:
            cfg = getattr(self.cs.Cfg, "CONTROLS")
            for regi in cfg.keys():
                self.logger.log(f'\t{regi}')
        except AttributeError as e:
            self.logger.log(f"\tError retrieving controls: {e}")
        return

    def lock_details(self):
        """Display lock details."""
        self.logger.log("\nLOCKS")
        try:
            locks = self.cs.Cfg.get_lock_list()
            for lock in locks:
                lock_cfg = self.cs.Cfg.get_lock_obj(lock)
                self.logger.log(f'\t{lock_cfg}')
        except AttributeError as e:
            self.logger.log(f"\tError retrieving locks: {e}")
        return

    def scope_details(self):
        """Display the contents of the scope manager."""
        self.logger.log("\nSCOPE MANAGER")
        
        # Display parent keys
        self.logger.log("\nParent Keys:")
        for key in self.cs.Cfg.scope_manager.parent_keys:
            self.logger.log(f"\t{key}")
            
        # Display child keys
        self.logger.log("\nChild Keys:")
        for key in self.cs.Cfg.scope_manager.child_keys:
            self.logger.log(f"\t{key}")
            
        # Display current scope
        self.logger.log("\nCurrent Scope:")
        for scope_key, scope_value in self.cs.Cfg.scope.items():
            key_name = scope_key if scope_key is not None else "DEFAULT"
            self.logger.log(f"\t{key_name}: {scope_value}")
            
        # BEGIN: Extended MMIO Functionality
        # Display memory bases if available
        if hasattr(self.cs.Cfg, 'memory_bases') and self.cs.Cfg.memory_bases:
            self.logger.log("\nMemory Bases:")
            for base_name, base_value in self.cs.Cfg.memory_bases.items():
                self.logger.log(f"\t{base_name}: 0x{base_value:x}")
                
        # Display IP addresses if available
        if hasattr(self.cs.Cfg, 'ip_addresses') and self.cs.Cfg.ip_addresses:
            self.logger.log("\nIP Addresses:")
            for ip_name, ip_value in self.cs.Cfg.ip_addresses.items():
                self.logger.log(f"\t{ip_name}: 0x{ip_value:x}")
        # END: Extended MMIO Functionality
            
        # Display available scopes in the configuration
        self.logger.log("\nAvailable Configuration Items:")
        
        # Go through parent keys and display available items
        for parent_key in self.cs.Cfg.scope_manager.parent_keys:
            if hasattr(self.cs.Cfg, parent_key):
                cfg_data = getattr(self.cs.Cfg, parent_key)
                if cfg_data:
                    self.logger.log(f"\n{parent_key}:")
                    for vid in cfg_data.keys():
                        self.logger.log(f"\t{vid}:")
                        if isinstance(cfg_data[vid], dict):
                            # Limit to first 10 items for readability
                            items = list(cfg_data[vid].keys())
                            for name in items[:10]:
                                self.logger.log(f"\t\t{name}")
                            if len(items) > 10:
                                remaining = len(items) - 10
                                self.logger.log(
                                    f"\t\t... ({remaining} more items)"
                                )
        return


commands = {'config': CONFIGCommand}
