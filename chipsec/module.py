# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2021, Intel Corporation
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


import re
import os
import json
import traceback
from typing import Dict, Any, List, Optional, Tuple
import chipsec.module_common
import chipsec.library.logger
from chipsec.library.file import get_main_dir
from chipsec.library.url import url
from chipsec.library.returncode import ModuleResult, generate_hash_id, get_module_ids_dictionary

_importlib = True
try:
    import importlib
except ImportError:
    _importlib = False

MODPATH_RE = re.compile(r'^\w+(\.\w+)*$')


class Module:
    """
    CHIPSEC module wrapper class for dynamic module loading and execution.

    This class provides a standardized interface for loading, managing, and
    executing CHIPSEC security assessment modules.
    """

    def __init__(self, name: str) -> None:
        """
        Initialize a new Module instance.

        Args:
            name: The fully qualified module name (e.g., 'chipsec.modules.common.bios_wp')
        """
        self.logger = chipsec.library.logger.logger()
        self.name = name
        self.module: Optional[Any] = None
        self.mod_obj: Optional[Any] = None
        self.module_ids: Dict[str, str] = get_module_ids_dictionary()
        self.url = url()

    def __lt__(self, other: 'Module') -> bool:
        """Compare modules by name for sorting."""
        return self.name < other.name

    def __le__(self, other: 'Module') -> bool:
        """Compare modules by name for sorting."""
        return self.name <= other.name

    def __gt__(self, other: 'Module') -> bool:
        """Compare modules by name for sorting."""
        return self.name > other.name

    def __ge__(self, other: 'Module') -> bool:
        """Compare modules by name for sorting."""
        return self.name >= other.name

    def get_name(self) -> str:
        """
        Get the module name.

        Returns:
            The fully qualified module name
        """
        return self.name

    def do_import(self) -> bool:
        """
        Import the module dynamically.

        Returns:
            True if the module was successfully imported, False otherwise

        Raises:
            BaseException: If module import fails and DEBUG is enabled
        """
        loaded = False
        if not MODPATH_RE.match(self.get_name()):
            self.logger.log_error(f'Invalid module path: {self.name}')
        else:
            try:
                if _importlib:
                    self.module = importlib.import_module(self.name)
                loaded = True
                if self.logger.DEBUG:
                    self.logger.log_good(f'imported: {self.name}')
            except BaseException as msg:
                error_msg = (f"Exception occurred during import of {self.name}: "
                            f"'{str(msg)}'")
                self.logger.log_error(error_msg)
                if self.logger.DEBUG:
                    self.logger.log_bad(traceback.format_exc())
                raise msg
        return loaded

    def update_module_ids_file(self) -> None:
        """Update the module IDs file with current module mappings."""
        module_ids_path = os.path.join(get_main_dir(), 'chipsec', 'library',
                                       'module_ids.json')
        with open(module_ids_path, 'w') as module_ids_file:
            module_ids_file.write(json.dumps(self.module_ids))

    def get_module_id(self, module_name: str) -> str:
        """
        Get or generate a unique ID for the module.

        Args:
            module_name: The name of the module

        Returns:
            A unique string identifier for the module
        """
        if module_name in self.module_ids:
            module_id = self.module_ids[module_name]
        else:
            module_id = generate_hash_id(module_name)
            self.module_ids[module_name] = module_id
            self.update_module_ids_file()
        return module_id

    def run(self, module_argv: Optional[List[str]] = None) -> int:
        """
        Run the module with the given arguments.

        Args:
            module_argv: Optional list of arguments to pass to the module

        Returns:
            The module's return code
        """
        self.get_module_object()

        if module_argv:
            self.logger.log(f'[*] Module arguments ({len(module_argv):d}):')
            self.logger.log(module_argv)
        else:
            module_argv = []

        if isinstance(self.mod_obj, chipsec.module_common.BaseModule):
            self.mod_obj.result.id = self.get_module_id(self.name)
            self.mod_obj.result.url = self.url.get_module_url(self.name)
            if self.mod_obj.is_supported():
                result = self.mod_obj.run(module_argv)
            else:
                self.mod_obj.result.setStatusBit(
                    self.mod_obj.result.status.NOT_APPLICABLE)
                result = self.mod_obj.result.getReturnCode(
                    ModuleResult.NOTAPPLICABLE)
                skip_msg = (f'Skipping module {self.name} since it is not '
                            f'applicable in this environment and/or platform')
                self.logger.log(skip_msg)

        return result

    def get_module_object(self) -> None:
        """
        Get the module object by introspecting the loaded module.

        This method finds the appropriate BaseModule subclass within the
        loaded module and instantiates it.
        """
        if self.mod_obj is None:
            try:
                if _importlib:
                    pkg = getattr(self.module, "__package__")
                    class_name = getattr(self.module, "__name__")
                    if pkg:
                        class_name = class_name.replace(pkg, '')
                    if class_name.startswith('.'):
                        class_name = class_name.replace('.', '')
                    for iname, iref in self.module.__dict__.items():
                        if isinstance(iref, type):
                            if issubclass(iref,
                                          chipsec.module_common.BaseModule):
                                if iname.lower() == class_name.lower():
                                    self.mod_obj = iref()
                if self.mod_obj is None:
                    raise ModuleNotFoundError(self.module)
            except (AttributeError, TypeError, ModuleNotFoundError):
                self.logger.chipsecLogger.exception(
                    'Error getting module object')

    def get_location(self) -> str:
        """
        Get the file location of the module.

        Returns:
            The file path of the module, or empty string if not available
        """
        myfile = ''
        try:
            if _importlib:
                myfile = getattr(self.module, '__file__')
        except (AttributeError, TypeError):
            pass
        return myfile

    def get_tags(self) -> Tuple[List[str], List[str]]:
        """
        Get the tags and metadata tags for the module.

        Returns:
            A tuple containing (module_tags, metadata_tags)
        """
        module_tags = []
        metadata_tags = []
        try:
            if _importlib:
                module_tags = getattr(self.module, 'TAGS')
                metadata_tags = getattr(self.module, 'METADATA_TAGS')
        except (AttributeError, TypeError):
            pass

        return module_tags, metadata_tags

    def __str__(self) -> str:
        """Return the string representation of the module."""
        return self.get_name()
