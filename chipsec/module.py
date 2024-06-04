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
import traceback
import json
import chipsec.library.logger
from chipsec.library.file import get_main_dir
from chipsec.library.url import url
from chipsec.library.returncode import ModuleResult, generate_hash_id

_importlib = True
try:
    import importlib
except ImportError:
    _importlib = False

MODPATH_RE = re.compile(r'^\w+(\.\w+)*$')


class Module:
    def __init__(self, name):
        self.logger = chipsec.library.logger.logger()
        self.name = name
        self.module = None
        self.mod_obj = None
        self.module_ids = self.get_module_ids_dictionary()
        self.url = url()

    def __lt__(self, other):
        return self.name < other.name

    def __le__(self, other):
        return self.name <= other.name

    def __gt__(self, other):
        return self.name > other.name

    def __ge__(self, other):
        return self.name >= other.name

    def get_name(self):
        return self.name

    def do_import(self):
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
                self.logger.log_error(f"Exception occurred during import of {self.name}: '{str(msg)}'")
                if self.logger.DEBUG:
                    self.logger.log_bad(traceback.format_exc())
                raise msg
        return loaded

    def get_module_ids_dictionary(self):
        with open(os.path.join(get_main_dir(), 'chipsec', 'library', 'module_ids.json'), 'r') as module_ids_file:
            module_ids = json.loads(module_ids_file.read())
        return module_ids

    def update_module_ids_file(self):
        with open(os.path.join(get_main_dir(), 'chipsec', 'library', 'module_ids.json'), 'w') as module_ids_file:
            module_ids_file.write(json.dumps(self.module_ids))

    def get_module_id(self, module_name):
        if module_name in self.module_ids:
            module_id = self.module_ids[module_name]
        else:
            module_id = generate_hash_id(module_name)
            self.module_ids[module_name] = module_id
            self.update_module_ids_file()
        return module_id

    def run(self, module_argv):
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
                self.mod_obj.result.setStatusBit(self.mod_obj.result.status.NOT_APPLICABLE)
                result = self.mod_obj.result.getReturnCode(ModuleResult.NOTAPPLICABLE)
                self.logger.log(f'Skipping module {self.name} since it is not applicable in this environment and/or platform')

        return result

    def get_module_object(self):
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
                            if issubclass(iref, chipsec.module_common.BaseModule):
                                if iname.lower() == class_name.lower():
                                    self.mod_obj = iref()
                if self.mod_obj is None:
                    raise ModuleNotFoundError(self.module)
            except (AttributeError, TypeError, ModuleNotFoundError):
                self.logger.chipsecLogger.exception('Error getting module object')

    def get_location(self):
        myfile = ''
        try:
            if _importlib:
                myfile = getattr(self.module, '__file__')
        except:
            pass
        return myfile

    def get_tags(self):
        module_tags = []
        metadata_tags = []
        try:
            if _importlib:
                module_tags = getattr(self.module, 'TAGS')
                metadata_tags = getattr(self.module, 'MD_TAGS')
        except:
            pass

        return module_tags, metadata_tags

    def __str__(self):
        return self.get_name()
