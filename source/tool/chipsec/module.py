#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2014, Intel Corporation
# 
#This program is free software; you can redistribute it and/or
#modify it under the terms of the GNU General Public License
#as published by the Free Software Foundation; Version 2.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with this program; if not, write to the Free Software
#Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
#Contact information:
#chipsec@intel.com
#


import os
import sys
import re
import traceback
import chipsec.logger
from chipsec.module_common import ModuleResult

_importlib = True
try:
    import importlib
except ImportError:
    _importlib = False
    
MODPATH_RE      = re.compile("^\w+(\.\w+)*$")

class Module():
    def __init__(self,name):
        self.logger = chipsec.logger.logger()
        self.name = name
        self.module = None
        self.mod_obj = None

    
    def get_name(self):
        return self.name
    
    def do_import(self):
        loaded = False
        if not MODPATH_RE.match(self.get_name()):
            self.logger.error( "Invalid module path: %s" % self.name )
        else:
            try:
                if _importlib:
                    self.module = importlib.import_module( self.name )
                # Support for older Python < 2.5
                #else:
                #    #module = __import__(module_path)
                #    exec ('import ' + self.name)
                loaded = True
            except BaseException, msg:
                self.logger.error( "Exception occurred during import of %s: '%s'" % (self.name, str(msg)) )
                if self.logger.VERBOSE: self.logger.log_bad(traceback.format_exc())
        return loaded
    
    def run( self, module_argv ):
        result = self.get_module_object()

        if self.mod_obj != None and result == ModuleResult.PASSED:
            if module_argv is not None:
                self.logger.log( "[*] Module arguments (%d):" % len(module_argv) )
                self.logger.log( module_argv )
            else:
                module_argv = []

            if isinstance(self.mod_obj,chipsec.module_common.BaseModule):
                result = self.mod_obj.run(module_argv)

        return result 

    def get_module_object(self):
        result = ModuleResult.PASSED
        if self.mod_obj == None :
            try:
                if _importlib:
                    pkg = getattr( self.module, "__package__" )
                    class_name = getattr( self.module, "__name__" )
                    if pkg:
                        class_name = class_name.replace(pkg,'')
                    if class_name.startswith('.'): class_name = class_name.replace('.','')
                    self.mod_obj = getattr(self.module,class_name.lower())()
                # Support for older Python < 2.5
                #else:
                #    exec ('import ' + self.name)
                #    exec ( 'pkg = ' + self.name + '.__package__')
                #    exec ( 'class_name = ' + self.name + '.__name__')
                #    if pkg:
                #        class_name = class_name.replace(pkg,'')
                #    if class_name.startswith('.'): class_name = class_name.replace('.','')
                #    exec ('self.mod_obj = ' + self.name + '.' + class_name + '()')
            except AttributeError, ae:
                result = ModuleResult.DEPRECATED
        return result

    def get_location(self):
        myfile = ''
        try:
            if _importlib:
                myfile = getattr( self.module, "__file__" )
            # Support for older Python < 2.5
            #else:
            #    exec ('import ' + self.name)
            #    exec ( 'file = ' + self.name + '.__file__')
        except :
            pass
        return myfile


    def get_tags(self):
        module_tags=[]
        try:
            if _importlib:
                module_tags = getattr( self.module, 'TAGS' )
            # Support for older Python < 2.5
            #else:
            #    exec ('module_tags = ' +self.get_name() + '.TAGS')
        except:
            #self.logger.log(module_path)
            #self.logger.log_bad(traceback.format_exc())
            pass
        return module_tags
    
    def __str__(self):
        return self.get_name()