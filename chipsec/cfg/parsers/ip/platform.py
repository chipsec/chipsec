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

from chipsec.library.exceptions import CSConfigError, RegisterNotFoundError, ScopeNotFoundError, NonRegisterInScopeError, BARNotFoundError
from chipsec.library.register import BaseConfigRegisterHelper, ObjList
from chipsec.library.logger import logger
from re import match

class Recursable:      
        def _get_next_level_list(self) -> list:
            raise NotImplementedError('get_next_level_list() not implemented')
        
        def get_next_levels(self, key):
            key = key.replace('*', '.*')
            next_options = []
            next_options_list = [key] if '*' not in key and key in self._get_next_level_list() else self._get_next_level_list()
            for option in next_options_list:
                if match(key, option):
                    next_option = self._get_next_level(option)
                    if isinstance(next_option, list):
                        next_options.extend(next_option)
                    else:
                        next_options.append(next_option)
            return next_options

        def _get_next_level(self):
            raise NotImplementedError("get_next_level() not implemented")
        
class RegisterList:
    def __init__(self):
        self.register_list = {}

    def add_register(self, register_name, register_object):
        self.register_list[register_name] = register_object
        self.__setattr__(register_name, register_object)

    def get_register(self, register_name):
        if register_name in self.register_list:
            return ObjList(self.__getattribute__(register_name))
        else:
            raise RegisterNotFoundError(f'Invalid register name: {register_name}')


class Platform(Recursable):
    def __init__(self):
        self.vendor_list = []
    
    def add_vendor(self, vendor):
        if isinstance(vendor, Vendor):
            self.vendor_list.append(vendor.name)
            self.__setattr__(f'_{vendor.name}', vendor)
        else:
            raise CSConfigError(f'Invalid vendor object: {vendor}')
        
    def get_vendor(self, vendor_name) -> 'Vendor':
        if vendor_name in self.vendor_list:
            return self.__getattribute__(f'_{vendor_name}')
        else:
            raise CSConfigError(f'Invalid vendor name: {vendor_name}')
        
    def remove_vendor(self, vendor):
        if isinstance(vendor, Vendor) and vendor in self.vendor_list:
            self.vendor_list.remove(vendor.name)
            self.__delattr__(f'_{vendor.name}')
        else:
            raise CSConfigError(f'Invalid vendor object: {vendor}')
            
    def _get_next_level_list(self):
        return self.vendor_list
    
    def _get_next_level(self, name): 
        return self.get_vendor(name)
    
    def get_obj_from_scope(self, scope: str):
        logger().log_debug(f'Getting obj from scope: {scope}')
        if '*' in scope:
            raise Exception(f'Invalid scope: {scope}. No wildcards allowed for this function.')
        split_scope = scope.split('.')
        return Platform._get_obj_from_split_scope(self, split_scope)

    @staticmethod
    def _get_obj_from_split_scope(obj, scope: list):
        if not scope:
            raise ScopeNotFoundError(f'Scope {scope} on obj {obj} was not found')
        root_scope = scope.pop(0)
        next_level = obj._get_next_level(root_scope)

        if len(scope) == 0:
            return next_level
        return Platform._get_obj_from_split_scope(next_level, scope)

    def get_matches_from_scope(self, scope: str):
        logger().log_debug(f'Getting matches from scope: {scope}')
        split_scope = scope.split('.')
        return Platform._get_matches_from_split_scope([self], split_scope)

    @staticmethod
    def _get_matches_from_split_scope(objs: list, scope: list):
        if not scope:
            raise ScopeNotFoundError(f'Scope {scope} on objs: {objs} was not found')
        root_scope = scope.pop(0)
        next_level_list = []
        for obj in objs:
            next_level_list.extend(obj.get_next_levels(root_scope))

        if len(scope) == 0:
            return next_level_list
        return Platform._get_matches_from_split_scope(next_level_list, scope)
    
    def get_register_from_scope(self, scope: str):
        logger().log_debug(f'Getting register from scope: {scope}')
        if '*' in scope:
            raise Exception(f'Invalid scope: {scope}. No wildcards allowed for this function.')
        split_scope = scope.split('.')
        return Platform._get_register_from_split_scope(self, split_scope)
    
    @staticmethod
    def _get_register_from_split_scope(obj, scope: list):
        if not scope:
            raise ScopeNotFoundError(f'Scope {scope} on obj {obj} was not found')
        root_scope = scope.pop(0)
        if len(scope) == 0:
            return obj.get_register(root_scope)
        else:
            next_level = obj._get_next_level(root_scope)

        return Platform._get_register_from_split_scope(next_level, scope)

    def get_register_matches_from_scope(self, scope: list):
        logger().log_debug(f'Getting registers from matchscope: {scope}')
        objects = Platform._get_register_matches_from_split_scope([self], scope)
        return ObjList(objects)
        
    @staticmethod
    def _get_register_matches_from_split_scope(objs: list, scope: list):
        if not scope:
            raise ScopeNotFoundError(f'Scope {scope} on objs: {objs} was not found')
        root_scope = scope.pop(0)
        next_level_list = []
        if len(scope) == 0:
            for obj in objs:
                next_level_list.extend(obj.get_register(root_scope))
            return next_level_list
        else:
            for obj in objs:
                next_level_list.extend(obj.get_next_levels(root_scope))

        return Platform._get_register_matches_from_split_scope(next_level_list, scope)




class Vendor(Recursable):
    def __init__(self, name):
        self.ip_list = []
        self.name = name

    def add_ip(self, ip_name: str, obj):
        ip = IP(ip_name, obj)
        self.ip_list.append(ip.name)
        self.__setattr__(ip.name, ip)
        
    def get_ip(self, ip_name) -> 'IP':
        if ip_name in self.ip_list:
            return self.__getattribute__(ip_name)
        else:
            raise CSConfigError(f'Device: {ip_name} not found in Vendor: {self.name}')
        
    def _get_next_level_list(self):
        return self.ip_list
    
    def _get_next_level(self, ip_name):
        return self.get_ip(ip_name)

class IP(Recursable, RegisterList):
    def __init__(self, name, ipobj):
        RegisterList.__init__(self)
        self.bar_list = []
        self.name = name
        self.obj = ipobj

    def add_bar(self, bar_name: str, barobj):
        bar = Bar(bar_name, barobj)
        self.bar_list.append(bar.name)
        self.__setattr__(f'{bar.name}_', bar)
    
    def get_bar(self, bar_name: str):
        if bar_name in self.bar_list:
            return self.__getattribute__(f'{bar_name}_')
        else:
            raise BARNotFoundError(f'Bar: {bar_name} not found in IP: {self.name}')
        
    def _get_next_level_list(self):
        return self.bar_list + list(self.register_list.keys())
    
    def _get_next_level(self, id):
        if id in self._get_next_level_list():
            try:
                return self.get_bar(id)
            except BARNotFoundError:
                return self.get_register(id)
        else:
            raise CSConfigError(f'Next Level: {id} not found in in IP: {self.name}')
        

class Bar(Recursable, RegisterList):
    def __init__(self, name, barobj):
        RegisterList.__init__(self)
        self.name = name
        self.obj = barobj

    def _get_next_level_list(self):
        return self.register_list
    
    def _get_next_level(self, id):
        if id in self.register_list.keys():
            return self.get_register(id)
        else:
            raise CSConfigError(f'Bar: {id} not found in in IP: {self.name}')
    