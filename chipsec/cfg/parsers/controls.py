# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2023, Intel Corporation
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

from chipsec.parsers import BaseConfigHelper


class CONTROLHelper(BaseConfigHelper):
    def __init__(self, cfg_obj, reg_obj):
        super(CONTROLHelper, self).__init__(cfg_obj)
        self.name = cfg_obj['name']
        self.value = None
        self.desc = cfg_obj['desc']
        self.__reg = reg_obj
        self.instance = self.__reg.instance
        self.field = cfg_obj['field']

    def read(self):
        """Read the object"""
        self.value = self.__reg.read_field(self.field)
        return self.value

    def write(self, value):
        """Write the object"""
        self.__reg.write_field(self.field, value)

    def get_register_name(self):
        return self.__reg.name

    def __str__(self) -> str:
        return f"""Name {self.name}
        Register {self.__reg.name}
        Field {self.field}
        Value {self.value}"""
    
    def __repr__(self):
        return f'''Control: {self.name} -> {self.value} ({self.__reg.name}: {self.field})'''
