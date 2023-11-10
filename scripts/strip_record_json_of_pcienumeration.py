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
#

# Usage: python strip_record_json_of_pcienumeration.py recording.json
#     Where recording.json is generated from using "--helper recordhelper" on 
#     chipsec_main.py or chipsec_util.py

import sys
import os
from json import dumps, loads
class Split_Enumeration:
    def __init__(self, filename:str = "") -> None:
        self.data = {}
        self.enum_data = {}
        self.set_filename(filename)
        if self.filename:
            self.load_data()
        
    def set_filename(self, filename: str) -> None:
        self.filename = os.path.splitext(filename)[0]
        
    def load_data(self) -> None:
        if not self.filename:
            print("No file specified.")
            sys.exit(1)
        with open(self.filename+".json") as f:
            rawdata = f.read()
        self.data = loads(rawdata)


    def split_enumeration(self) -> None:
        fs_as_base_10_str = "4294967295" #0xFFFFFFFF
        
        self.pop_add_del_if_empty("cpuid", "(1,0)")
        
        cmd = "read_pci_reg"
        for b in range(256):
            for d in range(32):
                for f in range(8):
                    targs = f"({b},{d},{f},0,4)"
                    popdata = self.pop_add_del_if_empty(cmd, targs)
                    if f == 0 and popdata == fs_as_base_10_str:
                        break
                    if popdata != fs_as_base_10_str:
                        targs = f"({b},{d},{f},8,1)"
                        self.pop_add_del_if_empty(cmd, targs)

        self.save_all_jsons()

    def pop_add_del_if_empty(self, cmd:str, targs:str) -> str:
        popdata = self.data[cmd][targs].pop()
        self.add_to_enum_data(cmd, targs, popdata)
        if len(self.data[cmd][targs]) == 0:
            del self.data[cmd][targs]
            if len(self.data[cmd]) == 0:
                del self.data[cmd]
        return popdata

    def add_to_enum_data(self, cmd:str, targs:str, popdata:str) -> None:
        if cmd not in self.enum_data:
            self.enum_data[cmd] = {}
        if targs not in self.enum_data[cmd]:
            self.enum_data[cmd][targs] = []
        self.enum_data[cmd][targs].insert(0, popdata)

    def save_all_jsons(self) -> None:
        self.save_json(self.data, "test")
        self.save_json(self.enum_data, "enum")

    def save_json(self, data:dict, suffix:str) -> None:
        js = dumps(data, sort_keys=False, indent=2, separators=(',', ': ')) 
        with open(f"{self.filename}_{suffix}.json", 'w') as f:
            f.write(js)

if __name__ == '__main__':
    if len(sys.argv) == 2:
        Split_Enumeration(sys.argv[1]).split_enumeration()
    else:
        print("Expecting one argument: filename")
