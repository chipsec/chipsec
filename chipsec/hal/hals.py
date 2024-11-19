
# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2024, Intel Corporation
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

# -------------------------------------------------------------------------------
#
# CHIPSEC: Platform Hardware Security Assessment Framework
#
# -------------------------------------------------------------------------------

import os
from importlib import import_module
from typing import Dict, Any
from chipsec.library.logger import logger
from chipsec.library.file import get_main_dir
from chipsec.library.strings import make_hex_key_str
from chipsec.library.exceptions import HALNotFoundError, HALInitializationError
# Search subfolders for hals

class Hals:
    def __init__(self, cs):
        self.cs = cs
        self.hals_import_location = "chipsec.hal."
        self._available_hals = []
        self.update_available_hals() #['mem', 'msr', 'ucode', 'io', 'cpu', 'msgbus', 'mmio', 'iobar', 'igd']

    def available_hals(self) -> list:
        a_hals = []
        for i in self._available_hals:
            a_hals += i['name']
        return a_hals
    
    def list_loadable_hals(self) -> list:
        loadable_list = []
        if not self._available_hals:
            self.update_available_hals()
        for halobjs in self._available_hals:
            for hal in halobjs['name']:
                try:
                    loadable_list.append(self.find_best_hal_by_name(hal))
                except HALNotFoundError:
                    continue
        return loadable_list

    def __getattr__(self, name):
        best_hal = self.find_best_hal_by_name(name)
        try:
            hal_class = getattr(best_hal['mod'], name)
            setattr(self, name, hal_class(self.cs))
        except Exception as err:
            raise HALInitializationError(f'HAL with name {name} was not able to be initialized: {str(err)}')
        return super(Hals, self).__getattribute__(name)

    def find_best_hal_by_name(self, name:str) -> Any:
        # hal_path = f'{self.hals_import_location}{name}'
        selected_hals = []
        for hal in self._available_hals:
            if name in hal['name'] and make_hex_key_str(self.cs.Cfg.vid) in [arch.upper() for arch in hal['arch']]:
                hal['priority'] = 1
                selected_hals.append(hal)
            elif name in hal['name'] and 'FFFF' in [h.upper() for h in hal['arch']]:
                hal['priority'] = 2 
                selected_hals.append(hal)

        if not selected_hals:
            raise HALNotFoundError(f'HAL with name {name} was not found.')

        return sorted(selected_hals, key=lambda x: x['priority'])[0]


    def update_available_hals(self) -> Dict[str, Any]:
        """Determine available HAL modules"""
        hal_base_dir = os.path.join(get_main_dir(), "chipsec", "hal")
        hal_dirs = [f.name for f in os.scandir(hal_base_dir) if f.is_dir() and '__' not in f.name]
        hals = []
        for hal_dir in hal_dirs:
            hals += ([f'{hal_dir}.{i[:-3]}' for i in os.listdir(os.path.join(hal_base_dir, hal_dir)) if i[-3:] == ".py" and not i[:2] == "__"])
        logger().log_debug('[CHIPSEC] Loaded HALs:')
        logger().log_debug(f'   {hals}')
        module = None
        halsdata = []
        for hal in hals:
            try:
                hal_path = f'{self.hals_import_location}{hal}'
                module = import_module(hal_path)
                hd = getattr(module, 'haldata')
                hd['mod'] = module
                halsdata.append(hd)
            except ImportError as err:
                # Display the import error and continue to import commands
                logger().log_error(f"Exception occurred during import of {hal}: '{str(err)}'")
                continue
            except AttributeError as err:
                logger().log_error(f"HAL {hal} has not been updated with 'haldata' attribute: '{str(err)}'")
                continue
        self._available_hals = halsdata




# self.pci = pci.Pci(self)
#         self.mem = physmem.Memory(self)
#         self.msr = msr.Msr(self)
#         self.ucode = ucode.Ucode(self)
#         self.io = io.PortIO(self)
#         self.cpu = cpu.CPU(self)
#         self.msgbus = msgbus.MsgBus(self)
#         self.mmio = mmio.MMIO(self)
#         self.iobar = iobar.IOBAR(self)
#         self.igd = igd.IGD(self)