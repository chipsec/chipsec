#!/usr/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2019, Intel Corporation
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

from chipsec.command import BaseCommand
from chipsec.hal.smbios import SMBIOS

class smbios_cmd(BaseCommand):
    def requires_driver(self):
        return True

    def run(self):
        smbios = SMBIOS(self.cs)

        self.logger.log('[*] Attempting to detect SMBIOS structures')
        found = smbios.find_smbios_table()
        if found:
            if smbios.smbios_2_pa is not None:
                self.logger.log(smbios.smbios_2_ep)
            if smbios.smbios_3_pa is not None:
                self.logger.log(smbios.smbios_3_ep)
        else:
            self.logger.log_bad('Unable to detect SMBIOS structure(s)')

commands = {'smbios': smbios_cmd}
