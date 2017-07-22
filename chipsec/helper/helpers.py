#!/usr/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2016, Intel Corporation
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

import os, platform
import chipsec.file

from chipsec.helper.efi import *
from chipsec.helper.linux import *
from chipsec.helper.osx import *
if os.path.isfile("C:\\Windows\\System32\\drivers\\chipsec_hlpr.sys") or os.path.isfile(os.path.join( chipsec.file.get_main_dir(), "chipsec", "helper", "win", "win7_" + platform.machine().lower(), "chipsec_hlpr.sys")):
    from chipsec.helper.win import *
elif (os.path.isfile(os.path.join("C:\\Windows\\System32\\drivers\\RwDrv.sys")) or os.path.isfile(os.path.join( chipsec.file.get_main_dir(), "chipsec", "helper", "rwe", "win7_" + platform.machine().lower(), "RwDrv.sys" ))):
    from chipsec.helper.rwe import *

