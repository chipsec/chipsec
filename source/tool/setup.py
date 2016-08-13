#!/usr/local/bin/python
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



"""
Components for auxiliar tasks. Setup module for installing chipsec with distutils as a package
"""

import os
from distutils.core import setup, Extension
from distutils import dir_util
import platform

tool_dir = os.path.dirname(os.path.abspath(__file__))

package_data = { "chipsec.cfg": ["*.xml", "*.xsd"],
                 "chipsec": ["VERSION"]
               }

if platform.system().lower() == "windows":
    WIN_DRIVER_INSTALL_PATH = "Lib/site-packages/chipsec/helper/win"

    data_files = [
                  #(WIN_DRIVER_INSTALL_PATH + "/win7_amd64", ['chipsec/win/win7_amd64/chipsec_hlpr.sys','chipsec/win/win7_amd64/chipsec_amd64.cat','chipsec/win/win7_amd64/chipsec.inf']),
                  (WIN_DRIVER_INSTALL_PATH + "/win7_amd64", ['chipsec/helper/win/win7_amd64/chipsec_hlpr.sys']),
                  #(WIN_DRIVER_INSTALL_PATH + "/win7_x86"  , ['chipsec/helper/win/win7_x86/chipsec_hlpr.sys'])
                  #(WIN_DRIVER_INSTALL_PATH + "/winxp", ['chipsec/helper/win/winxp/chipsec_hlpr.sys'])
                 ]
    extensions = []

if platform.system().lower() == "linux":
    data_files = []
    extensions = [ Extension('chipsec.helper.linux.cores', sources=['chipsec/helper/linux/cores.c']) ]

version      = ""
VERSION_FILE = os.path.join(os.path.dirname(__file__), 'chipsec', 'VERSION')
if os.path.exists( VERSION_FILE ):
    with open(VERSION_FILE, "r") as verFile:
        version = "." + verFile.read()

build_dir = os.path.join(tool_dir, "build")
if os.path.exists( build_dir ):
    dir_util.remove_tree( build_dir )

#TODO: Replace with setuptools find_packages()
mypackages = []
for current, dirs, files in os.walk(tool_dir):
    for file in files:
        if file == "__init__.py":
            pkg = current.replace(tool_dir+os.path.sep,"")
            pkg = pkg.replace(os.path.sep,'.')
            mypackages.append(pkg)


setup(
        name            = 'chipsec',
        description     = 'CHIPSEC: Platform Security Assessment Framework',
        version         = '1.2.4',
        author          = 'chipsec developers',
        author_email    = '',
        url             = 'https://github.com/chipsec/chipsec',

        data_files      = data_files,
        scripts         = ['chipsec_main.py', 'chipsec_util.py'],
        packages        = mypackages,
        package_data    = package_data,
        ext_modules     = extensions
)
