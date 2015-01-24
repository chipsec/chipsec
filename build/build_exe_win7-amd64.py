#!/usr/bin/env python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2015, Intel Corporation
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



# -------------------------------------------------------------------------------
#
# CHIPSEC: Platform Hardware Security Assessment Framework
# (c) 2010-2012 Intel Corporation
#
# -------------------------------------------------------------------------------
## \addtogroup build Build scripts
# Executable build scripts

## \addtogroup build
# build_exe_win7-amd64.py -- py2exe setup module for building chipsec.exe Win executable for windows 7

##\file
# py2exe setup module for building chipsec.exe Win executable for windows 7
#
# To build Windows executable chipsec.exe using py2exe:
#
# 1. Install py2exe package from http://www.py2exe.org
# 2. run "python build_exe_<platform>.py py2exe"
# 3. chipsec.exe and all needed libraries will be created in "./bin/<platform>"
#


import os
import sys

print 'Python', (sys.version)

import py2exe
WIN_DRIVER_INSTALL_PATH = "chipsec/helper/win"
VERSION_FILE="VERSION"

build_dir = os.getcwd()
root_dir = os.path.abspath(os.pardir)
bin_dir = os.path.join(root_dir,"bin")
source_dir = os.path.join(root_dir,"source")
tool_dir   = os.path.join(source_dir,"tool")
cfg_dir    = os.path.join(tool_dir,"chipsec","cfg")

win_7_amd64 = os.path.join(bin_dir,'win7-amd64');


print os.getcwd()
os.chdir( tool_dir )
sys.path.append(tool_dir)
print os.getcwd()


data_files = [(WIN_DRIVER_INSTALL_PATH + "/win7_amd64", ['chipsec/helper/win/win7_amd64/chipsec_hlpr.sys'])]
for current, dirs, files in os.walk(cfg_dir ):
    for file in files:
        if file.endswith('.xml') :
            #xf = os.path.join('chipsec','cfg') ,os.path.join(cfg_dir,file)
            xf = 'chipsec/cfg' ,['chipsec/cfg/%s'%file]
            data_files.append( xf ) 

version=""
if os.path.exists(VERSION_FILE):
    data_files.append(('.',['VERSION']))
    with open(VERSION_FILE, "r") as verFile:
        version = "." + verFile.read()

mypackages = []
for current, dirs, files in os.walk(tool_dir ):
    if current.startswith(os.path.join(tool_dir,'build')): 
        #print "*********** skipped: %s"%current
        continue
    for file in files:
        if file == "__init__.py":
            pkg = current.replace(tool_dir+os.path.sep,"")
            pkg = pkg.replace(os.path.sep,'.')
            mypackages.append(pkg)
            print pkg

from distutils.core import setup


includes = []

setup(
        name            = 'chipsec',
        description     = 'CHIPSEC: Platform Security Assessment Framework',
        version         = '1.0'+version,
        console         = [ 'chipsec_main.py', 'chipsec_util.py' ],
        #zipfile         = None,
        data_files      =  data_files,
        options         = {
                            'build' : { 'build_base': build_dir },
                            'py2exe': {
                                        #"bundle_files": 1,
                                        #'includes'    : includes,
                                        'dist_dir'    : win_7_amd64,
                                        'packages'    : mypackages,
                                        'compressed'  : True
                                      }
                          }
)
