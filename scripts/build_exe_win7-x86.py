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


import os
import sys

print('Python', sys.version)

WIN_DRIVER_INSTALL_PATH = 'chipsec/helper/windows'
VERSION_FILE = 'VERSION'

build_dir = os.getcwd()
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir))
bin_dir = os.path.join(root_dir, 'bin')
tool_dir = root_dir
cfg_dir = os.path.join(tool_dir, 'chipsec', 'cfg')
version_file = os.path.join(root_dir, 'chipsec', VERSION_FILE)

win_7_x86 = os.path.join(bin_dir, 'windows-x86')

print(os.getcwd())
os.chdir(tool_dir)
sys.path.append(tool_dir)
print(os.getcwd())

data_files = [
    (WIN_DRIVER_INSTALL_PATH + '/windows_x86', ['chipsec/helper/windows/windows_x86/chipsec_hlpr.sys']),
    ('chipsec/modules/tools/uefi', ['chipsec/modules/tools/uefi/blockedlist.json']),
    ('chipsec/modules/tools/secureboot', [
        'chipsec/modules/tools/secureboot/Shell.efi',
        'chipsec/modules/tools/secureboot/te.cfg'
    ]),
]

for current, dirs, files in os.walk(cfg_dir):
    for file in files:
        if file.endswith('.xml'):
            tail = current.replace(cfg_dir, '').replace('\\', '/')
            xf = f'chipsec/cfg{tail}', [f'chipsec/cfg{tail}/{file}']
            data_files.append(xf)

version = ''
if os.path.exists(version_file):
    data_files.append(('.', [version_file]))
    with open(version_file, 'r') as verFile:
        version = verFile.read()
print(f'VERSION: {version}')

mypackages = []
for current, dirs, files in os.walk(tool_dir):
    if current.startswith(os.path.join(tool_dir, 'build')):
        continue
    for file in files:
        if file == '__init__.py':
            pkg = current.replace(tool_dir + os.path.sep, '')
            pkg = pkg.replace(os.path.sep, '.')
            mypackages.append(pkg)
            print(pkg)

if not os.path.exists(win_7_x86):
    os.makedirs(win_7_x86)

from setuptools import setup

includes = []

setup(
    name='chipsec',
    description='CHIPSEC: Platform Security Assessment Framework',
    version=version,
    console=['chipsec_main.py', 'chipsec_util.py'],
    data_files=data_files,
    options={
        'build': {'build_base': build_dir}
    }
)
