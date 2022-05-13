#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2021, Intel Corporation
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

doc_path = os.getcwd()
src_path = os.path.abspath(os.path.join(doc_path, '..', '..'))

# Get current version for manual
def getVersion():
    ver_path = os.path.join(src_path, 'chipsec', 'VERSION')
    scover_path = os.path.join(doc_path, '_templates','scover.tmpl')
    index_path = os.path.join(doc_path, 'index.rst')

    with open(os.path.join(ver_path), 'r') as f:
        version = f.read()
    
    with open(os.path.join(scover_path), 'r') as f:
        contents = f.read()
    splitContents = contents.split('\n')
    contents = contents.replace(splitContents[8], 'version ' + version)
    with open(os.path.join(scover_path), 'w') as f:
        f.write(contents)

    with open(os.path.join(index_path), 'r') as f:
        contents = f.read()
    splitContents = contents.split('\n')
    withVer = 'CHIPSEC ' + version
    contents = contents.replace(splitContents[5], withVer, 2)
    contents = contents.replace(splitContents[6], '=' * len(withVer), 1)
    with open(os.path.join(index_path), 'w') as f:
        f.write(contents)

if __name__ == "__main__":
    getVersion()