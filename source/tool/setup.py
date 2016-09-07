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
Setup module to install chipsec package via setuptools
"""

import io
import os
import platform
from setuptools import setup, find_packages, Extension
import subprocess

from setuptools.command.install import install as _install
from setuptools.command.build_ext import build_ext as _build_ext

here = os.path.abspath(os.path.dirname(__file__))

build_driver = False

def long_description():
    with io.open(os.path.join(here, "..", "..", "README.md"), encoding='utf-8') as f:
        return f.read()

def version():
    with io.open(os.path.join(here, 'chipsec', 'VERSION')) as f:
        return f.read()

def package_files(directory):
    paths = []
    for (path, directories, filenames) in os.walk(directory):
        for filename in filenames:
            paths.append(os.path.join('..', path, filename))
    return paths

class build_ext(_build_ext):
    def run(self):
        global build_driver
        if platform.system().lower() == "linux" and build_driver:
            bl = os.path.realpath(self.distribution.command_obj['build'].build_lib)
            subprocess.check_output( "make -C "+ bl +"/drivers/linux/", shell=True )
        _build_ext.run(self)

class FullInstall(_install):
    description = 'Build CHIPSEC Driver. Install CHIPSEC with Driver.'
    def run(self):
        if platform.system().lower() == "linux":
            global build_driver
            build_driver = True
            _install.do_egg_install(self)

package_data = { "": ["*.ini","*.cfg","*.json"],
                 "chipsec.cfg": ["*.xml", "*.xsd"],
                 "chipsec": ["VERSION"]
               }

if platform.system().lower() == "windows":
    package_data[ "chipsec.helper.win" ] = [ 'win7_amd64/*.sys' ]
    install_requires=['pywin32']
    kw = dict(ext_modules = [])

if platform.system().lower() == "linux":
    extra_files = package_files('drivers/linux')
    package_data[ "chipsec.helper.linux" ] = [ "*.c","Makefile" ] 
    package_data['']                       = extra_files
    install_requires=[]
    kw = dict(
        ext_modules = [
            Extension("chipsec.helper.linux.cores", ["chipsec/helper/linux/cores.c"]),
        ],
    )

setup(

    name = 'chipsec',
    version = version(),
    description = 'CHIPSEC: Platform Security Assessment Framework',
    author = 'CHIPSEC Team',
    author_email = 'chipsec@intel.com',
    url = 'https://github.com/chipsec/chipsec',
    download_url="https://github.com/chipsec/chipsec",
    license = 'GNU General Public License v2 (GPLv2)',
    platforms=['any'],
    long_description = long_description(),

    classifiers = [
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
        'Natural Language :: English',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX :: Linux',
        'Operating System :: MacOS :: MacOS X',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Topic :: Security',
        'Topic :: System :: Hardware'
    ],

    packages = find_packages(exclude=["tests.*", "tests"]),
    py_modules=['chipsec_main', 'chipsec_util'],

    install_requires = install_requires, 

    package_data = package_data,

    entry_points = {
        'console_scripts': [
            'chipsec_util=chipsec_util:main',
            'chipsec_main=chipsec_main:main',
        ],
    },
    #scripts         = ['chipsec_main.py', 'chipsec_util.py'],
    cmdclass={
        'full_install': FullInstall,
        'build_ext'   : build_ext,
    },
    **kw
)
