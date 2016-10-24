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

import os
import platform
from setuptools import setup, find_packages, Extension
import subprocess
import shutil

from setuptools.command.install import install as _install
from setuptools.command.build_ext import build_ext as _build_ext

def long_description():
    return open("README").read()

def version():
    return open(os.path.join("chipsec", "VERSION")).read()

def package_files(directory):
    paths = []
    for (path, directories, filenames) in os.walk(directory):
        for filename in filenames:
            paths.append(os.path.join('..', path, filename))
    return paths

skip_driver_opt = [("skip-driver", None,
                    ("Do not build the Chipsec kernel driver. "
                     "Only available on Linux."))
]

class build_ext(_build_ext):
    user_options = _build_ext.user_options + skip_driver_opt
    boolean_options = _build_ext.boolean_options + ["skip-driver"]

    def initialize_options(self):
        _build_ext.initialize_options(self)
        self.skip_driver = None

    def finalize_options(self):
        _build_ext.finalize_options(self)
        # Get the value of the skip-driver parameter from the install command.
        self.set_undefined_options("install", ("skip_driver", "skip_driver"))

    def run(self):
        bl = os.path.realpath(self.distribution.command_obj['build'].build_lib)
        if platform.system().lower() == "linux":
            if not self.skip_driver:
                subprocess.check_output(["make", "-C",
                                        os.path.join(bl, "drivers", "linux")])
            shutil.rmtree(os.path.join(bl, "drivers"))
        _build_ext.run(self)

class install(_install):
    user_options = _install.user_options + skip_driver_opt
    boolean_options = _install.boolean_options + ["skip-driver"]

    def initialize_options(self):
        _install.initialize_options(self)
        self.skip_driver = None


package_data = {
    "chipsec.cfg": ["*.xml", "*.xsd"],
    "chipsec": ["VERSION"]
}

install_requires = []
extra_files = [os.path.join("..", "chipsec-manual.pdf"), "WARNING.txt",
               "*.ini","*.cfg","*.json"
]
extra_kw = {}

if platform.system().lower() == "windows":
    package_data["chipsec.helper.win"] = ['win7_amd64/*.sys']
    extra_files.append(os.path.join("..", "chipsec_tools", "compression", "win" , "*"))
    install_requires.extend(['pywin32'])

if platform.system().lower() == "linux":
    extra_files.extend(package_files('drivers/linux'))
    extra_files.append(os.path.join("..", "chipsec_tools", "compression", "linux", "*"))
    package_data["chipsec.helper.linux"] = ["*.c","Makefile"]
    extra_kw["ext_modules"] = [
        Extension("chipsec.helper.linux.cores",
                  ["chipsec/helper/linux/cores.c"])
    ]

package_data[''] = extra_files

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
    package_data = package_data,
    install_requires = install_requires,

    py_modules=['chipsec_main', 'chipsec_util'],
    entry_points = {
        'console_scripts': [
            'chipsec_util=chipsec_util:main',
            'chipsec_main=chipsec_main:main',
        ],
    },
    cmdclass = {
        'install': install,
        'build_ext'   : build_ext,
    },
    **extra_kw
)
