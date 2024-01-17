#!/usr/bin/env python3
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


"""
Setup module to install chipsec package via setuptools
"""

import io
import os
import platform
import logging
import subprocess
from shutil import rmtree
from setuptools import setup, find_packages, Extension, __version__ as _sutver

if _sutver and int(_sutver.split('.')[0]) < 62:
    raise RuntimeError("Setuptools version must be greater than 62.0.0. Please upgrade using 'pip install setuptools --upgrade'")

from setuptools.command.install import install as _install
from setuptools.command.build import build as _build
from setuptools.command.sdist import sdist as _sdist
from setuptools.command.build_ext import build_ext as _build_ext

NO_DRIVER_MARKER_FILE = 'README.NO_KERNEL_DRIVER'



def long_description():
    return open('README').read()


def version():
    return open(os.path.join('chipsec', 'VERSION')).read()


def package_files(directory):
    paths = []
    for (path, directories, filenames) in os.walk(directory):
        for filename in filenames:
            paths.append(os.path.join(path, filename))
    return paths


skip_driver_opt = [('skip-driver', None,
                    ('Do not build the Chipsec kernel driver. '
                     'Only available on Linux.'))]


class build_ext(_build_ext):
    user_options = _build_ext.user_options + skip_driver_opt
    boolean_options = _build_ext.boolean_options + ['skip-driver']

    def initialize_options(self):
        _build_ext.initialize_options(self)
        self.skip_driver = None

    def finalize_options(self):
        _build_ext.finalize_options(self)
        # Get the value of the skip-driver parameter from the install command.
        self.set_undefined_options('install', ('skip_driver', 'skip_driver'))
        self.set_undefined_options('build', ('skip_driver', 'skip_driver'))

    def _build_linux_driver(self):
        logging.info('Building the linux driver')
        build_driver = os.path.join(self.real_build_lib, 'drivers', 'linux')
        ko_ext = os.path.join(build_driver, 'chipsec.ko')
        # We copy the drivers extension to the build directory.
        self.copy_tree(os.path.join('drivers', 'linux'), build_driver)
        # Run the makefile there.
        subprocess.check_output(['make', '-C', build_driver])
        # And copy the resulting .ko to the right place.
        # That is to the source directory if we are in 'develop' mode,
        # otherwise to the helper subdirectory in the build directory.
        root_dst = '' if self.inplace else self.real_build_lib
        dst = os.path.join(root_dst, 'chipsec', 'helper', 'linux')
        self.copy_file(ko_ext, dst)
        # Finally, we clean up the build directory.
        rmtree(os.path.join(self.real_build_lib, 'drivers'))

    def _build_win_driver(self, path):
        cur_dir = os.getcwd()
        os.chdir(path)
        # Run the makefile there.
        if platform.machine().endswith('64'):
            subprocess.call(['install.cmd'])
        else:
            subprocess.call(['install.cmd', '32'])
        os.chdir(cur_dir)

    def _build_all_win_drivers(self):
        logging.info('Building the windows chipsec driver')
        driver_path = os.path.join('drivers', 'windows', 'chipsec')
        self._build_win_driver(driver_path)
        logging.info('Building the windows pcifilter driver')
        driver_path = os.path.join('drivers', 'windows', 'pcifilter')
        self._build_win_driver(driver_path)

    def run(self):
        # First, we build the standard extensions.
        _build_ext.run(self)

        # Then, we build the compression tools and the driver if required
        def null_builder():
            return None
        driver_build_function = null_builder
        self.real_build_lib = os.path.realpath(self.build_lib)
        if platform.system().lower() == 'linux':
            driver_build_function = self._build_linux_driver
        elif platform.system().lower() == 'windows':
            driver_build_function = self._build_all_win_drivers

        if not self.skip_driver:
            driver_build_function()

    def get_source_files(self):
        files = _build_ext.get_source_files(self)
        if platform.system().lower() == 'linux':
            files.extend(package_files(os.path.join('drivers', 'linux')))
        return files


class install(_install):
    user_options = _install.user_options + skip_driver_opt
    boolean_options = _install.boolean_options + ['skip-driver']

    def initialize_options(self):
        _install.initialize_options(self)
        self.skip_driver = None

        # Do not build the driver if no-driver marker file is present.
        # This marker is only created by an sdist command when
        # 'python setup.py sdist' is executed. This allows having
        # driver-less PIP packages uploaded to PyPi.
        if os.path.exists(NO_DRIVER_MARKER_FILE):
            self.skip_driver = True


class build(_build):
    user_options = _build.user_options + skip_driver_opt
    boolean_options = _build.boolean_options + ['skip-driver']

    def initialize_options(self):
        _build.initialize_options(self)
        self.skip_driver = None


class sdist(_sdist):
    """Build sdist."""

    def make_release_tree(self, base_dir, files):
        pypi_msg = u"""PyPI-distributed chipsec PIP package doesn't contain a pre-built kernel\n""" \
            """driver. Please use it only when a kernel driver is already present on the\n""" \
            """system. Otherwise, please install chipsec from source, using the following\n""" \
            """procedure:""" \
            """\n  https://github.com/chipsec/chipsec/blob/main/chipsec-manual.pdf""" \
            """\n  https://chipsec.github.io/"""
        _sdist.make_release_tree(self, base_dir, files)
        no_driver_marker = os.path.join(base_dir, NO_DRIVER_MARKER_FILE)
        with io.open(no_driver_marker, 'w', encoding='utf-8') as fd:
            fd.write(pypi_msg)


package_data = {
    # Include any configuration file.
    '': ['*.ini', '*.cfg', '*.json'],
    'chipsec': ['*VERSION*', 'WARNING.txt', 'options/*.ini'],
    'chipsec.cfg': ['8086/*.xml', '1022/*.xml', '*.xml', '*.xsd'],
}
data_files = [('', ['chipsec-manual.pdf'])]
install_requires = []
extra_kw = []

if platform.system().lower() == 'windows':
    package_data['chipsec.helper.windows'] = ['windows_amd64/*.sys']
    package_data['chipsec.helper.rwe'] = ['windows_amd64/*.sys']
    package_data['chipsec_tools.compression'] = ['*']
    install_requires.append('pywin32')
    extra_kw = [
        Extension(
            'EfiCompressor',
            sources=[
                os.path.join('chipsec_tools', 'compression', 'Bra86.c'),
                os.path.join('chipsec_tools', 'compression', 'Decompress.c'),
                os.path.join('chipsec_tools', 'compression', 'Compress.c'),
                os.path.join('chipsec_tools', 'compression', 'EfiCompress.c'),
                os.path.join('chipsec_tools', 'compression', 'TianoCompress.c'),
                os.path.join('chipsec_tools', 'compression', 'EfiCompressor.c'),
            ],
            include_dirs=[
                os.path.join('chipsec_tools', 'compression', 'Include'),
                os.path.join('chipsec_tools', 'compression', 'Include', 'Common'),
                os.path.join('chipsec_tools', 'compression', 'Include', 'X64'),
            ],
        )
    ]

elif platform.system().lower() == 'linux':
    package_data['chipsec_tools.compression'] = ['*']
    extra_kw = [
        Extension(
            'EfiCompressor',
            sources=[
                os.path.join('chipsec_tools', 'compression', 'Bra86.c'),
                os.path.join('chipsec_tools', 'compression', 'Decompress.c'),
                os.path.join('chipsec_tools', 'compression', 'Compress.c'),
                os.path.join('chipsec_tools', 'compression', 'EfiCompress.c'),
                os.path.join('chipsec_tools', 'compression', 'TianoCompress.c'),
                os.path.join('chipsec_tools', 'compression', 'EfiCompressor.c'),
            ],
            include_dirs=[
                os.path.join('chipsec_tools', 'compression', 'Include'),
                os.path.join('chipsec_tools', 'compression', 'Include', 'Common'),
                os.path.join('chipsec_tools', 'compression', 'Include', 'X64'),
            ],
        )
    ]

setup(
    name='chipsec',
    version=version(),
    description='CHIPSEC: Platform Security Assessment Framework',
    author='CHIPSEC Team',
    author_email='chipsec@intel.com',
    url='https://github.com/chipsec/chipsec',
    download_url='https://github.com/chipsec/chipsec',
    license='GNU General Public License v2 (GPLv2)',
    platforms=['any'],
    long_description=long_description(),

    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
        'Natural Language :: English',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX :: Linux',
        'Operating System :: MacOS :: MacOS X',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Topic :: Security',
        'Topic :: System :: Hardware'
    ],

    data_files=data_files,
    packages=find_packages(exclude=['tests.*', 'tests']),
    package_data=package_data,
    install_requires=install_requires,

    py_modules=['chipsec_main', 'chipsec_util'],
    entry_points={
        'console_scripts': [
            'chipsec_util=chipsec_util:main',
            'chipsec_main=chipsec_main:main',
        ],
    },
    test_suite='tests',
    cmdclass={
        'install': install,
        'build': build,
        'build_ext': build_ext,
        'sdist': sdist,
    },
    ext_modules=extra_kw
)
