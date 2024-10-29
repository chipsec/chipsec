#!/usr/bin/env python3
# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2023, Intel Corporation
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
Script to automatically generate CHIPSEC's documentation using Sphinx.
It generates PDF plus either HTML or JSON formats.

Usage:
    ``python3 create_manual.py [format]``

    ``format`` - html or json

Examples:
    >>> python3 create_manual.py
    >>> python3 create_manual.py html
    >>> python3 create_manual.py json

References:
https://www.sphinx-doc.org/en/master/man/sphinx-apidoc.html
https://www.sphinx-doc.org/en/master/man/sphinx-build.html
https://www.sphinx-doc.org/en/master/usage/extensions/autodoc.html
"""

import os
try:
    from collections.abc import Sequence
except ImportError:
    from typing import Sequence
    print('!! Unable to import collections.abc !!')
import shutil
import sys

DOCS_DIR = os.getcwd()
RM_DIR = os.path.join(DOCS_DIR, '_remove')
SPHINX_DIR = os.path.join(DOCS_DIR, 'sphinx')
SPHINX_MOD_DIR = os.path.join(SPHINX_DIR, 'modules')
SPHINX_SCRIPTS_DIR = os.path.join(SPHINX_DIR, '_scripts')
CHIPSEC_DIR = os.path.normpath(DOCS_DIR + os.sep + os.pardir)


def RunAutoDoc() -> None:
    try:
        os.system(f'sphinx-apidoc -e -f -T -d 10 -o modules {CHIPSEC_DIR} {os.path.join(CHIPSEC_DIR, "*test*")} {os.path.join(CHIPSEC_DIR, "*exceptions*")} {os.path.join(CHIPSEC_DIR, "*tool*")}')
    except Exception:
        print('Unable to run sphinx-apidoc')
        raise


def CleanupFilesNotWantedInDoc() -> None:
    NotWantedFilesList = []
    for file in os.listdir(RM_DIR):
        with open(os.path.join(RM_DIR, file), 'r') as f:
            NotWantedFilesList = f.read()
        for not_needed_file in NotWantedFilesList.split(','):
            RemoveFile(not_needed_file)


def RemoveFile(file):
    try:
        os.remove(os.path.join(SPHINX_MOD_DIR, file))
    except Exception:
        print(f'\t\tUnable to remove {file}!!!')


def RunScripts() -> None:
    for script in os.listdir(os.path.join(SPHINX_SCRIPTS_DIR)):
        try:
            os.system(f'python3 {os.path.join(SPHINX_SCRIPTS_DIR, script)}')
        except Exception:
            print(f'Unable to run script: {script}')
            raise


def GeneratePDF() -> None:
    try:
        os.system(f'sphinx-build -b pdf -T {SPHINX_DIR} {CHIPSEC_DIR}')
    except Exception:
        print('Unable to generate PDF')
        raise


def GenerateHTML() -> None:
    try:
        os.system(f'sphinx-build -b html -T {SPHINX_DIR} {os.path.join(CHIPSEC_DIR, "manual")}')
    except Exception:
        print('Unable to generate HTML')
        raise


def GenerateJSON() -> None:
    try:
        os.system(f'sphinx-build -b json -T {SPHINX_DIR} {os.path.join(CHIPSEC_DIR, "manualJson")}')
    except Exception:
        print('Unable to generate JSON')
        raise


format_options_functions = {
    'html': GenerateHTML,
    'json': GenerateJSON
}


def GenerateHTMLorJSON(option: str) -> None:
    try:
        format_options_functions[option]()
    except Exception:
        print('Invalid format option')
        raise


def DeleteSphinxCollateral() -> None:
    shutil.rmtree(os.path.join(CHIPSEC_DIR, '.doctrees'))
    shutil.rmtree(os.path.join(SPHINX_DIR, 'logs'))
    shutil.rmtree(SPHINX_MOD_DIR)


def main(argv: Sequence[str] = sys.argv[1:]):
    print('******************** BUILDING DOCUMENTATION **************************')
    os.chdir(SPHINX_DIR)
    try:
        RunAutoDoc()
        CleanupFilesNotWantedInDoc()
        RunScripts()
        if (len(argv)==1):
            GenerateHTMLorJSON(argv[0])
        GeneratePDF()
        DeleteSphinxCollateral()
    except Exception:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
