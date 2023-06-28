@REM CHIPSEC: Platform Security Assessment Framework
@REM Copyright (c) 2019, Intel Corporation

@REM This program is free software; you can redistribute it and/or
@REM modify it under the terms of the GNU General Public License
@REM as published by the Free Software Foundation; Version 2.

@REM This program is distributed in the hope that it will be useful,
@REM but WITHOUT ANY WARRANTY; without even the implied warranty of
@REM MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
@REM GNU General Public License for more details.

@REM You should have received a copy of the GNU General Public License
@REM along with this program; if not, write to the Free Software
@REM Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

@REM Contact information:
@REM chipsec@intel.com

@REM This file incorporates work covered by the following copyright and permission notice

@REM @file
@REM   Windows batch file to find the Visual Studio set up script
@REM
@REM Copyright (c) 2013-2014, ARM Limited. All rights reserved.

@REM SPDX-License-Identifier: BSD-2-Clause-Patent
@REM

@echo off
@REM Check input for variable 32 if it exists build x86
:setup32
if not [%1] == ["32"] goto :setup64
set CHIPSEC_BUILD="32"
goto :main

:setup64
set CHIPSEC_BUILD="64"
goto :main

@REM loop through output of vswhere for VS install paths
:set_vsvars
for /f "usebackq tokens=1* delims=: " %%i in (`%*`) do (
  if /i "%%i"=="installationPath" (
    if %CHIPSEC_BUILD% == "64" (
      call "%%j\VC\Auxiliary\Build\vcvars64.bat"
      goto :donesetup
    )
    if %CHIPSEC_BUILD% == "32" (
      call "%%j\VC\Auxiliary\Build\vcvars32.bat"
      goto :donesetup
    )
  )
)
goto :donesetup

@REM Call vcvars bat file to get build tools for x86 or x64 build
:callbat
 if %CHIPSEC_BUILD% == "32" call "%TEMP%\VC\Auxiliary\Build\vcvars32.bat"
goto :donesetup

@REM NOTE: This file will find the most recent Visual Studio installation
@REM       and attempt to build CHIPSEC. Build will be based upon
@REM       processor architecture.
@REM       To use an older version, modify your environment set up.
@REM       (Or invoke the relevant vsvars32 file beforehand).

:main
@REM VCINSTALLDIR indicates a developer environment
if defined VCINSTALLDIR goto :donesetup
@REM search for VS installations
  if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"  call :set_vsvars "%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
  if exist "%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"       call :set_vsvars "%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"
goto :finish

:donesetup
if %CHIPSEC_BUILD% == "0" goto :finish

:newbuild
if %CHIPSEC_BUILD% == "64" call msbuild /t:Build /p:Configuration=Debug /p:Platform=x64 pcifilter.vcxproj
if %CHIPSEC_BUILD% == "32" call msbuild /t:Build /p:Configuration=Debug /p:Platform=x86 pcifilter.vcxproj
set CHIPSEC_BUILD="0"
goto :finish

:finish
