@REM # Copyright (c) 2019, Intel Corporation
@REM # 
@REM #This program is free software; you can redistribute it and/or
@REM #modify it under the terms of the GNU General Public License
@REM #as published by the Free Software Foundation; Version 2.
@REM #
@REM #This program is distributed in the hope that it will be useful,
@REM #but WITHOUT ANY WARRANTY; without even the implied warranty of
@REM #MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
@REM #GNU General Public License for more details.
@REM #
@REM #You should have received a copy of the GNU General Public License
@REM #along with this program; if not, write to the Free Software
@REM #Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
@REM #
@REM #Contact information:
@REM #chipsec@intel.com

goto :main

:set_buildvars
@echo Building compression
@echo off
@REM # Need to set EDK_TOOLS_PATH and BASE_TOOLS_PATH to current directory
set EDK_TOOLS_PATH=%CD%
set BASE_TOOLS_PATH=%CD%

@REM # Now call make and build the compression tools
call nmake -c

goto :end

@REM # Need to find Visual Studio
:main
call get_vsvars.bat

if defined VCINSTALLDIR goto :set_buildvars
    @echo.
    @echo !!! ERROR !!!! Cannot find Visual Studio.
    @echo Please download compression tools from https://github.com/tianocore/edk2-BaseTools-win32/archive/master.zip
    @echo Unzip the archive into the chipsec_tools/compression/bin directory
    @echo.
    goto end

:end