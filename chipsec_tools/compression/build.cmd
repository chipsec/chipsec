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

@REM # Need to set EDK_TOOLS_PATH and BASE_TOOLS_PATH to current directory and HOST_ARCH
if not defined EDK_TOOLS_PATH (
    set EDK_TOOLS_PATH=%CD%
)
if not defined BASE_TOOLS_PATH (
    set BASE_TOOLS_PATH=%CD%
)

set HOST_ARCH=IA32
if %PROCESSOR_ARCHITECTURE% == AMD64(
    set HOST_ARCH=X64
)

@REM # Now call make and build the compression tools
nmake -c


