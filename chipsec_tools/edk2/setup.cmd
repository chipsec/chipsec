@echo off
REM set custom paths for NASM, IASL, and PYTHON
REM set NASM_PREFIX=c:\nasm
REM set IASL=c:\ASL
REM set PYTHON_HOME=c:\Python
set BUILD_TOOLS=FALSE
set UPDATE_EDK2=FALSE

REM Set basic environment variables so edksetup.bat has all the data it needs
set WORKSPACE=%CD%
set CONF_PATH=%WORKSPACE%\Conf
set PACKAGES_PATH=%WORKSPACE%\edk2;%WORKSPACE%\edk2-libc
set EDK_TOOLS_PATH=%WORKSPACE%\edk2\BaseTools

REM Determine if edk has been downloaded
if not exist %WORKSPACE%\edk2 (
    echo Downloading EDK2 Source
    git clone https://github.com/tianocore/edk2
    echo Updating EDK2 Source
    cd edk2
    git submodule update --init
    git submodule foreach git reset --hard
    cd ..
)
if not exist %WORKSPACE%\edk2-libc (
    echo Downloading EDK2 libc Source
    git clone https://github.com/tianocore/edk2-libc
)

REM Determine additional setup tasks that may need to be preformed
if not exist %WORKSPACE%\edk2\BaseTools\Bin\Win32 set BUILD_TOOLS=TRUE
if not exist %WORKSPACE%\edk2\edksetup.bat (
    set BUILD_TOOLS=TRUE
)

REM Make sure all the required directories are created
if not exist %CONF_PATH% mkdir %CONF_PATH%


REM Setup the build environment
if "%BUILD_TOOLS%"=="TRUE" (
    echo Rebuilding basetools
    call %WORKSPACE%\edk2\edksetup.bat Rebuild
) else (
    echo Setting up basetools
    call %WORKSPACE%\edk2\edksetup.bat
)

REM Patch edk2-libc
cd edk2-libc
echo Applying patch to edk2-libc
git checkout -b chipsec_patch
git apply ..\libc-chipsec.patch
copy ..\PythonEFI\edk2module.c AppPkg\Applications\Python\Efi
cd ..

REM Build
echo Building Python File
build -p edk2-libc\AppPkg\AppPkg.dsc -a X64 -t VS2019 -b DEBUG
REM build -p edk2-libc\AppPkg\AppPkg.dsc -a IA32 -t VS2019 -b DEBUG
echo If no errors occured python.efi will be in the Build directory
