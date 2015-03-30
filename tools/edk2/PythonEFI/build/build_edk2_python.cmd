@echo off

set edk2=%1
set arch=%2
if "%edk2%"=="" goto usage
if "%arch%"=="" goto usage
goto continue

:usage
echo.
echo.
echo.
echo Build Python from EDK2. 
echo.
echo Usage: %0 {edk2_path} {arch}
echo.
echo    edk2_path = path for where edk2 is checked out
echo                usually checked out from  
echo                https://svn.code.sf.net/p/edk2/code/trunk/edk2
echo.
echo    arch       = one of X64, IA32, i586
echo.
echo.
echo.

goto :eof

:continue
@call %edk2%\edksetup.bat
@call %WORKSPACE%\DuetPkg\GetVariables.bat
set OUT_FOLDER=chipsec_uefi_%ARCH%
build -a %arch% -p AppPkg\AppPkg.dsc
set ec=%errorlevel%
if "%ec%"=="0" goto build_ok
goto all_done


:build_ok
@echo %WORKSPACE%\Build\AppPkg\%TARGET%_%TOOL_CHAIN_TAG%\%ARCH%\Python.efi
mkdir %OUT_FOLDER%\efi\Tools
xcopy %WORKSPACE%\Build\AppPkg\%TARGET%_%TOOL_CHAIN_TAG%\%ARCH%\Python.efi %OUT_FOLDER%\efi\Tools\ /y
mkdir %OUT_FOLDER%\efi\StdLib\lib\python.27
xcopy %WORKSPACE%\AppPkg\Applications\Python\Python-2.7.2\Lib\*    %OUT_FOLDER%\efi\StdLib\lib\python.27\      /Y /S /I


:all_done
exit /b %ec%




