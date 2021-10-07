@echo off

for %%I in ("%~dp0\..") do set "TARGET=%%~fI"

echo "************************ BUILDING DOCUMENTATION ******************************"

pushd %TARGET%\docs\sphinx

call sphinx-apidoc -e -f -T -o modules -d 99 %TARGET%
call python _scripts\removeStrRst.py
call python _scripts\getVersion.py

:: Clean up files that we do not want to process into documenation
del .\modules\chipsec_tools.*
del .\modules\tests.*
del .\modules\setup.rst
del .\modules\chipsec.rst
del .\modules\chipsec.cfg.rst
del .\modules\chipsec.chipset.rst
del .\modules\chipsec.command.rst
del .\modules\chipsec.defines.rst
del .\modules\chipsec.exceptions.rst
del .\modules\chipsec.file.rst
del .\modules\chipsec.logger.rst
del .\modules\chipsec.module.rst
del .\modules\chipsec.module_common.rst
del .\modules\chipsec.result_deltas.rst
del .\modules\chipsec.testcase.rst
del .\modules\chipsec_main.rst
del .\modules\chipsec_util.rst

:: create chipsec-manual.pdf
if "%1" == "pdf" call sphinx-build -b pdf -T . %TARGET%
:: create html pages
if "%1" == "html" call sphinx-build -b html -T . %TARGET%\manual
:: create json pages
if "%1" == "json" call sphinx-build -b json -T . %TARGET%\manualJson
:: create chipsec-manual.pdf and html/json pages
if "%1" == "" (
call sphinx-build -b pdf -T . %TARGET%
call sphinx-build -b html -T . %TARGET%\manual
call sphinx-build -b json -T . %TARGET%\manualJson
)
popd

:: remove sphinx folder
pushd %TARGET%
rmdir /s /q %TARGET%\.doctrees
rmdir /s /q %TARGET%\docs\sphinx\logs
rmdir /s /q %TARGET%\docs\sphinx\modules
popd

goto end

:usage
echo Usage: create_manual.cmd [CHIPSEC_PATH] [type] type - pdf, html or empty (both)

:end