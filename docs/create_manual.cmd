@echo off
if "%1" == "" goto usage
set TARGET=%1

echo "************************ BUILDING DOCUMENTATION ******************************"
echo "** Target: %TARGET%
echo "******************************************************************************"

set PYTHONPATH=%TARGET%

pushd %TARGET%
call python chipsec_main.py -h > %TARGET%\docs\sphinx\options.rst
popd

pushd %TARGET%\docs\sphinx
:: Update options.rst to make it a preformatted block
call python options.py

call sphinx-apidoc -e -f -T -o modules %TARGET%
call python removeStrRst.py

:: Clean up files that we do not want to process into documenation
del .\modules\chipsec_tools.*
del .\modules\tests.*
del .\modules\setup.rst
del .\modules\chipsec.rst
del .\modules\chipsec.cfg.common.rst
del .\modules\chipsec.chipset.rst
del .\modules\chipsec.command.rst
del .\modules\chipsec.defines.rst
del .\modules\chipsec.file.rst
del .\modules\chipsec.logger.rst
del .\modules\chipsec.module.rst
del .\modules\chipsec.module_common.rst
del .\modules\chipsec.result_deltas.rst
del .\modules\chipsec.testcase.rst
del .\modules\chipsec_main.rst
del .\modules\chipsec_util.rst

:: create chipsec-manual.pdf
call sphinx-build -b pdf -D pdf_stylesheets=sstylesheet . %TARGET%
popd

:: remove sphinx folder
pushd %TARGET%
rmdir /s /q %TARGET%\.doctrees
popd

goto end

:usage
echo Usage: create_manual.cmd [CHIPSEC_PATH]

:end