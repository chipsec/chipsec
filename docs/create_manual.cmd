rem @echo off
set TARGET=%1

echo "************************ BUILDING DOCUMENTATION ******************************"
echo "** Target: %TARGET%
echo "******************************************************************************"

set PYTHONPATH=%TARGET%

pushd %TARGET%
call python chipsec_main.py -h > %TARGET%\sphinx\options.rst
popd

pushd %TARGET%\sphinx

call sphinx-apidoc -e -f -T -o modules ..
call python removeStrRst.py

:: create chipsec-manual.pdf
call sphinx-build -b pdf -D pdf_stylesheets=sstylesheet . ..

:: remove sphinx folder
pushd %TARGET%
rmdir /s /q %TARGET%\.doctrees
popd