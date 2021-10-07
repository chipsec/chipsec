#!/bin/bash

TARGET=$(readlink -f $(dirname $0)/..)

echo "************************ BUILDING DOCUMENTATION ******************************"

pushd $TARGET/docs/sphinx

sphinx-apidoc -e -f -T -o modules -d 99 $TARGET
python _scripts/removeStrRst.py
python _scripts/getVersion.py

# Clean up files that we do not want to process into documentation
rm ./modules/chipsec_tools.*
rm ./modules/tests.*
rm ./modules/setup.rst
rm ./modules/chipsec.rst
rm ./modules/chipsec.cfg.rst
rm ./modules/chipsec.chipset.rst
rm ./modules/chipsec.command.rst
rm ./modules/chipsec.defines.rst
rm ./modules/chipsec.exceptions.rst
rm ./modules/chipsec.file.rst
rm ./modules/chipsec.logger.rst
rm ./modules/chipsec.module.rst
rm ./modules/chipsec.module_common.rst
rm ./modules/chipsec.result_rmtas.rst
rm ./modules/chipsec.testcase.rst
rm ./modules/chipsec_main.rst
rm ./modules/chipsec_util.rst

# create chipsec-manual.pdf or html manual
if [[ "$1" == "pdf" ]]; then 
    sphinx-build -b pdf -T . $TARGET
elif [[ "$1" == "html" ]]; then
    sphinx-build -b html -T . $TARGET/manual
elif [[ "$1" == "json" ]]; then
    sphinx-build -b json -T . $TARGET/manualJson
# create chipsec-manual.pdf and html pages
else
    sphinx-build -b pdf -T . $TARGET
    sphinx-build -b html -T . $TARGET/manual
    sphinx-build -b json -T . $TARGET/manualJson
fi
popd

# remove sphinx folders
pushd $TARGET
rm -r $TARGET/.doctrees
rm -r $TARGET/docs/sphinx/logs
rm -r $TARGET/docs/sphinx/modules
popd

exit 0