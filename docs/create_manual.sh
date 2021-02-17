#!/bin/bash

if [$1 == ""]; then 
    echo "Usage: create_manual.cmd [CHIPSEC_PATH] [type] type - pdf, html or empty (both)"
    exit 0; fi
TARGET="$1"

echo "************************ BUILDING DOCUMENTATION ******************************"

pushd $TARGET/docs/sphinx

sphinx-apidoc -e -f -T -o modules -d 99 $TARGET
python removeStrRst.py

# Clean up files that we do not want to process into documenation
rm ./modules/chipsec_tools.*
rm ./modules/tests.*
rm ./modules/setup.rst
rm ./modules/chipsec.rst
rm ./modules/chipsec.cfg.rst
rm ./modules/chipsec.chipset.rst
rm ./modules/chipsec.command.rst
rm ./modules/chipsec.defines.rst
rm ./modules/chipsec.file.rst
rm ./modules/chipsec.logger.rst
rm ./modules/chipsec.module.rst
rm ./modules/chipsec.module_common.rst
rm ./modules/chipsec.result_rmtas.rst
rm ./modules/chipsec.testcase.rst
rm ./modules/chipsec_main.rst
rm ./modules/chipsec_util.rst

# create chipsec-manual.pdf or html manual
if [[ "$2" == "pdf" ]]; then 
    sphinx-build -b pdf -T . $TARGET
elif [[ "$2" == "html" ]]; then
    sphinx-build -b html -T . $TARGET/manual
    touch $TARGET/manual/.nojekyll
# create chipsec-manual.pdf and html pages
else
    sphinx-build -b pdf -T . $TARGET
    sphinx-build -b html -T . $TARGET/manual
    touch $TARGET/manual/.nojekyll; 
fi
popd

# remove sphinx folder
pushd $TARGET
rm -r $TARGET/.doctrees
popd

exit 0