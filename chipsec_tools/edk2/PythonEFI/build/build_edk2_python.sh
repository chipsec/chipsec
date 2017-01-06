#!/bin/bash
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2016, Intel Corporation
#
#This program is free software; you can redistribute it and/or
#modify it under the terms of the GNU General Public License
#as published by the Free Software Foundation; Version 2.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with this program; if not, write to the Free Software
#Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
#Contact information:
#chipsec@intel.com
#

echo $#
if [ "$1" = "" ] || [ "$2" = "" ] 
then
	echo
	echo
	echo
	echo Build Python from EDK2. 
	echo
	echo Usage: $0 {edk2_path} {arch}
	echo
	echo    edk2_path = path for where edk2 is checked out
	echo                usually checked out from  
	echo                https://svn.code.sf.net/p/edk2/code/trunk/edk2
	echo
	echo    arch       = one of X64, IA32, i586
	echo
	echo
	echo
else

	edk2=$1
	arch=$2
	
	case $arch in
      X64)
        ARCH=X64
        ;;
      IA32)
        ARCH=IA32
        ;;
      i586)
        ARCH=IA32
        ;;
      *)
		echo "Unsupported architecture \'$arch\'"
		exit 1
        ;;
    esac
	
	pushd $edk2
	. $edk2/BaseTools/BuildEnv 
	gcc_version=$(gcc -v 2>&1 | tail -1 | awk '{print $3}')
    case $gcc_version in
      4.5.*)
        TARGET_TOOLS=GCC45
        ;;
      4.6.*)
        TARGET_TOOLS=GCC46
        ;;
      4.7.*)
        TARGET_TOOLS=GCC47
        ;;
      4.8.*)
        TARGET_TOOLS=GCC48
        ;;
      4.9.*|4.1[0-9].*)
        TARGET_TOOLS=GCC49
        ;;
      *)
        TARGET_TOOLS=GCC44
        ;;
    esac
	#. edksetup.sh 
	echo "====================== $arch "
	#source $WORKSPACE/DuetPkg/GetVariables.bat
	OUT_FOLDER=chipsec_uefi_$arch
	build cleanall -a $ARCH -p AppPkg/AppPkg.dsc
	make -C BaseTools/Source/C
	build -a $ARCH -p AppPkg/AppPkg.dsc
	status=$?
	if [ $status -ne 0 ]; then
		echo "error with build: $status" >&2
		popd
		exit $status
	fi
	popd
	echo $WORKSPACE/Build/AppPkg/DEBUG_$TARGET_TOOLS/$ARCH/Python.efi
	echo "====================== $OUT_FOLDER "
	mkdir -p -v ./$OUT_FOLDER/efi/Tools
	cp -r -v $WORKSPACE/Build/AppPkg/DEBUG_$TARGET_TOOLS/$ARCH/Python.efi $OUT_FOLDER/efi/Tools/ 
	mkdir -p -v ./$OUT_FOLDER/efi/StdLib/lib/python.27
	cp -r -v $WORKSPACE/AppPkg/Applications/Python/Python-2.7.2/Lib/*    $OUT_FOLDER/efi/StdLib/lib/python.27/
	find $WORKSPACE/ -name .svn -exec rm -rf {} \;

	echo "====================== $OUT_FOLDER "
	
	
fi





