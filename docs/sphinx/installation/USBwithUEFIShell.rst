Building a Bootable USB drive with UEFI Shell (x64)
===================================================

1. Format your media as FAT32
2. Create the following directory structure in the root of the new media

   -  ``/efi/boot``

3. Download the UEFI Shell (Shell.efi) from the following link

   -  https://github.com/tianocore/edk2/blob/UDK2018/ShellBinPkg/UefiShell/X64/Shell.efi

4. Rename the UEFI shell file to Bootx64.efi
5. Copy the UEFI shell (now Bootx64.efi) to the /efi/boot directory

Installing CHIPSEC
------------------

1. Extract the contents of ``__install__/UEFI/chipsec_py368_uefi_x64.zip`` to the USB drive, as appropriate.

   -  This will create a /efi/Tools directory with Python.efi and /efi/StdLib with subdirectories for dependencies.

2. Copy the contents of CHIPSEC to the USB drive.

   The contents of your drive should look like follows::

      -  fs0:
         -  efi
            -  boot
               -  bootx64.efi (optional)
            -  StdLib
               -  lib
                  -  python36.8
                     -  [lots of python files and directories]
            -  Tools
               -  Python.efi
         -  chipsec
            -  chipsec
               -  …
            -  chipsec_main.py
            -  chipsec_util.py
            -  …


3. Reboot to the USB drive (this will boot to UEFI shell).

   -  You may need to enable booting from USB in BIOS setup.
   -  You will need to disable UEFI Secure Boot to boot to the UEFI Shell.

Run CHIPSEC in UEFI Shell
-------------------------

   ``fs0:``

   ``cd chipsec``

   ``python.efi chipsec_main.py`` or ``python.efi chipsec_util.py``

   Next follow steps in section "Basic Usage" of :ref:`Running CHIPSEC <Running-Chipsec>`

Building UEFI Python 3.6.8 (optional)
-------------------------------------

#. Start with `Py368Readme.txt <https://github.com/tianocore/edk2-libc/blob/master/AppPkg/Applications/Python/Python-3.6.8/Py368ReadMe.txt>`_

    - Latest EDK2, visit `Tianocore EDK2 Github <https://github.com/tianocore/edk2>`_  (Make sure to update submodules)
    - Latest EDK2-LIBC, visit `Tianocore EDK2-LIBC Github <https://github.com/tianocore/edk2-libc>`_
    - Follow setup steps described in the ``Py368Readme.txt``

#. Make modifications as needed

    - CPython / C file(s):

      - `edk2module.c <https://github.com/tianocore/edk2-libc/blob/master/AppPkg/Applications/Python/Python-3.6.8/PyMod-3.6.8/Modules/edk2module.c>`_

    - ASM file(s):

      - `cpu.nasm <https://github.com/tianocore/edk2-libc/blob/master/AppPkg/Applications/Python/Python-3.6.8/PyMod-3.6.8/Modules/cpu.nasm>`_
      - `cpu_ia32.nasm <https://github.com/tianocore/edk2-libc/blob/master/AppPkg/Applications/Python/Python-3.6.8/PyMod-3.6.8/Modules/cpu_ia32.nasm>`_
      - `cpu_gcc.s <https://github.com/tianocore/edk2-libc/blob/master/AppPkg/Applications/Python/Python-3.6.8/PyMod-3.6.8/Modules/cpu_gcc.s>`_
      - `cpu_ia32_gcc.s <https://github.com/tianocore/edk2-libc/blob/master/AppPkg/Applications/Python/Python-3.6.8/PyMod-3.6.8/Modules/cpu_ia32_gcc.s>`_

    - INF file(s):

      - `Python368.inf <https://github.com/tianocore/edk2-libc/blob/master/AppPkg/Applications/Python/Python-3.6.8/Python368.inf>`_

#. Build and directory creation steps are covered in the `Py368Readme.txt <https://github.com/tianocore/edk2-libc/blob/master/AppPkg/Applications/Python/Python-3.6.8/Py368ReadMe.txt>`_

    - MSVS build tools are highly recommended
