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

1. Extract the contents of ``__install__/UEFI/chipsec_uefi_[x64|i586|IA32].zip`` to the USB drive, as appropriate.

   -  This will create a /efi/Tools directory with Python.efi and /efi/StdLib with subdirectories for dependencies.

2. Copy the contents of CHIPSEC to the USB drive.

   -  The contents of your drive should look like follows:

::

      -  fs0:
         -  efi
            -  boot
               -  bootx64.efi
            -  StdLib
               -  lib
                  -  python.27
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

   Next follow steps in section "Basic Usage" of :ref:`Running CHIPSEC <Running-Chipsec>`
