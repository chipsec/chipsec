.. toctree::

UEFI Shell Installation
=======================

Installing CHIPSEC for UEFI Shell
---------------------------------

1. Extract contents of ``__install__/UEFI/chipsec_uefi_<arch>.zip`` to the EFI drive which can be either USB flash drive (e.g. DUET USB drive) or HDD/SSD hard drive (e.g. EFI System Partition). ``<arch>`` should correspond to your UEFI shell and can be ``x64``, ``ia32`` or ``i586``. This will create ``/efi/Tools`` directory with ``Python.efi`` and ``/efi/StdLib`` with subdirectories

2. Copy contents of CHIPSEC anywhere on the EFI drive (for example, to ``chipsec`` directory in root). The contents of your drive should look like follows:

   ::

    \
        efi\
            boot\
                bootx64.efi
            StdLib\	
                lib\
                    python.27\
                        [lots of python files and directories]
            Tools\
                Python.efi
        chipsec\
            chipsec\
            chipsec_main.py
            chipsec_util.py
            ...
	

   .. note:: The EFI drive should already include a UEFI Shell binary in ``/efi/boot``. On 64-bit platforms the shell will likely be named ``bootx64.efi``

3. Run your UEFI shell

    - If UEFI shell is on the USB removable drive, you'll need to boot off of the USB drive (rebooting will load UEFI shell).
    - If your UEFI firmware allows booting from any file, choose to boot from your UEFI shell binary from the UEFI firmware setup options
    - Some systems have embedded UEFI shell which can be booted from setup options

4. Run CHIPSEC in UEFI shell
    
    1. ``fs0:``
    2. ``python chipsec_main.py`` or ``python chipsec_util.py``


(OPTIONAL) Extending CHIPSEC functionality for UEFI
---------------------------------------------------

Skip this section if you don't plan on extending native UEFI functionality for CHIPSEC. 

Native functions accessing HW resources are built directly into Python UEFI port in built-in edk2 module. If you want to add more native functionality to Python UEFI port for chipsec, you'll need to re-build Python for UEFI:

1. Check out `AppPkg with Python 2.7.2 <http://edk2.svn.sourceforge.net/svnroot/edk2/trunk/edk2>`_ port for UEFI from SVN

    - You'll also need to check out ``StdLib`` and ``StdLibPrivateInternalFiles`` packages from SVN
    - Alternatively download latest EADK (`EDK II Application Development Kit <http://sourceforge.net/apps/mediawiki/tianocore/index.php?title=EDKII_EADK>`_). EADK includes ``AppPkg/StdLib/StdLibPrivateInternalFiles``. Unfortunately, EADK Alpha 2 doesn't have Python 2.7.2 port so you'll need to check it out SVN.

2. Add functionality to Python port for UEFI

    - Python 2.7.2 port for UEFI is in ``<UDK>\AppPkg\Applications\Python``
    - All chipsec related functions are in ``<UDK>\AppPkg\Applications\Python\Efi\edk2module.c`` (``#ifdef CHIPSEC``)
    - Asm functions are in ``<UDK>\AppPkg\Applications\Python\Efi\cpu.asm`` e.g. ``<UDK>`` is ``C:\UDK2010.SR1``
    - Add cpu.asm under the Efi section in ``PythonCore.inf``

3. Build ``<UDK>/AppPkg`` with Python

    - Read instructions in ``<UDK>\AppPkg\ReadMe.txt`` and ``<UDK>\AppPkg\Applications\Python\PythonReadMe.txt``
    - Binaries of AppPkg and Python will be in ``<UDK>\Build\AppPkg\DEBUG_MYTOOLS\X64\``

4. Create directories and copy Python files on DUET USB drive

    - Read instructions in ``<UDK>\AppPkg\Applications\Python\PythonReadMe.txt``

(OPTIONAL) Building bootable USB thumb drive with UEFI Shell
------------------------------------------------------------

You can build bootable USB drive with UEFI shell using EDK DUET environment:

1. `Download UDK from Tianocore <http://sourceforge.net/apps/mediawiki/tianocore/index.php?title=UDK2010>`_ (Tested with ``UDK2010.SR1``)
2. Follow instructions in ``DuetPkg/ReadMe.txt`` to create a bootable USB thumb drive with UEFI Shell (DUET)
