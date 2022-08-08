Windows Installation
====================

| CHIPSEC supports the following versions:
| Windows 8, 8.1, 10, 11 - x86 and AMD64
| Windows Server 2012, 2016, 2019, 2022 - x86 and AMD64

.. note::

   CHIPSEC has removed support for the RWEverything (https://rweverything.com/) driver due to PCI configuration space access issues.

Install CHIPSEC Dependencies
----------------------------

Python 3.7 or higher (https://www.python.org/downloads/)

.. note::

   CHIPSEC has deprecated support for Python2 since June 2020 

To install requirements: 

   `pip install -r windows_requirements.txt`

which includes:

   * `pywin32 <https://pypi.org/project/pywin32/#files>`_: for Windows API support (`pip install pywin32`)
   * `setuptools <https://pypi.org/project/setuptools/>`_ (`pip install setuptools`)
   * `WConio2 <https://pypi.org/project/WConio2/>`_: Optional. For colored console output (`pip install Wconio2`)

To compile the driver:

   `Visual Studio and WDK <https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk>`_: for building the driver. 
   
   For best results use the latest available (**VS2022 + SDK/WDK 11** or **VS2019 + SDK/WDK 10 or 11**)
   
   .. note::

      Make sure to install compatible VS/SDK/WDK versions and the spectre mitigation packages


To clone the repo:

   `git <https://git-scm.com/>`_: open source distributed version control system

Building
--------

Clone CHIPSEC source

   ``git clone https://github.com/chipsec/chipsec.git``

Build the Driver and Compression Tools
   
   ``python setup.py build_ext -i``

.. note::

   If build errors are with signing are encountered, try running as Administrator
   The .vcxproj file points to the latest SDK, if this is incompatible with the WDK, change the configuration to a compatible SDK within the project properties

Turn off kernel driver signature checks
---------------------------------------

**Enable boot menu**

In CMD shell:
   
   ``bcdedit /set {bootmgr} displaybootmenu yes``

**With Secure Boot enabled:**

Method 1:

   - In CMD shell: ``shutdown /r /t 0 /o`` or Start button -> Power icon -> SHIFT key + Restart
   - Navigate: Troubleshooting -> Advanced Settings -> Startup Settings -> Reboot 
   - After reset choose F7 or 7 “Disable driver signature checks”

Method 2: 

   - Disable Secure Boot in the BIOS setup screen then disable driver signature checks as with Secure Boot disabled

**With Secure Boot disabled:**

Method 1: 

   - Boot in Test mode (allows self-signed certificates)
      - Start CMD.EXE as Adminstrator ``BcdEdit /set TESTSIGNING ON`` 
      - Reboot
      - If this doesn’t work, run these additional commands:
         - ``BcdEdit /set noIntegrityChecks ON``
         - ``BcdEdit /set loadoptions DDISABLE_INTEGRITY_CHECKS``

Method 2: 

   - Press F8 when booting Windows and choose “No driver signatures enforcement” option to turn off driver signature checks

Alternate Build Methods
-----------------------

**Build CHIPSEC kernel driver with Visual Studio**

Method 1:

   - Open the Visual Studio project file (drivers/win7/chipsec_hlpr.vcxproj) using Visual Studio
   - Select Platform and configuration (X86 or x64, Release)
   - Go to Build -> Build Solution

Method 2:

   - Open a VS developer command prompt
   - ``> cd <CHIPSEC_ROOT_DIR>\drivers\win7``
   - Build driver using msbuild command:
      - ``> msbuild /p:Platform=x64``
      or
      - ``> msbuild /p:Platform=x32``

If build process is completed without any errors, the driver binary will be moved into the chipsec helper directory: 
   
   ``<CHIPSEC_ROOT_DIR>\chipsec\helper\win\win7_amd64 (or i386)``

**Build the compression tools**

Method 1:

   - Navigate to the chipsec_tools\compression directory   
   - run the build.cmd

Method 2:

   - Download compression tools from https://github.com/tianocore/edk2-BaseTools-win32/archive/master.zip   
   - Unzip the archive into the chipsec_tools/compression/bin directory

**Alternate Method to load CHIPSEC service/driver**

To create and start CHIPSEC service

   ``sc create chipsec binpath="<PATH_TO_SYS>" type= kernel DisplayName="Chipsec driver"``
   ``sc start chipsec``

When finished running CHIPSEC stop/delete service:

   ``sc stop chipsec``
   ``sc delete chipsec``
