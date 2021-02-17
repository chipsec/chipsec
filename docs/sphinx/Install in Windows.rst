Windows Installation
====================

| CHIPSEC supports the following versions:
| Windows 7, 8, 8.1, 10 x86 and AMD64
| Windows Server 2008, 2012, 2016 x86 and AMD64

.. note::

   CHIPSEC has removed support for the RWEverything (https://rweverything.com/) driver due to PCI configuration space access issues.

Install CHIPSEC Dependencies
----------------------------

Python 3.7 or higher (https://www.python.org/downloads/)

.. note::

   CHIPSEC has deprecated support for Python2 since June 2020 

`pywin32 <https://pypi.org/project/pywin32/#files>`_: for Windows API support

   ``pip install pywin32``

`setuptools <https://pypi.org/project/setuptools/>`_

   `pip install setuptools`

`WConio <http://newcenturycomputers.net/projects/wconio.html>`_: Optional. For colored console output

`Visual Studio and WDK <https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk>`_: for building the driver

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

**Windows 10 64-bit**

In CMD shell:
   
   ``bcdedit /set {bootmgr} displaybootmenu yes``

**Windows 10 64-bit / Windows 8, 8.1 64-bit (with Secure Boot enabled) / Windows Server 2016 64-bit / Windows Server 2012 64-bit (with Secure Boot enabled):**

Method 1: - In CMD shell:

   - ``shutdown /r /t 0 /o``
   - Navigate: Troubleshooting > Advanced Settings > Startup Settings > Reboot 
   - After reset choose F7 “Disable driver signature checks”

Method 2: 

   - Disable Secure Boot in the BIOS setup screen then disable driver signature checks as in Windows 8 with Secure Boot disabled

**Windows 7 64-bit / Windows Server 2008 64-bit / Windows 8 (with Secure Boot disabled) / Windows Server 2012 (with Secure Boot disabled)):**

Method 1: 

   - Boot in Test mode (allows self-signed certificates) \
      - Start CMD.EXE as Adminstrator ``BcdEdit /set TESTSIGNING ON`` 
      - Reboot
      - If this doesn’t work, run these additional commands:
         ``BcdEdit /set noIntegrityChecks ON``
         ``BcdEdit /set loadoptions DDISABLE_INTEGRITY_CHECKS``

Method 2: 

   - Press F8 when booting Windows and choose “No driver signatures enforcement” option to turn off driver signature checks at all

Alternate Build Methods
-----------------------

**Build CHIPSEC kernel driver with Visual Studio**

- Open the Visual Studio project file (drivers/win7/chipsec_hlpr.vcxproj) using Visual Studio
- Select Platform and configuration (X86 or x64, Release)
- Go to Build -> Build Solution

If build process is completed without any errors, the driver binary will be moved into the chipsec helper directory: 
   
   ``<CHIPSEC_ROOT_DIR>\chipsec\helper\win\win7_amd64 (or i386)``

**Build CHIPSEC kernel driver (Old Method)**

Install WDK 7600 - (e.g. `WDK 7600.16385.1 <http://www.microsoft.com/en-us/download/details.aspx?id=11800>`_)
Open WDK build environment command prompt:

   ``"x86 Free Build Environment" or "x64 Free Build Environment" (for release build)``   
   ``"x86 Checked Build Environment" or "x64 Checked Build Environment" (for debug build)``   
   ``cd <CHIPSEC_ROOT_DIR>\drivers\win7``
   ``build -cZg``
  
If build process completed without errors, the driver binary (“chipsec_hlpr.sys”) will be in:
   
   ``<CHIPSEC_ROOT_DIR>\drivers\win7\sys\amd64``

Sign the driver

   - As Administrator, run in "x64 Free Build Environment" (or "x64 Checked Build Environment"):
   
      ``makecert -r -n "CN=Chipsec" -ss ChipsecCertStore -sr LocalMachine``
      ``cd <CHIPSEC_ROOT_DIR>\drivers\win7\sign``
   
   - Run "sign64_sys.bat" to sign "chipsec_hlpr.sys" file
   - If any error/warning is returned, create a new certificate store and modify "sign64_sys.bat" accordingly

Copy the driver to CHIPSEC framework
      
   - On Windows x64, copy signed "chipsec_hlpr.sys" to <CHIPSEC_ROOT_DIR>\chipsec\helper\win\win7_amd64 directory
   - On Windows x86, copy "chipsec_hlpr.sys" to <CHIPSEC_ROOT_DIR>\chipsec\helper\win\win7_x86 directory

Build the compression tools 

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
