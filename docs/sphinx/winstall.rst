.. toctree::

Windows Installation
====================
   
CHIPSEC supports the following versions:

- Windows 7, 8, 8.1, 10 x86 and 64-bit
- Windows Server 2008, 2012, 2016 x86 and 64-bit


Please follow the steps below to install CHIPSEC framework on Windows:

1. Install `Python <http://www.python.org/download/>`_

2. Install `pywin32 <http://sourceforge.net/projects/pywin32/>`_ and ``setuptools`` packages:

   ``pip install setuptools``

   ``pip install pywin32``

   To build chipsec executables, you may optionally want to install `py2exe <http://www.py2exe.org/>`_:

   ``pip install py2exe``

   To get colored console output, you may optionally want to install `WConio <http://newcenturycomputers.net/projects/wconio.html>`_.
    
3. Build CHIPSEC kernel driver. Please follow the instructions in ``\drivers\win7\readme``. Skip this step if you already have ``chipsec_hlpr.sys`` driver binary for your version of Windows

4. Copy CHIPSEC driver (``chipsec_hlpr.sys``) to proper directory ``\chipsec\helper\win\win7_<arch>`` where ``<arch>`` is "x86" or "amd64" (default path is ``\chipsec\helper\win\win7_amd64``)

5. Install CHIPSEC framework

   To automatically install from PyPI:

   ``pip install chipsec``

   To manually install CHIPSEC as a package:

   ``git clone https://github.com/chipsec/chipsec``

   ``python setup.py install``

   .. note:: When installing CHIPSEC on Windows, the driver isn't built automatically (as when installing on Linux). You'll need to build Windows driver and copy it to proper directory (see steps 3 and 4) prior to installing CHIPSEC

6. Turn off kernel driver signature checks 
   
   *Windows 10 64-bit / Windows 8, 8.1 64-bit (with Secure Boot enabled) / Windows Server 2016 64-bit / Windows Server 2012 64-bit (with Secure Boot enabled):*
   
   - In CMD.EXE: ``shutdown /r /t 0 /o``
   - Navigate: Troubleshooting > Advanced Settings > Startup Options > Reboot
   - After reset choose ``F7`` "Disable driver signature checks"

   Alternatively, disable Secure Boot in the BIOS setup screen then disable driver signature checks as with Secure Boot disabled

   *Windows 7 64-bit / Windows Server 2008 64-bit / Windows 8 (with Secure Boot disabled) / Windows Server 2012 (with Secure Boot disabled):*

   Boot in Test mode (allows self-signed certificates)

   - Start CMD.EXE as Adminstrator
   - ``BcdEdit /set TESTSIGNING ON``
   - Reboot
   
   If that doesn't work, run these additional commands:
   
       ``BcdEdit /set noIntegrityChecks ON``

       ``BcdEdit /set loadoptions DISABLE_INTEGRITY_CHECKS``
   
   Alternatively, press ``F8`` when booting Windows and choose "No driver signatures enforcement" option to turn off driver signature checks

7. Run CHIPSEC

   - Launch CMD.EXE as Administrator
   - You can use commands below to run CHIPSEC. CHIPSEC will automatically load the driver and unload it when done.

       ``python chipsec_main.py``

       ``python chipsec_util.py``

   - If CHIPSEC is used as a standalone tool, run above commands from where CHIPSEC is.


.. note:: You can manually register and start CHIPSEC service/driver. CHIPSEC will attempt to connect to already running chipsec service.

    To create and start chipsec service (in CMD.EXE)
   
    ``sc create chipsec binpath=<path_to_sys> type=kernel DisplayName="Chipsec driver"``

    ``sc start chipsec``
   
    Then to stop and delete chipsec service:
   
    ``sc stop chipsec``

    ``sc delete chipsec``
