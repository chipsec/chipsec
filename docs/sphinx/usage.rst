Using CHIPSEC
=============

CHIPSEC should be launched as Administrator/root.

- In command shell, run 

    ``# python chipsec_main.py``

    ``# python chipsec_util.py``

- For help, run
    
    ``# python chipsec_main.py --help``

    ``# python chipsec_util.py help``

Command Line Usage
------------------

.. toctree::

    options.rst

|   

CHIPSEC will automatically attempt to create and start its service, including load its kernel-mode driver. If chipsec service is already running then it will attempt to connect to the existing service.

Use ``--no-driver`` command-line option if you want CHIPSEC to use native OS API rather than own kernel module.
This option can also be used if loading kernel module is not needed to use desired functionality.

Use ``-m --module`` to run a specific module (e.g. security check, a tool or a PoC..):

    - ``# python chipsec_main.py -m common.bios_wp``
    - ``# python chipsec_main.py -m common.spi_lock``
    - ``# python chipsec_main.py -m common.smrr``

- You can also use CHIPSEC to access various hardware resources:
    
    ``# python chipsec_util.py``
        
Using CHIPSEC as a Python Package
---------------------------------

Install CHIPSEC manually or from PyPI as described in the Installation section.

You can then use CHIPSEC from your Python project or from the Python shell:

>>> import chipsec_main 
>>> chipsec_main.main()
>>> chipsec_main.main(['-m','common.bios_wp'])

>>> import chipsec_util 
>>> chipsec_util.main()
>>> chipsec_util.main(['spi','info'])


Compiling CHIPSEC Executables on Windows
----------------------------------------

Directories ``bin/<arch>`` (where ``<arch>`` is ``x86`` or ``amd64``) should already contain compiled CHIPSEC binaries: ``chipsec_main.exe``, ``chipsec_util.exe``

    - To run all security tests run ``chipsec_main.exe`` from ``bin`` directory:

        ``# chipsec_main.exe``

    - To access hardware resources run ``chipsec_util.exe`` from ``bin`` directory:

        ``# chipsec_util.exe``

    If directory ``bin`` doesn't exist, then you can compile CHIPSEC executables:
    
    - Install ``py2exe`` package from http://www.py2exe.org
    - From the ``scripts`` directory  run ``build_exe_<arch>.py`` as follows:
    
        ``# python build_exe_<arch>.py py2exe``
    
    - ``chipsec_main.exe``, ``chipsec_util.exe`` executables and required libraries will be created in ``bin/<arch>`` directory

.. toctree::


Writing Your Own Modules
------------------------

Your module class should subclass BaseModule and implement at least the methods named ``is_supported`` and ``run``. When chipsec_main runs, it will first run ``is_supported`` and if that returns true, then it will call ``run``.

As of CHIPSEC version 1.2.0, CHIPSEC implements an abstract name for platform *controls*. Module authors are encouraged to create controls in the XML configuration files for important platform configuration information and then use ``get_control`` and ``set_control`` within modules. This abstraction allows modules to test for the abstract control without knowning which register provides it. (This is especially important for test reuse across platform generations.) 

Most modules read some platform configuration and then pass or fail based on the result. For example:

1. Define the control in the platform XML file (in ``chispec/cfg``):

   .. code-block:: xml
    
    <control name="BiosLockEnable"     register="BC"    field="BLE"    desc="BIOS Lock Enable"/>

2. Get the current status of the control:

   .. code-block:: python
    
    ble = chipsec.chipset.get_control( self.cs, 'BiosLockEnable' )
    
3. React based on the status of the control:

   .. code-block:: python
    
    if ble: self.logger.log_passed_check("BIOS Lock is set.")       
    else: self.logger.log_failed_check("BIOS Lock is not set.")

4. Return:

   .. code-block:: python

    if ble: return ModuleResult.PASSED
    else: return ModuleResult.FAILED

When a module calls ``get_control`` or ``set_control``, CHIPSEC will look up the control in the platform XML file, look up the corresponding register/field, and call ``chipsec.chipset.read_register_field`` or ``chipsec_chipset.write_register_field``. This allows modules to be written for abstract *controls* that could be in different registers on differnet platforms.
    
The CHIPSEC HAL and other APIs are also available within these modules. See the next sections for details about the available functionality.

Copy your module into the ``chipsec/modules/`` directory structure 

- Modules specific to a certain platform should implement ``is_supported`` function which returns ``True`` for the platforms the module is applicable to

- Modules specific to a certain platform can also be located in ``chipsec/modules/<platform_code>`` directory, for example ``chipsec/modules/hsw``. Supported plaforms and their code can be found by running ``chipesec_main.py --help``

- Modules common to all platform which CHIPSEC supports can be located in ``chipsec/modules/common`` directory

If a new platform needs to be added: 

- Modify ``chipsec/chipset.py`` to include the Device ID for the platform you are adding

- Review the platform datasheet and include appropriate information in an XML configuration file for the platform. Place this file in chipsec/cfg. Registers that are correctly defined in ``common.xml`` will be inherited and do not need to be added. Use ``common.xml`` as an example. It is based on the 4th Generation Intel Core platform (Haswell). 
