Architecture Overview
=====================

.. figure:: ../_images/architecture.png
   :alt: CHIPSEC Architecture
   :width: 1100
   :height: 600

   CHIPSEC Architecture

Core components
---------------

    ===============================================  =================================================================================
    ``chipsec_main.py``                              main application logic and module execution
    ``chipsec_util.py``                              command-line access to CHIPSEC utility commands
    ``chipsec/chipset.py``                           chipset detection and CHIPSEC initialization
    ``chipsec/command.py``                           base class for utility commands
    ``chipsec/library/defines.py``                   common constants and definitions
    ``chipsec/library/file.py``                      file and path utilities
    ``chipsec/library/logger.py``                     logging functions
    ``chipsec/module.py``                            module discovery and loading
    ``chipsec/module_common.py``                     base class for security modules
    ``chipsec/library/result_deltas.py``             checking result deltas between test runs
    ``chipsec/testcase.py``                          result reporting and XML/JSON output
    ``chipsec/helper/basehelper.py``                 interface implemented by OS helpers
    ``chipsec/helper/oshelper.py``                   discovers and selects an OS helper backend
    ``chipsec/hal/``                                  hardware abstraction layer implementations
    ===============================================  =================================================================================

Commands
--------

Implement functionality of chipsec_util.

CHIPSEC utilities provide the capability for manual testing and direct hardware access.

.. warning:: DIRECT HARDWARE ACCESS PROVIDED BY THESE UTILITIES COULD MAKE YOUR SYSTEM UNBOOTABLE. MAKE SURE YOU KNOW WHAT YOU ARE DOING!

.. note:: All numeric values in the instructions are in hex.

.. toctree::

    List of Utility components <../modules/chipsec.utilcmd.rst>

HAL (Hardware Abstraction Layer)
--------------------------------

Useful abstractions for common tasks such as accessing the SPI.

.. toctree::

    List of HAL components <../modules/chipsec.hal.rst>

Fuzzing
-------

.. toctree::

    List of Fuzzing components <../modules/chipsec.fuzzing.rst>

CHIPSEC_MAIN Program Flow
-------------------------

1. Select :ref:`OS Helpers and Drivers <OS-Helpers-and-Drivers>`

   - Load Driver (optional)

2. :ref:`Detect Platform <Platform-Detection>`
3. Load :ref:`Configuration Files <Configuration-Files>`
4. Load Modules
5. Run Loaded Modules
6. Report Results
7. Cleanup

CHIPSEC_UTIL Program Flow
-------------------------

1. Select :ref:`OS Helpers and Drivers <OS-Helpers-and-Drivers>`

   - Load Driver (optional)

2. :ref:`Detect Platform <Platform-Detection>`
3. Load :ref:`Configuration Files <Configuration-Files>`
4. Load Utility Commands
5. Run Selected Command
6. Cleanup

Auxiliary components
--------------------

    - ``setup.py`` setup script to install CHIPSEC as a package

Executable build scripts
------------------------

    - ``<CHIPSEC_ROOT>/scripts/build_exe_*.py`` make files to build Windows executables