CHIPSEC Modules
===============

Introduction
------------

    ===============================================  ================================================================================================
     ``chipsec/modules/``                            modules including tests or tools (that's where most of the chipsec functionality is)        
     ``chipsec/modules/common/``                     modules common to all platforms                                                             
     ``chipsec/modules/<platform>/``                 modules specific to <platform>                                                
     ``chipsec/modules/tools/``                      security tools based on CHIPSEC framework (fuzzers, etc.)                                   
    ===============================================  ================================================================================================

A CHIPSEC module is just a python class that inherits from BaseModule and implements ``is_supported`` and ``run``. Modules are stored under the chipsec installation directory in a subdirectory "modules". The "modules" directory contains one subdirectory for each chipset that chipsec supports. There is also a directory for common modules that should apply to every platform.

Internally the chipsec application uses the concept of a module name, which is a string of the form: ``common.bios_wp``.
This means module ``common.bios_wp`` is a python script called ``bios_wp.py`` that is stored at ``<ROOT_DIR>\chipsec\modules\common\``.

Modules can be mapped to one or more security vulnerabilities being checked. Consult the documentation for an individual module for more information.

Modules Description
-------------------

.. toctree:: 

    List of modules <modules/chipsec.modules.rst>
