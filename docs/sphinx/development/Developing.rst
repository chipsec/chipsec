Writing Your Own Modules
========================

Your module class should subclass BaseModule and implement at least the methods named ``is_supported`` and ``run``. When chipsec_main runs, it will first run ``is_supported`` and if that returns true, then it will call ``run``.

As of CHIPSEC version 1.2.0, CHIPSEC implements an abstract name for platform *controls*. Module authors are encouraged to create controls in the XML configuration files for important platform configuration information and then use ``get_control`` and ``set_control`` within modules. This abstraction allows modules to test for the abstract control without knowing which register provides it. (This is especially important for test reuse across platform generations.)

Most modules read some platform configuration and then pass or fail based on the result. For example:

1. Define the control in the platform XML file (in ``chipsec/cfg``):

   .. code-block:: xml

    <control name="BiosLockEnable"     register="BC"    field="BLE"    desc="BIOS Lock Enable"/>

2. Get the current status of the control:

   .. code-block:: python

    ble = self.cs.control.get('BiosLockEnable')

3. React based on the status of the control:

   .. code-block:: python

    if ble:
        self.logger.log_passed("BIOS Lock is set.")
    else:
        self.logger.log_failed("BIOS Lock is not set.")

4. Set and Return ``self.res``:

   .. code-block:: python

    if ble:
        self.res = ModuleResult.PASSED
    else:
        self.res = ModuleResult.FAILED
    return self.res

The CHIPSEC HAL and other APIs are also available within these modules. See the next sections for details about the available functionality.

Copy your module into the ``chipsec/modules/`` directory structure.

- Modules specific to a certain platform should implement ``is_supported`` function which returns ``True`` for the platforms the module is applicable to.

- Modules specific to a certain platform can also be located in ``chipsec/modules/<platform_code>`` directory, for example ``chipsec/modules/hsw``. Supported platforms and their code can be found by running ``chipsec_main.py --help``.

- Modules common to all platform which CHIPSEC supports can be located in ``chipsec/modules/common`` directory.

If a new platform needs to be added:

- Review the platform datasheet and include appropriate information in an XML configuration file for the platform. Place this file in chipsec/cfg/8086. Registers that are correctly defined in ``common.xml`` will be inherited and do not need to be added. Use ``common.xml`` as an example. It is based on the 4th Generation Intel Core platform (Haswell).

.. seealso::
    `Creating CHIPSEC modules and commands <https://github.com/chipsec/chipsec/wiki/files/training/OSFC_2018_CHIPSEC_Workshop.pdf>`_