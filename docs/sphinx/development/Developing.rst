Developer Guide
===============

CHIPSEC modules are Python classes that assess or exercise a platform through
the CHIPSEC framework. Module code runs with privileged hardware access on
supported systems. Develop and test on a dedicated test system, and understand
the effect of every hardware read or write before running a module.

Module layout and lifecycle
---------------------------

Place modules under ``chipsec/modules/``. Use ``common/`` for checks intended
to work across supported platforms, or a platform-code directory for a
platform-specific check. The module name is its path relative to
``chipsec/modules`` without the ``.py`` suffix; for example,
``chipsec/modules/common/bios_wp.py`` is run as ``common.bios_wp``. The module
class name must match the Python file's base name.

Subclass ``BaseModule`` from ``chipsec.module_common``. CHIPSEC calls
``is_supported()`` before ``run(module_argv)``. Return ``False`` from
``is_supported`` when required hardware or configuration is unavailable; the
module is then reported as not applicable. ``run`` receives the arguments
provided with ``-a`` and returns the module result/return code. See
:doc:`Sample-Module-Code` for a starting point.

Core APIs
---------

``BaseModule`` provides these commonly used objects:

* ``self.cs`` is the active chipset object. Use its configuration interfaces
    to resolve platform-specific registers and controls instead of duplicating
    platform detection in a module.
* ``self.cs.register`` accesses configured registers. Check whether required
    names are defined before reading them; ``get_list_by_name(name)`` returns
    the configured register list.
* ``self.cs.control`` accesses abstract controls. A control maps a logical
    security setting to the register and field used by a platform. Check
    ``is_defined(name)`` and use ``get_list_by_name(name)`` to read it.
* ``self.cs.device`` provides configured device information. For common
    hardware operations, use the corresponding HAL exposed under
    ``self.cs.hals`` (for example, ``self.cs.hals.spi`` or
    ``self.cs.hals.uefi``). See :doc:`Architecture-Overview` and the generated
    CHIPSEC HAL API documentation for the available HALs.
* ``self.logger`` provides ``start_test``, ``log``, ``log_verbose``,
    ``log_warning``, ``log_passed``, ``log_failed`` and ``log_important`` for
    consistent output.
* ``self.result`` tracks return-code status bits. Use
    ``self.result.setStatusBit(...)`` to add a meaningful status such as
    ``LOCKS``, ``CONFIGURATION`` or ``VERIFY``. Follow nearby modules for the
    result style used in that part of the codebase; CHIPSEC retains the legacy
    ``ModuleResult`` interface for compatibility.

Platform controls are declared in configuration XML, not hard-coded into a
portable module. For example:

.. code-block:: xml

     <control name="BiosLockEnable" register="BC" field="BLE"
                        desc="BIOS Lock Enable"/>

A module can then query the abstract control without knowing which register
implements it on each platform:

.. code-block:: python

     lock = self.cs.control.get_list_by_name('BiosLockEnable')
     lock.read_and_verbose_print()
     if lock.is_all_value(1):
             self.logger.log_passed('BIOS Lock is set.')
     else:
             self.logger.log_failed('BIOS Lock is not set.')

See :doc:`Configuration-Files` for configuration structure and examples.

Development practices
---------------------

* Prefer read-only checks. If a check must modify hardware state, make the
    change explicit, preserve the original value, and restore it on every exit
    path. Document the risk and require an appropriate test platform.
* Use abstract controls and existing HALs so modules can be reused across
    platform generations. Put platform-specific register mappings in
    configuration XML.
* Treat missing definitions, disabled devices, failed reads and all-ones
    reads as unknown or unsupported input, not as evidence that a protection
    passed or failed. Report a warning or not-applicable result as appropriate.
* Validate assumptions and ranges before using hardware-derived values. Keep
    parsing and result handling explicit, and avoid swallowing exceptions that
    indicate a programming error.
* Keep checks focused, log the observed state and expected state, and add
    unit tests for parsing, decision logic and error paths. Follow the Python
    version and style rules in :doc:`../contribution/code-style-python`.
* Add module tags and metadata that accurately describe the module. Use
    existing modules in the same directory as examples of repository
    conventions.

Debugging and testing
---------------------

Start with a focused run from the CHIPSEC repository root:

.. code-block:: console

     python chipsec_main.py -m common.example

Increase diagnostic output with ``-v`` or ``-vv`` (verbose, HAL and debug
logging), and save it with ``-l example.log``. Use ``--failfast`` when you
need exceptions to stop the run rather than be masked by normal module
handling. ``--no-driver`` is only suitable for operations that do not need
kernel-driver access.

When diagnosing a module:

* If it is not found, check the module path/name, class name, and any
    additional module path passed with ``-I``.
* If it is not applicable, inspect ``is_supported`` and verify that the
    platform configuration defines and enables each required device, register
    and control.
* If a result is unexpected, use verbose output to inspect the values read,
    then confirm the register mapping and expected semantics against the
    platform documentation.
* If the module raises an exception, reproduce it with a single-module run
    and ``--failfast``; add a focused test for the failing input or decision
    path.

Run a focused unit test from the repository root, for example:

.. code-block:: console

     python -m pytest tests/modules/test_example.py -q

Hardware validation is separate from unit testing and must be performed only
on an appropriate test system. See :doc:`../usage/Running-Chipsec` for command
line options and the `contribution guide
<https://github.com/chipsec/chipsec/blob/master/CONTRIBUTING.md>`_ for
contribution requirements.

.. seealso::

     * :doc:`Architecture-Overview`
     * :doc:`Configuration-Files`
     * :doc:`Sample-Module-Code`
     * `Creating CHIPSEC modules and commands <https://github.com/chipsec/chipsec/wiki/files/training/OSFC_2018_CHIPSEC_Workshop.pdf>`_