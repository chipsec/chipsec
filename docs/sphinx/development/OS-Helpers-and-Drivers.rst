.. _OS-Helpers-and-Drivers:

OS Helpers and Drivers
======================

OS helpers provide low-level, operating-system-specific access to drivers and
system interfaces such as PCI configuration space, MSRs, physical memory and
UEFI variables. HAL implementations use the active helper to perform these
operations. Module authors should normally use the HAL API rather than invoke
the helper directly.

OS helper backends live in ``chipsec/helper/<name>/<name>helper.py``. During
initialization, ``OsHelper`` discovers these packages and selects the backend
for the current environment. Each backend exports a ``get_helper()`` factory
that returns its helper instance.

Implementing a new backend
--------------------------

Subclass ``Helper`` from ``chipsec.helper.basehelper`` and implement its
abstract operations. The interface includes driver lifecycle, PCI/MMIO,
physical memory, I/O ports, CPU registers, CPUID, and UEFI/ACPI services.
Implement only the behavior the target environment supports, and follow an
existing backend such as ``chipsec/helper/linux/linuxhelper.py`` for its
module structure and ``get_helper()`` factory. A helper backend is a
platform-integration change; ordinary security checks should be implemented
as modules and use the existing HALs.

Helper components
-----------------

.. toctree::
    :maxdepth: 2

    List of Helper components <../modules/chipsec.helper.rst>
