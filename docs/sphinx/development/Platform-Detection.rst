.. _Platform-Detection:

Platform Detection
==================

CHIPSEC identifies the processor platform and, where applicable, the PCH
using the SKU metadata and PCI device IDs in its configuration tree. PCI
enumeration provides device identities; CPU configuration can also use CPUID
detection values to distinguish platforms that share device IDs. The
platform-detection and configuration-loading flow is implemented by
``chipsec/chipset.py`` and ``chipsec/config.py``.

Platform Configuration Options
------------------------------

Use ``-p`` or ``--platform`` to request a platform code explicitly. Use
``--pch`` to request a PCH code. These options select configuration data; they
do not change the hardware being detected. The ``-i`` / ``--ignore_platform``
option is deprecated and should not be used for normal operation.
