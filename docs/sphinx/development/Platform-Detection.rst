.. _Platform-Detection:

Methods for Platform Detection
==============================

Uses PCI VendorID and DeviceID to detect processor and PCH
----------------------------------------------------------

Processor: 0:0.0

PCH: Scans enumerated PCI Devices for corresponding VID/DID per configurations. 

Chip information located in ``chipsec/chipset.py``
--------------------------------------------------

Currently requires VID of 0x8086 (Intel) or 0x1022 (AMD).

DeviceID is used as the lookup key.

If there are matching DeviceID, will fall back to cpuid check for CPU.

Platform Configuration Options
------------------------------

Select a specific platform using the ``–p`` flag.

Specify PCH using the ``–-pch`` flag.

~Ignore the platform specific registers using the ``-i`` flag.~
The ``-i`` flag has been deprecated and should not be used. 
