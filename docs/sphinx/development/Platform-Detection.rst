.. _Platform-Detection:

Methods for Platform Detection
==============================

Uses PCI VID and DID to detect processor and PCH
------------------------------------------------

Processor 0:0.0

PCH 0:31.0

Chip information located in ``chipsec/chipset.py``
--------------------------------------------------

Currently requires VID of 0x8086

DID is used as the lookup key

If there are matching DID, will fall back to cpuid check for CPU

Platform Configuration Options
------------------------------

Select a specific platform using the ``–p`` flag

Specify PCH using the ``–-pch`` flag

Ignore the platform specific registers using the ``-i`` flag
