.. _OS-Helpers-and-Drivers:

OS Helpers and Drivers
======================

Provide common interfaces to interact with system drivers/commands

Mostly invoked by HAL modules
-----------------------------

Directly invoking helpers from modules should be minimized

Helpers import from BaseHelper
------------------------------

Override applicable functions – default is to generate exception

I/O, PCI, MSR, UEFI Variables, etc.

Create a New Helper
-------------------

Helper needs to be added to the import list either within helpers.py or
custom_helpers.py

Example
~~~~~~~

The new helper should be added to either ``chipsec/helper/helpers.py``
or ``chipsec/helper/custom_helpers.py``

A new helper folder should be created under
``chipsec/helper/new_helper``

``chipsec/helper/new_helper/__init__.py`` within the new folder needs to
add the helper to avail_helpers list

::

   import platform
   from chipsec.helper.oshelper import avail_helpers

   if "linux" == platform.system().lower():
       __all__ = [ "linuxhelper" ]
       avail_helpers.append("linuxhelper")
   else:
       __all__ = [ ]

``chipsec/helper/new_helper/new_helper.py`` should import from Helper
Base Class

::

   from chipsec.helper.basehelper import Helper
   class NewHelper(Helper):

       def __init__(self):
           super(NewHelper, self).__init__()
           self.name = "NewHelper"
