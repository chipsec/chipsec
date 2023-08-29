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

Helper needs to be added into the helper folder with a folder structure like: ``chipsec/helper/<type>/<type>helper.py``

Example
~~~~~~~

The new helper should be added to ``chipsec/helper/new/newhelper.py`` and should import from Helper Base Class

::

   from chipsec.helper.basehelper import Helper
   class NewHelper(Helper):

       def __init__(self):
           super(NewHelper, self).__init__()
           self.name = "NewHelper"

Helper components
-----------------

.. toctree::
    :maxdepth: 2

    List of Helper components <../modules/chipsec.helper.rst>
