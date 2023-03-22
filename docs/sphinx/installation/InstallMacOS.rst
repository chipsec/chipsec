MacOS Installation
==================

.. warning::

   MacOS support is currently in Beta release. There's no support for M1 chips

Install CHIPSEC Dependencies
----------------------------

Python 3.7 or higher (https://www.python.org/downloads/)

.. note::

   CHIPSEC has deprecated support for Python2 since June 2020  

Install XCODE from the App Store (for best results use version 11 or newer)

Install PIP and setuptools packages. Please see instructions `here <http://docs.python-guide.org/en/latest/starting/install/osx/>`__

Turn the System Integrity Protection (SIP) off. See `Configuring SIP <https://developer.apple.com/library/mac/documentation/Security/Conceptual/System_Integrity_Protection_Guide/ConfiguringSystemIntegrityProtection/ConfiguringSystemIntegrityProtection.html>`__

An alternative to disabling SIP and allowing untrusted/unsigned kexts to load can be enabled by running the following command:

   ``# csrutil enable --without kext``

Building Chipsec
----------------

Clone CHIPSEC Git repository:

   ``# git clone https://github.com/chipsec/chipsec``

Run CHIPSEC
-----------

Follow steps in section "Using as a Python package" of :ref:`Running CHIPSEC <Running-Chipsec>`

To build chipsec.kext on your own and load please follow the instructions in drivers/osx/README

CHIPSEC Cleanup
---------------

When done using CHIPSEC, ensure the driver is unloaded and re-enable the System Integrity Protection:

   ``# kextunload -b com.google.chipsec``

   ``# csrutil enable``

Build Errors
------------

xcodebuild requires xcode error during CHIPSEC install:

   ``# sudo xcode-select -s /Applications/Xcode.app/Contents/Developer``
