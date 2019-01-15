.. toctree::

MacOS  Installation
=====================
   
**WARNING: MacOS support is currently in Beta release**

Install CHIPSEC Dependencies
----------------------------

Install XCODE from the App Store
  
Install Python 2.7, PIP and setuptools packages. Please see instructions `here <http://docs.python-guide.org/en/latest/starting/install/osx/>`_

Turn the System Integrity Protection (SIP) off. See `Configuring SIP <https://developer.apple.com/library/mac/documentation/Security/Conceptual/System_Integrity_Protection_Guide/ConfiguringSystemIntegrityProtection/ConfiguringSystemIntegrityProtection.html>`_

An alternative to disabling SIP and allowing untrusted/unsigned kexts to load can be enabled by running the following command.

::

	# csrutil enable --without kext


Installing CHIPSEC
------------------

Clone CHIPSEC Git repository::

	# git clone https://github.com/chipsec/chipsec

To install and run CHIPSEC as a package::

	# python setup.py install

	# sudo chipsec_main

To use CHIPSEC *in place* without installing it::

	# python setup.py build_ext -i

	# sudo python chipsec_main.py

To build chipsec.kext on your own and load::

	Please follow the instructions in drivers/osx/README

CHIPSEC Cleanup
---------------
When done using CHIPSEC, ensure the driver is unloaded and re-enable the System Integrity Protection::

	# kextunload -b com.google.chipsec
	
	# csrutil enable

Build Errors
------------
xcodebuild requires xcode error during CHIPSEC install::

	# sudo xcode-select -s /Applications/Xcode.app/Contents/Developer 