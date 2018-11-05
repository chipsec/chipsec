.. toctree::

Mac OS X Installation
=====================
   
.. warning:: Mac OS X support is currently in Beta release

Please follow the steps below to install CHIPSEC on Mac OS X.

#. Before installing CHIPSEC, install XCode, Python 2.7, PIP and setuptools packages. Please see instructions here: http://docs.python-guide.org/en/latest/starting/install/osx/

#. Turn the System Integrity Protection (SIP) off. See `Configuring SIP <https://developer.apple.com/library/mac/documentation/Security/Conceptual/System_Integrity_Protection_Guide/ConfiguringSystemIntegrityProtection/ConfiguringSystemIntegrityProtection.html>`_

**Installing Manually**

Clone chipsec Git repository and install it as a package:

	``# git clone https://github.com/chipsec/chipsec``

	``# python setup.py install``

	``# sudo chipsec_main``

To use CHIPSEC *in place* without installing it:

	``# python setup.py build_ext -i``

	``# sudo python chipsec_main.py``

.. note:: You can build chipsec.kext on your own and load it using ``kextutil``. Please follow the instructions in ``drivers/osx/README``.

	An alternative to disabling SIP and allowing untrusted/unsigned kexts to load can be enabled by running the following command.

	``# csrutil enable --without kext``

When done, unload the driver and re-enable the System Integrity Protection

	``# kextunload -b com.google.chipsec``
