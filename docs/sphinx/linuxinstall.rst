
Linux Installation
===================
   
Tested on:

- Fedora LXDE 64bit
- Ubuntu 64bit
- Debian 64bit and 32bit
- Linux UEFI Validation (LUV)


**Installing necessary packages**

You will need to install or update the following dependencies before installing CHIPSEC:

``# yum install kernel kernel-devel-$(uname -r) python python-devel gcc nasm redhat-rpm-config`` 
    
or 
    
``# apt-get install build-essential python-dev python gcc \``
``linux-headers-$(uname -r) nasm``

You can use CHIPSEC on a desired Linux distribution or create a live Linux image on a USB flash drive and boot to it. For example, you can use `liveusb-creator <https://fedorahosted.org/liveusb-creator/>`_ to create live Fedora image on a USB drive

You will also need to install ``setuptools`` package:

   ``pip install setuptools``


**Installing from PyPI**

1. Installing CHIPSEC from PyPI will automatically build all necessary components including kernel module and install CHIPSEC as a package. CHIPSEC will automatically load the kernel module and unload it when done.

	``# pip install chipsec``

2. Now you can use these commands from any directory to run CHIPSEC:

	``# sudo chipsec_main``

	``# sudo chipsec_util``

	``# sudo python -m chipsec_main``

	``# sudo python -m chipsec_util``

**Installing Manually**

Clone chipsec Git repository and install it as a package:

	``# git clone https://github.com/chipsec/chipsec``

	``# python setup.py install``

	``# sudo chipsec_main``

To use CHIPSEC *in place* without installing it:

	``# python setup.py build_ext -i``

	``# sudo python chipsec_main.py``

.. note:: To use CHIPSEC without installing it using ``setup.py``, just build kernel module and helper components in place:

	``# make -C ../drivers/linux``

	``# cp ../drivers/linux/chipsec.ko ../chipsec/helper/linux/``

	``# make -C ../chipsec/helper/linux/``
