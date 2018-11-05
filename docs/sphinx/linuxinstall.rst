
Linux Installation
===================
   
Tested on:

- Fedora LXDE 64bit
- Ubuntu 64bit
- Debian 64bit and 32bit
- Linux UEFI Validation (LUV)


**Installing necessary packages**

You will need to install or update the following dependencies before installing CHIPSEC:

``# yum install kernel kernel-devel-$(uname -r) python python-devel python-setuptools \``
``gcc nasm redhat-rpm-config`` 
    
or 
    
``# apt-get install build-essential python-dev python-setuptools python gcc \``
``linux-headers-$(uname -r) nasm``

You can use CHIPSEC on a desired Linux distribution or create a live Linux image on a USB flash drive and boot to it. For example, you can use `liveusb-creator <https://fedorahosted.org/liveusb-creator/>`_ to create live Fedora image on a USB drive

**Installing Manually**

Clone chipsec Git repository and install it as a package:

	``# git clone https://github.com/chipsec/chipsec``

	``# python setup.py install``

	``# sudo chipsec_main``

To use CHIPSEC *in place* without installing it:

	``# python setup.py build_ext -i``

	``# sudo python chipsec_main.py``
