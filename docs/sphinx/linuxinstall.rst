
Linux Installation
===================
   
Tested on:

- Fedora LXDE 64bit
- Ubuntu 64bit
- Debian 64bit and 32bit
- Linux UEFI Validation (LUV)
- ArchStrike Linux
- Kali Linux


**Installing necessary packages**

You will need to install or update the following dependencies before installing CHIPSEC:

``# dnf install kernel kernel-devel-$(uname -r) python python-devel gcc nasm \``
``redhat-rpm-config elfutils-libelf-devel git``

or

``# apt-get install build-essential python-dev python-setuptools python gcc \``
``linux-headers-$(uname -r) nasm``

or

``# pacman -S python2 python2-setuptools nasm linux-headers``

You can use CHIPSEC on a desired Linux distribution or create a live Linux image on a USB flash drive and boot to it. For example, you can use `liveusb-creator <https://fedorahosted.org/liveusb-creator/>`_ to create live Fedora image on a USB drive

**Installing Manually**

Clone chipsec Git repository and install it as a package:

	``# git clone https://github.com/chipsec/chipsec``

	``# python setup.py install``

	``# sudo chipsec_main``

To use CHIPSEC *in place* without installing it:

	``# python setup.py build_ext -i``

	``# sudo python chipsec_main.py``
