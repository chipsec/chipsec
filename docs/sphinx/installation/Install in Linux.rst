Linux Installation
==================

Tested on:
   - `Fedora LXDE 64bit <https://spins.fedoraproject.org/lxde/>`__
   - `Ubuntu 64bit <https://www.ubuntu.com/download>`__
   - `Debian 64bit and 32bit <https://www.debian.org/>`__
   - `Linux UEFI Validation (LUV) <https://01.org/linux-uefi-validation>`__
   - `ArchStrike Linux <https://archstrike.org/downloads>`__
   - `Kali Linux <https://www.kali.org/downloads/>`__

Run CHIPSEC on a desired Linux distribution or create a live Linux image on a USB flash drive and boot to it.

Prerequisites
-------------

Python 3.7 or higher (https://www.python.org/downloads/)

.. note::

   CHIPSEC has deprecated support for Python2 since June 2020 

Install or update necessary dependencies before installing CHIPSEC:

``dnf install kernel kernel-devel-$(uname -r) python python-devel gcc nasm redhat-rpm-config elfutils-libelf-devel git``

or

``apt-get install build-essential python-dev python gcc linux-headers-$(uname -r) nasm``

or

``pacman -S python2 python2-setuptools nasm linux-headers``

Install setuptools package:

``pip install setuptools``

Building
--------

Clone CHIPSEC source

   ``git clone https://github.com/chipsec/chipsec.git``

Build the Driver and Compression Tools 

   ``python setup.py build_ext -i``

Creating a Live Linux image
---------------------------

1. Download things you will need:

   -  Desired Linux image (e.g. Fedora LXDE 64bit)
   -  `liveusb-creator <https://fedorahosted.org/liveusb-creator/>`__

2. Use liveusb-creator to image a USB stick with the desired Linux
   image. Include as much persistent storage as possible.
3. Reboot to USB
