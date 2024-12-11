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

Creating a Live Linux image
---------------------------

1. Download things you will need:

   -  Desired Linux image (e.g. Fedora LXDE 64bit)
   -  `Rufus <https://rufus.ie/en/>`__

2. Use Rufus to image a USB stick with the desired Linux
   image. Include as much persistent storage as possible.
3. Reboot to USB

Installing Kali Linux
---------------------

`Download <https://www.kali.org/downloads/>`__ and `install <https://www.kali.org/docs/installation/>`__ Kali Linux

Prerequisites
-------------

Python 3.8 or higher (https://www.python.org/downloads/)

.. note::

   CHIPSEC has deprecated support for Python2 since June 2020 

Install or update necessary dependencies before installing CHIPSEC:

``dnf install kernel kernel-devel-$(uname -r) python3 python3-devel gcc nasm redhat-rpm-config elfutils-libelf-devel git``

or

``apt-get install build-essential python3-dev python3 gcc linux-headers-$(uname -r) nasm``

or

``pacman -S python3 python3-setuptools nasm linux-headers``

To install requirements: 

   ``pip install -r linux_requirements.txt``

Installing CHIPSEC
------------------

**Get latest CHIPSEC release from PyPI repository**

``pip install chipsec``

.. note::

   Version in PyPI is outdate please refrain from using until further notice

**Get CHIPSEC package from latest source code**

Download zip from CHIPSEC repo

   :ref:`Download CHIPSEC <Download>`

 or

Clone CHIPSEC source

   ``git clone https://github.com/chipsec/chipsec.git``

Building CHIPSEC
----------------

Build the Driver and Compression Tools 

   ``python setup.py build_ext -i``

Run CHIPSEC
-----------

Follow steps in section "Using as a Python package" of :ref:`Running CHIPSEC <Running-Chipsec>`
