Creating the Kali Linux Live USB
================================

`Download <https://www.kali.org/downloads/>`__ and `install <https://www.kali.org/docs/installation/>`__ Kali Linux

Installing CHIPSEC
------------------

**Install the dependencies**

``apt-get install python python-devel gcc nasm linux-headers-[version]-all``

.. note:: 

    Install the linux headers for the currently running version of the Linux kernel. You can determine this with ``uname -r``

``pip install setuptools``

**Install latest CHIPSEC release from PyPI repository**

``pip install chipsec``

**Install CHIPSEC package from latest source code**

Copy CHIPSEC to the USB drive (or install ``git``)

    ``git clone https://github.com/chipsec/chipsec``

    ``python setup.py install``

Run CHIPSEC
-----------

Follow steps in section "Using as a Python package" of :ref:`Running CHIPSEC <Running-Chipsec>`