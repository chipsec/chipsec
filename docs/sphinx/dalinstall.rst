.. toctree::

DAL Windows Installation
========================

#. Install Intel System Studio

    Should include Python

#. Install pywin32 and setuptools packages:

    ``pip install setuptools``

    ``pip install pypiwin32``

#. Clone CHIPSEC source:

    ``git clone https://github.com/chipsec/chipsec``

#. Install CHIPSEC support:

    Manually install CHIPSEC as a package:

    ``python setup.py install``

#. Connect and halt platform:

    Connect and set up debugger to system.

#. Import and run CHIPSEC main

    #. Launch a python Command-line.

    #. Import the chipsec_main module

        >>> import chipsec_main

    #. Run standard CHIPSEC modules:

        >>> chipsec_main.main()

    Example command-lines:

        Run a specific module:

        >>> chipsec_main.main([‘-m’, ‘common.bios_wp’])

        Generate a log file:

        >>> chipsec_main.main([‘-l’,’test.log’])

        Note: the test.log file can be found in ``C:\intel\DAL``

#. Import and run CHIPSEC util

    #. Launch a python Command-line.

    #. Import the IPC CLI module

        >>> import ipccli

    #. Import the chipsec_util module

        >>> import chipsec_util

    #. Run CHIPSEC util and list available commands:

        >>> chipsec_util.main()

    Example command-lines:

        Read SPI info…

        >>> chipsec_util.main([‘spi’, ‘info’])

        Read MSR…

        >>> chipsec_util.main([‘msr’, ‘0x1f2’])
