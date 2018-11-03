.. toctree::

DAL Windows Installation
========================

1. Install Intel System Studio

    Should include Python

2. Install pywin32 and setuptools packages:

    ``pip install setuptools``

    ``pip install pypiwin32``

3. Clone CHIPSEC source:

    ``git clone https://github.com/chipsec/chipsec``

4. Install CHIPSEC support:

    Manually install CHIPSEC as a package:

    ``python setup.py install``

5. Connect and halt platform:

    Connect and set up debugger to system.

6. Import and run CHIPSEC main

    1. Launch a python Command-line.

    2. Import the IPC CLI module

        >>> import ipccli

    3. Import the chipsec_main module

        >>> import chipsec_main

    4. Run standard CHIPSEC modules:

        >>> chipsec_main.main()

    Example command-lines:

        Run a specific module:

        >>> chipsec_main.main([‘-m’, ‘common.bios_wp’])

        Generate a log file:

        >>> chipsec_main.main([‘-l’,’test.log’])

        Note: the test.log file can be found in C:\intel\DAL

7. Import and run CHIPSEC util

    1. Launch a python Command-line.

    2. Import the IPC CLI module

        >>> import ipccli

    3. Import the chipsec_util module

        >>> import chipsec_util

    4. Run CHIPSEC util and list available commands:

        >>> chipsec_util.main()

    Example command-lines:

        Read SPI info…

        >>> chipsec_util.main([‘spi’, ‘info’])

        Read MSR…

        >>> chipsec_util.main([‘msr’, ‘0x1f2’])
