.. _Running-Chipsec:

Running CHIPSEC
===============

CHIPSEC should be launched as Administrator/root.

CHIPSEC will automatically attempt to create and start its service, including load its kernel-mode driver. If CHIPSEC service is already running then it will attempt to connect to the existing service.

Use --no-driver command-line option to skip loading the kernel module. This option will only work for certain commands or modules.

Use ``-m --module`` to run a specific module (e.g. security check, a tool or a PoC..):

    - ``# python chipsec_main.py -m common.bios_wp``
    - ``# python chipsec_main.py -m common.spi_lock``
    - ``# python chipsec_main.py -m common.smrr``

- You can also use CHIPSEC to access various hardware resources:

    ``# python chipsec_util.py``
    
Running in Shell
----------------

**Basic usage**

``# python chipsec_main.py``

``# python chipsec_util.py``

**For help, run**

``# python chipsec_main.py --help``

``# python chipsec_util.py --help``

Using as a Python Package
-------------------------

Install CHIPSEC manually or from PyPI. You can then use CHIPSEC from your Python project or from the Python shell:

To install and run CHIPSEC as a package:

``# python setup.py install``

``# sudo chipsec_main``

From the Python shell:

>>> import chipsec_main
>>> chipsec_main.main()
>>> chipsec_main.main(['-m','common.bios_wp'])

>>> import chipsec_util
>>> chipsec_util.main()
>>> chipsec_util.main(['spi','info'])

To use CHIPSEC *in place* without installing it:

``# python setup.py build_ext -i``

``# sudo python chipsec_main.py``

chipsec_main options
--------------------

::

   usage: chipsec_main.py [options]

   Options:
     -h, --help                      Show this message and exit
     -m, --module _MODULE            Specify module to run (example: -m common.bios_wp)
     -a, --module_args _MODULE_ARGV  Additional module arguments
     -v, --verbose                   Verbose mode
     -vv, --vverbose                 Very verbose HAL debug mode
     --hal                           HAL mode
     -d, --debug                     Debug mode
     -l, --log  LOG                  Output to log file

   Advanced Options:
     -p, --platform _PLATFORM            Explicitly specify platform code
     --pch _PCH                          Explicitly specify PCH code
     -n, --no_driver                     Chipsec won't need kernel mode functions so don't load chipsec driver
     -i, --ignore_platform               Run chipsec even if the platform is not recognized (not recommended)
     -j, --json _JSON_OUT                Specify filename for JSON output
     -x, --xml _XML_OUT                  Specify filename for xml output (JUnit style)
     -k, --markdown                      Specify filename for markdown output
     -t, --moduletype USER_MODULE_TAGS   Run tests of a specific type (tag)
     --list_tags                         List all the available options for -t,--moduletype
     -I, --include IMPORT_PATHS          Specify additional path to load modules from
     --failfast                          Fail on any exception and exit (don't mask exceptions)
     --no_time                           Don't log timestamps
     --deltas _DELTAS_FILE               Specifies a JSON log file to compute result deltas from
     --record _TO_FILE                   Run chipsec and clone helper results into JSON file
     --replay _FROM_FILE                 Replay a chipsec run with JSON file
     --helper _HELPER                    Specify OS Helper
     -nb, --no_banner                    Chipsec won't display banner information
     --skip_config                       Skip configuration and driver loading

chipsec_util options
--------------------

::

   usage: chipsec_util.py [options] <command>

   Options:
     -h, --help                   Show this message and exit
     -v, --verbose                Verbose mode
     --hal                        HAL mode
     -d, --debug                  Debug mode
     -l, --log  LOG               Output to log file
     -p, --platform _PLATFORM     Explicitly specify platform code
     --pch _PCH                   Explicitly specify PCH code
     -n, --no_driver              Chipsec won't need kernel mode functions so don't load chipsec driver
     -i, --ignore_platform        Run chipsec even if the platform is not recognized (not recommended)
     Command _CMD                 Util command to run
     Command _ARGS                All numeric values are in hex <width> is in {1 - byte, 2 - word, 4 - dword}